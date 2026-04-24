/**
 * DALOS Key Generation API — the user-facing surface for producing
 * Ouronet account keys from any of the six Genesis input types.
 *
 * Mirrors the high-level flow in `Elliptic/KeyGeneration.go`:
 *
 *          random / bitstring / int10 / int49 / seed words / bitmap
 *                           │
 *                           ▼   (input-specific reshape or hash)
 *                           │
 *                      1600-bit bitstring
 *                           │
 *                           ▼   (clamping: "1" + bits + cofactor-tail)
 *                           │
 *                        scalar (bigint)
 *                           │
 *                           ▼   (scalar · G)
 *                           │
 *                    affine public-key point
 *                           │
 *                           ▼   (AffineToPublicKey encoding)
 *                           │
 *             public key string    priv (int49)    priv (int10)    priv (bitstring)
 *                           │
 *                           ▼   (seven-fold Blake3 → 16×16 matrix)
 *                           │
 *             standard address ("Ѻ.xxx")   smart address ("Σ.xxx")
 *
 * Phase 4 exit criterion: EVERY address-bearing vector in
 * `../testvectors/v1_genesis.json` reproduces all fields byte-for-byte
 * when replayed through this module.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Bitmap } from './bitmap.js';
import { bitmapToBitString, validateBitmap } from './bitmap.js';
import { DALOS_ELLIPSE, type Ellipse, extended2Affine } from './curve.js';
import { affineToPublicKey, dalosAddressMaker, seedWordsToBitString } from './hashing.js';
import { Modular } from './math.js';
import { bigIntToBase49, scalarMultiplierWithGenerator } from './scalar-mult.js';

// ============================================================================
// Types
// ============================================================================

/**
 * A DALOS key pair — the minimal pair of strings stored / exchanged
 * for a given account. Matches Go's `DalosKeyPair`.
 */
export interface DalosKeyPair {
  /** Private key in base-49 representation (~285 chars for 1604-bit scalar). */
  readonly priv: string;
  /** Public key in `"{prefixLen}.{xyBase49}"` format. */
  readonly publ: string;
}

/**
 * Three representations of a DALOS private key. Matches Go's
 * `DalosPrivateKey`.
 */
export interface DalosPrivateKey {
  /** Core 1600-bit bitstring (the value the user "sees" / types / draws). */
  readonly bitString: string;
  /** Scalar as a decimal string (1604-bit scalar → ~483-digit decimal). */
  readonly int10: string;
  /** Scalar in base-49 (~285 chars). */
  readonly int49: string;
}

/**
 * A fully-materialised DALOS account: key pair + private-key
 * representations + both address forms. This is the object returned
 * by all six `from*` API entry points.
 */
export interface DalosFullKey {
  readonly privateKey: DalosPrivateKey;
  readonly keyPair: DalosKeyPair;
  readonly scalar: bigint;
  readonly standardAddress: string;
  readonly smartAddress: string;
}

// ============================================================================
// Validators
// ============================================================================

/**
 * Validates a raw bitstring: must have exactly `e.s` characters
 * (1600 for DALOS Genesis), each '0' or '1'.
 *
 * Returns a result tuple matching Go's `(total, length, structure)`
 * triple so callers can diagnose which check failed.
 */
export interface BitStringValidation {
  readonly valid: boolean;
  readonly lengthOk: boolean;
  readonly structureOk: boolean;
}

export function validateBitString(
  bitString: string,
  e: Ellipse = DALOS_ELLIPSE,
): BitStringValidation {
  const lengthOk = bitString.length === e.s;
  let structureOk = true;
  for (const ch of bitString) {
    if (ch !== '0' && ch !== '1') {
      structureOk = false;
      break;
    }
  }
  return { valid: lengthOk && structureOk, lengthOk, structureOk };
}

/**
 * Validates an integer-encoded private key and extracts the core
 * 1600-bit bitstring.
 *
 * Matches Go's `(*Ellipse).ValidatePrivateKey`:
 *   - Parse input as base-10 or base-49 bigint
 *   - Render in binary
 *   - Check: first char is '1'
 *   - Check: last two chars match cofactor's binary trailing two bits
 *     (cofactor = 4 → "100", so trailing two = "00")
 *   - Check: middle length == e.s (1600)
 *   - Return the middle 1600 chars as the bitstring
 */
export interface PrivateKeyValidation {
  readonly valid: boolean;
  readonly bitString: string;
  readonly reason?: string;
}

export function validatePrivateKey(
  privateKey: string,
  base: 10 | 49,
  e: Ellipse = DALOS_ELLIPSE,
): PrivateKeyValidation {
  let pk: bigint;
  try {
    if (base === 10) {
      if (!/^\d+$/.test(privateKey)) {
        return { valid: false, bitString: '', reason: 'invalid base-10 string' };
      }
      pk = BigInt(privateKey);
    } else {
      // Walk char-by-char via the base-49 alphabet semantics.
      pk = 0n;
      for (const ch of privateKey) {
        const v = digitValueBase49(ch);
        pk = pk * 49n + BigInt(v);
      }
    }
  } catch (err) {
    return { valid: false, bitString: '', reason: `parse error: ${err}` };
  }

  const binaryKey = pk.toString(2);
  if (binaryKey.length === 0 || binaryKey[0] !== '1') {
    return { valid: false, bitString: '', reason: 'first binary digit is not "1"' };
  }

  const cofactorBinary = e.r.toString(2);
  const cofactorTail = cofactorBinary.slice(-2);
  if (binaryKey.length < 2 || binaryKey.slice(-2) !== cofactorTail) {
    return {
      valid: false,
      bitString: '',
      reason: `last 2 bits must match cofactor tail "${cofactorTail}"`,
    };
  }

  const middleLength = binaryKey.length - cofactorBinary.length;
  if (middleLength !== e.s) {
    return {
      valid: false,
      bitString: '',
      reason: `core bits length ${middleLength} != safe-scalar size ${e.s}`,
    };
  }

  const bitString = binaryKey.slice(1, binaryKey.length - (cofactorBinary.length - 1));
  return { valid: true, bitString };
}

// Internal: base-49 digit map. Imported lazily to avoid circular deps.
function digitValueBase49(c: string): number {
  const code = c.charCodeAt(0);
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 122) return code - 97 + 10;
  if (code >= 65 && code <= 77) return code - 65 + 36;
  return 0;
}

// ============================================================================
// Core pipeline
// ============================================================================

/**
 * Generate a cryptographically-random 1600-bit bitstring.
 *
 * Uses Web Crypto (`globalThis.crypto.getRandomValues`) on 200 bytes
 * of entropy, rendered as a 1600-char `"01…"` string.
 *
 * Matches Go's `(*Ellipse).GenerateRandomBitsOnCurve` in *output shape*
 * (the exact bit pattern is non-deterministic by design, so no test
 * vector matches this function; end-to-end tests use fixed bitstrings
 * instead).
 */
export function generateRandomBitsOnCurve(e: Ellipse = DALOS_ELLIPSE): string {
  // Byte-align the randomness draw. DALOS has s=1600 → 200 bytes
  // exactly (back-compat preserved). Historical curves with
  // non-byte-aligned safe-scalars (LETO s=545, ARTEMIS s=1023) round up
  // to the next whole byte; the surplus bits above `e.s` are trimmed
  // below so the returned string is exactly `e.s` chars long.
  const bytesNeeded = Math.ceil(e.s / 8);
  const buf = new Uint8Array(bytesNeeded);
  globalThis.crypto.getRandomValues(buf);
  let out = '';
  for (const b of buf) {
    out += b.toString(2).padStart(8, '0');
  }
  // Trim off any excess bits introduced by ceiling — take the low `e.s`
  // bits (right-most, consistent with big-endian bigint interpretation).
  if (out.length > e.s) {
    out = out.slice(out.length - e.s);
  }
  return out;
}

/**
 * Apply DALOS clamping to a 1600-bit bitstring and produce a scalar.
 *
 * Clamping builds: `"1" + bitString + <cofactor-binary-minus-leading-1>`
 *   - For DALOS, cofactor R = 4 = `"100"`, trimmed = `"00"`, so
 *     the final binary is `"1" + 1600 bits + "00"` (1603 bits total)
 *   - Parse as bigint in base 2 → scalar
 *
 * Matches Go's `(*Ellipse).GenerateScalarFromBitString`.
 */
export function generateScalarFromBitString(bitString: string, e: Ellipse = DALOS_ELLIPSE): bigint {
  const { valid, reason } = {
    ...validateBitString(bitString, e),
    reason: undefined as string | undefined,
  };
  if (!valid) {
    const v = validateBitString(bitString, e);
    throw new Error(
      `generateScalarFromBitString: invalid bitstring (length ${bitString.length}, expected ${e.s}): ${v.lengthOk ? 'structure' : 'length'} check failed${reason ? ` (${reason})` : ''}`,
    );
  }

  const cofactorBinary = e.r.toString(2);
  const cofactorTrimmed = cofactorBinary.slice(1); // trim leading '1'
  const finalBinary = `1${bitString}${cofactorTrimmed}`;
  return BigInt(`0b${finalBinary}`);
}

/**
 * Extract the three private-key representations from a scalar.
 *
 * Matches Go's `(*Ellipse).ScalarToPrivateKey`:
 *   - Render scalar as base-10 decimal
 *   - Validate structure (first '1', last two bits match cofactor tail)
 *   - Extract middle bits → bitString
 *   - Render scalar as base-10 and base-49 strings
 */
export function scalarToPrivateKey(scalar: bigint, e: Ellipse = DALOS_ELLIPSE): DalosPrivateKey {
  const int10 = scalar.toString(10);
  const v = validatePrivateKey(int10, 10, e);
  if (!v.valid) {
    throw new Error(`scalarToPrivateKey: invalid scalar (${v.reason ?? 'unknown'})`);
  }
  return {
    bitString: v.bitString,
    int10,
    int49: bigIntToBase49(scalar),
  };
}

/**
 * Compute `scalar · G` and encode the resulting affine point as a
 * DALOS public-key string.
 *
 * Matches Go's `(*Ellipse).ScalarToPublicKey`.
 */
export function scalarToPublicKey(scalar: bigint, e: Ellipse = DALOS_ELLIPSE): string {
  // v1.2.0: thread a curve-specific Modular so historical curves (with
  // different P) don't silently fall back to DALOS_FIELD. DALOS's own
  // path is unchanged — e.p === DALOS_ELLIPSE.p produces an equivalent
  // Modular instance.
  const m = new Modular(e.p);
  const ext = scalarMultiplierWithGenerator(scalar, e, m);
  const aff = extended2Affine(ext, m);
  return affineToPublicKey(aff);
}

/**
 * Produce a complete key pair from a scalar: private (base-49) and
 * public (encoded string).
 *
 * Matches Go's `(*Ellipse).ScalarToKeys`.
 */
export function scalarToKeyPair(scalar: bigint, e: Ellipse = DALOS_ELLIPSE): DalosKeyPair {
  const priv = scalarToPrivateKey(scalar, e);
  return {
    priv: priv.int49,
    publ: scalarToPublicKey(scalar, e),
  };
}

// ============================================================================
// Full pipeline (internal)
// ============================================================================

/**
 * Runs the full pipeline from a validated bitstring to a DalosFullKey.
 * Shared by every `from*` entry point once they've reduced input to
 * a 1600-bit bitstring.
 */
function fullKeyFromBitString(bitString: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const scalar = generateScalarFromBitString(bitString, e);
  const privateKey = scalarToPrivateKey(scalar, e);
  const publ = scalarToPublicKey(scalar, e);
  const keyPair: DalosKeyPair = { priv: privateKey.int49, publ };
  return {
    privateKey,
    keyPair,
    scalar,
    standardAddress: dalosAddressMaker(publ, false),
    smartAddress: dalosAddressMaker(publ, true),
  };
}

// ============================================================================
// Six public entry points
// ============================================================================

/**
 * Path 1 — cryptographically-random 1600 bits.
 */
export function fromRandom(e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  return fullKeyFromBitString(generateRandomBitsOnCurve(e), e);
}

/**
 * Path 2 — user-provided 1600-bit bitstring ("01…").
 */
export function fromBitString(bitString: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  return fullKeyFromBitString(bitString, e);
}

/**
 * Path 3 — user-provided base-10 integer representation of the
 * already-clamped scalar (the "int10" private-key form).
 */
export function fromIntegerBase10(n: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validatePrivateKey(n, 10, e);
  if (!v.valid) {
    throw new Error(`fromIntegerBase10: invalid private key (${v.reason ?? 'unknown'})`);
  }
  return fullKeyFromBitString(v.bitString, e);
}

/**
 * Path 4 — user-provided base-49 integer representation of the
 * already-clamped scalar (the "int49" private-key form).
 */
export function fromIntegerBase49(n: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validatePrivateKey(n, 49, e);
  if (!v.valid) {
    throw new Error(`fromIntegerBase49: invalid private key (${v.reason ?? 'unknown'})`);
  }
  return fullKeyFromBitString(v.bitString, e);
}

/**
 * Path 5 — UTF-8 seed words (any length, any Unicode content).
 *
 * The words are joined with single spaces and fed through seven-fold
 * Blake3 to derive the 1600-bit bitstring.
 */
export function fromSeedWords(words: readonly string[], e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const bits = seedWordsToBitString(words, e);
  return fullKeyFromBitString(bits, e);
}

/**
 * Path 6 — 40×40 bitmap.
 *
 * Black pixels = 1, white = 0, row-major top-to-bottom, left-to-right
 * scan. Equivalent to `fromBitString(bitmapToBitString(b))`.
 */
export function fromBitmap(b: Bitmap, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validateBitmap(b);
  if (!v.valid) {
    throw new Error(`fromBitmap: ${v.reason ?? 'invalid bitmap'}`);
  }
  return fullKeyFromBitString(bitmapToBitString(b), e);
}
