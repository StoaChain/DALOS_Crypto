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
 * SCOPE NOTE (v4.0.2, F-MED-018): the six `from*` entry points in this
 * module are **DALOS-default** — they accept an optional `Ellipse` curve
 * parameter for the keypair derivation, but the returned `standardAddress`
 * and `smartAddress` ALWAYS use DALOS Genesis prefixes (`Ѻ.` / `Σ.`)
 * regardless of the curve passed in. The keypair (`scalar`, `privateKey`,
 * `keyPair.publ`) IS correctly per-curve; only the human-readable address
 * prefix is hardcoded.
 *
 * For non-DALOS curves (LETO, ARTEMIS, APOLLO, or any future Gen-N
 * primitive), use the **registry-mediated path** instead:
 *
 * ```typescript
 * import { CryptographicRegistry } from '@stoachain/dalos-crypto/registry';
 * import { Apollo } from '@stoachain/dalos-crypto/registry';
 *
 * const registry = new CryptographicRegistry();
 * registry.register(Apollo);
 * const apollo = registry.get('dalos-apollo');
 * const fullKey = apollo.generateFromBitString(bitString);
 * // fullKey.standardAddress now correctly starts with '₱.' (APOLLO),
 * // not 'Ѻ.' (DALOS).
 * ```
 *
 * The registry adapter at `../registry/gen1-factory.ts:103-104`
 * re-stamps the addresses with each primitive's correct prefix pair
 * (defined in `../registry/<primitive>.ts`). This is the canonical
 * pattern — the only known production consumer (OuronetUI's
 * `src/lib/dalos/registry.ts`) uses exactly this approach.
 *
 * The gen1 entry points stay DALOS-default by design: gen1 = curve-
 * agnostic crypto math; per-curve display prefixes are a registry-layer
 * concern. Mirrors the architectural boundary documented for the
 * Bitmap helpers (F-API-006 / F-TEST-002).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Bitmap } from './bitmap.js';
import { bitmapToBitString, validateBitmap } from './bitmap.js';
import { DALOS_ELLIPSE, type Ellipse, extended2Affine } from './curve.js';
import { InvalidBitStringError, InvalidBitmapError, InvalidPrivateKeyError } from './errors.js';
import { affineToPublicKey, dalosAddressMaker, seedWordsToBitString } from './hashing.js';
import {
  bigIntToBase49,
  digitValueBase49,
  isValidBase49Char,
  scalarMultiplierWithGenerator,
} from './scalar-mult.js';

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
  // REQ-28: shape symmetry with PrivateKeyValidation + validateBitmap.
  // Populated on failure (length mismatch and/or non-binary character),
  // omitted on success.
  readonly reason?: string;
}

export function validateBitString(
  bitString: string,
  e: Ellipse = DALOS_ELLIPSE,
): BitStringValidation {
  const lengthOk = bitString.length === e.s;
  // PAT-002: always run the structure walk so both booleans reflect actual
  // measurements, matching Go's `(*Ellipse).ValidateBitString`
  // (Elliptic/KeyGeneration.go:190-208) which never short-circuits.
  let structureOk = true;
  let badChar = '';
  let badPos = -1;
  for (let i = 0; i < bitString.length; i++) {
    const ch = bitString[i]!;
    if (ch !== '0' && ch !== '1') {
      structureOk = false;
      badChar = ch;
      badPos = i;
      break;
    }
  }
  if (lengthOk && structureOk) {
    return { valid: true, lengthOk: true, structureOk: true };
  }
  let reason: string;
  if (!lengthOk && !structureOk) {
    reason = `length mismatch (got ${bitString.length}, expected ${e.s}) AND non-binary character "${badChar}" at position ${badPos}`;
  } else if (!lengthOk) {
    reason = `length mismatch: got ${bitString.length}, expected ${e.s}`;
  } else {
    reason = `non-binary character "${badChar}" at position ${badPos}`;
  }
  return { valid: false, lengthOk, structureOk, reason };
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
      // REQ-20 (F-API-007): reject mixed-validity inputs at the earliest
      // boundary. Without this, unknown characters (e.g. '!', '@', uppercase
      // past 'M') would silently accumulate as digit 0, producing a non-zero
      // bigint that downstream checks reject with a misleading "core bits
      // length" / "first bit not '1'" reason rather than the actual
      // "invalid base-49 character" cause.
      for (const ch of privateKey) {
        if (!isValidBase49Char(ch)) {
          return { valid: false, bitString: '', reason: `invalid base-49 character '${ch}'` };
        }
      }
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
  // REQ-28 (F-PERF-005 + F-ARCH-006): single validator call; the diagnostic
  // detail flows from `validateBitString`'s `reason` field instead of a dead
  // `${reason ? ` (${reason})` : ''}` placeholder that was always undefined.
  const v = validateBitString(bitString, e);
  if (!v.valid) {
    // F-MED-008 (v4.0.2): typed error so consumers can `catch (e) { if
    // (e instanceof InvalidBitStringError) ... }` instead of message-
    // string sniffing.
    throw new InvalidBitStringError(
      `generateScalarFromBitString: invalid bitstring (length ${bitString.length}, expected ${e.s}): ${v.reason ?? 'unknown validation failure'}`,
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
    // F-MED-008 (v4.0.2): typed error.
    throw new InvalidPrivateKeyError(
      `scalarToPrivateKey: invalid scalar (${v.reason ?? 'unknown'})`,
    );
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
  // v4.0.0 Phase 5: use the curve's own Modular helper (populated at
  // construction). Eliminates the v1.2.0-era pattern of allocating a fresh
  // `new Modular(e.p)` per call — `e.field` is the canonical bind that
  // makes the per-curve modulus contract structural rather than vigilance-
  // dependent.
  const m = e.field;
  const ext = scalarMultiplierWithGenerator(scalar, e);
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
 *
 * SCOPE NOTE (v4.0.2, F-MED-018): the returned `standardAddress` and
 * `smartAddress` use DALOS Genesis prefixes (`Ѻ.` / `Σ.`) regardless
 * of which curve `e` is passed. The keypair derivation (`scalar`,
 * `privateKey`, `publ`) IS correctly per-curve; only the human-
 * readable address prefix character is DALOS-default by design. See
 * the module docstring above for the registry-mediated workaround for
 * non-DALOS curves.
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
    // F-MED-018 (v4.0.2): DALOS-prefixed by design. For per-curve
    // prefix-stamping use the registry — see module docstring.
    standardAddress: dalosAddressMaker(publ, false),
    smartAddress: dalosAddressMaker(publ, true),
  };
}

// ============================================================================
// Six public entry points
// ============================================================================

/**
 * Path 1 — cryptographically-random 1600 bits.
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
 */
export function fromRandom(e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  return fullKeyFromBitString(generateRandomBitsOnCurve(e), e);
}

/**
 * Path 2 — user-provided 1600-bit bitstring ("01…").
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
 */
export function fromBitString(bitString: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  return fullKeyFromBitString(bitString, e);
}

/**
 * Path 3 — user-provided base-10 integer representation of the
 * already-clamped scalar (the "int10" private-key form).
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
 */
export function fromIntegerBase10(n: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validatePrivateKey(n, 10, e);
  if (!v.valid) {
    // F-MED-008 (v4.0.2): typed error.
    throw new InvalidPrivateKeyError(
      `fromIntegerBase10: invalid private key (${v.reason ?? 'unknown'})`,
    );
  }
  return fullKeyFromBitString(v.bitString, e);
}

/**
 * Path 4 — user-provided base-49 integer representation of the
 * already-clamped scalar (the "int49" private-key form).
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
 */
export function fromIntegerBase49(n: string, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validatePrivateKey(n, 49, e);
  if (!v.valid) {
    // F-MED-008 (v4.0.2): typed error.
    throw new InvalidPrivateKeyError(
      `fromIntegerBase49: invalid private key (${v.reason ?? 'unknown'})`,
    );
  }
  return fullKeyFromBitString(v.bitString, e);
}

/**
 * Path 5 — UTF-8 seed words (any length, any Unicode content).
 *
 * The words are joined with single spaces and fed through seven-fold
 * Blake3 to derive the 1600-bit bitstring.
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
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
 *
 * F-MED-018: addresses are DALOS-prefixed regardless of `e`. See module
 * docstring for the registry-mediated workaround for non-DALOS curves.
 * Note: the bitmap input itself is also DALOS-only (40×40 = 1600 bits);
 * for non-DALOS curves with perfect-square scalar sizes (e.g. APOLLO
 * 32×32 = 1024), do consumer-side dimensioning and use `fromBitString`
 * — see OuronetUI's `src/lib/dalos/bitmap-local.ts` for the reference
 * pattern (F-TEST-002 scope decision).
 */
export function fromBitmap(b: Bitmap, e: Ellipse = DALOS_ELLIPSE): DalosFullKey {
  const v = validateBitmap(b);
  if (!v.valid) {
    // F-MED-008 (v4.0.2): typed error.
    throw new InvalidBitmapError(`fromBitmap: ${v.reason ?? 'invalid bitmap'}`);
  }
  return fullKeyFromBitString(bitmapToBitString(b), e);
}
