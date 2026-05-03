/**
 * DALOS Schnorr v2 signature scheme — TypeScript port of
 * `Elliptic/Schnorr.go` in the Go reference at tag `v2.0.0`.
 *
 * v2 hardening (all seven audit findings resolved):
 *   SC-1  Length-prefixed Fiat–Shamir transcript
 *   SC-2  RFC-6979-style deterministic nonces via tagged Blake3 KDF
 *   SC-3  Domain-separation tags
 *   SC-4  Canonical s ∈ (0, Q) range check on verify
 *   SC-5  On-curve validation of R and P
 *   SC-6  Explicit error handling (no nil-deref risk)
 *   SC-7  Inherits constant-time scalar multiplication (Phase 2)
 *
 * Deterministic output: `SchnorrSign(key, message)` produces
 * byte-for-byte identical signatures across runs and across
 * implementations for the same inputs. This closes the Sony-PS3
 * random-nonce-reuse attack family at the API level.
 *
 * Signature format: `"{R-in-public-key-format}|{s-in-base49}"`
 *   where R is encoded via `affineToPublicKey` (length-prefixed X +
 *   base-49 concatenation of X and Y), and s is rendered in base 49
 *   directly. Both sides use `big.Int`/`BigInt` arithmetic for
 *   bit-identity with the Go reference.
 *
 * Reference spec: `../../docs/SCHNORR_V2_SPEC.md`.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { blake3SumCustom } from '../dalos-blake3/index.js';
import type { CoordAffine } from './coords.js';
import {
  DALOS_ELLIPSE,
  type Ellipse,
  affine2Extended,
  arePointsEqual,
  extended2Affine,
  isInfinityPoint,
  isOnCurve,
} from './curve.js';
import { SchnorrSignError } from './errors.js';
import { affineToPublicKey, parseBigIntInBase, publicKeyToAffineCoords } from './hashing.js';
import type { DalosKeyPair } from './key-gen.js';
import { bigIntToBytesBE, bytesToBigIntBE } from './math.js';
import { addition } from './point-ops.js';
import {
  bigIntToBase49,
  getOrBuildGeneratorPM,
  scalarMultiplier,
  scalarMultiplierAsync,
  scalarMultiplierWithGenerator,
} from './scalar-mult.js';
// Self-namespace re-import: routes the in-module `schnorrHash` reference
// through this module's exports object so test-time `vi.spyOn(schnorrModule,
// 'schnorrHash')` actually intercepts the call. Without this indirection,
// same-module local bindings are inlined and bypass the spy. The runtime
// cost is a single property lookup per sign — negligible relative to scalar
// multiplication. The throw-contract tests at tests/gen1/schnorr.test.ts
// rely on this seam.
import * as self from './schnorr.js';

// ============================================================================
// Constants
// ============================================================================

/** Domain-separation tag for the Fiat–Shamir challenge hash. */
export const SCHNORR_HASH_DOMAIN_TAG = 'DALOS-gen1/SchnorrHash/v1';

/** Domain-separation tag for the deterministic-nonce derivation. */
export const SCHNORR_NONCE_DOMAIN_TAG = 'DALOS-gen1/SchnorrNonce/v1';

/** Sub-tag appended to the nonce DST when hashing the message for nonce derivation. */
const SCHNORR_MSG_SUBTAG = '/msg';

const utf8 = new TextEncoder();

// ============================================================================
// Types
// ============================================================================

/**
 * A parsed Schnorr signature — internal structure used by
 * `parseSignature` / `serializeSignature`.
 */
export interface SchnorrSignature {
  readonly r: CoordAffine;
  readonly s: bigint;
}

// ============================================================================
// Internal helpers (match Go's helpers byte-for-byte)
// ============================================================================

/**
 * 4-byte big-endian length prefix followed by the data bytes.
 * Matches Go's `writeLenPrefixed` that uses
 * `binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))`.
 *
 * Exported for byte-pinning in unit tests (REQ-18). Wire-format helper
 * — internal callers should still prefer building the transcript via
 * the surrounding `schnorrHash` API.
 */
export function lenPrefixedConcat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += 4 + p.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const p of parts) {
    view.setUint32(offset, p.length, false); // false = big-endian
    offset += 4;
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Canonical big-endian byte encoding for a non-negative bigint.
 *
 * Matches Go's `bigIntBytesCanon`:
 *   - `nil` / zero → `[0x00]` (1-byte marker so the length prefix is
 *     well-defined even for the zero input)
 *   - otherwise `x.Bytes()` — canonical big-endian, no leading zeros
 */
export function bigIntBytesCanon(x: bigint | null | undefined): Uint8Array {
  if (x === null || x === undefined || x === 0n) {
    return new Uint8Array([0x00]);
  }
  return bigIntToBytesBE(x);
}

/** Encode a string-or-bytes message as UTF-8 bytes. */
function encodeMessage(message: string | Uint8Array): Uint8Array {
  return typeof message === 'string' ? utf8.encode(message) : message;
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize a `SchnorrSignature` to its canonical string form
 * `"{R-in-public-key-format}|{s-in-base49}"`.
 *
 * Matches Go's `ConvertSchnorrSignatureToString`.
 */
export function serializeSignature(sig: SchnorrSignature): string {
  const rString = affineToPublicKey(sig.r);
  const sString = bigIntToBase49(sig.s);
  return `${rString}|${sString}`;
}

/**
 * Parse a signature string into a `SchnorrSignature` struct.
 * Returns `null` on any format error (matches Go's v2.1.0 behaviour
 * where the caller treats a parse failure as a verification rejection).
 */
export function parseSignature(sigString: string): SchnorrSignature | null {
  const parts = sigString.split('|');
  if (parts.length !== 2) return null;
  const rPart = parts[0];
  const sPart = parts[1];
  if (rPart === undefined || sPart === undefined) return null;
  if (rPart.length === 0 || sPart.length === 0) return null;

  let r: CoordAffine;
  let s: bigint;
  try {
    r = publicKeyToAffineCoords(rPart);
    s = parseBigIntInBase(sPart, 49);
  } catch {
    return null;
  }
  return { r, s };
}

// ============================================================================
// Fiat–Shamir challenge hash
// ============================================================================

/**
 * Compute the Fiat–Shamir challenge `e = H(tag || R.x || P.x || P.y || m) mod Q`.
 *
 * Matches Go's `(*Ellipse).SchnorrHash` v2 exactly:
 *   - Length-prefixed transcript (SC-1)
 *   - Domain-separation tag (SC-3)
 *   - Blake3 XOF at `e.s / 8` bytes (200 bytes for DALOS)
 *   - Reduced mod Q to canonical (0, Q) range
 *
 * Returns `null` if the public key fails to parse — matches the Go v2.1.0
 * behaviour where `SchnorrHash` returns `nil` on pubkey-parse failure.
 */
export function schnorrHash(
  R: bigint,
  publicKey: string,
  message: string | Uint8Array,
  e: Ellipse = DALOS_ELLIPSE,
): bigint | null {
  let pkAffine: CoordAffine;
  try {
    pkAffine = publicKeyToAffineCoords(publicKey);
  } catch {
    return null;
  }
  if (pkAffine.ax === undefined || pkAffine.ay === undefined) return null;

  const transcript = lenPrefixedConcat([
    utf8.encode(SCHNORR_HASH_DOMAIN_TAG),
    bigIntBytesCanon(R),
    bigIntBytesCanon(pkAffine.ax),
    bigIntBytesCanon(pkAffine.ay),
    encodeMessage(message),
  ]);

  // Byte-align. DALOS s=1600 → 200 bytes exactly (back-compat
  // preserved). Historical curves (LETO s=545, ARTEMIS s=1023) use
  // Math.ceil; the reduction `hashInt % e.q` below naturally absorbs
  // the surplus bits, so this is safe and preserves determinism.
  const outputSize = Math.ceil(e.s / 8);
  const digest = blake3SumCustom(transcript, outputSize);

  const hashInt = bytesToBigIntBE(digest);
  return hashInt % e.q;
}

// ============================================================================
// Deterministic nonce derivation (RFC-6979-style, Blake3-adapted)
// ============================================================================

/**
 * Build the deterministic-nonce seed buffer:
 * `tag || 0x00 sentinel || canonical(k) || msgHash`.
 *
 * The 0x00 sentinel byte is the SC-2 length-extension defense: without
 * it, an attacker controlling k could craft (k_alt, m_alt) such that
 * `tag || canonical(k_alt) == tag || 0x00 || canonical(k)`, causing
 * nonce reuse across distinct inputs.
 *
 * Exported separately so the sentinel placement can be byte-pinned in
 * unit tests (REQ-18) — otherwise it's unobservable through the
 * `deterministicNonce` API, which only returns a single bigint.
 */
export function buildNonceSeed(
  tag: Uint8Array,
  k: bigint,
  msgHash: Uint8Array,
): Uint8Array {
  const kBytes = bigIntBytesCanon(k);
  const out = new Uint8Array(tag.length + 1 + kBytes.length + msgHash.length);
  out.set(tag, 0);
  out[tag.length] = 0x00; // SC-2 sentinel
  out.set(kBytes, tag.length + 1);
  out.set(msgHash, tag.length + 1 + kBytes.length);
  return out;
}

/**
 * Derive a deterministic nonce `z ∈ [1, Q-1]` from the private key and
 * a message digest. Matches Go's `(*Ellipse).deterministicNonce` exactly:
 *
 *   seed = TAG_NONCE || 0x00 || canonical(k) || msgHash
 *   expansion = Blake3_XOF(seed, 2 · S / 8)     // 400 bytes for DALOS
 *   z = bigint(expansion) mod Q
 *   if z == 0: z = 1                             // negligibly rare
 *
 * The 400-byte (double-width) expansion yields negligible modular bias
 * when reduced mod the 1604-bit Q — bias is ≤ 2^-(1596).
 */
export function deterministicNonce(
  k: bigint,
  messageHash: Uint8Array,
  e: Ellipse = DALOS_ELLIPSE,
): bigint {
  const tagBytes = utf8.encode(SCHNORR_NONCE_DOMAIN_TAG);
  const seed = buildNonceSeed(tagBytes, k, messageHash);

  // Byte-align. DALOS s=1600 → 400 bytes exactly (back-compat). For
  // non-byte-aligned safe-scalars (LETO s=545 → 137 bytes, ARTEMIS
  // s=1023 → 256 bytes) we round up; the surplus is absorbed by the
  // `% e.q` reduction below.
  const expansionSize = Math.ceil((2 * e.s) / 8);
  const expansion = blake3SumCustom(seed, expansionSize);

  let z = bytesToBigIntBE(expansion) % e.q;
  if (z === 0n) z = 1n;
  return z;
}

/**
 * Hash the message once (separately from the Fiat–Shamir challenge)
 * for nonce derivation. Matches Go:
 *
 *   msgHashInput = TAG_NONCE || "/msg" || message
 *   msgDigest = Blake3_XOF(msgHashInput, 64)
 */
export function schnorrMessageDigest(message: string | Uint8Array): Uint8Array {
  const msgBytes = encodeMessage(message);
  const tagBytes = utf8.encode(SCHNORR_NONCE_DOMAIN_TAG + SCHNORR_MSG_SUBTAG);
  const combined = new Uint8Array(tagBytes.length + msgBytes.length);
  combined.set(tagBytes, 0);
  combined.set(msgBytes, tagBytes.length);
  return blake3SumCustom(combined, 64);
}

// ============================================================================
// Sign
// ============================================================================

/**
 * Produce a DALOS Schnorr v2 signature over `message` using `keyPair`'s
 * private scalar.
 *
 * Deterministic: same (keyPair, message) always produces byte-identical
 * output. Signature format is the canonical `"{R-in-pubkey-form}|{s-base49}"`.
 *
 * @throws {SchnorrSignError} when the Fiat-Shamir challenge cannot be
 *   derived (typically caused by an unparseable public key in
 *   `keyPair.publ`). Catch via `instanceof SchnorrSignError`.
 */
export function schnorrSign(
  keyPair: DalosKeyPair,
  message: string | Uint8Array,
  e: Ellipse = DALOS_ELLIPSE,
): string {
  // v4.0.0 Phase 5 + origin v3.1.0 merge: use the curve's own Modular
  // helper (populated at construction time on the Ellipse interface).
  // The v1.2.0 fix threaded a curve-specific Modular through the arithmetic
  // helpers; v3.1.0 hoisted that into a per-Ellipse WeakMap cache via
  // `getModularFor`; Phase 5 superseded both with the structural `e.field`
  // property — same per-curve instance semantics, no separate cache needed
  // because `field` is computed once at curve construction and pinned to
  // the Ellipse object lifetime.
  const m = e.field;

  // Parse private key from base-49
  const k = parseBigIntInBase(keyPair.priv, 49);

  // Hash the message for nonce derivation
  const msgDigest = schnorrMessageDigest(message);

  // Deterministic nonce z ∈ [1, Q-1]
  const z = deterministicNonce(k, msgDigest, e);

  // R = z · G
  const rExtended = scalarMultiplierWithGenerator(z, e);
  const rAffine = extended2Affine(rExtended, m);
  const rX = rAffine.ax;

  // Fiat–Shamir challenge (may fail if pubkey unparseable). Routed through
  // `self.schnorrHash` so test-time spies intercept this call site.
  const challenge = self.schnorrHash(rX, keyPair.publ, message, e);
  if (challenge === null) {
    throw new SchnorrSignError(
      'Fiat-Shamir challenge produced null — likely caused by an unparseable public key in keyPair.publ',
    );
  }

  // s = (z + e·k) mod Q — canonical range (0, Q)
  let s = (challenge * k) % e.q;
  s = (s + z) % e.q;

  return serializeSignature({ r: rAffine, s });
}

// ============================================================================
// Verify
// ============================================================================

/**
 * Verify a DALOS Schnorr v2 signature. Returns `true` iff the signature
 * is well-formed, the components are on-curve and in-range, and the
 * verification equation `s·G = R + e·P` holds.
 *
 * Hardening (all v2 items active):
 *   - SC-4: rejects `s ≤ 0` or `s ≥ Q`
 *   - SC-5: rejects off-curve R or P
 *   - SC-6: explicit false returns on parse failure, nil components,
 *           addition failures, etc.
 */
export function schnorrVerify(
  signature: string,
  message: string | Uint8Array,
  publicKey: string,
  e: Ellipse = DALOS_ELLIPSE,
): boolean {
  // v4.0.0 Phase 5: use the curve's own Modular via the structural
  // `e.field` property — see schnorrSign for the merge-context rationale.
  const m = e.field;

  const sig = parseSignature(signature);
  if (sig === null) return false;

  // SC-6: nil-safety
  if (sig.r.ax === undefined || sig.r.ay === undefined) return false;

  // SC-4: canonical s range (0, Q)
  if (sig.s <= 0n || sig.s >= e.q) return false;

  // SC-5: R on curve
  const rExtended = affine2Extended(sig.r, m);
  const [onCurveR] = isOnCurve(rExtended, e);
  if (!onCurveR) return false;

  // F-SEC-001: cofactor subgroup-membership check on R.
  // Legitimate R = [k]·G has [4]·R = [4k]·G ≠ O (gcd(4, Q)=1, k ∈ [1, Q-1]).
  // Rejects order-4 small-subgroup attack points.
  const rCofactor = scalarMultiplier(e.r, rExtended, e);
  if (isInfinityPoint(rCofactor)) return false;

  // Parse public key
  let pkAffine: CoordAffine;
  try {
    pkAffine = publicKeyToAffineCoords(publicKey);
  } catch {
    return false;
  }
  if (pkAffine.ax === undefined || pkAffine.ay === undefined) return false;

  // SC-5: P on curve
  const pExtended = affine2Extended(pkAffine, m);
  const [onCurveP] = isOnCurve(pExtended, e);
  if (!onCurveP) return false;

  // F-SEC-001: cofactor subgroup-membership check on P (public key).
  // Same rationale as R — rejects order-4 small-subgroup attack public keys.
  const pCofactor = scalarMultiplier(e.r, pExtended, e);
  if (isInfinityPoint(pCofactor)) return false;

  // Fiat–Shamir challenge
  const challenge = schnorrHash(sig.r.ax, publicKey, message, e);
  if (challenge === null) return false;

  // Compute right term: R + e·P
  const ePExt = scalarMultiplier(challenge, pExtended, e);
  let rightTerm: ReturnType<typeof addition>;
  try {
    rightTerm = addition(rExtended, ePExt, e);
  } catch {
    return false;
  }

  // Compute left term: s·G
  const leftTerm = scalarMultiplierWithGenerator(sig.s, e);

  return arePointsEqual(leftTerm, rightTerm, e);
}

// ============================================================================
// Async sign / verify (browser-friendly)
// ============================================================================

/**
 * Async variant of `schnorrSign`. Delegates the scalar-multiplication
 * step to `scalarMultiplierAsync` (yields every 8 iterations,
 * data-independent). All other operations remain synchronous within
 * the async body.
 *
 * Use this in browser contexts to keep Interaction-to-Next-Paint (INP)
 * under 200 ms during full-curve-scale signing. The yield trigger
 * depends only on the scalar-mult outer-loop iteration index — never
 * on the scalar value or any secret-derived branch — so the
 * constant-time property of the sync path is preserved.
 *
 * Output is byte-identical to `schnorrSign(keyPair, message, e)` for
 * the same inputs (deterministic v2 RFC-6979-style nonces).
 *
 * @throws {SchnorrSignError} (rejected promise) when the Fiat-Shamir
 *   challenge cannot be derived (typically caused by an unparseable
 *   public key in `keyPair.publ`). Catch via `instanceof SchnorrSignError`.
 */
export async function schnorrSignAsync(
  keyPair: DalosKeyPair,
  message: string | Uint8Array,
  e: Ellipse = DALOS_ELLIPSE,
): Promise<string> {
  // Phase 5: structural `e.field` instead of the eliminated DALOS_FIELD/m
  // default-param footgun. Origin v3.1.0 used a separate WeakMap cache
  // (`getModularFor`); same per-curve instance semantics — see schnorrSign.
  const m = e.field;

  const k = parseBigIntInBase(keyPair.priv, 49);

  const msgDigest = schnorrMessageDigest(message);

  const z = deterministicNonce(k, msgDigest, e);

  // R = z · G — the only async delegation. The cached generator-PM
  // (populated lazily via getOrBuildGeneratorPM) is threaded through
  // scalarMultiplierAsync's `precomputed` parameter so the matrix is
  // built at most once per curve across both sync and async callers.
  const rExtended = await scalarMultiplierAsync(
    z,
    affine2Extended(e.g, m),
    e,
    getOrBuildGeneratorPM(e),
  );
  const rAffine = extended2Affine(rExtended, m);
  const rX = rAffine.ax;

  // Routed through `self.schnorrHash` so test-time spies intercept (mirrors
  // the sync site above).
  const challenge = self.schnorrHash(rX, keyPair.publ, message, e);
  if (challenge === null) {
    throw new SchnorrSignError(
      'Fiat-Shamir challenge produced null — likely caused by an unparseable public key in keyPair.publ',
    );
  }

  let s = (challenge * k) % e.q;
  s = (s + z) % e.q;

  return serializeSignature({ r: rAffine, s });
}

/**
 * Async variant of `schnorrVerify`. Delegates the scalar-multiplication
 * steps to `scalarMultiplierAsync` (yields every 8 iterations,
 * data-independent). All other operations remain synchronous within
 * the async body.
 *
 * Use this in browser contexts to keep Interaction-to-Next-Paint (INP)
 * under 200 ms during full-curve-scale verification. The yield trigger
 * depends only on the scalar-mult outer-loop iteration index — never
 * on the scalar value or any secret-derived branch — so the
 * constant-time property of the sync path is preserved.
 *
 * The `e·P` call rebuilds the per-`P` PrecomputeMatrix on every
 * invocation (P varies per call); the `s·G` call hits the cached
 * generator-PM via `getOrBuildGeneratorPM`.
 */
export async function schnorrVerifyAsync(
  signature: string,
  message: string | Uint8Array,
  publicKey: string,
  e: Ellipse = DALOS_ELLIPSE,
): Promise<boolean> {
  // Phase 5: structural `e.field`. See schnorrSign for merge rationale.
  const m = e.field;

  const sig = parseSignature(signature);
  if (sig === null) return false;

  if (sig.r.ax === undefined || sig.r.ay === undefined) return false;

  // SC-4: canonical s range (0, Q)
  if (sig.s <= 0n || sig.s >= e.q) return false;

  // SC-5: R on curve
  const rExtended = affine2Extended(sig.r, m);
  const [onCurveR] = isOnCurve(rExtended, e);
  if (!onCurveR) return false;

  // F-SEC-001 (Phase 6): cofactor subgroup-membership check on R — security
  // parity with the sync `schnorrVerify` path. Origin v3.1.0 added the
  // async surface BEFORE Phase 6 landed; without this check the async
  // verifier would accept order-4 small-subgroup attack signatures the
  // sync verifier rejects. Same construction: legitimate R = [k]·G has
  // [4]·R = [4k]·G ≠ O (gcd(4, Q) = 1, k ∈ [1, Q-1]).
  const rCofactor = scalarMultiplier(e.r, rExtended, e);
  if (isInfinityPoint(rCofactor)) return false;

  let pkAffine: CoordAffine;
  try {
    pkAffine = publicKeyToAffineCoords(publicKey);
  } catch {
    return false;
  }
  if (pkAffine.ax === undefined || pkAffine.ay === undefined) return false;

  // SC-5: P on curve
  const pExtended = affine2Extended(pkAffine, m);
  const [onCurveP] = isOnCurve(pExtended, e);
  if (!onCurveP) return false;

  // F-SEC-001 (Phase 6): cofactor subgroup-membership check on P — same
  // rationale as R above; rejects order-4 small-subgroup public keys.
  const pCofactor = scalarMultiplier(e.r, pExtended, e);
  if (isInfinityPoint(pCofactor)) return false;

  const challenge = schnorrHash(sig.r.ax, publicKey, message, e);
  if (challenge === null) return false;

  // e·P — async, no PM cache reuse (P varies per call).
  const ePExt = await scalarMultiplierAsync(challenge, pExtended, e);
  let rightTerm: ReturnType<typeof addition>;
  try {
    rightTerm = addition(rExtended, ePExt, e);
  } catch {
    return false;
  }

  // s·G — async, hits the cached generator-PM via getOrBuildGeneratorPM.
  const leftTerm = await scalarMultiplierAsync(
    sig.s,
    affine2Extended(e.g, m),
    e,
    getOrBuildGeneratorPM(e),
  );

  return arePointsEqual(leftTerm, rightTerm, e);
}
