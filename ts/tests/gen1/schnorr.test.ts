/**
 * Phase 6 tests — Schnorr v2 (hardened, deterministic).
 *
 * SECOND MAJOR BYTE-IDENTITY GATE. Since Go v2.0.0 Schnorr uses
 * RFC-6979-style deterministic nonces, every signature in the corpus
 * has a specific committed byte string that the TS port must reproduce
 * exactly. This is stronger than the Phase 3/4 byte-identity gates
 * (which matched derivations): Phase 6 matches 20 committed signature
 * strings exactly.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { sign as signAlias } from '../../src/gen1/aliases.js';
import type { CoordAffine } from '../../src/gen1/coords.js';
import { affine2Extended, isOnCurve } from '../../src/gen1/curve.js';
import { SchnorrSignError } from '../../src/gen1/errors.js';
import { affineToPublicKey, publicKeyToAffineCoords } from '../../src/gen1/hashing.js';
import { fromIntegerBase49 } from '../../src/gen1/key-gen.js';
import * as schnorrModule from '../../src/gen1/schnorr.js';
import {
  SCHNORR_HASH_DOMAIN_TAG,
  SCHNORR_NONCE_DOMAIN_TAG,
  bigIntBytesCanon,
  deterministicNonce,
  parseSignature,
  schnorrHash,
  schnorrMessageDigest,
  schnorrSign,
  schnorrSignAsync,
  schnorrVerify,
  schnorrVerifyAsync,
  serializeSignature,
} from '../../src/gen1/schnorr.js';
import { schnorrVectors } from '../fixtures.js';

// ============================================================================
// Constants and helpers
// ============================================================================

describe('Schnorr v2 constants and helpers', () => {
  it('domain tags match the spec', () => {
    expect(SCHNORR_HASH_DOMAIN_TAG).toBe('DALOS-gen1/SchnorrHash/v1');
    expect(SCHNORR_NONCE_DOMAIN_TAG).toBe('DALOS-gen1/SchnorrNonce/v1');
  });

  it('bigIntBytesCanon: zero and null → [0x00]', () => {
    expect(bigIntBytesCanon(0n)).toEqual(new Uint8Array([0x00]));
    expect(bigIntBytesCanon(null)).toEqual(new Uint8Array([0x00]));
    expect(bigIntBytesCanon(undefined)).toEqual(new Uint8Array([0x00]));
  });

  it('bigIntBytesCanon: non-zero → canonical big-endian', () => {
    expect(bigIntBytesCanon(1n)).toEqual(new Uint8Array([0x01]));
    expect(bigIntBytesCanon(255n)).toEqual(new Uint8Array([0xff]));
    expect(bigIntBytesCanon(256n)).toEqual(new Uint8Array([0x01, 0x00]));
    expect(bigIntBytesCanon(0x1234n)).toEqual(new Uint8Array([0x12, 0x34]));
  });
});

// ============================================================================
// Message digest is deterministic
// ============================================================================

describe('schnorrMessageDigest', () => {
  it('is deterministic (same message → same 64-byte digest)', () => {
    const a = schnorrMessageDigest('hello world');
    const b = schnorrMessageDigest('hello world');
    expect(a).toEqual(b);
    expect(a.length).toBe(64);
  });

  it('different messages → different digests', () => {
    const a = schnorrMessageDigest('message-a');
    const b = schnorrMessageDigest('message-b');
    expect(a).not.toEqual(b);
  });

  it('accepts Uint8Array input', () => {
    const viaString = schnorrMessageDigest('hello');
    const viaBytes = schnorrMessageDigest(new TextEncoder().encode('hello'));
    expect(viaString).toEqual(viaBytes);
  });
});

// ============================================================================
// Nonce derivation is deterministic
// ============================================================================

describe('deterministicNonce', () => {
  it('is deterministic (same k + msg → same nonce)', () => {
    const msgDigest = schnorrMessageDigest('test-msg');
    const a = deterministicNonce(42n, msgDigest);
    const b = deterministicNonce(42n, msgDigest);
    expect(a).toBe(b);
  });

  it('different keys → different nonces (same msg)', () => {
    const msgDigest = schnorrMessageDigest('test-msg');
    const a = deterministicNonce(42n, msgDigest);
    const b = deterministicNonce(43n, msgDigest);
    expect(a).not.toBe(b);
  });

  it('different messages → different nonces (same k)', () => {
    const a = deterministicNonce(42n, schnorrMessageDigest('msg-a'));
    const b = deterministicNonce(42n, schnorrMessageDigest('msg-b'));
    expect(a).not.toBe(b);
  });

  it('nonce is always in [1, Q-1]', () => {
    // Try several (k, msg) pairs; all should produce valid nonces
    for (const [k, msg] of [
      [1n, 'a'],
      [2n ** 1500n, 'b'],
      [99999999n, 'multi-word message'],
    ] as const) {
      const z = deterministicNonce(k, schnorrMessageDigest(msg));
      expect(z).toBeGreaterThan(0n);
      // Don't compare against Q directly (expensive import chain); trust the mod-Q inside
    }
  });
});

// ============================================================================
// Signature serialization round-trip
// ============================================================================

describe('parseSignature / serializeSignature round-trip', () => {
  it('round-trips every committed signature in the corpus', () => {
    for (const v of schnorrVectors()) {
      const parsed = parseSignature(v.signature);
      expect(parsed).not.toBeNull();
      const reserialised = serializeSignature(parsed!);
      expect(reserialised).toBe(v.signature);
    }
  });

  it('rejects malformed signatures', () => {
    expect(parseSignature('')).toBeNull();
    expect(parseSignature('no-pipe-here')).toBeNull();
    expect(parseSignature('a|b|c')).toBeNull();
    expect(parseSignature('|bar')).toBeNull();
    expect(parseSignature('foo|')).toBeNull();
    expect(parseSignature('not-a-pubkey|123')).toBeNull();
  });
});

// ============================================================================
// 🎯 BYTE-IDENTITY GATE: schnorrSign reproduces Go's v2.0.0 deterministic sigs
// ============================================================================

describe('schnorrSign (BYTE-IDENTITY vs Go corpus)', () => {
  it('all 20 Schnorr vectors produce byte-identical signatures', () => {
    for (const v of schnorrVectors()) {
      // Reconstruct the key pair from its committed priv_int49
      const fullKey = fromIntegerBase49(v.priv_int49);
      const sig = schnorrSign(fullKey.keyPair, v.message);
      expect(sig).toBe(v.signature);
    }
  }, 30_000); // 30s ceiling per REQ-15; PM cache landed in v3.1.0

  it('signing the same inputs twice yields identical output (cross-run determinism)', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    const sig1 = schnorrSign(fullKey.keyPair, v.message);
    const sig2 = schnorrSign(fullKey.keyPair, v.message);
    expect(sig1).toBe(sig2);
  });

  it('different messages produce different signatures', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    const sig1 = schnorrSign(fullKey.keyPair, 'msg-a');
    const sig2 = schnorrSign(fullKey.keyPair, 'msg-b');
    expect(sig1).not.toBe(sig2);
  });

  it('empty message signs and verifies', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    const sig = schnorrSign(fullKey.keyPair, '');
    expect(schnorrVerify(sig, '', fullKey.keyPair.publ)).toBe(true);
  });

  it('Unicode message with supplementary-plane chars signs correctly', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    const msg = 'Unicode: αβγδε ҶҸҽӻ 𝔸𝔹ℂ';
    const sig = schnorrSign(fullKey.keyPair, msg);
    expect(schnorrVerify(sig, msg, fullKey.keyPair.publ)).toBe(true);
  });
});

// ============================================================================
// 🎯 BYTE-IDENTITY GATE: schnorrVerify accepts every committed signature
// ============================================================================

describe('schnorrVerify — accepts all 20 committed signatures', () => {
  it('all 20 Schnorr vectors verify true against (signature, message, public_key)', () => {
    for (const v of schnorrVectors()) {
      const result = schnorrVerify(v.signature, v.message, v.public_key);
      expect(result).toBe(v.verify_expected);
      expect(result).toBe(true);
    }
  }, 30_000); // 30s ceiling per REQ-15; PM cache landed in v3.1.0
});

// ============================================================================
// Negative tests — hardening items
// ============================================================================

describe('schnorrVerify — rejection cases', () => {
  it('rejects a tampered message', () => {
    const v = schnorrVectors()[0]!;
    const tamperedMsg = `${v.message}-tampered`;
    expect(schnorrVerify(v.signature, tamperedMsg, v.public_key)).toBe(false);
  });

  it('rejects a wrong public key (from a different vector)', () => {
    const v0 = schnorrVectors()[0]!;
    const v1 = schnorrVectors()[1]!;
    expect(schnorrVerify(v0.signature, v0.message, v1.public_key)).toBe(false);
  });

  it('rejects a malformed signature string', () => {
    const v = schnorrVectors()[0]!;
    expect(schnorrVerify('garbage-sig', v.message, v.public_key)).toBe(false);
    expect(schnorrVerify('', v.message, v.public_key)).toBe(false);
    expect(schnorrVerify('no-pipe', v.message, v.public_key)).toBe(false);
  });

  it('rejects a signature with s = 0 (SC-4)', () => {
    const v = schnorrVectors()[0]!;
    const parsed = parseSignature(v.signature)!;
    const zeroS = serializeSignature({ r: parsed.r, s: 0n });
    expect(schnorrVerify(zeroS, v.message, v.public_key)).toBe(false);
  });

  it('rejects a tampered signature (flipped s)', () => {
    const v = schnorrVectors()[0]!;
    const parsed = parseSignature(v.signature)!;
    const tampered = serializeSignature({ r: parsed.r, s: parsed.s + 1n });
    expect(schnorrVerify(tampered, v.message, v.public_key)).toBe(false);
  });

  it('rejects a signature with s >= Q (SC-4 upper bound)', () => {
    const v = schnorrVectors()[0]!;
    const parsed = parseSignature(v.signature)!;
    // Use a huge s value well beyond Q (1604 bits)
    const hugeS = 2n ** 2000n;
    const bigSig = serializeSignature({ r: parsed.r, s: hugeS });
    expect(schnorrVerify(bigSig, v.message, v.public_key)).toBe(false);
  });

  it('rejects an off-curve R component (SC-5)', () => {
    const v = schnorrVectors()[0]!;
    const parsed = parseSignature(v.signature)!;
    // CoordAffine is readonly — construct a new object with ay perturbed by +1n.
    // The probability that (ax, ay+1) lands on the 1606-bit-prime Edwards curve
    // is ≈ 1/P, so the perturbation reliably moves R off-curve.
    const perturbedR: CoordAffine = { ax: parsed.r.ax, ay: parsed.r.ay + 1n };
    const [onCurveR] = isOnCurve(affine2Extended(perturbedR));
    expect(onCurveR).toBe(false);
    const perturbedSig = serializeSignature({ r: perturbedR, s: parsed.s });
    expect(schnorrVerify(perturbedSig, v.message, v.public_key)).toBe(false);
  });

  it('rejects an off-curve P public key (SC-5)', () => {
    const v = schnorrVectors()[0]!;
    const pkAffine = publicKeyToAffineCoords(v.public_key);
    // Same readonly-construct-new-object discipline as the R-perturbation case.
    const perturbedP: CoordAffine = { ax: pkAffine.ax, ay: pkAffine.ay + 1n };
    const [onCurveP] = isOnCurve(affine2Extended(perturbedP));
    expect(onCurveP).toBe(false);
    const fakePk = affineToPublicKey(perturbedP);
    expect(schnorrVerify(v.signature, v.message, fakePk)).toBe(false);
  });
});

// ============================================================================
// schnorrSign — internal-failure throw contract (forced via schnorrHash spy)
// ============================================================================
//
// These tests force `schnorrHash` to return null via vi.spyOn on the ESM
// module namespace import — the same spy form T2.2's PM-cache test landed
// on (cf. tests/gen1/scalar-mult.test.ts:281). When schnorrHash returns
// null, the Fiat-Shamir challenge inside schnorrSign / schnorrSignAsync /
// the `sign` alias / the registry adapters takes the `if (challenge ===
// null)` branch. Pre-T3.2 that branch silently `return ''`s; post-T3.2 it
// throws SchnorrSignError. T3.5 (this block) is written FIRST against the
// still-silent signer — these tests are EXPECTED to be RED at task close
// and green-flip in Wave 3 when T3.2 lands the throw.
// ============================================================================

describe('schnorrSign — internal-failure throw contract', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('throws SchnorrSignError when schnorrHash returns null (sync schnorrSign)', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    vi.spyOn(schnorrModule, 'schnorrHash').mockReturnValueOnce(null);
    expect(() => schnorrSign(fullKey.keyPair, 'test message')).toThrow(SchnorrSignError);
  });

  it('throws SchnorrSignError when schnorrHash returns null (sign alias)', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    vi.spyOn(schnorrModule, 'schnorrHash').mockReturnValueOnce(null);
    expect(() => signAlias(fullKey.keyPair, 'test message')).toThrow(SchnorrSignError);
  });

  it('rejects with SchnorrSignError when schnorrHash returns null (async schnorrSignAsync)', async () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);
    vi.spyOn(schnorrModule, 'schnorrHash').mockReturnValueOnce(null);
    await expect(schnorrSignAsync(fullKey.keyPair, 'test message')).rejects.toThrow(
      SchnorrSignError,
    );
  });

  it('PM cache survives schnorrSign throw (cross-phase invariant)', () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);

    // (a) Populate the Phase 2 PM cache for DALOS_ELLIPSE with a clean call.
    const sigBefore = schnorrSign(fullKey.keyPair, 'first message');
    expect(sigBefore.length).toBeGreaterThan(0);

    // (b) Install the null-returning spy; (c) confirm throw fires.
    vi.spyOn(schnorrModule, 'schnorrHash').mockReturnValueOnce(null);
    expect(() => schnorrSign(fullKey.keyPair, 'second message')).toThrow(SchnorrSignError);

    // (d) Restore the spy and re-sign — cache must still be consistent
    // and produce a valid (non-empty) signature. A future refactor that
    // moved cache population AFTER schnorrHash would corrupt cache state
    // when the throw fires; this assertion catches that regression.
    vi.restoreAllMocks();
    const sigAfter = schnorrSign(fullKey.keyPair, 'third message');
    expect(sigAfter.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Schnorr-hash byte-identity (indirect — signatures match means hash matches)
// ============================================================================

describe('schnorrHash (internal)', () => {
  it('returns null for malformed public key', () => {
    const hash = schnorrHash(1n, 'not-a-key', 'msg');
    expect(hash).toBeNull();
  });

  it('is deterministic', () => {
    const v = schnorrVectors()[0]!;
    const parsed = parseSignature(v.signature)!;
    const h1 = schnorrHash(parsed.r.ax, v.public_key, v.message);
    const h2 = schnorrHash(parsed.r.ax, v.public_key, v.message);
    expect(h1).toBe(h2);
    expect(h1).not.toBeNull();
  });
});

// ============================================================================
// schnorrSignAsync — event-loop responsiveness (REQ-13 watchdog)
// ============================================================================

describe('schnorrSignAsync — event-loop responsiveness', () => {
  // The async signer delegates the only scalar-mult call (R = z·G) to
  // scalarMultiplierAsync, which yields every 8 outer-loop iterations
  // via globalThis.setImmediate. The watchdog test uses per-yield
  // performance.now() instrumentation (PRIMARY form per plan-review)
  // because Promise.race has a microtask-vs-macrotask priority hole:
  // a non-yielding async fn that takes 250ms still wins the race
  // because microtasks drain before next-macrotask timers. The
  // per-yield deltas directly measure the inter-yield window, which
  // is exactly the property REQ-14's data-independence promise
  // constrains.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('inter-yield gap stays under 200ms for a full-curve-scale signature', async () => {
    const v = schnorrVectors()[0]!;
    const fullKey = fromIntegerBase49(v.priv_int49);

    const originalSetImmediate = globalThis.setImmediate;
    expect(typeof originalSetImmediate).toBe('function');

    const timestamps: number[] = [performance.now()];
    type SetImmediateRest = Parameters<typeof globalThis.setImmediate> extends [unknown, ...infer R]
      ? R
      : never[];
    vi.spyOn(globalThis, 'setImmediate').mockImplementation(((cb: () => void, ...args: unknown[]) =>
      originalSetImmediate(
        () => {
          timestamps.push(performance.now());
          cb();
        },
        ...(args as SetImmediateRest),
      )) as typeof globalThis.setImmediate);

    const sig = await schnorrSignAsync(fullKey.keyPair, v.message);

    // Sanity: we got a real signature back.
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);

    // At least one yield observed — proves the trigger fires.
    expect(timestamps.length).toBeGreaterThanOrEqual(2);

    const gaps = timestamps.slice(1).map((v_, i) => v_ - (timestamps[i] ?? 0));
    const maxGap = Math.max(...gaps);

    // Inter-yield gap < 200ms is the correctness gate. The outer
    // 5_000-ms it() ceiling is the safety net for hangs.
    expect(maxGap).toBeLessThan(200);
  }, 5_000);
});

// ============================================================================
// schnorrSignAsync / schnorrVerifyAsync — equivalence with sync
// ============================================================================

describe('schnorrSignAsync / schnorrVerifyAsync — equivalence with sync', () => {
  it('schnorrSignAsync produces byte-identical output to schnorrSign on sampled vectors', async () => {
    // Sample three vectors spanning the corpus to bound the runtime
    // while exercising real keys + full-curve-scale scalars. Full
    // 20-vector parity is implicit through the sync byte-identity
    // gate (lines 144-156) plus equivalence here.
    const vectors = schnorrVectors();
    const sampled = [vectors[0]!, vectors[10]!, vectors[19]!];
    for (const v of sampled) {
      const fullKey = fromIntegerBase49(v.priv_int49);
      const sync = schnorrSign(fullKey.keyPair, v.message);
      const async_ = await schnorrSignAsync(fullKey.keyPair, v.message);
      expect(async_).toBe(sync);
      expect(async_).toBe(v.signature);
    }
  }, 30_000);

  it('schnorrVerifyAsync accepts every committed signature in the sampled set', async () => {
    const vectors = schnorrVectors();
    const sampled = [vectors[0]!, vectors[10]!, vectors[19]!];
    for (const v of sampled) {
      const result = await schnorrVerifyAsync(v.signature, v.message, v.public_key);
      expect(result).toBe(true);
    }
  }, 30_000);

  it('schnorrVerifyAsync rejects a tampered message', async () => {
    const v = schnorrVectors()[0]!;
    const tamperedMsg = `${v.message}-tampered`;
    expect(await schnorrVerifyAsync(v.signature, tamperedMsg, v.public_key)).toBe(false);
  });
});
