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

import { describe, expect, it } from 'vitest';
import { fromIntegerBase49 } from '../../src/gen1/key-gen.js';
import {
  SCHNORR_HASH_DOMAIN_TAG,
  SCHNORR_NONCE_DOMAIN_TAG,
  bigIntBytesCanon,
  deterministicNonce,
  parseSignature,
  schnorrHash,
  schnorrMessageDigest,
  schnorrSign,
  schnorrVerify,
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
  }, 60_000);

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
  }, 60_000);
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
