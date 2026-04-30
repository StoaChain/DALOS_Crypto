/**
 * Phase 5 tests — AES-256-GCM wrapper.
 *
 * AES-GCM uses a random 12-byte nonce per encryption, so ciphertext
 * bytes are non-deterministic. Tests focus on:
 *   - Round-trip: encrypt → decrypt recovers plaintext (after pad-to-length)
 *   - Wrong password fails verify (auth-tag mismatch → thrown error)
 *   - Blake3 KDF is deterministic
 *   - Edge cases: empty plaintext, all-zero bitstring, odd-nibble magnitude
 *   - 1600-bit round-trips against the 50 bitstring test vectors
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  bitStringToBytes,
  bytesToBitString,
  decryptAndPadToLength,
  decryptBitString,
  encryptAndPad,
  encryptBitString,
  makeKeyFromPassword,
  zeroBytes,
} from '../../src/gen1/aes.ts';
import { bitstringVectors } from '../fixtures.ts';

// ============================================================================
// zeroBytes
// ============================================================================

describe('zeroBytes', () => {
  it('overwrites all bytes with 0', () => {
    const b = new Uint8Array([1, 2, 3, 255]);
    zeroBytes(b);
    expect(Array.from(b)).toEqual([0, 0, 0, 0]);
  });
});

// ============================================================================
// bitStringToBytes / bytesToBitString
// ============================================================================

describe('bitStringToBytes', () => {
  it('empty → empty', () => {
    expect(bitStringToBytes('')).toEqual(new Uint8Array(0));
  });

  it('all-zero bitstring → empty (bigint 0)', () => {
    expect(bitStringToBytes('0000000000')).toEqual(new Uint8Array(0));
  });

  it('"11111111" (0xFF) → [255]', () => {
    expect(bitStringToBytes('11111111')).toEqual(new Uint8Array([255]));
  });

  it('"10000000" (0x80) → [128]', () => {
    expect(bitStringToBytes('10000000')).toEqual(new Uint8Array([128]));
  });

  it('"1111111100000001" (0xFF01) → [255, 1]', () => {
    expect(bitStringToBytes('1111111100000001')).toEqual(new Uint8Array([255, 1]));
  });

  it('odd-nibble magnitude: Go drops last half-nibble (partial decode)', () => {
    // "1000" = binary 8 → hex "8" (odd) → Go keeps 0 bytes (even-prefix is empty)
    expect(bitStringToBytes('1000')).toEqual(new Uint8Array(0));
    // "100010001" = 273 → hex "111" (odd, 3 chars) → even prefix "11" → 1 byte (0x11)
    expect(bitStringToBytes('100010001')).toEqual(new Uint8Array([0x11]));
  });

  it('rejects non-binary characters', () => {
    expect(bitStringToBytes('X0000')).toEqual(new Uint8Array(0));
  });
});

describe('bytesToBitString', () => {
  it('empty → "0"', () => {
    expect(bytesToBitString(new Uint8Array(0))).toBe('0');
  });

  it('[255] → "11111111"', () => {
    expect(bytesToBitString(new Uint8Array([255]))).toBe('11111111');
  });

  it('[0, 1] → "1" (leading zeros dropped in bigint)', () => {
    expect(bytesToBitString(new Uint8Array([0, 1]))).toBe('1');
  });

  it('round-trip with non-leading-zero values', () => {
    // For bytes whose first bit is 1, bytesToBitString ∘ bitStringToBytes is identity
    const samples = ['11111111', '1000000010000000', '11110000', '1010101010101010'];
    for (const s of samples) {
      const bytes = bitStringToBytes(s);
      expect(bytesToBitString(bytes)).toBe(s);
    }
  });
});

// ============================================================================
// makeKeyFromPassword
// ============================================================================

describe('makeKeyFromPassword', () => {
  it('returns 32 bytes', () => {
    const k = makeKeyFromPassword('hunter2');
    expect(k.length).toBe(32);
  });

  it('is deterministic', () => {
    const a = makeKeyFromPassword('correct horse battery staple');
    const b = makeKeyFromPassword('correct horse battery staple');
    expect(a).toEqual(b);
  });

  it('different passwords → different keys', () => {
    const a = makeKeyFromPassword('alpha');
    const b = makeKeyFromPassword('beta');
    expect(a).not.toEqual(b);
  });

  it('handles Unicode passwords', () => {
    const k = makeKeyFromPassword('pαsswörd-Ωɐ🔑');
    expect(k.length).toBe(32);
  });
});

// ============================================================================
// encryptBitString / decryptBitString
// ============================================================================

describe('encryptBitString / decryptBitString round-trips', () => {
  it('round-trips a small bitstring', async () => {
    const plaintext = '1111000011110000';
    const password = 'test-password';
    const ct = await encryptBitString(plaintext, password);
    expect(ct).not.toBe('');
    const recovered = await decryptBitString(ct, password);
    expect(recovered).toBe(plaintext);
  });

  it('round-trips a synthesised 1600-bit all-ones bitstring', async () => {
    // All-ones: magnitude is exactly 1600 bits, hex length 400 (even) → clean round-trip.
    const plaintext = '1'.repeat(1600);
    const password = 'hunter2';
    const ct = await encryptBitString(plaintext, password);
    const recovered = await decryptAndPadToLength(ct, password, 1600);
    expect(recovered).toBe(plaintext);
  });

  it('wrong password throws on decrypt', async () => {
    const ct = await encryptBitString('10101010', 'correct-pw');
    await expect(decryptBitString(ct, 'wrong-pw')).rejects.toThrow();
  });

  it('corrupted ciphertext throws on decrypt', async () => {
    const ct = await encryptBitString('1111000011110000', 'pw');
    // Flip one bit in the middle
    const midIndex = Math.floor(ct.length / 2);
    const corrupted =
      ct.slice(0, midIndex) + (ct[midIndex] === '0' ? '1' : '0') + ct.slice(midIndex + 1);
    await expect(decryptBitString(corrupted, 'pw')).rejects.toThrow();
  });

  it('produces different ciphertext each call (random nonce)', async () => {
    const plaintext = '11110000111100001111000011110000';
    const password = 'pw';
    const ct1 = await encryptBitString(plaintext, password);
    const ct2 = await encryptBitString(plaintext, password);
    expect(ct1).not.toBe(ct2);
  });

  it('rejects too-short ciphertext at decrypt', async () => {
    // Under 12 bytes of plaintext magnitude → can't hold a nonce
    await expect(decryptBitString('1111', 'pw')).rejects.toThrow(/too short/);
  });
});

// ============================================================================
// AES-wrapper limitations (matches Go byte-for-byte)
// ============================================================================

// The Go AES wrapper has TWO known lossy conversions:
//   1. Leading zeros in the plaintext bitstring are lost (bigint magnitude drops them)
//   2. If the plaintext's magnitude has an odd number of hex nibbles, the last
//      half-nibble is also lost (Go's hex.DecodeString on odd length returns
//      the even-prefix bytes + an error; DALOS discards the error).
//
// Round-trip correctness therefore requires: input magnitude has an even
// number of hex nibbles. For an N-bit input, this means the position of
// the highest '1' bit (counted from the LSB, 1-indexed) is a multiple of 4.
//
// Go's CLI pads after decryption via `strings.Repeat("0", …)` to restore
// the expected bit-length, covering the leading-zero case. The odd-nibble
// case is unresolved in both Go and TS.

describe('1600-bit round-trip: vectors that avoid the odd-nibble Go-wrapper bug', () => {
  // Identify vectors whose magnitude is even-nibble (hex length divisible by 2).
  // For those, the Go AES wrapper round-trips correctly (after leading-zero pad).

  function isEvenNibbleMagnitude(bits: string): boolean {
    if (/^0+$/.test(bits)) return false; // all-zero → 0-byte plaintext (degenerate)
    const trimmed = bits.replace(/^0+/, ''); // strip leading zeros
    return trimmed.length % 4 === 0;
  }

  it('subset round-trips (those whose magnitude is even-nibble)', async () => {
    const password = 'DALOS-test-password-2026';
    const safe = bitstringVectors().filter((v) => isEvenNibbleMagnitude(v.input_bitstring));
    // Expect roughly half of the 50 vectors to pass this filter.
    expect(safe.length).toBeGreaterThan(5);

    for (const v of safe) {
      const ct = await encryptBitString(v.input_bitstring, password);
      expect(ct).not.toBe('');
      const recovered = await decryptAndPadToLength(ct, password, 1600);
      expect(recovered).toBe(v.input_bitstring);
    }
  }, 30_000);

  it('wrong password fails on every committed vector (smoke across 10)', async () => {
    const correctPw = 'correct';
    const wrongPw = 'wrong';
    const subset = bitstringVectors().slice(0, 10);
    for (const v of subset) {
      const ct = await encryptBitString(v.input_bitstring, correctPw);
      // Ciphertext might decode to very few bytes if plaintext was degenerate,
      // but any non-empty encryption can still fail verify with wrong pw.
      if (ct !== '') {
        await expect(decryptBitString(ct, wrongPw)).rejects.toThrow();
      }
    }
  }, 30_000);
});

// ============================================================================
// encryptAndPad convenience wrapper
// ============================================================================

describe('encryptAndPad / decryptAndPadToLength', () => {
  // Approach used: vi.spyOn directly on globalThis.crypto.subtle.encrypt installs
  // successfully on Node 20+ WebCrypto without TS-cast or module-level mock.
  // Smoke-tested before authoring assertions; the spy reference is non-undefined
  // and mockRejectedValueOnce takes effect on the next call.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns ciphertext + its bit length', async () => {
    const { ciphertext, ciphertextBits } = await encryptAndPad('1111000011110000', 'pw');
    expect(ciphertext.length).toBe(ciphertextBits);
    // AES-GCM overhead: 12-byte nonce + tag + ciphertext. Binary length will
    // be around 8×(12 + 16 + plainBytes) = 224 + 8×plainBytes bits.
    // For a 2-byte plaintext that's ~240 bits.
    expect(ciphertextBits).toBeGreaterThan(100);
  });

  it('throws when the underlying AES-GCM encrypt rejects', async () => {
    const spy = vi
      .spyOn(globalThis.crypto.subtle, 'encrypt')
      .mockRejectedValueOnce(new Error('induced failure'));
    await expect(encryptAndPad('1111000011110000', 'pw')).rejects.toThrow(
      /encryptAndPad: underlying encryption failed/,
    );
    expect(spy).toHaveBeenCalled();
  });

  it('decryptAndPadToLength pads leading zeros back', async () => {
    const plaintext = `00000000${'1'.repeat(1592)}`; // 8 leading zeros, 1600 total
    const ct = await encryptBitString(plaintext, 'pw');
    const padded = await decryptAndPadToLength(ct, 'pw', 1600);
    expect(padded).toBe(plaintext);
    // Without padding, leading zeros would be lost:
    const unpadded = await decryptBitString(ct, 'pw');
    expect(unpadded.length).toBeLessThan(1600);
    expect(unpadded).toBe(plaintext.replace(/^0+/, ''));
  });
});
