/**
 * Phase 1 frontend-fixes — ergonomic alias wrappers (gen1).
 *
 * Covers the six plain-string-friendly exports added at v3.0.3:
 *   - textToBitString / bitStringToText (UTF-8 ↔ MSB-first bitstring)
 *   - sign / verify (thin wrappers over schnorrSign / schnorrVerify)
 *   - encrypt / decrypt (UTF-8 → AES-256-GCM round-trip)
 *
 * RED-phase note: tests target `../../src/gen1/aliases.ts`, which is
 * a stub at the time these tests are written. Every assertion MUST
 * fail with a thrown `Error('not implemented')` from the stub —
 * never a "Cannot find module" collection-phase abort.
 */

import { describe, expect, it } from 'vitest';
import {
  bitStringToText,
  decrypt,
  encrypt,
  sign,
  textToBitString,
  verify,
} from '../../src/gen1/aliases.ts';
import { fromRandom } from '../../src/gen1/key-gen.ts';

// ============================================================================
// textToBitString
// ============================================================================

describe('textToBitString', () => {
  it('encodes a single ASCII character to 8-bit MSB-first', () => {
    expect(textToBitString('A')).toBe('01000001');
  });

  it('returns empty string for empty input', () => {
    expect(textToBitString('')).toBe('');
  });

  it('encodes multi-byte UTF-8 char to bytes*8 bits', () => {
    // "é" = U+00E9 → UTF-8 [0xC3, 0xA9] → 2 bytes → 16 bits
    const out = textToBitString('é');
    expect(out.length).toBe(16);
    expect(out).toBe('1100001110101001');
  });

  it('round-trips a multi-byte UTF-8 string via bitStringToText', () => {
    const original = 'héllo 世界';
    const recovered = bitStringToText(textToBitString(original));
    expect(recovered).toBe(original);
  });
});

// ============================================================================
// bitStringToText
// ============================================================================

describe('bitStringToText', () => {
  it('decodes "01000001" back to "A"', () => {
    expect(bitStringToText('01000001')).toBe('A');
  });

  it('throws verbatim message for length not divisible by 8', () => {
    expect(() => bitStringToText('0100000')).toThrow(
      'bitStringToText: input must be a 0/1 string of length divisible by 8',
    );
  });

  it('throws verbatim message for non-binary characters', () => {
    expect(() => bitStringToText('0100000X')).toThrow(
      'bitStringToText: input must be a 0/1 string of length divisible by 8',
    );
  });
});

// ============================================================================
// sign / verify
// ============================================================================

describe('sign / verify', () => {
  it('round-trips a plain string message via fromRandom keypair', () => {
    const fullKey = fromRandom();
    const message = 'hello world';
    const sig = sign(fullKey.keyPair, message);
    expect(verify(sig, message, fullKey.keyPair.publ)).toBe(true);
  });
});

// ============================================================================
// encrypt / decrypt
// ============================================================================

describe('encrypt / decrypt', () => {
  it('round-trips a plain ASCII string', async () => {
    const plaintext = 'secret message';
    const password = 'pw';
    const ct = await encrypt(plaintext, password);
    const recovered = await decrypt(ct, password);
    expect(recovered).toBe(plaintext);
  });

  it('round-trips a multi-byte UTF-8 string', async () => {
    const plaintext = 'héllo 世界';
    const password = 'pw';
    const ct = await encrypt(plaintext, password);
    const recovered = await decrypt(ct, password);
    expect(recovered).toBe(plaintext);
  });

  it('rejects empty plaintext (round-trip would lose the empty-string distinction)', async () => {
    await expect(encrypt('', 'pw')).rejects.toThrow(/encrypt: empty plaintext is not supported/);
  });
});
