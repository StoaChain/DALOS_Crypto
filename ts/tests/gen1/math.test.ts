/**
 * Tests for the Modular arithmetic helper — the foundation of every
 * higher-level computation.
 */

import { describe, expect, it } from 'vitest';
import { Modular, bigIntToBytesBE, bytesToBigIntBE, parseBase10 } from '../../src/gen1/math.js';

describe('Modular', () => {
  const m = new Modular(97n); // small prime for readable tests

  it('canonicalises negative and large values', () => {
    expect(m.canon(0n)).toBe(0n);
    expect(m.canon(5n)).toBe(5n);
    expect(m.canon(97n)).toBe(0n);
    expect(m.canon(98n)).toBe(1n);
    expect(m.canon(-1n)).toBe(96n);
    expect(m.canon(-100n)).toBe(94n); // -100 mod 97 = -3 → 94
  });

  it('add / sub / mul / neg all produce canonical results', () => {
    expect(m.add(50n, 50n)).toBe(3n);
    expect(m.sub(3n, 50n)).toBe(50n);
    expect(m.mul(10n, 12n)).toBe(120n % 97n);
    expect(m.neg(5n)).toBe(92n);
  });

  it('inv(a) · a ≡ 1 (mod p) for every a in [1, p-1]', () => {
    for (let a = 1n; a < 97n; a++) {
      const ai = m.inv(a);
      expect(m.mul(a, ai)).toBe(1n);
    }
  });

  it('inv(0) throws', () => {
    expect(() => m.inv(0n)).toThrow();
  });

  it('div(a, b) = a · inv(b) mod p', () => {
    expect(m.div(6n, 2n)).toBe(3n);
    expect(m.div(10n, 3n)).toBe(m.mul(10n, m.inv(3n)));
  });

  it('exp computes modular exponentiation', () => {
    expect(m.exp(2n, 10n)).toBe(1024n % 97n);
    expect(m.exp(5n, 0n)).toBe(1n);
    // Fermat: a^(p-1) ≡ 1 mod p for gcd(a, p) = 1
    expect(m.exp(3n, 96n)).toBe(1n);
  });

  it('rejects non-positive modulus', () => {
    expect(() => new Modular(0n)).toThrow();
    expect(() => new Modular(-5n)).toThrow();
  });
});

describe('Modular — DALOS-sized modulus', () => {
  // Use the DALOS prime to ensure our implementation scales to 1606-bit ops.
  const P = (1n << 1605n) + 2315n;
  const m = new Modular(P);

  it('handles 1606-bit multiplication round-trip', () => {
    const a = (1n << 1000n) + 42n;
    const b = (1n << 1100n) + 7n;
    const c = m.mul(a, b);
    const cPrime = m.mul(b, a);
    expect(c).toBe(cPrime); // commutativity
  });

  it('computes inverses of large operands', () => {
    const a = (1n << 500n) + 1234567n;
    const ai = m.inv(a);
    expect(m.mul(a, ai)).toBe(1n);
  });
});

describe('byte/bigint conversion helpers', () => {
  it('bytesToBigIntBE / bigIntToBytesBE round-trip', () => {
    const samples = [0n, 1n, 255n, 256n, (1n << 256n) - 1n, (1n << 1000n) + 42n];
    for (const n of samples) {
      const bytes = bigIntToBytesBE(n);
      const nBack = bytesToBigIntBE(bytes);
      expect(nBack).toBe(n);
    }
  });

  it('bigIntToBytesBE produces no leading zeros (matches Go big.Int.Bytes())', () => {
    expect(bigIntToBytesBE(0n)).toEqual(new Uint8Array([]));
    expect(bigIntToBytesBE(1n)).toEqual(new Uint8Array([1]));
    expect(bigIntToBytesBE(255n)).toEqual(new Uint8Array([255]));
    expect(bigIntToBytesBE(256n)).toEqual(new Uint8Array([1, 0]));
  });

  it('rejects negative input', () => {
    expect(() => bigIntToBytesBE(-1n)).toThrow();
  });
});

describe('parseBase10', () => {
  it('accepts valid decimals', () => {
    expect(parseBase10('0')).toBe(0n);
    expect(parseBase10('42')).toBe(42n);
    expect(parseBase10('-17')).toBe(-17n);
    expect(parseBase10('123456789012345678901234567890')).toBe(123456789012345678901234567890n);
  });

  it('rejects invalid strings', () => {
    expect(() => parseBase10('abc')).toThrow();
    expect(() => parseBase10('12.5')).toThrow();
    expect(() => parseBase10('')).toThrow();
  });
});
