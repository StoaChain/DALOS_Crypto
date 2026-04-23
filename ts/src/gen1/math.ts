/**
 * Modular arithmetic over a prime field, matching the Go reference's
 * Elliptic/PointConverter.go (AddModulus, SubModulus, MulModulus,
 * QuoModulus) and Elliptic/PointOperations.go (AddModP, SubModP,
 * MulModP, QuoModP).
 *
 * Genesis invariant: every operation produces the same bigint as the
 * corresponding Go big.Int operation for equal inputs. Verified by
 * byte-identical address/key derivation in the test-vector corpus.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/** Constants used throughout the DALOS cryptographic stack. */
export const ZERO = 0n;
export const ONE = 1n;
export const TWO = 2n;

/**
 * Modular arithmetic helper. Wraps a prime modulus and exposes the
 * operations the Go reference's `(*Ellipse).AddModP` etc. use.
 *
 * Note: all operations canonicalise to the range [0, p). JavaScript's
 * `%` operator can return negative results for negative operands; we
 * normalise to match Go's `Mod` (which returns [0, |m|) when the
 * modulus is positive).
 */
export class Modular {
  public readonly p: bigint;

  constructor(p: bigint) {
    if (p <= ZERO) {
      throw new Error('Modular.p must be positive');
    }
    this.p = p;
  }

  /** Canonical form in [0, p). Handles negative inputs. */
  canon(a: bigint): bigint {
    const r = a % this.p;
    return r < ZERO ? r + this.p : r;
  }

  /** (a + b) mod p. */
  add(a: bigint, b: bigint): bigint {
    return this.canon(a + b);
  }

  /** (a - b) mod p, always in [0, p). */
  sub(a: bigint, b: bigint): bigint {
    return this.canon(a - b);
  }

  /** (a * b) mod p. */
  mul(a: bigint, b: bigint): bigint {
    return this.canon(a * b);
  }

  /** -a mod p. */
  neg(a: bigint): bigint {
    return this.canon(-a);
  }

  /** Modular inverse via extended Euclidean (returns a^-1 mod p). */
  inv(a: bigint): bigint {
    const ac = this.canon(a);
    if (ac === ZERO) {
      throw new Error('Modular.inv: cannot invert 0');
    }
    // Extended Euclidean algorithm.
    let [oldR, r] = [ac, this.p];
    let [oldS, s] = [ONE, ZERO];
    while (r !== ZERO) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    if (oldR !== ONE) {
      throw new Error('Modular.inv: gcd(a, p) != 1 — a is not invertible');
    }
    return this.canon(oldS);
  }

  /** (a / b) mod p = a * b^-1 mod p. */
  div(a: bigint, b: bigint): bigint {
    return this.mul(a, this.inv(b));
  }

  /** (a ^ e) mod p, using square-and-multiply. e must be non-negative. */
  exp(a: bigint, e: bigint): bigint {
    if (e < ZERO) {
      throw new Error('Modular.exp: negative exponent not supported (use inv + pos exp)');
    }
    let result = ONE;
    let base = this.canon(a);
    let exp = e;
    while (exp > ZERO) {
      if ((exp & ONE) === ONE) {
        result = this.mul(result, base);
      }
      base = this.mul(base, base);
      exp >>= ONE;
    }
    return result;
  }
}

/**
 * Convert a byte array (big-endian, as Go's big.Int.Bytes() produces)
 * into a bigint.
 */
export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let n = ZERO;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

/**
 * Convert a bigint to a minimal big-endian byte array (no leading
 * zeros), matching Go's big.Int.Bytes(). Non-negative values only.
 * Zero returns an empty Uint8Array (same as Go).
 */
export function bigIntToBytesBE(n: bigint): Uint8Array {
  if (n < ZERO) {
    throw new Error('bigIntToBytesBE: negative bigint not supported');
  }
  if (n === ZERO) {
    return new Uint8Array(0);
  }
  const hex = n.toString(16);
  const padded = hex.length % 2 === 1 ? `0${hex}` : hex;
  const out = new Uint8Array(padded.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = padded.slice(i * 2, i * 2 + 2);
    out[i] = Number.parseInt(byte, 16);
  }
  return out;
}

/**
 * Parse a base-10 decimal string into a bigint. Matches Go's
 * big.Int.SetString(s, 10).
 */
export function parseBase10(s: string): bigint {
  if (!/^-?\d+$/.test(s)) {
    throw new Error(`parseBase10: invalid decimal string "${s}"`);
  }
  return BigInt(s);
}
