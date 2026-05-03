/**
 * Phase 2 tests — base-49 Horner scalar multiplication.
 *
 * The critical test is `scalarMultiplier(Q, G) === O`: this is a full
 * 1604-bit scalar multiplication that produces the identity point if
 * and only if G has the prime order Q that `Elliptic/Parameters.go`
 * claims. Passing it is strong evidence that both the scalar-mult
 * algorithm AND the underlying point operations are correct.
 *
 * Other tests cover small-scalar identities that catch transcription
 * errors in the base-49 Horner evaluation.
 */

import { describe, expect, it } from 'vitest';
import { INFINITY_POINT_EXTENDED } from '../../src/gen1/coords.js';
import {
  DALOS_ELLIPSE,
  affine2Extended,
  arePointsEqual,
  extended2Affine,
  isOnCurve,
} from '../../src/gen1/curve.js';
import { addition, doubling, fortyNiner, tripling } from '../../src/gen1/point-ops.js';
import {
  BASE49_ALPHABET,
  bigIntToBase49,
  digitValueBase49,
  scalarMultiplier,
  scalarMultiplierWithGenerator,
} from '../../src/gen1/scalar-mult.js';

const G = affine2Extended(DALOS_ELLIPSE.g, DALOS_ELLIPSE.field);

describe('base-49 alphabet', () => {
  it('has exactly 49 characters', () => {
    expect(BASE49_ALPHABET).toHaveLength(49);
  });

  it('matches the Go big.Int.Text(49) alphabet order', () => {
    expect(BASE49_ALPHABET).toBe('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM');
  });

  it('has no duplicate characters', () => {
    const set = new Set(BASE49_ALPHABET);
    expect(set.size).toBe(49);
  });
});

describe('digitValueBase49', () => {
  it('maps 0-9 to 0-9', () => {
    for (let v = 0; v <= 9; v++) {
      expect(digitValueBase49(String(v))).toBe(v);
    }
  });

  it('maps a-z to 10-35', () => {
    for (let v = 10; v <= 35; v++) {
      const ch = BASE49_ALPHABET[v];
      expect(ch).toBeDefined();
      expect(digitValueBase49(ch!)).toBe(v);
    }
  });

  it('maps A-M to 36-48', () => {
    for (let v = 36; v <= 48; v++) {
      const ch = BASE49_ALPHABET[v];
      expect(ch).toBeDefined();
      expect(digitValueBase49(ch!)).toBe(v);
    }
  });

  it('returns 0 for invalid characters (Go default case)', () => {
    expect(digitValueBase49('N')).toBe(0); // above 'M' in ASCII
    expect(digitValueBase49('Z')).toBe(0);
    expect(digitValueBase49('!')).toBe(0);
    expect(digitValueBase49(' ')).toBe(0);
  });

  it('consistent with BASE49_ALPHABET indexing', () => {
    for (let v = 0; v < 49; v++) {
      const ch = BASE49_ALPHABET[v];
      expect(ch).toBeDefined();
      expect(digitValueBase49(ch!)).toBe(v);
    }
  });
});

describe('bigIntToBase49', () => {
  it('0 → "0"', () => {
    expect(bigIntToBase49(0n)).toBe('0');
  });

  it('1..48 → single-digit base-49 (reverse of BASE49_ALPHABET)', () => {
    for (let v = 0; v < 49; v++) {
      expect(bigIntToBase49(BigInt(v))).toBe(BASE49_ALPHABET[v]);
    }
  });

  it('49 → "10"', () => {
    expect(bigIntToBase49(49n)).toBe('10');
  });

  it('48*49 + 48 = 2400 → "MM"', () => {
    expect(bigIntToBase49(2400n)).toBe('MM');
  });

  it('round-trip: every small scalar converts and parses identically', () => {
    for (let i = 0n; i < 500n; i++) {
      const s = bigIntToBase49(i);
      // Reverse: parse base-49 string back
      let back = 0n;
      for (const ch of s) {
        back = back * 49n + BigInt(digitValueBase49(ch));
      }
      expect(back).toBe(i);
    }
  });

  it('rejects negative input', () => {
    expect(() => bigIntToBase49(-1n)).toThrow();
  });

  it('handles large scalars (Q-sized)', () => {
    const big = DALOS_ELLIPSE.q;
    const s = bigIntToBase49(big);
    // Expected length: ceil(1604 * log(2) / log(49)) ≈ 285 digits
    expect(s.length).toBeGreaterThan(280);
    expect(s.length).toBeLessThan(290);
    // First character must be non-zero (no leading zeros)
    expect(s[0]).not.toBe('0');
  });
});

describe('scalarMultiplier — small-scalar identities', () => {
  it('scalarMultiplier(0, G) === INFINITY', () => {
    const result = scalarMultiplier(0n, G);
    expect(arePointsEqual(result, INFINITY_POINT_EXTENDED)).toBe(true);
  });

  it('scalarMultiplier(1, G) === G', () => {
    const result = scalarMultiplier(1n, G);
    expect(arePointsEqual(result, G)).toBe(true);
  });

  it('scalarMultiplier(2, G) === doubling(G) === addition(G, G)', () => {
    const via2 = scalarMultiplier(2n, G);
    const viaDbl = doubling(G);
    const viaAdd = addition(G, G);
    expect(arePointsEqual(via2, viaDbl)).toBe(true);
    expect(arePointsEqual(via2, viaAdd)).toBe(true);
  });

  it('scalarMultiplier(3, G) === tripling(G)', () => {
    const via3 = scalarMultiplier(3n, G);
    const viaTrip = tripling(G);
    expect(arePointsEqual(via3, viaTrip)).toBe(true);
  });

  it('scalarMultiplier(49, G) === fortyNiner(G)', () => {
    const via49 = scalarMultiplier(49n, G);
    const viaFN = fortyNiner(G);
    expect(arePointsEqual(via49, viaFN)).toBe(true);
  });

  it('scalarMultiplier(k, G) === chain of k additions (for k in 1..20)', () => {
    let chain: typeof G = G;
    for (let k = 1n; k <= 20n; k++) {
      if (k > 1n) {
        chain = addition(chain, G);
      }
      const viaMult = scalarMultiplier(k, G);
      expect(arePointsEqual(viaMult, chain)).toBe(true);
    }
  });

  it('scalarMultiplier(50, G) === scalarMultiplier(49, G) + G (first multi-digit case)', () => {
    // 50 in base-49 is "11" — exercises the fortyNiner between digits.
    const via50 = scalarMultiplier(50n, G);
    const chain = addition(fortyNiner(G), G);
    expect(arePointsEqual(via50, chain)).toBe(true);
  });
});

describe('scalarMultiplier — linearity and on-curve properties', () => {
  it('result of scalarMultiplier(k, G) is always on curve for small k', () => {
    for (let k = 1n; k <= 30n; k++) {
      const result = scalarMultiplier(k, G);
      const [onCurve] = isOnCurve(result);
      expect(onCurve).toBe(true);
    }
  });

  it('scalarMultiplier(a+b, G) === scalarMultiplier(a, G) + scalarMultiplier(b, G)', () => {
    const a = 17n;
    const b = 23n;
    const viaCombined = scalarMultiplier(a + b, G);
    const viaParts = addition(scalarMultiplier(a, G), scalarMultiplier(b, G));
    expect(arePointsEqual(viaCombined, viaParts)).toBe(true);
  });

  it('scalarMultiplier(2k, G) === doubling(scalarMultiplier(k, G))', () => {
    for (const k of [1n, 7n, 49n, 100n, 343n]) {
      const viaDouble = doubling(scalarMultiplier(k, G));
      const viaMult = scalarMultiplier(2n * k, G);
      expect(arePointsEqual(viaDouble, viaMult)).toBe(true);
    }
  });
});

describe('scalarMultiplierWithGenerator', () => {
  it('matches scalarMultiplier(k, G) for several k', () => {
    for (const k of [0n, 1n, 42n, 49n, 100n, 2400n]) {
      const viaGen = scalarMultiplierWithGenerator(k);
      const viaFull = scalarMultiplier(k, G);
      expect(arePointsEqual(viaGen, viaFull)).toBe(true);
    }
  });
});

describe('scalarMultiplier — CRITICAL: [Q]·G = O', () => {
  // This is the Phase 2 exit criterion. A full 1604-bit scalar mult
  // that MUST produce the identity element if and only if:
  //   (a) the base-49 Horner is implemented correctly, AND
  //   (b) all HWCD point operations produce correct output, AND
  //   (c) G actually has order Q as the curve parameters claim.
  //
  // The curve parameters themselves were independently verified in
  // verification/verify_dalos_curve.py; this test closes the loop
  // by proving the TypeScript arithmetic reproduces that result.

  it('scalarMultiplier(Q, G) produces the identity point (affine = (0, 1))', () => {
    const result = scalarMultiplier(DALOS_ELLIPSE.q, G);
    const affine = extended2Affine(result, DALOS_ELLIPSE.field);
    expect(affine.ax).toBe(0n);
    expect(affine.ay).toBe(1n);
    // And arePointsEqual against INFINITY:
    expect(arePointsEqual(result, INFINITY_POINT_EXTENDED)).toBe(true);
  }, 120_000); // allow up to 2 min for the 1604-bit computation

  it('scalarMultiplier(Q-1, G) + G === INFINITY (same property, different angle)', () => {
    const Qm1G = scalarMultiplier(DALOS_ELLIPSE.q - 1n, G);
    const sum = addition(Qm1G, G);
    expect(arePointsEqual(sum, INFINITY_POINT_EXTENDED)).toBe(true);
  }, 120_000);
});

describe('scalarMultiplier — arithmetic at full curve scale', () => {
  // A scalar size comparable to real private keys. Doesn't need to
  // match any specific reference value; just needs to not crash and
  // produce an on-curve point.

  it('produces on-curve result for a 1600-bit random-ish scalar', () => {
    // Pseudo-"random" but deterministic: 2^1000 + 42
    const k = (1n << 1000n) + 42n;
    const result = scalarMultiplier(k, G);
    const [onCurve] = isOnCurve(result);
    expect(onCurve).toBe(true);
  }, 60_000);
});
