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

import { afterEach, describe, expect, it, vi } from 'vitest';
import { INFINITY_POINT_EXTENDED } from '../../src/gen1/coords.js';
import {
  DALOS_ELLIPSE,
  affine2Extended,
  arePointsEqual,
  extended2Affine,
  isOnCurve,
} from '../../src/gen1/curve.js';
import * as pointOps from '../../src/gen1/point-ops.js';
import { addition, doubling, fortyNiner, tripling } from '../../src/gen1/point-ops.js';
import {
  BASE49_ALPHABET,
  bigIntToBase49,
  digitValueBase49,
  scalarMultiplier,
  scalarMultiplierAsync,
  scalarMultiplierWithGenerator,
} from '../../src/gen1/scalar-mult.js';

const G = affine2Extended(DALOS_ELLIPSE.g);

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
    const affine = extended2Affine(result);
    expect(affine.ax).toBe(0n);
    expect(affine.ay).toBe(1n);
    // And arePointsEqual against INFINITY:
    expect(arePointsEqual(result, INFINITY_POINT_EXTENDED)).toBe(true);
  }, 30_000); // 30s ceiling per REQ-15; PM cache landed in v3.1.0

  it('scalarMultiplier(Q-1, G) + G === INFINITY (same property, different angle)', () => {
    const Qm1G = scalarMultiplier(DALOS_ELLIPSE.q - 1n, G);
    const sum = addition(Qm1G, G);
    expect(arePointsEqual(sum, INFINITY_POINT_EXTENDED)).toBe(true);
  }, 30_000);
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

describe('scalarMultiplierWithGenerator — PM cache', () => {
  // The generator's PrecomputeMatrix is curve-specific and immutable;
  // building it costs 24 doublings + 24 additions (~tens of ms) which
  // dominates a single sign or verify when the scalar itself is small.
  // A module-level WeakMap<Ellipse, PrecomputeMatrix> populated lazily
  // on first call eliminates the rebuild for every subsequent call on
  // the same curve. Custom curves remain GC-eligible because WeakMap
  // does not pin its keys.
  //
  // Cache test uses a freshly-cloned Ellipse object as the WeakMap key
  // so prior tests (which populate the cache for the canonical
  // DALOS_ELLIPSE singleton) cannot leak hits into this test.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('builds the generator PrecomputeMatrix exactly once across N calls on the same curve', () => {
    const freshCurve: typeof DALOS_ELLIPSE = { ...DALOS_ELLIPSE };
    const spy = vi.spyOn(pointOps, 'precomputeMatrix');
    const scalar = 42n;
    for (let i = 0; i < 5; i++) {
      scalarMultiplierWithGenerator(scalar, freshCurve);
    }
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('produces correct results across cached calls (algebraic identity preserved)', () => {
    const r1 = scalarMultiplierWithGenerator(0n, DALOS_ELLIPSE);
    const r2 = scalarMultiplierWithGenerator(1n, DALOS_ELLIPSE);
    const r3 = scalarMultiplierWithGenerator(2n, DALOS_ELLIPSE);
    expect(arePointsEqual(r1, INFINITY_POINT_EXTENDED)).toBe(true);
    expect(arePointsEqual(r2, G)).toBe(true);
    expect(arePointsEqual(r3, addition(G, G))).toBe(true);
  });
});

describe('scalarMultiplierAsync', () => {
  // The async variant mirrors scalarMultiplier's outer loop body byte-for-byte
  // and inserts an event-loop yield every 8 outer iterations on a fixed,
  // data-independent cadence (i & 0x07) === 0x07. The yield trigger depends
  // ONLY on the iteration index — never on the scalar value or any digit
  // value — so the constant-time property of the sync path is preserved
  // verbatim. Equivalence with the sync path is the correctness gate;
  // yield-count constant-time is the REQ-14 mechanical guard.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('produces byte-identical result to scalarMultiplier for k = 0', async () => {
    const sync = scalarMultiplier(0n, G);
    const async_ = await scalarMultiplierAsync(0n, G);
    expect(arePointsEqual(async_, sync)).toBe(true);
    expect(async_.ex).toBe(sync.ex);
    expect(async_.ey).toBe(sync.ey);
    expect(async_.ez).toBe(sync.ez);
    expect(async_.et).toBe(sync.et);
  });

  it('produces byte-identical result to scalarMultiplier for several small scalars', async () => {
    for (const k of [1n, 2n, 17n, 49n, 100n, 2400n, 12345n]) {
      const sync = scalarMultiplier(k, G);
      const async_ = await scalarMultiplierAsync(k, G);
      expect(async_.ex).toBe(sync.ex);
      expect(async_.ey).toBe(sync.ey);
      expect(async_.ez).toBe(sync.ez);
      expect(async_.et).toBe(sync.et);
    }
  });

  it('rejects negative scalars (matches sync behaviour)', async () => {
    await expect(scalarMultiplierAsync(-1n, G)).rejects.toThrow();
  });

  it('await scalarMultiplierAsync(Q, G) produces the identity point', async () => {
    const result = await scalarMultiplierAsync(DALOS_ELLIPSE.q, G);
    const affine = extended2Affine(result);
    expect(affine.ax).toBe(0n);
    expect(affine.ay).toBe(1n);
    expect(arePointsEqual(result, INFINITY_POINT_EXTENDED)).toBe(true);
  }, 30_000);

  it('REQ-14: yield count is identical for scalars of the same base-49 length but different values', async () => {
    // Three scalars chosen to share the SAME base-49 digit length but
    // have very different numerical values. If any future change makes
    // the yield trigger data-dependent (e.g. early-exit on zero digits),
    // this assertion will fail.
    // All three scalars produce a 100-digit base-49 representation but with
    // very different leading digits and bit patterns:
    //   k1 = 49^99           → "1" followed by 99 zeros
    //   k2 = 49^100 - 1      → 100 'M's (max 100-digit value, every digit = 48)
    //   k3 = 42·49^99 + 17   → leading digit ~G, mostly zeros, trailing "h"
    const k1 = 49n ** 99n;
    const k2 = 49n ** 100n - 1n;
    const k3 = 42n * 49n ** 99n + 17n;

    // Sanity: confirm all three produce the same base-49 length.
    const len1 = bigIntToBase49(k1).length;
    const len2 = bigIntToBase49(k2).length;
    const len3 = bigIntToBase49(k3).length;
    expect(len2).toBe(len1);
    expect(len3).toBe(len1);

    // Spy on the underlying yield mechanism. The production module's
    // yieldToEventLoop helper calls globalThis.setImmediate when
    // available (Node 20+/Vitest), which is the path this test runs.
    // mockImplementation preserves original behaviour (the yield still
    // resolves) while letting us count call sites — no module-mutation,
    // no test-only production export, just intercept the platform API.
    const originalSetImmediate = globalThis.setImmediate;
    expect(typeof originalSetImmediate).toBe('function');
    type SetImmediateArgs = Parameters<typeof globalThis.setImmediate>;
    const spy = vi
      .spyOn(globalThis, 'setImmediate')
      .mockImplementation(((cb: () => void, ...args: unknown[]) =>
        originalSetImmediate(
          cb,
          ...(args as SetImmediateArgs extends [unknown, ...infer R] ? R : never[]),
        )) as typeof globalThis.setImmediate);

    await scalarMultiplierAsync(k1, G);
    const count1 = spy.mock.calls.length;

    spy.mockClear();
    await scalarMultiplierAsync(k2, G);
    const count2 = spy.mock.calls.length;

    spy.mockClear();
    await scalarMultiplierAsync(k3, G);
    const count3 = spy.mock.calls.length;

    // All three must yield the same number of times — proves the
    // cadence depends only on the iteration index `i`, not on the
    // scalar value or any digit value.
    expect(count2).toBe(count1);
    expect(count3).toBe(count1);

    // For a 100-digit scalar with trigger (i & 0x07) === 0x07, the
    // hits are i ∈ {7, 15, 23, 31, 39, 47, 55, 63, 71, 79, 87, 95} = 12.
    expect(count1).toBe(12);
  }, 30_000);
});
