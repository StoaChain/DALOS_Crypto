/**
 * Historical-curves integrity tests.
 *
 * Per curve we verify:
 *   1. P has the declared bit width, Q has the declared bit width
 *   2. R = (P + 1 − T) / Q divides cleanly and equals 4
 *   3. G is on the curve (i.e. `a·Gx² + Gy² ≡ 1 + d·Gx²·Gy²` mod P)
 *   4. [Q]·G = O — G has prime order Q in the subgroup, which is the
 *      single most important consistency check: if this fails, the
 *      math does not work on this curve parameter set.
 *   5. Name string matches the upstream Go identifier
 *
 * Test (4) is the "audit-lite" — it proves end-to-end that our
 * parameterized HWCD point-ops + base-49 Horner scalar-mult produce
 * the group identity on the correct order, which is only true if P,
 * Q, T, R, a, d, Gx, Gy are all self-consistent.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { describe, expect, it } from 'vitest';
import type { Ellipse } from '../../src/gen1/curve.js';
import { affine2Extended, isInfinityPoint, isOnCurve } from '../../src/gen1/curve.js';
import { scalarMultiplierWithGenerator } from '../../src/gen1/scalar-mult.js';
import { APOLLO, ARTEMIS, LETO } from '../../src/historical/index.js';

interface CurveCase {
  readonly curve: Ellipse;
  readonly name: string;
  readonly pBits: number;
  readonly qBits: number;
  readonly sBits: number;
  readonly dValue: bigint;
  readonly gxValue: bigint;
}

const CASES: readonly CurveCase[] = [
  {
    curve: LETO,
    name: 'LETO',
    // P = 2^551 + 335 → top bit stays set → 552 bits.
    pBits: 552,
    // Q = 2^549 − rest → top bit cleared → 549 bits.
    qBits: 549,
    sBits: 545,
    dValue: -1874n,
    gxValue: 5n,
  },
  {
    curve: ARTEMIS,
    name: 'ARTEMIS',
    // P = 2^1029 + 639 → 1030 bits.
    pBits: 1030,
    // Q = 2^1027 − rest → 1027 bits.
    qBits: 1027,
    sBits: 1023,
    dValue: -200n,
    gxValue: 18n,
  },
  {
    curve: APOLLO,
    name: 'APOLLO',
    // P = 2^1029 + 639 → 1030 bits (shared with ARTEMIS — twin curves).
    pBits: 1030,
    // Q = 2^1027 + rest → top bit stays set → 1028 bits.
    qBits: 1028,
    sBits: 1024,
    dValue: -729n,
    gxValue: 18n, // shares Gx with ARTEMIS (twin)
  },
];

for (const tc of CASES) {
  describe(`Historical curve: ${tc.name}`, () => {
    // Phase 5 (REQ-14): use the curve's own field, not a local re-allocation.
    const field = tc.curve.field;

    it('name matches upstream Go identifier', () => {
      expect(tc.curve.name).toBe(tc.name);
    });

    it(`P has ${tc.pBits} bits`, () => {
      expect(tc.curve.p.toString(2).length).toBe(tc.pBits);
    });

    it(`Q has ${tc.qBits} bits`, () => {
      expect(tc.curve.q.toString(2).length).toBe(tc.qBits);
    });

    it('coefficient a = 1', () => {
      expect(tc.curve.a).toBe(1n);
    });

    it(`coefficient d = ${tc.dValue}`, () => {
      expect(tc.curve.d).toBe(tc.dValue);
    });

    it('cofactor R = 4 (computed from P+1−T / Q)', () => {
      expect(tc.curve.r).toBe(4n);
    });

    it('cofactor identity: (P + 1 − T) mod Q = 0', () => {
      const order = tc.curve.p + 1n - tc.curve.t;
      expect(order % tc.curve.q).toBe(0n);
      expect(order / tc.curve.q).toBe(tc.curve.r);
    });

    it(`safe-scalar bits = ${tc.sBits}`, () => {
      expect(tc.curve.s).toBe(tc.sBits);
    });

    it(`generator Gx = ${tc.gxValue}`, () => {
      expect(tc.curve.g.ax).toBe(tc.gxValue);
    });

    it('generator G is on the curve', () => {
      const [onCurve] = isOnCurve(affine2Extended(tc.curve.g, field), tc.curve);
      expect(onCurve).toBe(true);
    });

    // The critical end-to-end math consistency test. Very slow on the
    // 1030-bit curves (~10s each on CI) because Q has 1028 bits and
    // scalar-mult is O(S/7) point additions. The 552-bit curve runs
    // in well under a second.
    it('[Q]·G = O (generator has order Q)', () => {
      const result = scalarMultiplierWithGenerator(tc.curve.q, tc.curve);
      expect(isInfinityPoint(result)).toBe(true);
    }, 60_000);
  });
}

// REQ-30 (F-API-008): the historical/* subpath now re-exports the math
// helpers so consumers can build field arithmetic against any historical
// curve from a single import statement, mirroring registry/index.ts's
// re-export of AddressPrefixPair + DALOS_PREFIXES.
describe('historical subpath — Modular helpers re-export (REQ-30)', () => {
  it('Modular class is re-exported from historical/index.ts', async () => {
    const historical = (await import('../../src/historical/index.js')) as Record<string, unknown>;
    expect(historical.Modular).toBeDefined();
    expect(typeof historical.Modular).toBe('function');
  });

  it('Modular re-exported from historical is identity-equal to gen1/math', async () => {
    const fromHistorical = (await import('../../src/historical/index.js')) as Record<
      string,
      unknown
    >;
    const fromMath = (await import('../../src/gen1/math.js')) as Record<string, unknown>;
    expect(fromHistorical.Modular).toBe(fromMath.Modular);
  });

  it('ZERO, ONE, TWO are re-exported with the correct bigint values', async () => {
    const historical = (await import('../../src/historical/index.js')) as Record<string, unknown>;
    expect(historical.ZERO).toBe(0n);
    expect(historical.ONE).toBe(1n);
    expect(historical.TWO).toBe(2n);
  });

  it('bytesToBigIntBE, bigIntToBytesBE, parseBase10 are re-exported (PAT-001 expansion)', async () => {
    const historical = (await import('../../src/historical/index.js')) as Record<string, unknown>;
    expect(typeof historical.bytesToBigIntBE).toBe('function');
    expect(typeof historical.bigIntToBytesBE).toBe('function');
    expect(typeof historical.parseBase10).toBe('function');
  });

  it('LETO + Modular round-trip (single-import consumer ergonomics)', async () => {
    const { LETO: LetoCurve, Modular: M } = await import('../../src/historical/index.js');
    const field = new M(LetoCurve.p);
    expect(field.canon(LetoCurve.p + 5n)).toBe(5n);
    expect(field.add(3n, 4n)).toBe(7n);
  });
});
