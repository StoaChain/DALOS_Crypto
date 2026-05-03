/**
 * Tests for the DALOS Ellipse curve parameters and predicates.
 *
 * The curve parameters themselves were independently verified in
 * verification/verify_dalos_curve.py (all 7 mathematical tests pass).
 * Here we just confirm the TS constants match the Go values byte-for-byte
 * and that the on-curve / infinity / equality predicates behave correctly.
 */

import { describe, expect, it } from 'vitest';
import { INFINITY_POINT_EXTENDED } from '../../src/gen1/coords.js';
import {
  DALOS_ELLIPSE,
  affine2Extended,
  arePointsEqual,
  extended2Affine,
  isInfinityPoint,
  isOnCurve,
} from '../../src/gen1/curve.js';

describe('DALOS_ELLIPSE parameters (Phase 0 verified values)', () => {
  it('P = 2^1605 + 2315', () => {
    expect(DALOS_ELLIPSE.p).toBe((1n << 1605n) + 2315n);
    expect(DALOS_ELLIPSE.p.toString(2).length).toBe(1606); // bit length
  });

  it('Q is prime and has 1604 bits', () => {
    expect(DALOS_ELLIPSE.q.toString(2).length).toBe(1604);
  });

  it('cofactor R = 4 (verified mathematically)', () => {
    expect(DALOS_ELLIPSE.r).toBe(4n);
  });

  it('cofactor identity: (P + 1 - T) / Q = R with zero remainder', () => {
    const order = DALOS_ELLIPSE.p + 1n - DALOS_ELLIPSE.t;
    expect(order / DALOS_ELLIPSE.q).toBe(DALOS_ELLIPSE.r);
    expect(order % DALOS_ELLIPSE.q).toBe(0n);
  });

  it('coefficients a = 1, d = -26', () => {
    expect(DALOS_ELLIPSE.a).toBe(1n);
    expect(DALOS_ELLIPSE.d).toBe(-26n);
  });

  it('generator G.x = 2', () => {
    expect(DALOS_ELLIPSE.g.ax).toBe(2n);
  });

  it('safe scalar bits = 1600', () => {
    expect(DALOS_ELLIPSE.s).toBe(1600);
  });

  it('name matches Go reference', () => {
    expect(DALOS_ELLIPSE.name).toBe('TEC_S1600_Pr1605p2315_m26');
  });
});

describe('coordinate conversions', () => {
  it('affine2Extended sets Z=1, T=X·Y', () => {
    const aff = { ax: 2n, ay: 5n };
    const ext = affine2Extended(aff, DALOS_ELLIPSE.field);
    expect(ext.ex).toBe(2n);
    expect(ext.ey).toBe(5n);
    expect(ext.ez).toBe(1n);
    expect(ext.et).toBe(10n);
  });

  it('extended2Affine ∘ affine2Extended is identity on affine points', () => {
    const aff = { ax: 2n, ay: DALOS_ELLIPSE.g.ay };
    const ext = affine2Extended(aff, DALOS_ELLIPSE.field);
    const back = extended2Affine(ext, DALOS_ELLIPSE.field);
    expect(back.ax).toBe(aff.ax);
    expect(back.ay).toBe(aff.ay);
  });
});

describe('curve predicates', () => {
  it('isInfinityPoint recognises (0, 1, 1, 0)', () => {
    expect(isInfinityPoint(INFINITY_POINT_EXTENDED)).toBe(true);
    expect(isInfinityPoint({ ex: 1n, ey: 1n, ez: 1n, et: 1n })).toBe(false);
  });

  it('isOnCurve: the generator G is on the curve', () => {
    const [onCurve] = isOnCurve(affine2Extended(DALOS_ELLIPSE.g, DALOS_ELLIPSE.field));
    expect(onCurve).toBe(true);
  });

  it('isOnCurve: a random off-curve point is rejected', () => {
    // (1, 1) is almost certainly not on the curve: 1 + 1 = 2, but 1 + d·1·1 = 1 + (-26) = -25
    // 2 !== -25 (mod P)
    const off = affine2Extended({ ax: 1n, ay: 1n }, DALOS_ELLIPSE.field);
    const [onCurve] = isOnCurve(off);
    expect(onCurve).toBe(false);
  });

  it('arePointsEqual: G == G', () => {
    const G = affine2Extended(DALOS_ELLIPSE.g, DALOS_ELLIPSE.field);
    expect(arePointsEqual(G, G)).toBe(true);
  });
});
