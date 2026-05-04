/**
 * DALOS Ellipse — the 1606-bit Twisted Edwards curve.
 *
 * Equation:  y² + a·x²  ≡  1 + d·x²·y²   (mod P)
 *
 * Parameters match `DalosEllipse()` in Elliptic/Parameters.go byte-for-byte.
 * Verified mathematically via verification/verify_dalos_curve.py (all 7 tests
 * pass; see verification/VERIFICATION_LOG.md).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { CoordAffine, CoordExtended } from './coords.js';
import { Modular, ZERO } from './math.js';

/**
 * Fully-specified elliptic curve parameters.
 */
export interface Ellipse {
  /** Human-readable curve identifier. */
  readonly name: string;
  /** Prime field modulus P. */
  readonly p: bigint;
  /** Base-point order Q (prime). */
  readonly q: bigint;
  /** Trace of Frobenius T. */
  readonly t: bigint;
  /** Cofactor R = (P + 1 - T) / Q. */
  readonly r: bigint;
  /** Safe-scalar size in bits (1600 for DALOS). */
  readonly s: number;
  /** Curve coefficient a. */
  readonly a: bigint;
  /** Curve coefficient d. */
  readonly d: bigint;
  /** Generator base point G, in affine form. */
  readonly g: CoordAffine;
  /**
   * Modular arithmetic helper bound to this curve's prime field P.
   * Eliminates the `DALOS_FIELD` default-parameter footgun where a
   * non-DALOS curve passed without an explicit `Modular` instance
   * would silently use DALOS's modulus. Populated at curve
   * construction; immutable thereafter.
   */
  readonly field: Modular;
}

/**
 * DALOS Genesis curve parameters. Permanently frozen.
 *
 * Name:           TEC_S1600_Pr1605p2315_m26
 * P   = 2^1605 + 2315                         (1606-bit prime)
 * Q   = 2^1603 + 1258387…1380413               (1604-bit prime)
 * T   = −5033548…5519336                       (negative, accepted)
 * R   = 4                                      (cofactor)
 * a   = 1,  d = −26                            (non-square mod P → addition complete)
 * G   = (2, 479577721234…0907472)              (prime-order subgroup generator)
 * S   = 1600                                   (safe-scalar bits)
 */
export const DALOS_ELLIPSE: Ellipse = (() => {
  const P = (1n << 1605n) + 2315n;
  const Q =
    (1n << 1603n) +
    BigInt(
      '1258387060301909514024042379046449850251725029634697115619073843890' +
        '7054814400467405522041996358838852729449149046554835019160236782061' +
        '6759665036782681184686215753495299000438683946338696349451686206793' +
        '3899764941962204635259228497801901380413',
    );
  const T = BigInt(
    '-503354824120763805609616951618579940100690011853878846247629537556' +
      '28219257601869622088167985435355410917796596186219340076640947128246' +
      '70386601471307247387448630139811960017547357853547853978067448271735' +
      '599059767848818541036913991207605519336',
  );
  // R = (P + 1 - T) / Q   must divide cleanly; Python verification confirms R = 4.
  const R = (P + 1n - T) / Q;
  const gx = 2n;
  const gy = BigInt(
    '4795777212347418913161293140620964402032248005985613626047765189933' +
      '48406897758651324205216647014453759416735508511915279509434960064559' +
      '68658074176720175237005587177020300925418247272234245659775250616598' +
      '38848673516492833533929194015371071302326547437192193299900676686378' +
      '76645065665284755295099198801899803461121192253205447281506198423683' +
      '29096001485935093383651645052487303245401559750153298840589485856119' +
      '38939219048967245099046226322321825316983934844110822182736812267535' +
      '90907472',
  );
  const field = new Modular(P);
  return {
    name: 'TEC_S1600_Pr1605p2315_m26',
    p: P,
    q: Q,
    t: T,
    r: R,
    s: 1600,
    a: 1n,
    d: -26n,
    g: { ax: gx, ay: gy },
    field,
  };
})();

/**
 * Public re-export retained for npm backward compatibility (external
 * consumers imported `DALOS_FIELD` directly in v3.x). New code should
 * derive `m = e.field` from the curve passed in — see Phase 5 of the
 * audit-2026-04-29 spec for the rationale (the v4.0.0 footgun-elimination
 * pass that made per-curve modulus binding structural rather than vigilance-
 * dependent). Functionally equivalent to `DALOS_ELLIPSE.field`.
 */
export const DALOS_FIELD = new Modular(DALOS_ELLIPSE.p);

/**
 * Affine → Extended conversion.
 *
 * Sets EX = AX, EY = AY, EZ = 1, ET = AX·AY mod P.
 * Matches Go's `(*Ellipse).Affine2Extended`.
 */
export function affine2Extended(p: CoordAffine, m: Modular): CoordExtended {
  return {
    ex: p.ax,
    ey: p.ay,
    ez: 1n,
    et: m.mul(p.ax, p.ay),
  };
}

/**
 * Extended → Affine conversion.
 *
 * AX = EX / EZ mod P, AY = EY / EZ mod P.
 * Matches Go's `(*Ellipse).Extended2Affine`.
 */
export function extended2Affine(p: CoordExtended, m: Modular): CoordAffine {
  return {
    ax: m.div(p.ex, p.ez),
    ay: m.div(p.ey, p.ez),
  };
}

/**
 * Check whether a point is the infinity point in Extended coords.
 * Matches Go's `(*Ellipse).IsInfinityPoint`:
 *   EX = 0 AND ET = 0 AND EY = EZ
 */
export function isInfinityPoint(p: CoordExtended): boolean {
  return p.ex === ZERO && p.et === ZERO && p.ey === p.ez;
}

/**
 * Check whether a point lies on the DALOS curve.
 *
 * Affine equation:  a·x² + y²  ≡  1 + d·x²·y²   (mod P)
 *
 * F-PERF-003 / F-PERF-004 (audit cycle 2026-05-04, v4.0.1): homogenized
 * to extended HWCD coordinates with x = X/Z, y = Y/Z, T = XY/Z. Multiplying
 * by Z² and using x²·y² = T²/Z² (since T² = X²Y²/Z²) gives:
 *
 *   a·X² + Y²  ≡  Z² + d·T²   (mod P)
 *
 * Old path projected to affine via extended2Affine first, paying 2
 * `Modular.div` calls (each a modular inverse) purely for the representation
 * change. New path computes the homogenized equation directly: 0 inverses.
 *
 * Equivalence is pinned by the Go-side TestIsOnCurve_OldVsNew_Equivalence
 * + the Genesis 105-vector + 30-vector historical + 5-vector adversarial
 * corpus byte-identity SHA-256 regression guard. The TS suite cross-checks
 * every deterministic vector against the Go-produced corpus on each
 * `npm test` run; behavioural divergence between Go and TS would fail
 * those byte-identity assertions.
 *
 * Infinity point always reports on-curve (by convention). Returns a tuple
 * `[onCurve, isInfinity]` matching Go's signature.
 */
export function isOnCurve(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
): readonly [onCurve: boolean, isInfinity: boolean] {
  const m = e.field;
  const infinity = isInfinityPoint(p);
  // Extended-coords curve equation: a·X² + Y² ≡ Z² + d·T² (mod P).
  const x2 = m.mul(p.ex, p.ex);
  const y2 = m.mul(p.ey, p.ey);
  const z2 = m.mul(p.ez, p.ez);
  const t2 = m.mul(p.et, p.et);
  const left = m.add(m.mul(e.a, x2), y2);
  const right = m.add(z2, m.mul(e.d, t2));
  return [left === right, infinity];
}

/**
 * Compare two Extended points for equality (as affine points).
 *
 * F-PERF-003 / F-PERF-004 (audit cycle 2026-05-04, v4.0.1): two HWCD
 * extended points represent the same affine point iff
 *
 *   X1·Z2  ≡  X2·Z1   (mod P)   AND   Y1·Z2  ≡  Y2·Z1   (mod P)
 *
 * (Derivation: P1 == P2 in affine iff X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2;
 * cross-multiply by Z1·Z2 to clear denominators.)
 *
 * Old path called extended2Affine on BOTH points, paying 4 `Modular.div`
 * calls (each a modular inverse) before the comparison. New path: 4
 * multiplications and 2 comparisons, 0 inverses. Modular inverses are
 * the most expensive single operation in this codebase; eliminating 4
 * per Schnorr verify is a meaningful hot-path win.
 *
 * Equivalence is pinned by the Go-side TestArePointsEqual_OldVsNew_Equivalence
 * (covers same-self, same-projective-different-extended across many scale
 * factors, and full N×N cross-pair consistency on 12 distinct points)
 * + the Genesis + historical + adversarial corpus byte-identity SHA-256
 * regression guards. The TS suite cross-checks the Go-produced corpus.
 *
 * Matches Go's `(*Ellipse).ArePointsEqual` post-v4.0.1.
 */
export function arePointsEqual(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
): boolean {
  const m = e.field;
  const x1z2 = m.mul(p1.ex, p2.ez);
  const x2z1 = m.mul(p2.ex, p1.ez);
  if (x1z2 !== x2z1) return false;
  const y1z2 = m.mul(p1.ey, p2.ez);
  const y2z1 = m.mul(p2.ey, p1.ez);
  return y1z2 === y2z1;
}

/**
 * Check whether two points are inverses of each other on the curve.
 * The inverse of (x, y) is (-x, y). Matches Go's `IsInverseOnCurve`.
 */
export function isInverseOnCurve(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
): boolean {
  const m = e.field;
  const a1 = extended2Affine(p1, m);
  const a2 = extended2Affine(p2, m);
  return m.canon(-a1.ax) === a2.ax && a1.ay === a2.ay;
}
