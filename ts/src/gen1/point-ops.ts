/**
 * HWCD (Hisil–Wong–Carter–Dawson, 2008) point operations for the DALOS
 * Twisted Edwards curve in Extended coordinates.
 *
 * Source of truth: `Elliptic/PointOperations.go` in the Go reference.
 * Formula sources: https://www.hyperelliptic.org/EFD/g1p/
 *   - mmadd-2008-hwcd      (AdditionV1, both Z = 1)
 *   - madd-2008-hwcd-2     (AdditionV2, P2.Z = 1, P1.Z ≠ 1)
 *   - add-2008-hwcd        (AdditionV3, general — P2.Z ≠ 1)
 *   - mdbl-2008-hwcd       (DoublingV1, Z = 1)
 *   - dbl-2008-hwcd        (DoublingV2, Z ≠ 1)
 *   - tpl-2015-c           (Tripling)
 *
 * Every function here mirrors the Go code line-for-line. Intermediate
 * variable names are preserved (A, B, C, D, E, F, G, H, v1..v6, etc.)
 * to make cross-language review trivial.
 *
 * Byte-identity: Phase 1 exit criterion is that 49·G computed via
 * these ops matches the Go reference's output bit-for-bit. See
 * tests/gen1/point-ops.test.ts.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { CoordExtended } from './coords.js';
import { INFINITY_POINT_EXTENDED } from './coords.js';
import { DALOS_ELLIPSE, DALOS_FIELD, type Ellipse } from './curve.js';
import type { Modular } from './math.js';
import { ONE, TWO } from './math.js';

// ============================================================================
// Addition
// ============================================================================

/**
 * Twisted Edwards extended-coordinate addition — dispatcher.
 *
 * Selects one of three variants based on the Z-coordinates to save
 * multiplications when one or both inputs are already in affine form
 * (Z = 1). Mirrors Go's `(*Ellipse).Addition`.
 */
export function addition(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p1.ez === ONE && p2.ez === ONE) {
    return additionV1(p1, p2, e, m);
  }
  if (p2.ez === ONE) {
    return additionV2(p1, p2, e, m);
  }
  return additionV3(p1, p2, e, m);
}

/**
 * AdditionV1 — mmadd-2008-hwcd. Both Z1 = Z2 = 1 (pure affine case).
 */
export function additionV1(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p1.ez !== ONE || p2.ez !== ONE) {
    throw new Error('additionV1 requires both Z1 and Z2 to be 1');
  }
  const A = m.mul(p1.ex, p2.ex); // A = X1·X2
  const B = m.mul(p1.ey, p2.ey); // B = Y1·Y2
  const C = m.mul(p1.et, m.mul(e.d, p2.et)); // C = T1·d·T2
  const v1 = m.add(p1.ex, p1.ey);
  const v2 = m.add(p2.ex, p2.ey);
  const v3 = m.mul(v1, v2);
  const v4 = m.sub(v3, A);
  const E = m.sub(v4, B); // E = (X1+Y1)(X2+Y2) − A − B
  const F = m.sub(ONE, C); // F = 1 − C
  const G = m.add(ONE, C); // G = 1 + C
  const H = m.sub(B, m.mul(e.a, A)); // H = B − a·A
  const ex = m.mul(E, F); // X3 = E·F
  const ey = m.mul(G, H); // Y3 = G·H
  const et = m.mul(E, H); // T3 = E·H
  const ez = m.sub(ONE, m.mul(C, C)); // Z3 = 1 − C²
  return { ex, ey, ez, et };
}

/**
 * AdditionV2 — madd-2008-hwcd-2. P2.Z = 1, P1.Z can be anything.
 */
export function additionV2(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p2.ez !== ONE) {
    throw new Error('additionV2 requires P2.Z to be 1');
  }
  const A = m.mul(p1.ex, p2.ex);
  const B = m.mul(p1.ey, p2.ey);
  const C = m.mul(p1.ez, p2.et);
  const D = p1.et;
  const E = m.add(C, D);
  const v1 = m.sub(p1.ex, p1.ey);
  const v2 = m.add(p2.ex, p2.ey);
  const v3 = m.mul(v1, v2);
  const v4 = m.add(v3, B);
  const F = m.sub(v4, A);
  const v5 = m.mul(A, e.a);
  const G = m.add(B, v5);
  const H = m.sub(D, C);
  return {
    ex: m.mul(E, F),
    ey: m.mul(G, H),
    et: m.mul(E, H),
    ez: m.mul(F, G),
  };
}

/**
 * AdditionV3 — add-2008-hwcd. General case (P2.Z ≠ 1).
 */
export function additionV3(
  p1: CoordExtended,
  p2: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p2.ez === ONE) {
    throw new Error('additionV3 requires P2.Z to differ from 1');
  }
  const A = m.mul(p1.ex, p2.ex);
  const B = m.mul(p1.ey, p2.ey);
  const v1 = m.mul(e.d, p2.et);
  const C = m.mul(p1.et, v1);
  const D = m.mul(p1.ez, p2.ez);
  const v2 = m.add(p1.ex, p1.ey);
  const v3 = m.add(p2.ex, p2.ey);
  const v4 = m.mul(v2, v3);
  const v5 = m.sub(v4, A);
  const E = m.sub(v5, B);
  const F = m.sub(D, C);
  const G = m.add(D, C);
  const v6 = m.mul(e.a, A);
  const H = m.sub(B, v6);
  return {
    ex: m.mul(E, F),
    ey: m.mul(G, H),
    et: m.mul(E, H),
    ez: m.mul(F, G),
  };
}

// ============================================================================
// Doubling
// ============================================================================

/**
 * Extended-coordinate doubling — dispatcher.
 * Mirrors Go's `(*Ellipse).Doubling`.
 */
export function doubling(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p.ez === ONE) {
    return doublingV1(p, e, m);
  }
  return doublingV2(p, e, m);
}

/**
 * DoublingV1 — mdbl-2008-hwcd. Z = 1.
 */
export function doublingV1(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  if (p.ez !== ONE) {
    throw new Error('doublingV1 requires Z to be 1');
  }
  const A = m.mul(p.ex, p.ex);
  const B = m.mul(p.ey, p.ey);
  const D = m.mul(A, e.a);
  const v1 = m.add(p.ex, p.ey);
  const v2 = m.mul(v1, v1);
  const v3 = m.sub(v2, A);
  const E = m.sub(v3, B);
  const G = m.add(D, B);
  const H = m.sub(D, B);
  const v4 = m.sub(G, TWO);
  const ex = m.mul(E, v4);
  const ey = m.mul(G, H);
  const et = m.mul(E, H);
  const v5 = m.mul(TWO, G);
  const v6 = m.mul(G, G);
  const ez = m.sub(v6, v5);
  return { ex, ey, ez, et };
}

/**
 * DoublingV2 — dbl-2008-hwcd. General Z.
 */
export function doublingV2(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  const A = m.mul(p.ex, p.ex);
  const B = m.mul(p.ey, p.ey);
  const v1 = m.mul(p.ez, p.ez);
  const C = m.mul(TWO, v1);
  const D = m.mul(A, e.a);
  const v2 = m.add(p.ex, p.ey);
  const v3 = m.mul(v2, v2);
  const v4 = m.sub(v3, A);
  const E = m.sub(v4, B);
  const G = m.add(D, B);
  const F = m.sub(G, C);
  const H = m.sub(D, B);
  return {
    ex: m.mul(E, F),
    ey: m.mul(G, H),
    et: m.mul(E, H),
    ez: m.mul(F, G),
  };
}

// ============================================================================
// Tripling
// ============================================================================

/**
 * Tripling — tpl-2015-c. Computes 3·P directly (cheaper than 2·P + P).
 */
export function tripling(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  const YY = m.mul(p.ey, p.ey);
  const XX = m.mul(p.ex, p.ex);
  const aXX = m.mul(e.a, XX);
  const Ap = m.add(YY, aXX);
  const ZZ = m.mul(p.ez, p.ez);
  const v1 = m.mul(TWO, ZZ);
  const v2 = m.sub(v1, Ap);
  const B = m.mul(TWO, v2);
  const xB = m.mul(aXX, B);
  const yB = m.mul(YY, B);
  const v3 = m.sub(YY, aXX);
  const AA = m.mul(Ap, v3);
  const F = m.sub(AA, yB);
  const G = m.add(AA, xB);
  const v4 = m.add(yB, AA);
  const xE = m.mul(p.ex, v4);
  const v5 = m.sub(xB, AA);
  const yH = m.mul(p.ey, v5);
  const zF = m.mul(p.ez, F);
  const zG = m.mul(p.ez, G);
  return {
    ex: m.mul(xE, zF),
    ey: m.mul(yH, zG),
    ez: m.mul(zF, zG),
    et: m.mul(xE, yH),
  };
}

// ============================================================================
// FortyNiner — 49·P via chained doublings + additions
// ============================================================================

/**
 * 49·P via: 3P → 6P → 12P → 24P → 48P → 48P + P = 49P.
 *
 * Six Go-level operations: 1 Tripling + 4 Doublings + 1 Addition.
 * Mirrors Go's `(*Ellipse).FortyNiner` exactly.
 */
export function fortyNiner(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): CoordExtended {
  const P03 = tripling(p, e, m);
  const P06 = doubling(P03, e, m);
  const P12 = doubling(P06, e, m);
  const P24 = doubling(P12, e, m);
  const P48 = doubling(P24, e, m);
  const P49 = addition(P48, p, e, m);
  return P49;
}

// ============================================================================
// PrecomputeMatrix — builds [P, 2P, 3P, …, 49P] as a 7×7 array
// ============================================================================

/** A 7×7 precompute matrix. Element [i][j] is (i·7 + j + 1) · P. */
export type PrecomputeMatrix = readonly [
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
  readonly [
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
    CoordExtended,
  ],
];

/**
 * Builds the 49-element precompute matrix used by base-49 Horner
 * scalar multiplication. Mirrors Go's `(*Ellipse).PrecomputeMatrix`
 * operation-for-operation (48 ops: 24 Doublings + 24 Additions).
 */
export function precomputeMatrix(
  p: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  m: Modular = DALOS_FIELD,
): PrecomputeMatrix {
  const P02 = doubling(p, e, m);
  const P03 = addition(P02, p, e, m);
  const P04 = doubling(P02, e, m);
  const P05 = addition(P04, p, e, m);
  const P06 = doubling(P03, e, m);
  const P07 = addition(P06, p, e, m);
  const P08 = doubling(P04, e, m);
  const P09 = addition(P08, p, e, m);
  const P10 = doubling(P05, e, m);
  const P11 = addition(P10, p, e, m);
  const P12 = doubling(P06, e, m);
  const P13 = addition(P12, p, e, m);
  const P14 = doubling(P07, e, m);
  const P15 = addition(P14, p, e, m);
  const P16 = doubling(P08, e, m);
  const P17 = addition(P16, p, e, m);
  const P18 = doubling(P09, e, m);
  const P19 = addition(P18, p, e, m);
  const P20 = doubling(P10, e, m);
  const P21 = addition(P20, p, e, m);
  const P22 = doubling(P11, e, m);
  const P23 = addition(P22, p, e, m);
  const P24 = doubling(P12, e, m);
  const P25 = addition(P24, p, e, m);
  const P26 = doubling(P13, e, m);
  const P27 = addition(P26, p, e, m);
  const P28 = doubling(P14, e, m);
  const P29 = addition(P28, p, e, m);
  const P30 = doubling(P15, e, m);
  const P31 = addition(P30, p, e, m);
  const P32 = doubling(P16, e, m);
  const P33 = addition(P32, p, e, m);
  const P34 = doubling(P17, e, m);
  const P35 = addition(P34, p, e, m);
  const P36 = doubling(P18, e, m);
  const P37 = addition(P36, p, e, m);
  const P38 = doubling(P19, e, m);
  const P39 = addition(P38, p, e, m);
  const P40 = doubling(P20, e, m);
  const P41 = addition(P40, p, e, m);
  const P42 = doubling(P21, e, m);
  const P43 = addition(P42, p, e, m);
  const P44 = doubling(P22, e, m);
  const P45 = addition(P44, p, e, m);
  const P46 = doubling(P23, e, m);
  const P47 = addition(P46, p, e, m);
  const P48 = doubling(P24, e, m);
  const P49 = addition(P48, p, e, m);

  return [
    [p, P02, P03, P04, P05, P06, P07],
    [P08, P09, P10, P11, P12, P13, P14],
    [P15, P16, P17, P18, P19, P20, P21],
    [P22, P23, P24, P25, P26, P27, P28],
    [P29, P30, P31, P32, P33, P34, P35],
    [P36, P37, P38, P39, P40, P41, P42],
    [P43, P44, P45, P46, P47, P48, P49],
  ];
}

// Re-export the infinity point so consumers don't need to know about coords.ts
export { INFINITY_POINT_EXTENDED };
