/**
 * Point coordinate representations for the DALOS Twisted Edwards curve.
 *
 * Mirrors the Go reference's `Elliptic/PointConverter.go`:
 *   - CoordAffine    : (X, Y)                    - canonical
 *   - CoordExtended  : (X : Y : Z : T), x=X/Z, y=Y/Z, xy=T/Z - used for arithmetic
 *   - CoordInverted  : (X : Y : Z),    x=Z/X, y=Z/Y            - alternative
 *   - CoordProjective: (X : Y : Z),    x=X/Z, y=Y/Z            - alternative
 *
 * Point-operation code (in ./point-ops.ts) works in Extended coords
 * because the HWCD addition formulas are specified in that system.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/**
 * Affine coordinates — the canonical (X, Y) representation.
 * Public keys, signature R-points, and the generator are stored affine.
 */
export interface CoordAffine {
  readonly ax: bigint;
  readonly ay: bigint;
}

/**
 * Extended coordinates (HWCD): (X : Y : Z : T) such that
 *   x = X/Z
 *   y = Y/Z
 *   x*y = T/Z
 *
 * All point arithmetic happens in this system for efficiency.
 */
export interface CoordExtended {
  readonly ex: bigint;
  readonly ey: bigint;
  readonly ez: bigint;
  readonly et: bigint;
}

/**
 * Inverted coordinates: (X : Y : Z) with x = Z/X, y = Z/Y.
 * Defined for parity with the Go reference; not used by Genesis ops.
 */
export interface CoordInverted {
  readonly ix: bigint;
  readonly iy: bigint;
  readonly iz: bigint;
}

/**
 * Projective coordinates: (X : Y : Z) with x = X/Z, y = Y/Z.
 * Defined for parity with the Go reference; not used by Genesis ops.
 */
export interface CoordProjective {
  readonly px: bigint;
  readonly py: bigint;
  readonly pz: bigint;
}

/**
 * The infinity / neutral / identity point, in Extended coordinates.
 * Value in the Go reference: `CoordExtended{Zero, One, One, Zero}`.
 *
 * Identity property: for any point P,  P + INFINITY_POINT = P.
 */
export const INFINITY_POINT_EXTENDED: CoordExtended = {
  ex: 0n,
  ey: 1n,
  ez: 1n,
  et: 0n,
};
