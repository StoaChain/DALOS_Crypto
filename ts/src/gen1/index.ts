/**
 * DALOS Genesis (gen-1) TypeScript port — public surface.
 *
 * Phase 1 (v2.3.0): math foundation + coordinates + curve + point ops.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

// Math
export {
  Modular,
  ZERO,
  ONE,
  TWO,
  bytesToBigIntBE,
  bigIntToBytesBE,
  parseBase10,
} from './math.js';

// Coordinates
export type {
  CoordAffine,
  CoordExtended,
  CoordInverted,
  CoordProjective,
} from './coords.js';
export { INFINITY_POINT_EXTENDED } from './coords.js';

// Curve parameters + predicates
export type { Ellipse } from './curve.js';
export {
  DALOS_ELLIPSE,
  DALOS_FIELD,
  affine2Extended,
  extended2Affine,
  isInfinityPoint,
  isOnCurve,
  arePointsEqual,
  isInverseOnCurve,
} from './curve.js';

// Point operations
export type { PrecomputeMatrix } from './point-ops.js';
export {
  addition,
  additionV1,
  additionV2,
  additionV3,
  doubling,
  doublingV1,
  doublingV2,
  tripling,
  fortyNiner,
  precomputeMatrix,
} from './point-ops.js';
