/**
 * Typed exception classes for the gen1 surface.
 *
 * These classes are caught by consumers via `instanceof` checks rather
 * than string matching. The explicit `this.name` assignment is required
 * because ES2015 class extension does not auto-propagate the subclass
 * name onto Error subclasses — without it, `error.name` would default
 * to `'Error'` and break catch-by-name patterns.
 *
 * Catch-by-class pattern for npm consumers:
 *
 * ```typescript
 * import { fromBitString, InvalidBitStringError } from '@stoachain/dalos-crypto/gen1';
 *
 * try {
 *   const key = fromBitString(userInput);
 * } catch (e) {
 *   if (e instanceof InvalidBitStringError) {
 *     // handle bitstring-specific error (wrong length, bad chars)
 *   } else {
 *     throw e; // rethrow unknown errors
 *   }
 * }
 * ```
 *
 * F-MED-008 (audit cycle 2026-05-04, v4.0.2): pre-v4.0.2 the gen1
 * surface threw bare `Error` instances and consumers had to do
 * `String(err.message).includes(...)` to disambiguate failure modes —
 * brittle to message-wording changes (v3.0.3's F-FE-001 spec already
 * changed wording once). The Schnorr surface had `SchnorrSignError`
 * since v3.0.3 but the key-gen surface lagged. This module brings the
 * two into parity.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/**
 * Thrown by `schnorrSign` / `schnorrSignAsync` when the Fiat-Shamir
 * challenge step returns null (typically caused by an unparseable
 * public key in the keypair). v3.0.3 introduction.
 */
export class SchnorrSignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SchnorrSignError';
  }
}

/**
 * Thrown by `generateScalarFromBitString` (and any `from*` entry point
 * that funnels through it) when the input bitstring fails validation:
 * wrong length (must be `e.s` characters; default 1600 for DALOS) OR
 * contains characters outside the `{'0', '1'}` alphabet.
 *
 * The error message includes the diagnostic `reason` returned by
 * `validateBitString`. Consumers should catch by class and surface a
 * UI-appropriate prompt (e.g., "Bitstring must be exactly 1600 chars
 * of 0 and 1").
 *
 * Introduced in v4.0.2 (F-MED-008) — pre-v4.0.2 this was a bare `Error`.
 */
export class InvalidBitStringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidBitStringError';
  }
}

/**
 * Thrown by `scalarToPrivateKey`, `fromIntegerBase10`, and
 * `fromIntegerBase49` when the input fails private-key validation.
 *
 * Validation rejects scalars whose binary representation:
 *   - Doesn't have '1' as the first bit (failed clamping)
 *   - Doesn't end with the cofactor's binary tail
 *   - Has a middle-bit count != `e.s`
 *
 * The error message includes the diagnostic `reason`. Consumers catching
 * this class can surface "Invalid private-key format" or branch on
 * `error.message` for finer detail (the reason text format is now
 * stable post-F-MED-016 since it's returned from the validator rather
 * than printed inline).
 *
 * Introduced in v4.0.2 (F-MED-008).
 */
export class InvalidPrivateKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPrivateKeyError';
  }
}

/**
 * Thrown by `fromBitmap` when the bitmap fails structural validation:
 * wrong row/column count (must be 40×40 = 1600 cells for the DALOS
 * default) OR malformed shape (rows undefined, etc.).
 *
 * Bitmap input is DALOS-only at the gen1 layer — non-DALOS curves with
 * perfect-square scalar sizes (e.g. APOLLO 32×32 = 1024) require
 * consumer-side dimensioning + `fromBitString` per F-TEST-002 / the
 * scope note on `fromBitmap`. This error class catches structural
 * failures of the DALOS 40×40 bitmap input specifically.
 *
 * Introduced in v4.0.2 (F-MED-008).
 */
export class InvalidBitmapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidBitmapError';
  }
}
