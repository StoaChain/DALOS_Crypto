/**
 * Scalar multiplication on the DALOS Twisted Edwards curve.
 *
 * Mirrors `Elliptic/PointOperations.go` in the v1.3.0+ Go reference,
 * which uses base-49 Horner evaluation with a branch-free linear scan
 * over the 48-element precompute matrix. The pre-v1.3.0 Go code used
 * a 49-case switch statement on the base-49 digit character — that
 * exposed a macro-level timing channel which PO-1 hardening closed.
 *
 * This port preserves the hardened algorithm:
 *
 *   for each digit d in scalar.base49():
 *     toAdd ← INFINITY
 *     for idx ← 1..48:
 *       if d == idx: toAdd ← PM[(idx-1)/7][(idx-1)%7]
 *     acc ← acc + toAdd
 *     if not last digit: acc ← 49·acc
 *
 * Byte-identity: produces the same affine output as the Go reference
 * for every scalar (verified end-to-end in Phase 4 via the test-vector
 * corpus). Here in Phase 2 we prove correctness via algebraic identities:
 *   - scalarMultiplier(0, G) === INFINITY
 *   - scalarMultiplier(1, G) === G
 *   - scalarMultiplier(49, G) === fortyNiner(G)
 *   - scalarMultiplier(Q, G) === INFINITY       (the critical one: proves G has order Q)
 *
 * Residual: Go `math/big` is not CPU-instruction-level constant-time;
 * JavaScript's native bigint has similar variable-time arithmetic.
 * True constant-time would require a custom limb-oriented implementation.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { CoordExtended } from './coords.js';
import { INFINITY_POINT_EXTENDED } from './coords.js';
import { DALOS_ELLIPSE, type Ellipse, affine2Extended } from './curve.js';
import { ZERO } from './math.js';
import { type PrecomputeMatrix, addition, fortyNiner, precomputeMatrix } from './point-ops.js';

/**
 * Base-49 alphabet used by Go's `big.Int.Text(49)`.
 *
 * Characters 0-9   → values 0-9
 * Characters a-z   → values 10-35
 * Characters A-M   → values 36-48
 *
 * Go's full base-62 alphabet is "0-9a-zA-Z"; base 49 uses the first
 * 49 characters of that. This must match byte-for-byte for
 * cross-implementation compatibility.
 */
export const BASE49_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM' as const;

/**
 * Returns the numeric value (0..48) of a single base-49 digit character.
 *
 * Invalid characters return 0 — matching the Go switch statement's
 * default behaviour (treated as a zero digit, which produces a no-op
 * Addition with the infinity point).
 */
export function digitValueBase49(c: string): number {
  const code = c.charCodeAt(0);
  // '0'..'9' → 0..9
  if (code >= 48 && code <= 57) return code - 48;
  // 'a'..'z' → 10..35
  if (code >= 97 && code <= 122) return code - 97 + 10;
  // 'A'..'M' → 36..48
  if (code >= 65 && code <= 77) return code - 65 + 36;
  return 0;
}

/**
 * Returns true iff `c` is a valid base-49 digit character (i.e.,
 * `digitValueBase49(c)` would return a real digit value, not the
 * silent-0 sentinel for unknown characters).
 *
 * Used by callers that need to reject mixed-validity inputs
 * (validatePrivateKey, parseBigIntInBase) — REQ-20 + REQ-21.
 */
export function isValidBase49Char(c: string): boolean {
  const code = c.charCodeAt(0);
  if (code >= 48 && code <= 57) return true; // '0'..'9'
  if (code >= 97 && code <= 122) return true; // 'a'..'z'
  if (code >= 65 && code <= 77) return true; // 'A'..'M'
  return false;
}

/**
 * Convert a non-negative bigint to its base-49 string representation
 * as produced by Go's `big.Int.Text(49)`.
 *
 * For `0` returns `"0"` (the single-digit representation). Negative
 * inputs are rejected — scalars in cryptographic use should always be
 * non-negative.
 */
export function bigIntToBase49(n: bigint): string {
  if (n < ZERO) {
    throw new Error('bigIntToBase49: negative scalar not supported');
  }
  if (n === ZERO) {
    return '0';
  }
  let result = '';
  let x = n;
  while (x > ZERO) {
    const digit = Number(x % 49n);
    result = BASE49_ALPHABET[digit] + result;
    x = x / 49n;
  }
  return result;
}

/**
 * Computes `scalar · P` on the DALOS curve in Extended coordinates.
 *
 * Algorithm: branch-free base-49 Horner (v1.3.0+ hardened). Every
 * iteration does exactly one `addition` and, between digits, one
 * `fortyNiner`. Point selection scans all 48 PM entries linearly
 * with no early exit — the Go-level operation sequence is identical
 * for every scalar of the same base-49 length.
 *
 * Optional `precomputed` parameter skips the PrecomputeMatrix
 * construction (useful for generator-based mult where G's PM can be
 * cached across calls).
 *
 * @param scalar — non-negative bigint scalar (typically in [0, Q-1])
 * @param P      — base point in Extended coordinates
 * @param e      — curve (default DALOS_ELLIPSE)
 * @param precomputed — optional pre-built PrecomputeMatrix for P
 */
export function scalarMultiplier(
  scalar: bigint,
  P: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  precomputed?: PrecomputeMatrix,
): CoordExtended {
  if (scalar < ZERO) {
    throw new Error('scalarMultiplier: negative scalar not supported');
  }

  const PM = precomputed ?? precomputeMatrix(P, e);
  const digits = bigIntToBase49(scalar);
  let result: CoordExtended = INFINITY_POINT_EXTENDED;

  for (let i = 0; i < digits.length; i++) {
    const ch = digits[i];
    if (ch === undefined) {
      // Defensive: shouldn't happen with valid base-49 string, but the
      // compiler doesn't know that under noUncheckedIndexedAccess.
      continue;
    }
    const value = digitValueBase49(ch);

    // Branch-free point selection over all 48 precompute entries.
    // Always examines every index — no early exit.
    let toAdd: CoordExtended = INFINITY_POINT_EXTENDED;
    for (let idx = 1; idx <= 48; idx++) {
      const row = Math.floor((idx - 1) / 7);
      const col = (idx - 1) % 7;
      if (value === idx) {
        const candidate = PM[row]?.[col];
        if (candidate !== undefined) {
          toAdd = candidate;
        }
      }
    }

    result = addition(result, toAdd, e);

    if (i !== digits.length - 1) {
      result = fortyNiner(result, e);
    }
  }

  return result;
}

/**
 * Shortcut: computes `scalar · G` where G is the curve's generator.
 *
 * Mirrors Go's `(*Ellipse).ScalarMultiplierWithGenerator`. Does NOT
 * cache the generator's PM across calls — each invocation rebuilds.
 * Phase 4's key-generation API layer will add an explicit
 * pre-cache-and-reuse pattern for the hot paths.
 */
export function scalarMultiplierWithGenerator(
  scalar: bigint,
  e: Ellipse = DALOS_ELLIPSE,
): CoordExtended {
  return scalarMultiplier(scalar, affine2Extended(e.g, e.field), e);
}
