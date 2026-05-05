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

// ============================================================================
// Module-level caches
// ============================================================================

/**
 * Module-level cache of generator PrecomputeMatrix per curve.
 *
 * Populated lazily on first call to `scalarMultiplierWithGenerator` for
 * a given curve and reused on every subsequent call. The four production
 * curve singletons (`DALOS_ELLIPSE`, `LETO`, `ARTEMIS`, `APOLLO`) live for
 * the process lifetime; consumer-defined custom curves remain GC-eligible
 * because `WeakMap` does not pin its keys.
 *
 * Co-located with the consuming function. Schnorr's async signer/verifier
 * read this cache through `getOrBuildGeneratorPM` to thread the cached
 * matrix into `scalarMultiplierAsync`'s `precomputed` parameter.
 */
const generatorPMCache = new WeakMap<Ellipse, PrecomputeMatrix>();

/**
 * Returns the cached generator-PrecomputeMatrix for `e`, building and
 * memoising it on first miss. The `Modular` is ALWAYS derived internally
 * from `e.p` to prevent cache-poisoning: a public caller passing a wrong-`m`
 * default (e.g. `scalarMultiplierWithGenerator(z, LETO)` with the implicit
 * `DALOS_FIELD` default) would otherwise persist a wrong-field PM into the
 * cache for the process lifetime. Deriving `m` from `e.p` here is sound
 * because `Modular` is stateless after construction and a curve's prime
 * field is fixed.
 *
 * @internal Exported solely to allow `schnorr.ts`'s async signer/verifier
 * to thread the cached PM through `scalarMultiplierAsync`'s `precomputed`
 * parameter. Not part of the public API; consumers should not import this
 * directly. Use `scalarMultiplierWithGenerator(scalar, e)` instead.
 */
export function getOrBuildGeneratorPM(e: Ellipse): PrecomputeMatrix {
  let pm = generatorPMCache.get(e);
  if (!pm) {
    // Phase 5 post-merge: precomputeMatrix derives the field internally
    // from `e.field` (was: explicit `m: Modular = DALOS_FIELD` parameter
    // pre-Phase-5). Use `e.field` for the affine→extended conversion which
    // still takes an explicit Modular argument.
    pm = precomputeMatrix(affine2Extended(e.g, e.field), e);
    generatorPMCache.set(e, pm);
  }
  return pm;
}

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
  // REQ-29: O(n) array-push + reverse + join, not O(n²) string-prepend.
  // The digit index is mathematically guaranteed to be in [0, 48] by
  // `Number(x % 49n)`, so the BASE49_ALPHABET lookup is always defined;
  // the non-null assertion is honest about that bound.
  const digits: string[] = [];
  let x = n;
  while (x > ZERO) {
    const digit = Number(x % 49n);
    digits.push(BASE49_ALPHABET[digit]!);
    x = x / 49n;
  }
  return digits.reverse().join('');
}

/**
 * F-LOW-006 (audit cycle 2026-05-04, v4.0.3): flatten the 7×7
 * PrecomputeMatrix into a 48-element linear array ONCE per
 * scalar-mult call. The pre-fix inner loop recomputed
 * `Math.floor((idx-1)/7)` and `(idx-1)%7` on every one of the 48
 * iterations, then did an optional-chain probe `PM[row]?.[col]` plus
 * an `=== undefined` check — about 4 arithmetic ops + a nested
 * lookup per iteration. For the typical DALOS scalar (~250 base-49
 * digits), that's ~250 × 48 = 12,000 redundant `Math.floor` calls
 * and the same number of `%` ops per scalar-mult.
 *
 * Post-flatten: the inner loop just does `flat[idx - 1]` — one
 * pre-computed lookup. Builder cost is the same 48 iterations done
 * ONCE up front, paying the optional-chain probe + undefined check
 * exactly once per (row, col) instead of repeatedly inside the hot
 * loop.
 *
 * Constant-time property preserved: `flat` is fully populated before
 * the outer Horner loop starts; the inner 48-entry scan still runs
 * every iteration to completion (no early exit), and `value === idx`
 * still uniformly probes every position. The optimisation only
 * removes per-iteration arithmetic, not data-dependent branching.
 *
 * Helper is module-private (consumers should always go through
 * `scalarMultiplier` / `scalarMultiplierAsync`).
 */
function flattenPM(PM: PrecomputeMatrix): CoordExtended[] {
  const flat: CoordExtended[] = new Array(48);
  for (let idx = 1; idx <= 48; idx++) {
    const row = Math.floor((idx - 1) / 7);
    const col = (idx - 1) % 7;
    const candidate = PM[row]?.[col];
    if (candidate === undefined) {
      // PrecomputeMatrix from precomputeMatrix() / PrecomputeMatrix-
      // WithGenerator() is always 7×7-defined by construction. A
      // missing slot here would indicate a malformed PM passed via
      // the optional `precomputed` parameter — surface loudly rather
      // than silently substituting INFINITY_POINT_EXTENDED.
      throw new Error(
        `flattenPM: PrecomputeMatrix is malformed (missing entry at PM[${row}][${col}], idx=${idx})`,
      );
    }
    flat[idx - 1] = candidate;
  }
  return flat;
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
  // F-LOW-006 (v4.0.3): flatten 7×7 PM → 48-entry linear array ONCE
  // per call. See flattenPM docstring above for rationale.
  const flat = flattenPM(PM);
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
    // Always examines every index — no early exit. F-LOW-006 (v4.0.3):
    // post-flatten, each iteration is a single `flat[idx - 1]` lookup
    // plus the `value === idx` selector — no per-iter Math.floor / %.
    // The non-null assertion is justified by flattenPM's invariant
    // that all 48 entries are populated (it throws otherwise).
    let toAdd: CoordExtended = INFINITY_POINT_EXTENDED;
    for (let idx = 1; idx <= 48; idx++) {
      if (value === idx) {
        toAdd = flat[idx - 1]!;
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
 * Mirrors Go's `(*Ellipse).ScalarMultiplierWithGenerator`. Caches the
 * generator's PrecomputeMatrix per `Ellipse` via a module-level
 * `WeakMap`; first call populates, subsequent calls reuse. The cache
 * is shared with `schnorrSignAsync`/`schnorrVerifyAsync` through
 * `getOrBuildGeneratorPM` so sync and async paths never rebuild the
 * matrix more than once per curve per process.
 */
export function scalarMultiplierWithGenerator(
  scalar: bigint,
  e: Ellipse = DALOS_ELLIPSE,
): CoordExtended {
  // Origin v3.1.0 added the generator-PM WeakMap cache (F-PERF-001); Phase 5
  // post-merge transformation: use `e.field` instead of the eliminated
  // `DALOS_FIELD`/`m` default-param footgun.
  const PM = getOrBuildGeneratorPM(e);
  return scalarMultiplier(scalar, affine2Extended(e.g, e.field), e, PM);
}

/**
 * Yields control to the event loop via `setImmediate` (Node) or
 * `setTimeout(_, 0)` (browser/Deno fallback). The cross-runtime guard
 * mirrors the existing `globalThis.crypto.subtle` precedent in `aes.ts`.
 *
 * Module-private. Tests verify yield cadence by spying on
 * `globalThis.setImmediate` directly (the platform API this helper calls),
 * so no `export` is needed for test instrumentation.
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof globalThis.setImmediate === 'function') {
      globalThis.setImmediate(resolve);
    } else {
      setTimeout(resolve, 0);
    }
  });
}

/**
 * Async variant of `scalarMultiplier` that yields to the event loop
 * every 8 outer-loop iterations to keep the host responsive during a
 * full-curve-scale (~285-digit) base-49 Horner evaluation.
 *
 * The body mirrors `scalarMultiplier` byte-for-byte EXCEPT for one
 * additional statement at the bottom of the outer-loop body:
 *
 *     if ((i & 0x07) === 0x07) await yieldToEventLoop();
 *
 * The yield trigger depends ONLY on the iteration index `i` and is
 * identical for all scalars of the same base-49 length. It NEVER
 * branches on the scalar value, the digit value, or any quantity
 * derived from secret material. The constant-time property of the
 * sync path (every iteration does exactly one `addition` + one
 * `fortyNiner`, branch-free linear scan over 48 PM entries) is
 * preserved verbatim by the async path; the yield happens BETWEEN
 * iterations, never INSIDE the inner branch-free 48-entry scan.
 *
 * Yield cadence: every 8 iterations. A full 1604-bit scalar produces
 * ~285 base-49 digits, so a complete async multiplication yields ~36
 * times. With per-iteration cost of ~5-10 ms in big-int arithmetic on
 * a typical browser, the inter-yield window is ~40-80 ms — well under
 * the 200 ms INP target.
 *
 * Phase 5 post-merge: dropped the `m: Modular = DALOS_FIELD` default-param
 * footgun (origin v3.1.0 added this function with the old pattern; we
 * normalize to the post-Phase-5 `e.field` convention used everywhere else
 * in the gen1 layer). All point-ops calls below also drop the redundant
 * `m` argument now that addition/fortyNiner/precomputeMatrix derive it
 * internally from `e.field`.
 *
 * @param scalar — non-negative bigint scalar (typically in [0, Q-1])
 * @param P      — base point in Extended coordinates
 * @param e      — curve (default DALOS_ELLIPSE)
 * @param precomputed — optional pre-built PrecomputeMatrix for P
 *                      (consumers thread the cached generator-PM here)
 */
export async function scalarMultiplierAsync(
  scalar: bigint,
  P: CoordExtended,
  e: Ellipse = DALOS_ELLIPSE,
  precomputed?: PrecomputeMatrix,
): Promise<CoordExtended> {
  if (scalar < ZERO) {
    throw new Error('scalarMultiplierAsync: negative scalar not supported');
  }

  const PM = precomputed ?? precomputeMatrix(P, e);
  // F-LOW-006 (v4.0.3): same flatten-once optimisation as the sync
  // path. See flattenPM docstring for rationale + constant-time
  // preservation argument.
  const flat = flattenPM(PM);
  const digits = bigIntToBase49(scalar);
  let result: CoordExtended = INFINITY_POINT_EXTENDED;

  for (let i = 0; i < digits.length; i++) {
    const ch = digits[i];
    if (ch === undefined) {
      continue;
    }
    const value = digitValueBase49(ch);

    // Branch-free 48-entry scan, post-flatten — single lookup per iter.
    let toAdd: CoordExtended = INFINITY_POINT_EXTENDED;
    for (let idx = 1; idx <= 48; idx++) {
      if (value === idx) {
        toAdd = flat[idx - 1]!;
      }
    }

    result = addition(result, toAdd, e);

    if (i !== digits.length - 1) {
      result = fortyNiner(result, e);
    }

    // Data-independent yield cadence: trigger depends only on `i`.
    // Placed at the BOTTOM of the outer-loop body so a fully-completed
    // iteration (addition + fortyNiner) precedes each yield.
    if ((i & 0x07) === 0x07) {
      await yieldToEventLoop();
    }
  }

  return result;
}
