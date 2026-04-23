/**
 * @stoachain/dalos-crypto/historical
 *
 * Three novel Twisted-Edwards curves discovered during Kjrekntolopon's
 * original Cryptoplasm research (the very first iteration of what would
 * eventually become DALOS). Named after the Delian family — LETO (the
 * mother), ARTEMIS, and APOLLO (the twin children) — matching the
 * aesthetic of DALOS itself (the sacred island).
 *
 * Same structural family as DALOS_ELLIPSE — cofactor 4,
 * `y² + x² = 1 + d·x²·y²` with negative `d` — but with smaller primes
 * (545, 1023, 1024 safe-scalar bits respectively). APOLLO and ARTEMIS
 * are twin curves: they share the same prime P (2^1029 + 639), diverging
 * only in the curve coefficient `d` and consequently in Q.
 *
 * **These are historical artifacts, not production primitives.** They
 * are NOT registered in the `CryptographicRegistry`, they do NOT derive
 * Ouronet addresses, and they do NOT participate in Schnorr signing.
 * The gen-1 arithmetic engine happens to accept any Ellipse-shaped curve
 * in the cofactor-4 TEC family, so these constants can be plugged into
 * `scalarMultiplierWithGenerator(k, curve, new Modular(curve.p))` for
 * point-of-interest research, debugging, or benchmarking.
 *
 * See `docs/HISTORICAL_CURVES.md` for the birthstory of each curve and
 * `verification/VERIFICATION_LOG.md` for the full 7-test audit.
 *
 * Ouronet reality-check: every real Ouronet account is derived from
 * DALOS_ELLIPSE. Genesis is frozen; the curves below are never used
 * to mint addresses.
 */

export { LETO } from './leto.js';
export { ARTEMIS } from './artemis.js';
export { APOLLO } from './apollo.js';
