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
 * **Production primitives as of v3.0.0+.** Each historical curve is
 * wrapped by a full `CryptographicPrimitive` adapter at
 * `ts/src/registry/{leto,artemis,apollo}.ts` exposing key-gen across 5
 * input paths (random / bitString / integerBase10 / integerBase49 /
 * seedWords) plus Schnorr v2 sign / verify. Cross-implementation
 * byte-identity formalized in v3.0.0+ via `testvectors/v1_historical.json`
 * (schema_version 2); requires Go reference v3.0.0 or later (XCURVE-1..4
 * fixes resolved the Math.ceil vs Math.floor divergence on non-byte-aligned
 * curves). NOT auto-registered in `createDefaultRegistry()` — register
 * explicitly via `registry.register(Leto)` etc. Address prefixes are
 * disjoint: LETO `Ł`/`Λ`, ARTEMIS `R`/`Ř`, APOLLO `₱`/`Π`, distinct
 * from DALOS Genesis `Ѻ`/`Σ`.
 *
 * See `docs/HISTORICAL_CURVES.md` for the birthstory of each curve,
 * `docs/SCHNORR_V2_SPEC.md` for the Schnorr construction, and
 * `verification/VERIFICATION_LOG.md` for the full 7-test audit.
 *
 * Ouronet reality-check: every real Ouronet account is derived from
 * DALOS_ELLIPSE. Genesis is frozen; the historical curves are
 * production primitives but registered opt-in.
 */

export { LETO } from './leto.js';
export { ARTEMIS } from './artemis.js';
export { APOLLO } from './apollo.js';
