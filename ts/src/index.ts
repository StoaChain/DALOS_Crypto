/**
 * @stoachain/dalos-crypto — TypeScript port of the DALOS Genesis cryptographic primitive.
 *
 * Phase 1 landed (v2.3.0): Genesis math foundation is now exported.
 * Phase 2 onward adds scalar multiplication, hashing, key generation,
 * AES, Schnorr, and the modular primitive registry.
 *
 * @see ../../docs/TS_PORT_PLAN.md
 */

// Re-export the gen1 subpath at the top level for discoverability.
// Canonical import path is still `@stoachain/dalos-crypto/gen1`.
export * as gen1 from './gen1/index.js';

// Re-export the registry subpath — the idiomatic entry point for
// consumers who want to work at the primitive-registry level rather
// than calling gen1 functions directly.
export * as registry from './registry/index.js';

// Re-export the historical-curves subpath at the top level for discoverability.
// Canonical import path is still `@stoachain/dalos-crypto/historical`. The three production
// primitives (LETO / ARTEMIS / APOLLO) are exposed but NOT auto-registered in `createDefaultRegistry()` — see `ts/src/historical/index.ts:20-24`.
export * as historical from './historical/index.js';

// Re-export the dalos-blake3 subpath at the top level for discoverability.
// Canonical import path is still `@stoachain/dalos-crypto/dalos-blake3`. Exposes `blake3SumCustom`
// and `sevenFoldBlake3` — the Genesis seven-fold construction. This subpath WILL be extracted to a sibling npm package in Phase 11; the root namespace re-export is a forward-compatible alias.
export * as blake3 from './dalos-blake3/index.js';
