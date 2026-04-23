/**
 * @stoachain/dalos-crypto — TypeScript port of the DALOS Genesis cryptographic primitive.
 *
 * Phase 1 landed (v2.3.0): Genesis math foundation is now exported.
 * Phase 2 onward adds scalar multiplication, hashing, key generation,
 * AES, Schnorr, and the modular primitive registry.
 *
 * @see ../../docs/TS_PORT_PLAN.md
 */

export const SCAFFOLD_VERSION = '0.6.0';

// Re-export the gen1 subpath at the top level for discoverability.
// Canonical import path is still `@stoachain/dalos-crypto/gen1`.
export * as gen1 from './gen1/index.js';
