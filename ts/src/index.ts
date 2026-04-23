/**
 * @stoachain/dalos-crypto — TypeScript port of the DALOS Genesis cryptographic primitive.
 *
 * Scaffold placeholder. Real exports land in Phase 1 onward:
 *   Phase 1 → src/gen1/math.ts, coords.ts, curve.ts, point-ops.ts
 *   Phase 2 → src/gen1/scalar-mult.ts
 *   Phase 3 → src/gen1/hashing.ts, character-matrix.ts (+ @stoachain/dalos-blake3 dep)
 *   Phase 4 → src/gen1/key-gen.ts, bitmap.ts, validate.ts
 *   Phase 5 → src/gen1/aes.ts
 *   Phase 6 → src/gen1/schnorr.ts
 *   Phase 7 → src/registry/primitive.ts, registry.ts, genesis.ts
 *
 * Every function will be validated byte-for-byte against the v2.1.0 Go
 * reference's testvectors/v1_genesis.json (105 records).
 *
 * @see ../../docs/TS_PORT_PLAN.md
 */

export const SCAFFOLD_VERSION = '0.0.1';
