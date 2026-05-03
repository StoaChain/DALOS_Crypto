/**
 * `Apollo` — cryptographic primitive wrapping the APOLLO curve
 * (1024-bit safe scalar). Production-ready: full key-gen across 5 input
 * paths and Schnorr v2 sign / verify.
 *
 * Addresses:
 *   - Standard: `₱.xxxxx…` (Peso Sign,                    matrix [1,1])
 *   - Smart:    `Π.xxxxx…` (Greek Capital Pi,             matrix [11,6])
 *
 * Both prefix characters are part of the DALOS 256-rune character
 * matrix. The Peso sign + Greek Pi pair was chosen for maximum visual
 * distinctiveness within the P-family letterforms available.
 *
 * **Production primitive as of v3.0.0+** — wraps the APOLLO curve from
 * `ts/src/historical/apollo.ts` with full key-gen across 5 input paths
 * (random / bitString / integerBase10 / integerBase49 / seedWords) plus
 * Schnorr v2 sign / verify. APOLLO has S=1024 (byte-aligned), so the
 * XCURVE-1..4 ceiling-vs-floor fix is a no-op on APOLLO's output;
 * cross-implementation byte-identity formalized in v3.0.0+ regardless
 * via `testvectors/v1_historical.json` (schema_version 2); requires Go
 * reference v3.0.0+. NOT auto-registered in `createDefaultRegistry()` —
 * import and register explicitly via `registry.register(Apollo)`.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { APOLLO } from '../historical/apollo.js';
import { createGen1Primitive } from './gen1-factory.js';
import type { CryptographicPrimitive } from './primitive.js';

export const Apollo: CryptographicPrimitive = createGen1Primitive({
  id: 'dalos-apollo',
  description:
    'APOLLO — 1024-bit safe-scalar Twisted Edwards curve, twin of ARTEMIS (shared prime P, divergent D). Same structural family as DALOS Genesis. Addresses use ₱ (standard) / Π (smart) prefixes.',
  version: 1,
  generation: 'apollo',
  curve: APOLLO,
  prefixes: {
    standard: '₱',
    smart: 'Π',
  },
  extraMetadata: {
    historicalNote:
      'Named after Apollo, twin brother of Artemis, born on Delos. Slightly larger twin — 2^1024 ≈ 1.8 × 10^308 keys. Shares its prime P with ARTEMIS.',
    twinOf: 'dalos-artemis',
  },
});
