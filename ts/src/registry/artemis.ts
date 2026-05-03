/**
 * `Artemis` — cryptographic primitive wrapping the ARTEMIS curve
 * (1023-bit safe scalar). Production-ready: full key-gen across 5 input
 * paths and Schnorr v2 sign / verify.
 *
 * Addresses:
 *   - Standard: `R.xxxxx…` (Latin Capital R,              matrix [2,5])
 *   - Smart:    `Ř.xxxxx…` (Latin R with háček,           matrix [6,11])
 *
 * Both prefix characters are part of the DALOS 256-rune character
 * matrix. Since neither Greek Α nor Cyrillic А are in the matrix,
 * ARTEMIS uses two distinctive Latin R-variants to clearly mark its
 * standard/smart pair.
 *
 * **Production primitive as of v3.0.0+** — wraps the ARTEMIS curve from
 * `ts/src/historical/artemis.ts` with full key-gen across 5 input paths
 * (random / bitString / integerBase10 / integerBase49 / seedWords) plus
 * Schnorr v2 sign / verify. Cross-implementation byte-identity formalized
 * in v3.0.0+ via `testvectors/v1_historical.json` (schema_version 2);
 * requires Go reference v3.0.0+ (XCURVE-1..4 fixes). NOT auto-registered
 * in `createDefaultRegistry()` — import and register explicitly via
 * `registry.register(Artemis)`.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { ARTEMIS } from '../historical/artemis.js';
import { createGen1Primitive } from './gen1-factory.js';
import type { CryptographicPrimitive } from './primitive.js';

export const Artemis: CryptographicPrimitive = createGen1Primitive({
  id: 'dalos-artemis',
  description:
    'ARTEMIS — 1023-bit safe-scalar Twisted Edwards curve, twin of APOLLO (shared prime P, divergent D). Same structural family as DALOS Genesis. Addresses use R (standard) / Ř (smart) prefixes.',
  version: 1,
  generation: 'artemis',
  curve: ARTEMIS,
  prefixes: {
    standard: 'R',
    smart: 'Ř',
  },
  extraMetadata: {
    historicalNote:
      'Named after Artemis, twin sister of Apollo, born on Delos. Slightly smaller twin — 2^1023 ≈ 9.0 × 10^307 keys. Shares its prime P with APOLLO.',
    twinOf: 'dalos-apollo',
  },
});
