/**
 * `Leto` — cryptographic primitive wrapping the LETO curve (545-bit
 * safe scalar). Production-ready: full key-gen across 5 input paths
 * (random / bitString / integerBase10 / integerBase49 / seedWords) and
 * Schnorr v2 sign / verify.
 *
 * Addresses:
 *   - Standard: `Ł.xxxxx…` (Latin Capital L with stroke, matrix [6,2])
 *   - Smart:    `Λ.xxxxx…` (Greek Capital Lambda,         matrix [11,4])
 *
 * Both prefix characters are part of the DALOS 256-rune character
 * matrix and render natively in every downstream tool.
 *
 * NOT registered in `createDefaultRegistry()` by default — import and
 * register explicitly when you want it. Byte-identity with the Go
 * reference is formalized as of v3.0.0+ (requires Go reference v3.0.0
 * or later; XCURVE-1..4 fixes resolved the Math.ceil-vs-floor
 * divergence on non-byte-aligned curves).
 *
 * v1.2.0+, byte-identity formalized v3.0.0+. Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { LETO } from '../historical/leto.js';
import { createGen1Primitive } from './gen1-factory.js';
import type { CryptographicPrimitive } from './primitive.js';

export const Leto: CryptographicPrimitive = createGen1Primitive({
  id: 'dalos-leto',
  description:
    'LETO — 545-bit safe-scalar Twisted Edwards curve from the original Cryptoplasm research. Same structural family as DALOS Genesis (cofactor 4, negative D). Addresses use Ł (standard) / Λ (smart) prefixes.',
  version: 1,
  generation: 'leto',
  curve: LETO,
  prefixes: {
    standard: 'Ł',
    smart: 'Λ',
  },
  extraMetadata: {
    historicalNote:
      'Named after Leto, Titaness who gave birth to Apollo and Artemis on Delos. The smallest of the three historical curves — 2^545 ≈ 1.15 × 10^164 keys.',
  },
});
