/**
 * `createGen1Primitive` — shared factory for Gen-1-family cryptographic
 * primitives (same math, different curve + address prefixes).
 *
 * DalosGenesis itself does not use this factory — it's kept in
 * `genesis.ts` as the reference wrapping to preserve byte-identity
 * against the Go corpus without inadvertent drift. This factory is for
 * the historical curves (LETO / ARTEMIS / APOLLO) and any future
 * Gen-1-family primitives that consumers want to wire into their
 * registries.
 *
 * Every primitive produced by this factory:
 *   - Uses the same HWCD point arithmetic + base-49 Horner scalar-mult
 *     (parameterised on `Ellipse`)
 *   - Uses the same Schnorr v2 sign / verify (parameterised on `Ellipse`)
 *   - Uses the same seven-fold Blake3 address derivation (parameterised
 *     on the prefix pair)
 *   - Supports all 5 universal input paths (random, bitString,
 *     integerBase10, integerBase49, seedWords)
 *
 * The 6th input path (40×40 bitmap → 1600 bits) is intrinsically tied
 * to DALOS's 1600-bit safe-scalar and is NOT included here. Primitives
 * from this factory implement only the base `CryptographicPrimitive`
 * interface, not the `DalosGenesisPrimitive` extension.
 *
 * v1.2.0 — introduced when LETO / ARTEMIS / APOLLO were promoted from
 * historical artefacts to production-ready cryptographic primitives.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Ellipse } from '../gen1/curve.js';
import { type AddressPrefixPair, dalosAddressMaker } from '../gen1/hashing.js';
import {
  type DalosFullKey,
  fromBitString,
  fromIntegerBase10,
  fromIntegerBase49,
  fromRandom,
  fromSeedWords,
} from '../gen1/key-gen.js';
import { schnorrSign, schnorrVerify } from '../gen1/schnorr.js';
import type { CryptographicPrimitive, FullKey, PrimitiveMetadata } from './primitive.js';

export interface Gen1PrimitiveConfig {
  /** Stable identifier, e.g. "dalos-leto" / "dalos-artemis" / "dalos-apollo". */
  readonly id: string;
  /** Human-readable one-line description. */
  readonly description: string;
  /** Monotonic version, typically 1 for a primitive's initial shipment. */
  readonly version: number;
  /** Generation name, e.g. "leto" / "artemis" / "apollo". */
  readonly generation: string;
  /** The curve parameters — any `Ellipse`-shaped value. */
  readonly curve: Ellipse;
  /** The two-character prefix pair that brands this primitive's addresses. */
  readonly prefixes: AddressPrefixPair;
  /** Optional per-primitive metadata merged into the returned `metadata` object. */
  readonly extraMetadata?: Record<string, unknown>;
}

/**
 * Build a `CryptographicPrimitive` from a Gen-1-family config.
 *
 * The returned primitive's addresses use the config's prefix pair (not
 * DALOS's `Ѻ` / `Σ`). Everything else — key-gen, Schnorr, metadata
 * population — comes from the shared gen1 modules with the config's
 * curve.
 */
export function createGen1Primitive(cfg: Gen1PrimitiveConfig): CryptographicPrimitive {
  const { id, description, version, generation, curve: e, prefixes, extraMetadata } = cfg;

  const metadata: PrimitiveMetadata = {
    curveName: e.name,
    primeField: e.p,
    order: e.q,
    cofactor: e.r,
    baseBitLength: e.s,
    equation: 'x^2 + y^2 ≡ 1 + d*x^2*y^2  (mod P)',
    coefficientA: e.a,
    coefficientD: e.d,
    generator: { ax: e.g.ax, ay: e.g.ay },
    addressPrefixStandard: prefixes.standard,
    addressPrefixSmart: prefixes.smart,
    hashingScheme: 'seven-fold Blake3',
    signatureScheme: 'Schnorr v2 (deterministic, RFC-6979-style Blake3 nonces)',
    signatureDomainTags: {
      fiatShamir: 'DALOS-gen1/SchnorrHash/v1',
      nonce: 'DALOS-gen1/SchnorrNonce/v1',
    },
    ...extraMetadata,
  };

  /**
   * Adapt the gen-1 module's `DalosFullKey` to the registry `FullKey`
   * while re-stamping the two addresses with this primitive's prefix
   * pair. The public key itself is identical regardless of prefix —
   * only the leading prefix character differs.
   */
  const toFullKey = (dk: DalosFullKey): FullKey => ({
    keyPair: dk.keyPair,
    privateKey: dk.privateKey,
    standardAddress: dalosAddressMaker(dk.keyPair.publ, false, prefixes),
    smartAddress: dalosAddressMaker(dk.keyPair.publ, true, prefixes),
    scalar: dk.scalar,
  });

  return {
    id,
    description,
    version,
    generation,
    metadata,

    generateRandom: () => toFullKey(fromRandom(e)),
    generateFromBitString: (bits: string) => toFullKey(fromBitString(bits, e)),
    generateFromInteger: (n: string, base: 10 | 49) =>
      toFullKey(base === 10 ? fromIntegerBase10(n, e) : fromIntegerBase49(n, e)),
    generateFromSeedWords: (words: readonly string[]) => toFullKey(fromSeedWords(words, e)),

    publicKeyToAddress: (publicKey: string, isSmart: boolean) =>
      dalosAddressMaker(publicKey, isSmart, prefixes),

    detectGeneration: (address: string) =>
      address.startsWith(`${prefixes.standard}.`) || address.startsWith(`${prefixes.smart}.`),

    sign: (keyPair, message) => schnorrSign(keyPair, message, e),
    verify: (signature, message, publicKey) => schnorrVerify(signature, message, publicKey, e),
  };
}
