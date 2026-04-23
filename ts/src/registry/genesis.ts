/**
 * `DalosGenesis` — the first registered `CryptographicPrimitive`.
 *
 * Wraps the Phase 1–6 Gen-1 implementation into the registry-compatible
 * `CryptographicPrimitive` interface. Also exposes the Gen-1-specific
 * bitmap input path via `DalosGenesisPrimitive`.
 *
 * All methods here are thin adapters — they defer to the underlying
 * `ts/src/gen1/*.ts` modules. No new cryptography lives in this file.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Bitmap } from '../gen1/bitmap.js';
import { SMART_ACCOUNT_PREFIX, STANDARD_ACCOUNT_PREFIX } from '../gen1/character-matrix.js';
import { DALOS_ELLIPSE } from '../gen1/curve.js';
import { dalosAddressMaker } from '../gen1/hashing.js';
import {
  type DalosFullKey,
  fromBitString,
  fromBitmap,
  fromIntegerBase10,
  fromIntegerBase49,
  fromRandom,
  fromSeedWords,
} from '../gen1/key-gen.js';
import { schnorrSign, schnorrVerify } from '../gen1/schnorr.js';
import type { DalosGenesisPrimitive, FullKey } from './primitive.js';

/**
 * Convert the Gen-1 module's `DalosFullKey` shape into the registry's
 * `FullKey` shape. They're structurally identical for Genesis; this
 * function exists to decouple future Gen-2 types.
 */
function toFullKey(dk: DalosFullKey): FullKey {
  return {
    keyPair: dk.keyPair,
    privateKey: dk.privateKey,
    standardAddress: dk.standardAddress,
    smartAddress: dk.smartAddress,
    scalar: dk.scalar,
  };
}

/**
 * The DALOS Genesis cryptographic primitive — registered under the
 * stable ID `"dalos-gen-1"`. Every Ouronet `Ѻ.` / `Σ.` account in
 * existence was produced by this primitive (or its Go counterpart).
 *
 * Permanent freeze: the output of every method on this primitive is
 * bit-for-bit identical to the Go reference at tag `v2.0.0` and later.
 * Any future modification that would change output becomes a NEW
 * primitive with a new ID, never an update to `dalos-gen-1`.
 */
export const DalosGenesis: DalosGenesisPrimitive = {
  // --- Identity -------------------------------------------------------------

  id: 'dalos-gen-1',

  description:
    'DALOS Genesis — 1606-bit Twisted Edwards curve, 16x16 character matrix, seven-fold Blake3, Schnorr v2 deterministic signatures. The original Ouronet cryptographic primitive.',

  version: 1,

  generation: 'genesis',

  metadata: {
    curveName: DALOS_ELLIPSE.name,
    primeField: DALOS_ELLIPSE.p,
    order: DALOS_ELLIPSE.q,
    cofactor: DALOS_ELLIPSE.r,
    baseBitLength: DALOS_ELLIPSE.s,
    equation: 'x^2 + y^2 ≡ 1 + d*x^2*y^2  (mod P)',
    coefficientA: DALOS_ELLIPSE.a,
    coefficientD: DALOS_ELLIPSE.d,
    generator: {
      ax: DALOS_ELLIPSE.g.ax,
      ay: DALOS_ELLIPSE.g.ay,
    },
    bitmapDimensions: { rows: 40, cols: 40, totalBits: 1600 },
    addressPrefixStandard: STANDARD_ACCOUNT_PREFIX,
    addressPrefixSmart: SMART_ACCOUNT_PREFIX,
    hashingScheme: 'seven-fold Blake3',
    signatureScheme: 'Schnorr v2 (deterministic, RFC-6979-style Blake3 nonces)',
    signatureDomainTags: {
      fiatShamir: 'DALOS-gen1/SchnorrHash/v1',
      nonce: 'DALOS-gen1/SchnorrNonce/v1',
    },
  },

  // --- Universal key-generation paths ---------------------------------------

  generateRandom(): FullKey {
    return toFullKey(fromRandom());
  },

  generateFromBitString(bits: string): FullKey {
    return toFullKey(fromBitString(bits));
  },

  generateFromInteger(n: string, base: 10 | 49): FullKey {
    return toFullKey(base === 10 ? fromIntegerBase10(n) : fromIntegerBase49(n));
  },

  generateFromSeedWords(words: readonly string[]): FullKey {
    return toFullKey(fromSeedWords(words));
  },

  // --- Gen-1 extension ------------------------------------------------------

  generateFromBitmap(bitmap: Bitmap): FullKey {
    return toFullKey(fromBitmap(bitmap));
  },

  // --- Address derivation ---------------------------------------------------

  publicKeyToAddress(publicKey: string, isSmart: boolean): string {
    return dalosAddressMaker(publicKey, isSmart);
  },

  /**
   * Gen-1 detection: an address belongs to Genesis iff it starts with
   * `Ѻ.` (standard) or `Σ.` (smart).
   */
  detectGeneration(address: string): boolean {
    return (
      address.startsWith(`${STANDARD_ACCOUNT_PREFIX}.`) ||
      address.startsWith(`${SMART_ACCOUNT_PREFIX}.`)
    );
  },

  // --- Signing (v2 hardened, deterministic) ---------------------------------

  sign(keyPair, message) {
    return schnorrSign(keyPair, message);
  },

  verify(signature, message, publicKey) {
    return schnorrVerify(signature, message, publicKey);
  },
};
