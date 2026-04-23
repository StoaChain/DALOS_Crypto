/**
 * The `CryptographicPrimitive` interface — the abstract surface that
 * any DALOS-compatible cryptographic generation must implement.
 *
 * Genesis ("gen-1", DALOS Genesis) is the first and currently only
 * registered primitive. Future generations (e.g., a post-quantum
 * primitive) can register alongside under a new `id` without breaking
 * any existing Gen-1 accounts — the registry dispatches based on
 * `detectGeneration` when needed, and the `default()` primitive
 * controls which generation is used for NEW key creation.
 *
 * Design principles:
 *   - All primitives expose the same core input paths (random, bitstring,
 *     integer, seed words) for cross-generation portability.
 *   - Primitives can expose additional gen-specific methods by
 *     extending this interface (e.g., `DalosGenesisPrimitive` adds
 *     `generateFromBitmap`).
 *   - Signing is optional — a primitive may be keygen-only.
 *   - `metadata` is a strict typed shape covering the five key
 *     invariants (curve, field, order, cofactor, bit-length) plus
 *     arbitrary additional per-primitive fields.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Bitmap } from '../gen1/bitmap.js';

// ============================================================================
// Value types (generation-agnostic)
// ============================================================================

/**
 * A key pair: private and public key in their canonical string forms.
 *
 * For DALOS Genesis:
 *   - `priv` is the base-49 scalar (~285 chars)
 *   - `publ` is the `"{prefixLen}.{xyBase49}"` encoded public key
 *
 * Future generations may use different encodings but the shape is
 * stable (two strings, both treated as opaque by the registry).
 */
export interface KeyPair {
  readonly priv: string;
  readonly publ: string;
}

/**
 * The three private-key representations used by DALOS Genesis. Future
 * generations may leave `bitString` / `int10` / `int49` empty strings
 * if those representations are not meaningful for their key format.
 */
export interface PrivateKeyForms {
  readonly bitString: string;
  readonly int10: string;
  readonly int49: string;
}

/**
 * A fully-materialised account: key pair + private-key representations
 * + both address forms. Returned by every `generateFrom*` entry point.
 */
export interface FullKey {
  readonly keyPair: KeyPair;
  readonly privateKey: PrivateKeyForms;
  readonly standardAddress: string;
  readonly smartAddress: string;
  /**
   * Optional scalar representation — present for Gen-1 (elliptic-curve
   * private scalar), may be absent for primitives with different
   * internal key structure.
   */
  readonly scalar?: bigint;
}

/**
 * Standard metadata fields every primitive must expose, plus an
 * open-ended string-keyed map for per-primitive additional fields.
 */
export interface PrimitiveMetadata {
  readonly curveName: string;
  readonly primeField: bigint;
  readonly order: bigint;
  readonly cofactor: bigint;
  readonly baseBitLength: number;
  readonly [key: string]: unknown;
}

// ============================================================================
// Core interface (every primitive must implement)
// ============================================================================

/**
 * Abstract cryptographic primitive. DALOS Genesis is the reference
 * implementation. Future generations register under new `id`s.
 */
export interface CryptographicPrimitive {
  /** Stable identifier, e.g., `"dalos-gen-1"`. */
  readonly id: string;

  /** Human-readable description. */
  readonly description: string;

  /** Monotonic version (1 for Genesis). */
  readonly version: number;

  /** Generation name: `"genesis"`, `"gen2"`, `"pq"`, etc. */
  readonly generation: string;

  /** Curve / scheme parameters for inspection. */
  readonly metadata: PrimitiveMetadata;

  // --- Universal key-generation paths (shared by all primitives) -------------

  /**
   * Generate a fresh key from cryptographically-random bits.
   * Output is non-deterministic.
   */
  generateRandom(): FullKey;

  /**
   * Generate a key from a user-provided bit-string. Bit-string length
   * is primitive-specific; Genesis requires exactly 1600 bits.
   */
  generateFromBitString(bits: string): FullKey;

  /**
   * Generate a key from an integer representation in the given base.
   */
  generateFromInteger(n: string, base: 10 | 49): FullKey;

  /**
   * Generate a key from a UTF-8 seed-word list. The primitive defines
   * how words are combined (Genesis: space-joined, seven-fold Blake3).
   */
  generateFromSeedWords(words: readonly string[]): FullKey;

  // --- Address ---------------------------------------------------------------

  /**
   * Derive an address from a public key. `isSmart` selects between
   * the two Ouronet address types (`Ѻ.` standard vs `Σ.` smart).
   */
  publicKeyToAddress(publicKey: string, isSmart: boolean): string;

  /**
   * Return true if the given address string belongs to this primitive's
   * generation. Used by `CryptographicRegistry.detect` to dispatch
   * operations on existing addresses to the correct primitive.
   */
  detectGeneration(address: string): boolean;

  // --- Optional signing ------------------------------------------------------

  /**
   * Produce a signature over `message` using `keyPair`'s private key.
   * Returns `""` on internal failure. Output determinism is
   * primitive-specific: Gen-1 Schnorr v2 is fully deterministic.
   */
  sign?(keyPair: KeyPair, message: string | Uint8Array): string;

  /**
   * Verify a signature. `true` iff the signature is well-formed and
   * valid under `publicKey`.
   */
  verify?(signature: string, message: string | Uint8Array, publicKey: string): boolean;
}

// ============================================================================
// DALOS Genesis extension (adds the bitmap input path)
// ============================================================================

/**
 * DALOS Genesis extends the base interface with the 40×40 bitmap
 * input path. Other primitives won't have this.
 */
export interface DalosGenesisPrimitive extends CryptographicPrimitive {
  generateFromBitmap(bitmap: Bitmap): FullKey;
}

/**
 * Type guard — narrow a generic primitive to `DalosGenesisPrimitive`
 * if it supports the bitmap input path.
 */
export function isDalosGenesisPrimitive(p: CryptographicPrimitive): p is DalosGenesisPrimitive {
  return typeof (p as DalosGenesisPrimitive).generateFromBitmap === 'function';
}
