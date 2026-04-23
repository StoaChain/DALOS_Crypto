/**
 * DALOS hashing, address encoding, and public-key string format.
 *
 * Ports the address-derivation pipeline from `Elliptic/KeyGeneration.go`
 * line-for-line:
 *
 *   seed-words / public-key-integer
 *          │
 *          ▼  UTF-8 encode   (Go's []byte(string))
 *          ▼  seven-fold Blake3 with specific output size
 *          │        (200 bytes for bit-string, 160 bytes for address)
 *          ▼  convertHashToBitString (for bitstring path)
 *                OR
 *          ▼  convertToLetters via 16×16 CHARACTER_MATRIX (for address path)
 *          │
 *          ▼  output
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { sevenFoldBlake3 } from '../dalos-blake3/index.js';
import {
  CHARACTER_MATRIX_FLAT,
  SMART_ACCOUNT_PREFIX,
  STANDARD_ACCOUNT_PREFIX,
} from './character-matrix.js';
import type { CoordAffine } from './coords.js';
import { DALOS_ELLIPSE, type Ellipse } from './curve.js';
import { BASE49_ALPHABET, bigIntToBase49, digitValueBase49 } from './scalar-mult.js';

// ============================================================================
// Utilities
// ============================================================================

/**
 * UTF-8 encode a string to a Uint8Array. Matches Go's `[]byte(string)`
 * which also uses UTF-8.
 */
const utf8 = new TextEncoder();
export function toUtf8Bytes(s: string): Uint8Array {
  return utf8.encode(s);
}

/**
 * Parse a string of digits in the given base (10 or 49) to a bigint.
 *
 * For base 10 this is a simple `BigInt(s)` call. For base 49 we walk
 * the string character-by-character, mapping via `digitValueBase49`
 * and accumulating.
 */
export function parseBigIntInBase(s: string, base: 10 | 49): bigint {
  if (base === 10) {
    if (!/^\d+$/.test(s)) {
      throw new Error(`parseBigIntInBase: invalid base-10 string "${s}"`);
    }
    return BigInt(s);
  }
  // base 49
  let result = 0n;
  for (const ch of s) {
    const v = digitValueBase49(ch);
    result = result * 49n + BigInt(v);
  }
  return result;
}

// ============================================================================
// Bit-string derivation (seed words, generic hashes)
// ============================================================================

/**
 * Derive a 1600-bit bitstring from a list of seed words.
 *
 * Pipeline (matches Go's `(*Ellipse).SeedWordsToBitString`):
 *   1. Join words with a single space
 *   2. UTF-8 encode to bytes
 *   3. Apply seven-fold Blake3 with output size S/8 = 200 bytes
 *   4. Interpret the 200-byte output as a big-endian bigint
 *   5. Render in base 2, left-pad with zeros to length S = 1600
 */
export function seedWordsToBitString(
  seedWords: readonly string[],
  e: Ellipse = DALOS_ELLIPSE,
): string {
  const joined = seedWords.join(' ');
  const bytes = toUtf8Bytes(joined);
  const outputSize = e.s / 8; // 1600 / 8 = 200
  const digest = sevenFoldBlake3(bytes, outputSize);
  return convertHashToBitString(digest, e.s);
}

/**
 * Convert a hash byte-slice into a bit-string padded to `bitLength`
 * characters.
 *
 * Matches Go's `(*Ellipse).ConvertHashToBitString`:
 *   1. bytes → hex string
 *   2. hex → bigint (base 16)
 *   3. bigint → binary string (leading zeros stripped by big.Int.Text(2))
 *   4. left-pad with '0' to exactly `bitLength` characters
 */
export function convertHashToBitString(hash: Uint8Array, bitLength: number): string {
  // bytes → bigint (big-endian, same as Go's big.Int.SetBytes)
  let n = 0n;
  for (const b of hash) {
    n = (n << 8n) | BigInt(b);
  }
  const binary = n.toString(2);
  if (binary.length >= bitLength) {
    return binary;
  }
  return '0'.repeat(bitLength - binary.length) + binary;
}

// ============================================================================
// Public-key string format
// ============================================================================

/**
 * Encode an affine point as a DALOS public-key string.
 *
 * Format: `"{prefixLenBase49}.{xyBase49}"`
 *   - `prefixLenBase49` — length of X's base-10 representation, in base 49
 *   - `xyBase49`        — concatenation of X and Y base-10 strings, parsed
 *                         as a base-10 bigint, re-rendered in base 49
 *
 * Matches Go's `AffineToPublicKey`.
 */
export function affineToPublicKey(input: CoordAffine): string {
  const xString = input.ax.toString(10);
  const yString = input.ay.toString(10);
  const xStringLength = BigInt(xString.length);
  const publicKeyPrefix = bigIntToBase49(xStringLength);
  const xyString = xString + yString;
  const publicKeyInteger = BigInt(xyString);
  const publicKey = bigIntToBase49(publicKeyInteger);
  return `${publicKeyPrefix}.${publicKey}`;
}

/**
 * Reverse of `affineToPublicKey`.
 *
 * Matches Go's `ConvertPublicKeyToAffineCoords`.
 * Throws on malformed input.
 */
export function publicKeyToAffineCoords(publicKey: string): CoordAffine {
  const parts = publicKey.split('.');
  if (parts.length !== 2) {
    throw new Error('publicKeyToAffineCoords: invalid format (missing ".")');
  }
  const prefix = parts[0];
  const body = parts[1];
  if (prefix === undefined || body === undefined) {
    throw new Error('publicKeyToAffineCoords: empty prefix or body');
  }

  const xLengthBig = parseBigIntInBase(prefix, 49);
  const xLength = Number(xLengthBig);
  if (!Number.isSafeInteger(xLength) || xLength < 1) {
    throw new Error(`publicKeyToAffineCoords: invalid X-length prefix ${xLengthBig}`);
  }

  const totalValue = parseBigIntInBase(body, 49);
  const totalValueStr = totalValue.toString(10);
  if (totalValueStr.length < xLength) {
    throw new Error('publicKeyToAffineCoords: body shorter than claimed X-length');
  }

  const xStr = totalValueStr.slice(0, xLength);
  const yStr = totalValueStr.slice(xLength);
  if (yStr.length === 0) {
    throw new Error('publicKeyToAffineCoords: Y component missing');
  }

  return { ax: BigInt(xStr), ay: BigInt(yStr) };
}

// ============================================================================
// Address derivation
// ============================================================================

/**
 * Derive the 160-character address body from a public-key integer.
 *
 * Pipeline (matches Go's `DalosAddressComputer`):
 *   1. publicKeyInt.toString(10) → bytes (UTF-8, which is ASCII here)
 *   2. Seven-fold Blake3 with output size = 160 bytes
 *   3. For each byte b: look up `CHARACTER_MATRIX[b/16][b%16]`
 *   4. Concatenate → 160-character string
 */
export function dalosAddressComputer(publicKeyInt: bigint): string {
  const decimalBytes = toUtf8Bytes(publicKeyInt.toString(10));
  const digest = sevenFoldBlake3(decimalBytes, 160);
  return convertToLetters(digest);
}

/**
 * Map each byte of `hash` through the 16×16 character matrix and
 * concatenate. Matches Go's `ConvertToLetters`.
 *
 * The output has exactly `hash.length` characters (each byte produces
 * one Unicode rune from the matrix).
 */
export function convertToLetters(hash: Uint8Array): string {
  let out = '';
  for (const b of hash) {
    out += CHARACTER_MATRIX_FLAT[b] ?? '';
  }
  return out;
}

/**
 * Compute the 160-character address body for a public-key string.
 *
 * 1. Strip the `{prefixLen}.` prefix
 * 2. Parse the base-49 body to a bigint
 * 3. `dalosAddressComputer` on that bigint
 *
 * Matches Go's `PublicKeyToAddress`.
 */
export function publicKeyToAddress(publicKey: string): string {
  const parts = publicKey.split('.');
  if (parts.length !== 2) {
    throw new Error('publicKeyToAddress: invalid format (missing ".")');
  }
  const body = parts[1];
  if (body === undefined) {
    throw new Error('publicKeyToAddress: empty body');
  }
  const publicKeyInt = parseBigIntInBase(body, 49);
  return dalosAddressComputer(publicKeyInt);
}

/**
 * Compose a full Ouronet account address from a public-key string.
 *
 * - `isSmart = true`   → `"Σ." + address-body`
 * - `isSmart = false`  → `"Ѻ." + address-body`
 *
 * Matches Go's `DalosAddressMaker`.
 */
export function dalosAddressMaker(publicKey: string, isSmart: boolean): string {
  const body = publicKeyToAddress(publicKey);
  const prefix = isSmart ? SMART_ACCOUNT_PREFIX : STANDARD_ACCOUNT_PREFIX;
  return `${prefix}.${body}`;
}

// Re-export alphabet for discoverability from the hashing entry point
export { BASE49_ALPHABET };
