/**
 * Ergonomic plain-string-friendly wrappers over the gen1 primitives.
 *
 * `textToBitString` / `bitStringToText` give callers a UTF-8 ↔ MSB-first
 * bitstring bridge that preserves leading zero bits per byte (unlike
 * `bytesToBitString` in `aes.ts`, which goes via a single bigint and
 * therefore drops leading zeros across the whole byte array).
 *
 * `sign` / `verify` are thin synchronous pass-throughs to the Schnorr v2
 * primitives, hiding the optional `Ellipse` parameter so typical callers
 * only need to pass keypair, message, signature, and public key.
 *
 * `encrypt` / `decrypt` give a UTF-8 plaintext ↔ AES-256-GCM ciphertext
 * round-trip on top of `encryptBitString` / `decryptBitString`. The
 * decrypt path left-pads the recovered bitstring up to the nearest
 * multiple of 8 bits to compensate for leading zeros stripped by the
 * underlying bigint round-trip in `bytesToBitString`.
 *
 * v3.0.3+. Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { decryptBitString, encryptBitString } from './aes.js';
import { toUtf8Bytes } from './hashing.js';
import type { DalosKeyPair } from './key-gen.js';
import { schnorrSign, schnorrVerify } from './schnorr.js';

const utf8Decoder = new TextDecoder();

/**
 * UTF-8 encode `text` and emit the concatenation of each byte's 8-bit
 * MSB-first binary representation, zero-padded so every byte contributes
 * exactly eight characters.
 *
 * Empty input returns the empty string. Leading zero bits are preserved
 * per byte — this is the critical difference from `bytesToBitString`,
 * which routes through a bigint and strips zeros across the entire
 * array.
 */
export function textToBitString(text: string): string {
  const bytes = toUtf8Bytes(text);
  let out = '';
  for (const b of bytes) {
    out += b.toString(2).padStart(8, '0');
  }
  return out;
}

/**
 * Inverse of `textToBitString`.
 *
 * Validates that `bitString.length` is a multiple of 8 and that every
 * character is `'0'` or `'1'`; on either failure throws the verbatim
 * message documented in the spec. Valid input is split into 8-bit
 * chunks, each parsed as a byte, and the resulting `Uint8Array` is
 * decoded as UTF-8.
 */
export function bitStringToText(bitString: string): string {
  const length = bitString.length;
  if (length % 8 !== 0) {
    throw new Error('bitStringToText: input must be a 0/1 string of length divisible by 8');
  }
  for (const ch of bitString) {
    if (ch !== '0' && ch !== '1') {
      throw new Error('bitStringToText: input must be a 0/1 string of length divisible by 8');
    }
  }
  const bytes = new Uint8Array(length / 8);
  for (let i = 0; i < length; i += 8) {
    bytes[i / 8] = Number.parseInt(bitString.slice(i, i + 8), 2);
  }
  return utf8Decoder.decode(bytes);
}

/**
 * Sign `message` (a plain UTF-8 string) under `keyPair` using DALOS
 * Schnorr v2. Synchronous pass-through to `schnorrSign` with the
 * default `DALOS_ELLIPSE`.
 *
 * Deterministic: the same `(keyPair, message)` always yields a
 * byte-identical signature.
 */
export function sign(keyPair: DalosKeyPair, message: string): string {
  return schnorrSign(keyPair, message);
}

/**
 * Verify a DALOS Schnorr v2 `signature` over `message` against
 * `publicKey`. Synchronous pass-through to `schnorrVerify` with the
 * default `DALOS_ELLIPSE`. Returns `true` iff the signature is valid.
 */
export function verify(signature: string, message: string, publicKey: string): boolean {
  return schnorrVerify(signature, message, publicKey);
}

/**
 * Encrypt a UTF-8 `plaintext` string under `password` using AES-256-GCM
 * (Blake3-derived key). Returns the ciphertext as the bitstring emitted
 * by `encryptBitString`.
 *
 * Empty plaintext is rejected: the underlying `encryptBitString` of
 * an empty input round-trips to `'\x00'` rather than `''` once the
 * decrypt-side pad-to-8 fixup runs, breaking the symmetry of the alias
 * surface. Power users can still call `encryptBitString('', password)`
 * directly if they need that pathway.
 */
export async function encrypt(plaintext: string, password: string): Promise<string> {
  if (plaintext === '') {
    throw new Error(
      'encrypt: empty plaintext is not supported — use encryptBitString directly if intentional',
    );
  }
  return encryptBitString(textToBitString(plaintext), password);
}

/**
 * Decrypt a `ciphertext` bitstring (as produced by `encrypt`) under
 * `password` and decode the recovered bytes as UTF-8.
 *
 * The recovered bitstring is left-padded with `'0'` to the nearest
 * multiple of 8 before UTF-8 decoding. This compensates for the leading
 * zero bits stripped by the bigint round-trip inside
 * `bytesToBitString`, restoring round-trip correctness for plaintexts
 * whose first UTF-8 byte is in `0x01..0xFF`. Plaintexts starting with
 * `\x00` (U+0000) lose the entire leading null byte and are not
 * supported through this alias surface.
 */
export async function decrypt(ciphertext: string, password: string): Promise<string> {
  const bits = await decryptBitString(ciphertext, password);
  const padded = bits.padStart(Math.ceil(bits.length / 8) * 8, '0');
  return bitStringToText(padded);
}
