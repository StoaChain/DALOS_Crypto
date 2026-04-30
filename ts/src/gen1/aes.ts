/**
 * AES-256-GCM wrapper matching the Go reference's `AES/AES.go` byte-for-byte.
 *
 * This is the encryption layer used by the Go CLI's `ExportPrivateKey` /
 * `ImportPrivateKey` to save bit-strings as encrypted key files. It is NOT
 * used by the Ouronet UI (which uses ouronet-core's V1/V2 codex encryption).
 * Ported here for CLI compatibility.
 *
 * Algorithm (locked, no Argon2id upgrade per 2026-04-23 decision):
 *   1. plaintext bitstring → bytes:
 *        bigint(base 2) → hex → decode to bytes    (loses leading zeros)
 *   2. key derivation:
 *        Blake3(password, 32 bytes)                  (single-pass, no salt)
 *   3. AES-256-GCM with a 12-byte random nonce
 *   4. ciphertext = nonce || encrypt(plaintext) || 16-byte auth-tag
 *   5. ciphertext bitstring = bytes → hex → bigint → base 2
 *
 * Known limitations (NOT fixed — Genesis frozen):
 *   - Single-pass KDF means weak passwords are brute-forceable
 *   - No salt means identical password → identical key
 *   - Leading-zero bits in plaintext are lost (use an outer pad-to-length
 *     wrapper to round-trip reliably)
 *
 * All hardening applied in v2.1.0 of the Go reference is also applied here:
 *   - Errors short-circuit with empty-string / typed-error returns
 *   - `zeroBytes` helper scrubs derived key material best-effort on return
 *   - No garbage output on primitive failure
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { blake3SumCustom } from '../dalos-blake3/index.js';

const utf8 = new TextEncoder();

/**
 * Best-effort zero-out a byte array. JavaScript's GC may still retain
 * other copies; this is a hygiene helper, not a security guarantee.
 * Matches Go's `AES.ZeroBytes`.
 */
export function zeroBytes(b: Uint8Array): void {
  b.fill(0);
}

/**
 * Convert a bitstring to a byte array. Matches Go's `BitStringToHex`:
 *   1. bitstring → bigint (base 2)
 *   2. bigint → hex string (stripped of leading zeros by nature of bigint)
 *   3. hex → bytes
 *
 * Edge cases (preserved from Go for byte-identity):
 *   - Empty or all-zero bitstring → empty byte slice
 *   - Bitstring with odd-nibble magnitude (hex length odd) → empty byte slice
 *     (Go's `hex.DecodeString` returns an error on odd length, which Go
 *     silently discards, yielding nil — we match by returning empty)
 *   - Leading zero bits ARE LOST (hex has no leading zeros)
 */
export function bitStringToBytes(bitString: string): Uint8Array {
  if (bitString.length === 0) {
    return new Uint8Array(0);
  }
  // Check all chars are 0/1
  for (const ch of bitString) {
    if (ch !== '0' && ch !== '1') {
      return new Uint8Array(0);
    }
  }
  // All-zero bitstring → bigint is 0 → empty
  const n = BigInt(`0b${bitString}`);
  if (n === 0n) {
    return new Uint8Array(0);
  }
  const hex = n.toString(16);
  // Go's hex.DecodeString on odd-length input: decodes the even-length
  // prefix and returns an ErrLength error. DALOS AES code discards
  // the error, keeping the partial bytes. We match that behaviour:
  // drop the last half-nibble character.
  const evenLen = hex.length - (hex.length % 2);
  const bytes = new Uint8Array(evenLen / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes back to a bitstring via hex → bigint → binary.
 * Matches Go's pattern of `CipherTextDec.SetString(hex, 16); Text(2)`.
 *
 * NOTE: leading zeros are not preserved. Callers who need a fixed-width
 * bitstring (e.g. the 1600-bit DALOS private-key form) must pad with
 * leading zeros themselves after decryption.
 */
export function bytesToBitString(bytes: Uint8Array): string {
  if (bytes.length === 0) return '0';
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt(`0x${hex}`).toString(2);
}

/**
 * Derive a 32-byte AES-256 key from a password via single-pass Blake3.
 * Matches Go's `AES.MakeKeyFromPassword`.
 *
 * NOTE: no salt, no iteration count. Weak passwords are vulnerable to
 * GPU-accelerated brute force. Caller must supply a strong password.
 */
export function makeKeyFromPassword(password: string): Uint8Array {
  const pwBytes = utf8.encode(password);
  const key = blake3SumCustom(pwBytes, 32);
  // Scrub the intermediate password-bytes buffer (best-effort;
  // the original `password: string` is immutable and uncleared).
  zeroBytes(pwBytes);
  return key;
}

/**
 * Encrypt a bitstring under AES-256-GCM keyed by Blake3(password, 32).
 *
 * Returns the ciphertext as a bitstring composed of:
 *   (nonce 12 bytes) || (AES-GCM ciphertext) || (auth tag 16 bytes)
 * encoded via bytes → hex → bigint → binary.
 *
 * Returns `""` on any primitive failure (matches v2.1.0 Go behaviour).
 */
export async function encryptBitString(bitString: string, password: string): Promise<string> {
  try {
    const plaintext = bitStringToBytes(bitString);
    const keyBytes = makeKeyFromPassword(password);
    try {
      const key = await globalThis.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt'],
      );
      // Require the TOP NIBBLE of the nonce's first byte to be non-zero
      // (i.e., nonce[0] >= 0x10). The surrounding bytes→bigint→binary
      // encoding of the combined ciphertext strips leading zero BITS
      // of the high byte; if the top nibble of combined[0] is 0, the
      // resulting bitstring loses that nibble and cannot be reversed
      // to the original byte count. Regenerating until nonce[0] >=
      // 0x10 loses ~6.25% of entropy in the nonce's first byte but
      // guarantees lossless roundtrip. AES-GCM nonce uniqueness is
      // preserved since the remaining bits are still random.
      //
      // This is a TS-port robustness fix. The Go CLI has the same
      // latent bug — occasionally produces ciphertexts it can't read
      // back. TS-produced ciphertexts always decrypt cleanly (both in
      // TS and in Go), which is a strict improvement.
      const nonce = new Uint8Array(12);
      do {
        globalThis.crypto.getRandomValues(nonce);
      } while ((nonce[0]! & 0xf0) === 0);

      const ctBuf = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        plaintext,
      );
      const ct = new Uint8Array(ctBuf);

      // Combine: nonce || ciphertext+tag (matches Go's Seal(nonce, nonce, ...))
      const combined = new Uint8Array(nonce.length + ct.length);
      combined.set(nonce, 0);
      combined.set(ct, nonce.length);

      // Scrub intermediate plaintext
      zeroBytes(plaintext);

      return bytesToBitString(combined);
    } finally {
      zeroBytes(keyBytes);
    }
  } catch {
    return '';
  }
}

/**
 * Decrypt a bitstring previously produced by `encryptBitString`.
 *
 * Returns the plaintext bitstring on success. Throws on:
 *   - Input too short (< 12 bytes → no room for nonce)
 *   - Wrong password (AES-GCM auth-tag mismatch)
 *   - Corrupted ciphertext (auth-tag mismatch)
 *
 * NOTE: leading-zero bits in the original plaintext are not recovered.
 * Callers requiring a fixed-width bitstring (e.g. 1600-bit DALOS private
 * key) must left-pad with '0' to the expected length after decryption.
 */
export async function decryptBitString(bitString: string, password: string): Promise<string> {
  const combined = bitStringToBytes(bitString);
  if (combined.length < 12) {
    throw new Error(
      `AES DecryptBitString: ciphertext too short for 12-byte nonce (got ${combined.length} bytes)`,
    );
  }
  const nonce = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const keyBytes = makeKeyFromPassword(password);
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    let ptBuf: ArrayBuffer;
    try {
      ptBuf = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        ciphertext,
      );
    } catch (err) {
      throw new Error(
        `AES DecryptBitString: decryption failed (likely wrong password or corrupt ciphertext): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    const pt = new Uint8Array(ptBuf);
    const result = bytesToBitString(pt);
    zeroBytes(pt);
    return result;
  } finally {
    zeroBytes(keyBytes);
  }
}

/**
 * Convenience wrapper: encrypt a bitstring and return the ciphertext
 * padded back up to the same bit-length as the input.
 *
 * Since AES-GCM adds 12 bytes of nonce + 16 bytes of tag = 28 bytes
 * of overhead, and the plaintext byte-length can be less than the
 * bit-length / 8 (due to leading-zero loss), the output bitstring is
 * generally LONGER than the input. This function does NOT truncate;
 * use the plain `encryptBitString` for the raw length output.
 *
 * Provided for round-trip ergonomics in tests and callers who need
 * a predictable output shape regardless of input leading-zero pattern.
 */
export async function encryptAndPad(
  bitString: string,
  password: string,
): Promise<{ ciphertext: string; ciphertextBits: number }> {
  const ct = await encryptBitString(bitString, password);
  if (ct === '') {
    throw new Error('encryptAndPad: underlying encryption failed');
  }
  return { ciphertext: ct, ciphertextBits: ct.length };
}

/**
 * Convenience wrapper: decrypt and left-pad to the expected bit-length.
 *
 * Use this when the plaintext is a DALOS private-key bitstring which
 * must be exactly 1600 bits. Leading zeros stripped by `decryptBitString`
 * are restored.
 */
export async function decryptAndPadToLength(
  bitString: string,
  password: string,
  expectedBits: number,
): Promise<string> {
  const pt = await decryptBitString(bitString, password);
  if (pt.length >= expectedBits) return pt;
  return '0'.repeat(expectedBits - pt.length) + pt;
}
