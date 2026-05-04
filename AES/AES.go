package AES

import (
	"DALOS_Crypto/Blake3"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// ============================================================================
// AES-3 hardening (v2.1.0): proper error handling
// ============================================================================
//
// Pre-v2.1.0 this file printed errors via fmt.Println and then
// continued execution, producing garbage output from invalid state.
// From v2.1.0 onward, the public functions short-circuit on any AES
// primitive failure:
//   - EncryptBitString returns "" on any failure (no more garbage)
//   - DecryptBitString returns a non-nil error on any failure
//
// Signatures are unchanged so every existing caller compiles without
// modification. New callers should treat an empty-string return from
// EncryptBitString as an error signal.
//
// KG-3 hardening (v2.1.0): best-effort zeroing of password-derived
// buffers and intermediate plaintext byte slices after use. Go strings
// are immutable and cannot be zeroed — callers must keep passwords in
// byte slices if memory-lifetime hygiene matters to them.
// ============================================================================

// BitStringToHex converts a String of 0s and 1s to a Slice of bytes via the
// path: bigint(base 2) -> Text(16) -> hex.DecodeString.
//
// AES-4 / F-ERR-004 note (documented, not fixed):
// When the intermediate hex string `BitStringHex` has an odd character count,
// `hex.DecodeString` returns `(<partial-bytes>, hex.ErrLength)` — it decodes
// the even-length prefix and signals the length error. This function silently
// discards that error via the blank identifier on the `hex.DecodeString` call
// below, KEEPING the partial bytes. In effect the trailing LSB half-nibble of
// the hex form is truncated (e.g. `"1"` -> hex `"1"` -> `[]byte{}`; `"100"` ->
// hex `"4"` -> `[]byte{}`; bigint(`"100000000"`)=256 -> hex `"100"` ->
// `[]byte{0x10}`).
//
// This is intentional: the Genesis key-gen pipeline (frozen at v1.0.0) was
// generated against this exact behavior. Changing the truncation rule would
// invalidate every existing Ѻ./Σ. account derived from a bitstring whose
// even-padded hex form has an odd character count. See AUDIT.md "Documented,
// not fixed" for the full rationale.
//
// Sibling caveat AES-2 (single-pass Blake3 KDF without salt) is also recorded
// as NOT-FIXED-BY-DESIGN in AUDIT.md for the same Genesis-format reason.
//
// The TypeScript port mirrors this behavior verbatim — see the matching
// commentary in `ts/src/gen1/aes.ts` lines 74-77 ("Go's hex.DecodeString on
// odd-length input ... DALOS AES code discards the error ... We match that
// behaviour: drop the last half-nibble character").
func BitStringToHex(BitString string) []byte {
	var TwoToTen = new(big.Int)
	//Converting BitString to HEX
	TwoToTen.SetString(BitString, 2)
	BitStringHex := TwoToTen.Text(16)
	BitStringToEncrypt, _ := hex.DecodeString(BitStringHex)
	return BitStringToEncrypt
}

//
// Hashes a Password with Blake3 and creates a slice of bytes 32 units long
// that can be used as a KEY for AES Encryption and Decryption.
//
// KG-3 note: the returned slice is caller-owned. Callers should call
// ZeroBytes on it when finished to best-effort scrub the AES key from
// memory. Go's GC may still retain copies in internal buffers; this
// is a best-effort mitigation, not a guarantee.
func MakeKeyFromPassword(Password string) []byte {
	PasswordToByteSlice := []byte(Password)
	HashedPassword := Blake3.SumCustom(PasswordToByteSlice, 32)

	// Best-effort zeroing of the intermediate password-bytes buffer.
	ZeroBytes(PasswordToByteSlice)

	// Copy out to an owned slice so we can zero the Blake3 output
	// without affecting the caller's key.
	Key := make([]byte, len(HashedPassword))
	copy(Key, HashedPassword)
	ZeroBytes(HashedPassword)
	return Key
}

// ZeroBytes overwrites a byte slice with zeros. Best-effort memory
// hygiene helper for secret material (passwords, derived keys,
// intermediate plaintext). KG-3 hardening (v2.1.0).
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptBitString encrypts a 0/1 bitstring under AES-256-GCM keyed
// by Blake3(password, 32 bytes).
//
// v2.1.0: returns "" on any AES primitive failure (cipher setup, GCM
// construction, or nonce generation) instead of printing and returning
// garbage. A valid input always produces a non-empty output.
func EncryptBitString(BitString, Password string) (BitStringOutput string) {
	var CipherTextDec = new(big.Int)

	BitStringToEncrypt := BitStringToHex(BitString)
	Key := MakeKeyFromPassword(Password)
	defer ZeroBytes(Key) // KG-3: scrub AES key on return

	Block, err := aes.NewCipher(Key)
	if err != nil {
		return ""
	}

	AesGcm, err := cipher.NewGCM(Block)
	if err != nil {
		return ""
	}

	nonce := make([]byte, AesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}

	CipherText := AesGcm.Seal(nonce, nonce, BitStringToEncrypt, nil)

	CipherTextHex := hex.EncodeToString(CipherText)
	CipherTextDec.SetString(CipherTextHex, 16)
	BitStringOutput = CipherTextDec.Text(2)

	// KG-3: scrub intermediate plaintext byte slice
	ZeroBytes(BitStringToEncrypt)
	return BitStringOutput
}

// DecryptBitString is the inverse of EncryptBitString.
//
// v2.1.0: returns a non-nil error on any AES primitive failure or
// malformed ciphertext. Pre-v2.1.0 this printed and returned garbage.
//
// HARDENING (v4.0.2, audit cycle 2026-05-04, F-NEEDS-001 + F-MED-005):
// the error-message policy has been audited and aligned with OWASP
// guidance on cryptographic-failure disclosure. The two distinct error
// classes returned by this function are now treated differently:
//
//   1. Authentication failure (AesGcm.Open returning err) — caused by
//      EITHER a wrong password OR tampered ciphertext. These two cases
//      are CRYPTOGRAPHICALLY INDISTINGUISHABLE on the verifier side
//      (that is the entire point of authenticated encryption — GCM's
//      tag check is a single boolean), and DELIBERATELY KEPT
//      INDISTINGUISHABLE in the API surface to avoid building a
//      decrypt-oracle on the boundary. Pre-v4.0.2 the wrap was
//      `%w` + parenthetical "(likely wrong password or corrupt
//      ciphertext)" — both leak the inner GCM error string to any
//      consumer that calls `errors.Unwrap`. Post-v4.0.2 the auth
//      failure returns a flat generic error with NO unwrap path; the
//      consumer cannot distinguish bad-password from tampered-blob
//      from version-skew. This is the F-NEEDS-001 resolution.
//
//   2. Structural / internal failures (NewCipher / NewGCM / nonce-too-
//      short) — these are NOT password-dependent and NOT user-input-
//      authentication failures. They indicate either an environment
//      problem (NewCipher/NewGCM should never fail with a valid 32-byte
//      key) or a malformed wallet file (nonce-too-short). These KEEP
//      `%w`-wrap so operators debugging "why does this wallet refuse to
//      open" can drill into the underlying cause. This is the F-MED-005
//      resolution.
//
// Net effect: the auth-tag-mismatch oracle is closed at the primitive
// boundary; the diagnostic uplift for genuinely-internal failures is
// preserved. Callers (keystore.ImportPrivateKey + AESDecrypt) should
// further flatten the auth-tag error to a user-friendly message
// without changing the wrap policy on the structural errors.
func DecryptBitString(BitString, Password string) (BitStringOutput string, Error error) {
	var DecryptedDataDec = new(big.Int)

	BitStringToDecrypt := BitStringToHex(BitString)
	Key := MakeKeyFromPassword(Password)
	defer ZeroBytes(Key) // KG-3

	// Internal failure — wrap with %w (F-MED-005).
	Block, err := aes.NewCipher(Key)
	if err != nil {
		return "", fmt.Errorf("AES DecryptBitString NewCipher: %w", err)
	}

	// Internal failure — wrap with %w (F-MED-005).
	AesGcm, err := cipher.NewGCM(Block)
	if err != nil {
		return "", fmt.Errorf("AES DecryptBitString NewGCM: %w", err)
	}

	// Structural pre-check — malformed ciphertext, not auth failure.
	// No underlying error to wrap; the message itself is the diagnostic.
	NonceSize := AesGcm.NonceSize()
	if len(BitStringToDecrypt) < NonceSize {
		return "", errors.New("AES DecryptBitString: ciphertext too short for nonce")
	}

	Nonce, CipherText := BitStringToDecrypt[:NonceSize], BitStringToDecrypt[NonceSize:]

	// AUTH-TAG MISMATCH — F-NEEDS-001 resolution. Pre-v4.0.2 wrapped the
	// inner GCM error with `%w` + a parenthetical hint identifying the
	// likely cause; both leaked oracle bits to any consumer that called
	// errors.Unwrap. Post-v4.0.2: flat generic error, no unwrap path.
	// Wrong-password and tampered-ciphertext are now indistinguishable
	// at every layer above this primitive. The inner err is deliberately
	// discarded.
	DecryptedData, err := AesGcm.Open(nil, Nonce, CipherText, nil)
	if err != nil {
		_ = err // intentionally not wrapped — see F-NEEDS-001 docstring above.
		return "", errors.New("AES DecryptBitString: authentication failed")
	}

	DecryptedDataHex := hex.EncodeToString(DecryptedData)
	DecryptedDataDec.SetString(DecryptedDataHex, 16)
	BitStringOutput = DecryptedDataDec.Text(2)

	ZeroBytes(DecryptedData)
	ZeroBytes(BitStringToDecrypt)
	return BitStringOutput, nil
}
