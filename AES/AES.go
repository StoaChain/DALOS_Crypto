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

//
// Converts a String of 0s and 1s to a Slice of bytes.
//
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
func DecryptBitString(BitString, Password string) (BitStringOutput string, Error error) {
	var DecryptedDataDec = new(big.Int)

	BitStringToDecrypt := BitStringToHex(BitString)
	Key := MakeKeyFromPassword(Password)
	defer ZeroBytes(Key) // KG-3

	Block, err := aes.NewCipher(Key)
	if err != nil {
		return "", fmt.Errorf("AES DecryptBitString NewCipher: %w", err)
	}

	AesGcm, err := cipher.NewGCM(Block)
	if err != nil {
		return "", fmt.Errorf("AES DecryptBitString NewGCM: %w", err)
	}

	NonceSize := AesGcm.NonceSize()
	if len(BitStringToDecrypt) < NonceSize {
		return "", errors.New("AES DecryptBitString: ciphertext too short for nonce")
	}

	Nonce, CipherText := BitStringToDecrypt[:NonceSize], BitStringToDecrypt[NonceSize:]

	DecryptedData, err := AesGcm.Open(nil, Nonce, CipherText, nil)
	if err != nil {
		return "", fmt.Errorf("AES DecryptBitString Open (likely wrong password or corrupt ciphertext): %w", err)
	}

	DecryptedDataHex := hex.EncodeToString(DecryptedData)
	DecryptedDataDec.SetString(DecryptedDataHex, 16)
	BitStringOutput = DecryptedDataDec.Text(2)

	ZeroBytes(DecryptedData)
	ZeroBytes(BitStringToDecrypt)
	return BitStringOutput, nil
}
