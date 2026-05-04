package keystore

import (
	"DALOS_Crypto/AES"
	el "DALOS_Crypto/Elliptic"
	"fmt"
)


// AESDecrypt decrypts the private key from base 49 using AES decryption.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. Already a free function pre-Phase-10;
// only the package binding changes. The internal call to
// `ConvertBase49toBase10` is now qualified as `el.ConvertBase49toBase10`
// since that helper stays in Elliptic/.
//
// v4.0.1 (audit cycle 2026-05-04, F-ERR-002): el.ConvertBase49toBase10
// now returns an error on malformed input. Propagate it with a wrapped
// message so a corrupted wallet ciphertext surfaces as a distinct error
// rather than the misleading "wrong password" downstream from AES.
func AESDecrypt(encryptedPrivateKeyBase49, password string) (string, error) {
	// Step 1: Convert the base 49 encrypted private key to base 10 (big.Int)
	encryptedBigInt, err := el.ConvertBase49toBase10(encryptedPrivateKeyBase49)
	if err != nil {
		return "", fmt.Errorf("AESDecrypt: malformed base-49 ciphertext (corrupted wallet file?): %w", err)
	}

	// Step 2: Convert the big.Int to a binary string (base 2)
	encryptedBitString := encryptedBigInt.Text(2)

	// Step 3: Decrypt the binary string using AES decryption
	decryptedBitString, err := AES.DecryptBitString(encryptedBitString, password)
	if err != nil {
		return "", err
	}

	// The decrypted private key (in bit string form) is returned
	return decryptedBitString, nil
}
