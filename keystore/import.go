package keystore

import (
	el "DALOS_Crypto/Elliptic"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ImportPrivateKey decrypts the private key, verifies the public key,
// and returns a Dalos Key Pair re-derived through the Genesis pipeline.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. Receiver-to-first-parameter rewrite.
func ImportPrivateKey(e *el.Ellipse, PathWithName, Password string) (el.DalosKeyPair, error) {
	var Output el.DalosKeyPair
	fmt.Println("DALOS Keys are being opened!")

	// Read the file content using os.ReadFile
	fileContent, err := os.ReadFile(PathWithName)
	if err != nil {
		return Output, err
	}

	// Extract the lines from the file content
	lines := strings.Split(string(fileContent), "\n")
	if len(lines) != 12 {
		return Output, errors.New("invalid file format")
	}

	// Line 2 contains the encrypted private key (index 2 - 3rd line)
	encryptedPrivateKey := strings.TrimSpace(lines[2])
	// Line 5 contains the public key (index 5 - 6th line)
	publicKeyFromFile := strings.TrimSpace(lines[5])

	// Decrypt the private key using the AESDecrypt function (same package)
	decryptedBitString, err2 := AESDecrypt(encryptedPrivateKey, Password)
	if err2 != nil {
		return Output, errors.New("incorrect password or decryption failed")
	}

	// Check if the decrypted bit string is less than the expected length (e.S = 1600 bits)
	expectedLength := int(e.S)
	currentLength := len(decryptedBitString)
	if currentLength < expectedLength {
		// Prepend zeros to make the length 1600 bits
		zerosToAdd := expectedLength - currentLength
		decryptedBitString = strings.Repeat("0", zerosToAdd) + decryptedBitString
	}

	// Generate the scalar from the decrypted bit string
	scalar, err3 := e.GenerateScalarFromBitString(decryptedBitString)
	if err3 != nil {
		return Output, errors.New("failed to generate scalar from bit string")
	}

	// Generate the DalosKeyPair from the scalar
	GeneratedDalosKeyPair, err4 := e.ScalarToKeys(scalar)
	if err4 != nil {
		return Output, errors.New("failed to generate keys from scalar")
	}

	// Verify the public key
	if GeneratedDalosKeyPair.PUBL != publicKeyFromFile {
		return Output, errors.New("computed public key does not match the public key in the file")
	}

	fmt.Println("Public Key verification successful!")
	Output = GeneratedDalosKeyPair
	// Return the decrypted bit string
	return Output, nil
}
