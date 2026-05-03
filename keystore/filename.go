package keystore

import (
	"fmt"
	"strings"
)

// GenerateFilenameFromPublicKey computes the canonical wallet-file
// basename from a DALOS public key (`<prefix>.<first7>...<last7>.txt`).
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. Already a free function — no signature
// rewrite needed.
func GenerateFilenameFromPublicKey(publicKey string) string {
	// Split the public key at the first occurrence of '.'
	parts := strings.SplitN(publicKey, ".", 2)

	if len(parts) < 2 {
		// Handle case where the public key doesn't contain a '.'
		fmt.Println("Invalid public key format. No dot found.")
		return "InvalidPublicKey.txt"
	}

	// Get the prefix and the part after the dot
	prefix := parts[0]
	afterDot := parts[1]

	// Extract the first 7 characters after the dot
	first7 := ""
	if len(afterDot) > 7 {
		first7 = afterDot[:7]
	} else {
		first7 = afterDot // Take the whole string if it's less than 7
	}

	// Extract the last 7 characters of the public key
	last7 := ""
	if len(publicKey) > 7 {
		last7 = publicKey[len(publicKey)-7:]
	} else {
		last7 = publicKey // Take the whole string if it's less than 7
	}

	// Combine into the filename
	filename := fmt.Sprintf("%s.%s...%s.txt", prefix, first7, last7)
	return filename
}
