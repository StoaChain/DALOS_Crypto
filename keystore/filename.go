package keystore

import (
	"fmt"
	"strings"
)

// GenerateFilenameFromPublicKey computes the canonical wallet-file
// basename from a DALOS public key (`<prefix>.<first7>...<last7>.txt`).
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-API-003): the pre-v4.0.1
// implementation had two contract violations for a public library
// function:
//   1. On malformed input it called `fmt.Println(...)` from inside a
//      library helper — a side-effect that breaks callers running in
//      non-CLI contexts (server, GUI, JSON pipe).
//   2. It returned a magic sentinel string `"InvalidPublicKey.txt"`
//      instead of a Go-idiomatic error. Consumers couldn't distinguish
//      a real wallet someone deliberately named that from a programming
//      error, and `ExportPrivateKey` (the sole caller) would silently
//      produce a wallet file literally named `InvalidPublicKey.txt`,
//      with multiple failed exports colliding on that filename.
//
// Post-v4.0.1 contract: returns `(string, error)` matching the sibling
// pattern used by `ImportPrivateKey` and `AESDecrypt` in this same
// package. No stdout side-effect. The carve-out window is the right
// time to lock the contract before external consumers depend on the
// v4.0.0 API.
func GenerateFilenameFromPublicKey(publicKey string) (string, error) {
	// Split the public key at the first occurrence of '.'
	parts := strings.SplitN(publicKey, ".", 2)

	if len(parts) < 2 {
		return "", fmt.Errorf("GenerateFilenameFromPublicKey: malformed public key (no \".\" separator): %q", publicKey)
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
	return filename, nil
}
