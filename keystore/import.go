package keystore

import (
	el "DALOS_Crypto/Elliptic"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Canonical wallet-file header strings. These match the lines emitted
// by ExportPrivateKey verbatim — header-anchored parsing in
// ImportPrivateKey (F-API-004, v4.0.1) locates the encrypted-PK and
// public-key bodies by these markers rather than by hard-coded line
// indices, so the import survives CRLF / trailing-newline / extra-
// blank-line drift.
//
// If you ever change the strings emitted by ExportPrivateKey, update
// these constants in lockstep — they form the wallet-file contract.
const (
	headerEncryptedPrivateKey = "Your DALOS Account PrivateKey in encrypted form is:"
	headerPublicKey           = "Your DALOS Account PublicKey:"
)

// ImportPrivateKey decrypts the private key, verifies the public key,
// and returns a Dalos Key Pair re-derived through the Genesis pipeline.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. Receiver-to-first-parameter rewrite.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-API-004): the pre-v4.0.1
// reader split the file content on "\n" and demanded EXACTLY 12
// elements, then trusted lines[2] (encrypted PK) and lines[5] (public
// key) by positional index. This was brittle in two ways:
//  1. CRLF normalisation (Windows clipboard, email transport, git's
//     core.autocrlf=true) replaced "\n" with "\r\n", leaving each split
//     part \r-terminated. Combined with any tool that "ensures final
//     newline" the count drifted off 12 → import rejected with the
//     generic "invalid file format" message → user with no recourse
//     other than manually editing whitespace.
//  2. No header validation — a malicious 12-line file (no need for valid
//     headers) could be fed to attempt password decrypt against lines[2],
//     turning the import surface into a brute-force oracle.
//
// Post-v4.0.1: header-anchored parsing. Walk the file lines (after CR
// trimming), locate each canonical header by content, take the next
// non-empty line as its body. Decouples parsing from Fprintln's implicit
// newline behaviour and from incidental trailing whitespace; rejects
// non-wallet files at the header-presence check before reaching AES.
//
// HARDENING (v4.0.2, audit cycle 2026-05-04, F-MED-009): the pre-v4.0.2
// implementation emitted "DALOS Keys are being opened!" and "Public Key
// verification successful!" to stdout from inside this library function.
// After the v4.0.0 carve-out made `keystore` a standalone consumable
// package, those prints became a contract violation: server / GUI /
// JSON-pipe consumers couldn't suppress them. Removed both. The CLI
// driver in Dalos.go now owns these breadcrumb prints around its
// `keystore.ImportPrivateKey(...)` call sites — the print-then-call
// and call-then-print pattern matches the broader "library returns
// data, CLI prints chrome" architectural boundary.
func ImportPrivateKey(e *el.Ellipse, PathWithName, Password string) (el.DalosKeyPair, error) {
	var Output el.DalosKeyPair

	// File-read failure — wrap with %w + path context (F-MED-005).
	// Useful for ops debugging "wrong filename / wrong cwd / file
	// missing" classes; not an authentication concern.
	fileContent, err := os.ReadFile(PathWithName)
	if err != nil {
		return Output, fmt.Errorf("ImportPrivateKey: cannot read wallet file %q: %w", PathWithName, err)
	}

	// Extract + normalise the lines. Strip \r per-line so CRLF-saved
	// files import correctly. Strip surrounding whitespace so trailing
	// blanks and indented headers are tolerated.
	rawLines := strings.Split(string(fileContent), "\n")
	lines := make([]string, len(rawLines))
	for i, raw := range rawLines {
		lines[i] = strings.TrimSpace(strings.TrimRight(raw, "\r"))
	}

	// Header-anchored extraction. findValueAfterHeader returns the first
	// non-empty line following the named header, or an error if the
	// header is missing or has no body following it.
	encryptedPrivateKey, err := findValueAfterHeader(lines, headerEncryptedPrivateKey)
	if err != nil {
		return Output, fmt.Errorf("invalid wallet file format (encrypted private key section): %w", err)
	}
	publicKeyFromFile, err := findValueAfterHeader(lines, headerPublicKey)
	if err != nil {
		return Output, fmt.Errorf("invalid wallet file format (public key section): %w", err)
	}

	// Decrypt the private key using the AESDecrypt function (same package).
	//
	// AUTH-TAG MISMATCH boundary (F-NEEDS-001 + F-MED-005, v4.0.2): we
	// deliberately FLATTEN the AES error here. AESDecrypt's auth-tag
	// failure path returns a generic `"AES DecryptBitString:
	// authentication failed"` (no %w wrap on the inner GCM error per
	// AES.go's F-NEEDS-001 hardening); we further flatten to a
	// user-friendly message, dropping all unwrap chains. Wrong-password
	// and tampered-ciphertext are intentionally indistinguishable here
	// to prevent building a decrypt-oracle. Other AES failure modes
	// (NewCipher / NewGCM / nonce-too-short) ARE structural and unrelated
	// to authentication; they are NOT reachable through this path in
	// practice (constant 32-byte key, fixed-format wallet) but if they
	// were, the policy would still be "flatten at this user-facing
	// boundary" — operators debugging genuinely-internal failures should
	// drop down to AESDecrypt directly, where the structural %w wraps
	// are preserved.
	decryptedBitString, err2 := AESDecrypt(encryptedPrivateKey, Password)
	if err2 != nil {
		_ = err2 // intentionally not wrapped — see F-NEEDS-001 docstring above.
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

	// POST-DECRYPT failures from this point on indicate either a
	// successful-decrypt-but-corrupt-payload condition or an internal
	// math/library error. Password was correct, ciphertext was authentic.
	// Wrap with %w to preserve diagnostics (F-MED-005); these errors
	// don't reveal anything about the password.
	scalar, err3 := e.GenerateScalarFromBitString(decryptedBitString)
	if err3 != nil {
		return Output, fmt.Errorf("ImportPrivateKey: decrypted bitstring rejected by scalar generator (wallet-file corruption?): %w", err3)
	}

	GeneratedDalosKeyPair, err4 := e.ScalarToKeys(scalar)
	if err4 != nil {
		return Output, fmt.Errorf("ImportPrivateKey: scalar rejected by key derivation (wallet-file corruption or version skew?): %w", err4)
	}

	// PUBL mismatch — astronomically improbable given a successful AEAD
	// decrypt + scalar generation. Indicates either deliberate file
	// tampering of just the PUBL line OR cross-curve confusion (wallet
	// produced under one curve, opened with another). No underlying err
	// to wrap; the message itself names both common causes.
	if GeneratedDalosKeyPair.PUBL != publicKeyFromFile {
		return Output, errors.New("ImportPrivateKey: computed public key does not match the public key in the file (file tampering or cross-curve mismatch)")
	}

	// F-MED-009 (v4.0.2): "Public Key verification successful!" stdout
	// print removed from this library function. The CLI driver now
	// emits this breadcrumb around its successful return.
	Output = GeneratedDalosKeyPair
	// Return the decrypted bit string
	return Output, nil
}

// findValueAfterHeader scans lines for the first occurrence of header
// and returns the first subsequent non-empty line (the header's
// "value"). Returns an error if the header is absent or has no
// non-empty line following it.
//
// Used by ImportPrivateKey's header-anchored parser (F-API-004).
// Tolerates extra blank lines between header and value (defensive
// against editor quirks), but requires the header text to match
// exactly (catches non-wallet files at the parse stage rather than
// turning the import into a brute-force oracle).
func findValueAfterHeader(lines []string, header string) (string, error) {
	for i, line := range lines {
		if line != header {
			continue
		}
		// Found the header at index i. Walk forward to the first
		// non-empty subsequent line.
		for j := i + 1; j < len(lines); j++ {
			if lines[j] != "" {
				return lines[j], nil
			}
		}
		return "", fmt.Errorf("header %q found but no value follows it", header)
	}
	return "", fmt.Errorf("header %q not found in file", header)
}
