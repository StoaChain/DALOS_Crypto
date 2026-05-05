package keystore

import (
	"DALOS_Crypto/AES"
	el "DALOS_Crypto/Elliptic"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// ExportPrivateKey serializes a Genesis private key to the canonical
// wallet file under the public-key-derived filename and returns nil
// on success or a wrapped error describing the failure mode.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. The receiver `(e *Ellipse)` is rewritten
// to `e *el.Ellipse` first parameter because Go forbids defining
// methods on types from external packages.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-ERR-005): the pre-v4.0.1
// implementation discarded every error from the 11× `fmt.Fprintln` and
// 1× `fmt.Fprint` calls plus the `defer Close`. If the disk filled
// mid-write, the network FS disconnected, or the I/O quota was hit
// between (e.g.) lines 5 and 6, the file ended up TRUNCATED — early
// lines (encrypted private key, public key) present, tail (smart/
// standard addresses, footer) missing — and the function returned with
// no signal. The matching ImportPrivateKey requires `len(lines) == 12`
// exactly, so a truncated wallet → unimportable with a generic
// "invalid file format" message → user has no recourse and may not
// realise the failure happened until later recovery attempts.
//
// Post-v4.0.1 contract:
//   - Build all content in a strings.Builder before touching the file
//     (eliminates inter-line truncation risk: there are now no
//     intermediate write points where partial state can land on disk).
//   - One `file.WriteString` for the entire payload. On failure: close
//     the file, `os.Remove(FileName)` to avoid leaving a partial
//     wallet on disk, return wrapped error.
//   - Explicit `Sync()` then `Close()` with errors checked. Sync is
//     where buffered data hits the platter; Close is where any
//     last-mile flush failure surfaces. Pre-fix both were silent.
//   - The function signature changes from `func(...)` (no return) to
//     `func(...) error`. CLI callers in process.go propagate to
//     stderr + os.Exit(1).
func ExportPrivateKey(e *el.Ellipse, BitString, Password string) error {
	// Helper function to convert from base 2 to base 49
	convertBase2ToBase49 := func(input string) string {
		// Convert the input string from base 2 to big.Int
		bigIntValue := new(big.Int)
		if _, success := bigIntValue.SetString(input, 2); success {
			// Convert the big.Int value to base 49
			return bigIntValue.Text(49)
		}
		return "" // Return an empty string on failure
	}
	encryptedRaw := AES.EncryptBitString(BitString, Password)
	if encryptedRaw == "" {
		return fmt.Errorf("AES encryption failed; aborting key export")
	}
	EncryptedPK := convertBase2ToBase49(encryptedRaw)

	Scalar, err := e.GenerateScalarFromBitString(BitString)
	if err != nil {
		return fmt.Errorf("invalid bit string in ExportPrivateKey: %w", err)
	}
	KeyPair, err := e.ScalarToKeys(Scalar)
	if err != nil {
		return fmt.Errorf("failed to derive key pair in ExportPrivateKey: %w", err)
	}
	PublicKey := KeyPair.PUBL
	// F-API-003 (v4.0.1): GenerateFilenameFromPublicKey now returns
	// (string, error). After F-ERR-003 the upstream PublicKeyToAddress
	// panics on malformed PUBL, so reaching this branch with a bad PUBL
	// is unreachable in practice — but the propagation is still correct
	// defense-in-depth and matches the keystore package's error contract.
	FileName, err := GenerateFilenameFromPublicKey(PublicKey)
	if err != nil {
		return fmt.Errorf("failed to derive wallet filename: %w", err)
	}
	SmartAddress := el.DalosAddressMaker(PublicKey, true)
	StandardAddress := el.DalosAddressMaker(PublicKey, false)

	String0 := "=====================ѺurѺ₿ѺrѺΣ====================="
	String1 := "Your DALOS Account PrivateKey in encrypted form is:"
	String2 := "Your DALOS Account PublicKey:"
	String3 := "Your Smart DALOS Account Address is:"
	String4 := "Your Standard DALOS Account Address is:"

	// Build the entire payload in memory first. Any failure during
	// payload construction is impossible (string concatenation cannot
	// fail), so once we open the file we either write the whole thing
	// or remove the partial file and report the error. There are no
	// intermediate per-line write points where partial state can land.
	var buf strings.Builder
	for _, line := range []string{
		String0, String1, EncryptedPK, String0,
		String2, PublicKey, String0,
		String3, SmartAddress,
		String4, StandardAddress,
	} {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	buf.WriteString(String0) // trailing line, no newline (matches pre-v4.0.1 fmt.Fprint shape)
	payload := buf.String()

	// F-SEC-002 (audit cycle 2026-05-04, v4.0.1): use 0600 instead of os.Create's
	// default 0644 so wallet files are owner-only on POSIX systems. The file holds
	// the AES-256-GCM-encrypted private key plus the matching public key — that's
	// enough material for an offline brute-force oracle if the password is weak.
	// Windows ignores the mode bits (NTFS uses ACLs); Linux/macOS honor them.
	//
	// F-LOW-014 (audit cycle 2026-05-04, v4.0.3): switched O_TRUNC → O_EXCL so a
	// filename collision is REJECTED rather than silently overwriting an existing
	// wallet on disk. GenerateFilenameFromPublicKey produces filenames of shape
	// {first7-PUBL-chars}...{last7-PUBL-chars}.txt (14 base-49 chars total →
	// ~1.4e-24 collision probability per pair) — astronomically improbable, but
	// the failure mode if it ever occurs would be silent destruction of an
	// existing wallet (and thus the only recoverable copy of the key it
	// protects). O_EXCL turns the race / collision into a hard error at the
	// open syscall, which the caller can surface to the user with the actual
	// filename for manual review. Pre-v4.0.3 the open succeeded, the new
	// wallet was written on top of the existing one, and the user would
	// discover the loss only when trying to recover the prior key.
	//
	// Operational note: if a re-export of the SAME wallet is ever needed
	// (e.g., after a partial-write recovery — though the WriteString error
	// path below cleans up via os.Remove), the user must manually delete the
	// pre-existing file first. This is intentional: explicit deletion forces
	// confirmation that overwriting the file is the desired action.
	OutputFile, err := os.OpenFile(FileName, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		// os.IsExist(err) catches the EEXIST case (the F-LOW-014 reject path);
		// surface it with a distinct, user-actionable message naming the
		// collision target. Other errors (permission denied, disk full at
		// create-time, etc.) flow through the generic wrap below.
		if os.IsExist(err) {
			fmt.Printf("Error: wallet file %q already exists — refusing to overwrite (F-LOW-014 collision protection).\n", FileName)
			fmt.Println("       Inspect the existing file before retrying. If you intended to replace it,")
			fmt.Println("       delete it manually and re-run the export.")
			return fmt.Errorf("export refused: file %q already exists (F-LOW-014 collision protection): %w", FileName, err)
		}
		fmt.Println("Error: failed to create export file:", err)
		return fmt.Errorf("failed to create export file %q: %w", FileName, err)
	}

	// Single all-or-nothing write. On any failure, close the file and
	// remove the partial wallet from disk (we don't want ImportPrivateKey
	// to find a half-written file later and fail with a generic
	// "invalid file format" — better to leave nothing).
	if _, err := OutputFile.WriteString(payload); err != nil {
		_ = OutputFile.Close()
		_ = os.Remove(FileName)
		return fmt.Errorf("failed to write wallet payload to %q: %w", FileName, err)
	}
	// Flush kernel buffers to durable storage. On a crash between
	// WriteString and Sync, the OS may have buffered the bytes without
	// writing them; explicit Sync makes the wallet durable before we
	// claim success.
	if err := OutputFile.Sync(); err != nil {
		_ = OutputFile.Close()
		_ = os.Remove(FileName)
		return fmt.Errorf("failed to sync wallet file %q: %w", FileName, err)
	}
	if err := OutputFile.Close(); err != nil {
		_ = os.Remove(FileName)
		return fmt.Errorf("failed to close wallet file %q: %w", FileName, err)
	}
	return nil
}
