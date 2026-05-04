package keystore

import (
	el "DALOS_Crypto/Elliptic"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// F-API-004 (audit cycle 2026-05-04, v4.0.1):
// ImportPrivateKey header-anchored parser
// =============================================================================
//
// Pre-v4.0.1 the reader split content on "\n" and demanded EXACTLY 12
// elements, then trusted lines[2] (encrypted PK) and lines[5] (public
// key) by positional index. Brittle to CRLF normalisation and editor
// "ensure final newline" behaviour; also turned the import surface
// into a brute-force oracle (no header validation, just position).
//
// Post-v4.0.1: walk lines, locate canonical headers, take the next
// non-empty line as the body. Tests below pin (a) round-trip happy
// path, (b) CRLF tolerance, (c) trailing-newline tolerance, (d)
// non-wallet rejection by header-presence check.

// roundTripFixture exports a wallet to a temp dir with a known scalar,
// then returns (path, password) for ImportPrivateKey-side test cases.
// Callers can mutate the file content between export and import to
// simulate CRLF / trailing-newline / non-wallet conditions.
func roundTripFixture(t *testing.T) (path, password string) {
	t.Helper()
	originalCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to capture original cwd: %v", err)
	}
	sandbox := t.TempDir()
	if err := os.Chdir(sandbox); err != nil {
		t.Fatalf("failed to chdir to sandbox %q: %v", sandbox, err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalCwd) })

	e := el.DalosEllipse()
	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected fixture: %v", err)
	}
	keyPair, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected scalar: %v", err)
	}
	filename, err := GenerateFilenameFromPublicKey(keyPair.PUBL)
	if err != nil {
		t.Fatalf("GenerateFilenameFromPublicKey rejected PUBL: %v", err)
	}
	password = "test-password"
	if err := ExportPrivateKey(&e, bs0001InputBitstring, password); err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}
	return filepath.Join(sandbox, filename), password
}

// TestImportPrivateKey_RoundTrip pins the happy path: export then
// import round-trips the same private key cleanly.
func TestImportPrivateKey_RoundTrip(t *testing.T) {
	path, password := roundTripFixture(t)
	e := el.DalosEllipse()
	keyPair, err := ImportPrivateKey(&e, path, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed on fresh export: %v", err)
	}
	if keyPair.PRIV == "" || keyPair.PUBL == "" {
		t.Errorf("imported keypair is empty: %+v", keyPair)
	}
}

// TestImportPrivateKey_AcceptsCRLF confirms wallets normalised to CRLF
// (Windows clipboard, email transport, git autocrlf=true) still import.
// Pre-fix this would have failed with "invalid file format" because
// strings.Split on "\n" leaves \r-terminated parts and the count drift.
func TestImportPrivateKey_AcceptsCRLF(t *testing.T) {
	path, password := roundTripFixture(t)

	// Read, normalise to CRLF, write back.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	crlfContent := strings.ReplaceAll(string(content), "\n", "\r\n")
	if err := os.WriteFile(path, []byte(crlfContent), 0o600); err != nil {
		t.Fatalf("failed to write CRLF fixture: %v", err)
	}

	e := el.DalosEllipse()
	keyPair, err := ImportPrivateKey(&e, path, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed on CRLF wallet: %v", err)
	}
	if keyPair.PRIV == "" {
		t.Errorf("imported keypair PRIV is empty after CRLF round-trip")
	}
}

// TestImportPrivateKey_AcceptsTrailingNewline confirms wallets with
// an extra trailing "\n" (any text editor that "ensures final newline")
// still import. Pre-fix this would have produced 13 split parts → reject.
func TestImportPrivateKey_AcceptsTrailingNewline(t *testing.T) {
	path, password := roundTripFixture(t)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	withTrailing := append(content, '\n', '\n', '\n') // multiple trailing newlines
	if err := os.WriteFile(path, withTrailing, 0o600); err != nil {
		t.Fatalf("failed to write trailing-newline fixture: %v", err)
	}

	e := el.DalosEllipse()
	keyPair, err := ImportPrivateKey(&e, path, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed on trailing-newline wallet: %v", err)
	}
	if keyPair.PRIV == "" {
		t.Errorf("imported keypair PRIV is empty after trailing-newline round-trip")
	}
}

// TestImportPrivateKey_RejectsNonWallet pins the header-presence guard.
// Pre-fix any 12-line file would flow into AES decrypt and surface as
// "incorrect password or decryption failed" — usable as a brute-force
// oracle. Post-fix the header-presence check rejects non-wallet content
// before reaching AES.
func TestImportPrivateKey_RejectsNonWallet(t *testing.T) {
	sandbox := t.TempDir()
	bogusPath := filepath.Join(sandbox, "not-a-wallet.txt")
	// 12 random non-empty lines, none matching the canonical headers.
	bogusContent := strings.Repeat("this is not a wallet file\n", 12)
	if err := os.WriteFile(bogusPath, []byte(bogusContent), 0o600); err != nil {
		t.Fatalf("failed to write bogus fixture: %v", err)
	}

	e := el.DalosEllipse()
	_, err := ImportPrivateKey(&e, bogusPath, "any-password")
	if err == nil {
		t.Fatal("expected error for non-wallet file, got nil")
	}
	// Must reject at the header check, NOT at AES (which would suggest
	// the brute-force-oracle vector still exists).
	if !strings.Contains(err.Error(), "header") && !strings.Contains(err.Error(), "wallet file format") {
		t.Errorf("expected header-not-found error; got: %v", err)
	}
	if strings.Contains(err.Error(), "incorrect password") || strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("non-wallet file should be rejected at header check, NOT at AES decrypt (oracle vector). Error: %v", err)
	}
}

// TestImportPrivateKey_RejectsMissingPublicKeyHeader pins the second-
// header guard. A file with the encrypted-PK header but no public-key
// header is malformed even if it has 12 lines.
func TestImportPrivateKey_RejectsMissingPublicKeyHeader(t *testing.T) {
	sandbox := t.TempDir()
	path := filepath.Join(sandbox, "partial-wallet.txt")
	content := "banner\n" +
		headerEncryptedPrivateKey + "\n" +
		"some-encrypted-body\n" +
		"banner\n" +
		"NOT THE PUBLIC KEY HEADER\n" +
		"some-body\n" +
		"banner\nfiller\nfiller\nfiller\nfiller\nfiller"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write partial-wallet fixture: %v", err)
	}

	e := el.DalosEllipse()
	_, err := ImportPrivateKey(&e, path, "any-password")
	if err == nil {
		t.Fatal("expected error for wallet missing public-key header, got nil")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("error should mention public key section; got: %v", err)
	}
}
