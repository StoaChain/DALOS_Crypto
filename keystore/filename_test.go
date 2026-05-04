package keystore

import (
	"os"
	"strings"
	"testing"
)

// =============================================================================
// F-API-003 (audit cycle 2026-05-04, v4.0.1):
// GenerateFilenameFromPublicKey contract
// =============================================================================
//
// Pre-v4.0.1 the function had two contract violations:
//   1. fmt.Println from inside a library helper on malformed input.
//   2. Returned the magic sentinel string "InvalidPublicKey.txt" instead
//      of an error.
// Post-v4.0.1: returns (string, error) matching the sibling pattern used
// by ImportPrivateKey + AESDecrypt in this same package. No stdout side-
// effect on the malformed-input path.

// TestGenerateFilenameFromPublicKey_AcceptsValidInput pins the happy path:
// a well-formed PUBL produces a non-empty filename and a nil error. Drives
// the canonical "<prefix>.<first7>...<last7>.txt" shape.
func TestGenerateFilenameFromPublicKey_AcceptsValidInput(t *testing.T) {
	// PUBL of the canonical "<xLength-base49>.<body-base49>" shape, long
	// enough to exercise both the first-7 and last-7 extraction branches.
	publicKey := "9G.2idxjKMabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMfatDK0u"
	filename, err := GenerateFilenameFromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("expected nil error for well-formed PUBL, got: %v", err)
	}
	if filename == "" {
		t.Fatal("expected non-empty filename, got empty string")
	}
	if !strings.HasSuffix(filename, ".txt") {
		t.Errorf("filename should end in .txt, got: %q", filename)
	}
	if !strings.Contains(filename, "...") {
		t.Errorf("filename should contain the canonical \"...\" separator, got: %q", filename)
	}
}

// TestGenerateFilenameFromPublicKey_RejectsMissingDot pins the
// malformed-input rejection. Pre-v4.0.1 this was a stdout side-effect +
// magic sentinel string "InvalidPublicKey.txt".
func TestGenerateFilenameFromPublicKey_RejectsMissingDot(t *testing.T) {
	cases := []string{
		"",                          // empty
		"no-dot-separator-anywhere", // no '.' in the entire string
	}
	for _, input := range cases {
		filename, err := GenerateFilenameFromPublicKey(input)
		if err == nil {
			t.Errorf("expected error for malformed input %q, got nil; filename=%q", input, filename)
			continue
		}
		if filename != "" {
			t.Errorf("expected empty string on error path for input %q, got: %q", input, filename)
		}
		if !strings.Contains(err.Error(), "GenerateFilenameFromPublicKey") {
			t.Errorf("error message should name function for input %q; got: %s", input, err.Error())
		}
		if !strings.Contains(err.Error(), "no \".\" separator") {
			t.Errorf("error message should describe the missing separator for input %q; got: %s", input, err.Error())
		}
		// Critical: the sentinel string must NOT appear anywhere — pre-fix
		// this is what the function returned on malformed input.
		if strings.Contains(filename, "InvalidPublicKey.txt") {
			t.Errorf("filename should not be the legacy sentinel; got: %q", filename)
		}
	}
}

// TestGenerateFilenameFromPublicKey_NoStdoutSideEffect verifies the function
// no longer prints to stdout on the malformed-input path. The pre-v4.0.1
// `fmt.Println("Invalid public key format. No dot found.")` made the
// function unsuitable for non-CLI consumers (server, GUI, JSON pipe).
//
// Verification strategy: source-text grep — the line should not contain
// `fmt.Println` or `fmt.Print` outside of comments. Behavioural verification
// via stdout-capture is also possible but the source-text check is more
// robust and faster.
func TestGenerateFilenameFromPublicKey_NoStdoutSideEffect(t *testing.T) {
	// Read the source file rather than reflecting on the running binary
	// — Go has no way to introspect a function's source text at runtime.
	srcBytes, err := os.ReadFile("filename.go")
	if err != nil {
		t.Fatalf("failed to read filename.go: %v", err)
	}
	src := string(srcBytes)

	// Walk the body looking for fmt.Println / fmt.Print / fmt.Printf in
	// non-comment lines. Skip `//` comments since the docstring legitimately
	// references the historical behaviour.
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, needle := range []string{"fmt.Println(", "fmt.Print(", "fmt.Printf("} {
			if strings.Contains(line, needle) {
				t.Errorf("filename.go must not call %q outside comments (library functions must not write to stdout). Offending line: %q", needle, line)
			}
		}
	}
}
