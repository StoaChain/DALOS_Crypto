package Elliptic

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestProcessIntegerFlag_NoOsExit is the regression guard for the empty-string
// sentinel adoption in ProcessIntegerFlag. The function must never abort the
// process via os.Exit (or log.Fatal/log.Panic) when ValidatePrivateKey rejects
// the input; it must print the existing "Error: Invalid private key." message
// to stdout and return "" so callers can decide how to react.
//
// Pre-fix: ProcessIntegerFlag called os.Exit(1) on invalid input, terminating
// the process and making the function non-composable inside library callers
// or test binaries.
//
// Post-fix: the invalid-input path uses fmt.Println + return "", matching the
// empty-string sentinel convention already established in AES.EncryptBitString
// (AES/AES.go:95,100,105) and Elliptic.SchnorrSign (Elliptic/Schnorr.go:315).
// The function's existing string return type is preserved.
func TestProcessIntegerFlag_NoOsExit(t *testing.T) {
	src, err := os.ReadFile("KeyGeneration.go")
	if err != nil {
		t.Fatalf("failed to read KeyGeneration.go: %v", err)
	}
	body := string(src)

	// Isolate the ProcessIntegerFlag function body so the assertion does not
	// false-positive on the legitimate os.Create / os.ReadFile usages
	// elsewhere in the file (ExportPrivateKey at line 547, ImportPrivateKey
	// at line 575).
	fnPattern := regexp.MustCompile(
		`(?s)func\s+\(e\s*\*Ellipse\)\s+ProcessIntegerFlag\([^)]*\)\s+string\s*\{(.*?)\n\}`,
	)
	match := fnPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("could not locate ProcessIntegerFlag function body in KeyGeneration.go")
	}
	fnBody := match[1]

	forbidden := []string{
		"os.Exit(",
		"log.Fatal(",
		"log.Fatalf(",
		"log.Fatalln(",
		"log.Panic(",
		"log.Panicf(",
		"log.Panicln(",
	}
	for _, needle := range forbidden {
		if strings.Contains(fnBody, needle) {
			t.Errorf("ProcessIntegerFlag must not contain %q (process-terminating call); empty-string sentinel pattern requires print + return \"\"", needle)
		}
	}

	// Positive assertion: the existing user-facing error message is preserved
	// verbatim. Drift in wording is a regression for any caller relying on
	// the message for diagnostics.
	expectedPrint := `fmt.Println("Error: Invalid private key.")`
	if !strings.Contains(fnBody, expectedPrint) {
		t.Errorf("ProcessIntegerFlag must contain the user-facing error print %q", expectedPrint)
	}

	// Positive assertion: the empty-string sentinel return is present in the
	// invalid-input branch. This pins the convention so a future refactor
	// cannot silently regress to os.Exit, panic, or to a non-empty fallback.
	if !strings.Contains(fnBody, `return ""`) {
		t.Errorf("ProcessIntegerFlag must contain `return \"\"` for the invalid private-key path (empty-string sentinel convention)")
	}
}

// TestProcessIntegerFlag_InvalidBranchShape pins the exact shape of the
// invalid-input block to the empty-string sentinel pattern used in
// AES.EncryptBitString and Elliptic.SchnorrSign. Drift in shape is a
// regression.
func TestProcessIntegerFlag_InvalidBranchShape(t *testing.T) {
	src, err := os.ReadFile("KeyGeneration.go")
	if err != nil {
		t.Fatalf("failed to read KeyGeneration.go: %v", err)
	}
	body := string(src)

	// Sentinel-shape: an `if !isValid` block that prints the canonical error
	// to stdout and returns "". The pattern uses arbitrary whitespace for
	// indentation tolerance.
	pattern := regexp.MustCompile(
		`if\s+!isValid\s*\{\s*` +
			`\n\s*fmt\.Println\("Error:\s+Invalid private key\."\)\s*` +
			`\n\s*return\s+""\s*` +
			`\n\s*\}`,
	)
	if !pattern.MatchString(body) {
		t.Errorf("ProcessIntegerFlag invalid-input block does not match the empty-string sentinel pattern shape (print-then-return-empty)")
	}
}
