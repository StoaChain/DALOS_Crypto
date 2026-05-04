package main

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
// Phase 10 (REQ-31, v4.0.0): moved verbatim from
// Elliptic/ProcessIntegerFlag_errpath_test.go alongside ProcessIntegerFlag's
// move to package main. The source-text target was retargeted from
// "KeyGeneration.go" to "process.go" (the Phase-10 home of the function), and
// the receiver-method regex was retargeted to the free-function form
// `func ProcessIntegerFlag(e *el.Ellipse, ...)`.
func TestProcessIntegerFlag_NoOsExit(t *testing.T) {
	src, err := os.ReadFile("process.go")
	if err != nil {
		t.Fatalf("failed to read process.go: %v", err)
	}
	body := string(src)

	// Isolate the ProcessIntegerFlag function body so the assertion does not
	// false-positive on legitimate os.* usages elsewhere.
	fnPattern := regexp.MustCompile(
		`(?s)func\s+ProcessIntegerFlag\([^)]*\)\s+string\s*\{(.*?)\n\}`,
	)
	match := fnPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("could not locate ProcessIntegerFlag function body in process.go")
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
	// (with the v4.0.2 F-MED-016 reason field appended). Drift in wording is
	// a regression for any caller relying on the message for diagnostics.
	expectedPrint := `fmt.Println("Error: Invalid private key:", reason)`
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
// invalid-input block to the empty-string sentinel pattern. Drift in shape
// is a regression.
//
// v4.0.2 (F-MED-016): the error print now includes the reason returned by
// ValidatePrivateKey (third return value) — message format:
//   `fmt.Println("Error: Invalid private key:", reason)`
// instead of the pre-v4.0.2 generic `fmt.Println("Error: Invalid private key.")`.
func TestProcessIntegerFlag_InvalidBranchShape(t *testing.T) {
	src, err := os.ReadFile("process.go")
	if err != nil {
		t.Fatalf("failed to read process.go: %v", err)
	}
	body := string(src)

	// Sentinel-shape: an `if !isValid` block that prints the canonical error
	// (with reason) to stdout and returns "". The pattern uses arbitrary
	// whitespace for indentation tolerance.
	pattern := regexp.MustCompile(
		`if\s+!isValid\s*\{\s*` +
			`\n\s*fmt\.Println\("Error:\s+Invalid private key:",\s+reason\)\s*` +
			`\n\s*return\s+""\s*` +
			`\n\s*\}`,
	)
	if !pattern.MatchString(body) {
		t.Errorf("ProcessIntegerFlag invalid-input block does not match the empty-string sentinel pattern shape (print-then-return-empty)")
	}
}
