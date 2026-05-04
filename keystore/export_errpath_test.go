package keystore

import (
    "os"
    "regexp"
    "strings"
    "testing"
)

// TestExportPrivateKey_NoLogFatal is the regression guard against
// process-terminating calls inside ExportPrivateKey. The function must
// never abort the process via log.Fatal/log.Panic/os.Exit. It must
// surface failures via its `error` return so CLI callers (e.g.
// SaveBitString in process.go) can decide how to react.
//
// Phase 10 (REQ-31, v4.0.0): moved verbatim from
// Elliptic/ExportPrivateKey_errpath_test.go alongside ExportPrivateKey's
// move to keystore/. The source-text target was retargeted from
// "KeyGeneration.go" to "export.go" (the Phase-10 home of the function).
//
// v4.0.1 (audit cycle 2026-05-04, F-ERR-005): the function signature
// changed from `func(...)` (no return) to `func(...) error` so disk
// failures during the 11-line wallet write are surfaced instead of
// silently truncating. The KG-2 sibling-pattern legacy `fmt.Println`
// remains for the OpenFile branch as defence-in-depth (CLI gets a
// stdout signal in addition to the returned error).
func TestExportPrivateKey_NoLogFatal(t *testing.T) {
    src, err := os.ReadFile("export.go")
    if err != nil {
        t.Fatalf("failed to read export.go: %v", err)
    }
    body := string(src)

    forbidden := []string{
        "log.Fatal(",
        "log.Fatalf(",
        "log.Fatalln(",
        "log.Panic(",
        "log.Panicf(",
        "log.Panicln(",
    }
    for _, needle := range forbidden {
        if strings.Contains(body, needle) {
            t.Errorf("export.go must not contain %q (process-terminating call); ExportPrivateKey must surface failures via its error return", needle)
        }
    }
    // os.Exit / panic checks: search the source-text but skip the doc
    // comment block that legitimately mentions os.Exit (when describing
    // CLI callers' behaviour). A simple "is the string outside a `//`
    // line" check suffices because export.go uses no /* ... */ blocks
    // and no string literals containing "os.Exit".
    forbiddenCalls := []string{"os.Exit(", "panic("}
    for _, line := range strings.Split(body, "\n") {
        trimmed := strings.TrimSpace(line)
        if strings.HasPrefix(trimmed, "//") {
            continue // skip comments
        }
        for _, needle := range forbiddenCalls {
            if strings.Contains(line, needle) {
                t.Errorf("export.go must not contain %q outside comments (process-terminating call); ExportPrivateKey must surface failures via its error return. Offending line: %q", needle, line)
            }
        }
    }

    // The "log" import must be absent now that no log.* call remains.
    // Match either a bare `"log"` import line or an aliased form.
    logImport := regexp.MustCompile(`(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"log"\s*$`)
    if logImport.MatchString(body) {
        t.Errorf("export.go must not import \"log\" (no log.* usages remain); go vet would also flag this")
    }

    // Positive assertion: the function returns error. This pins the
    // F-ERR-005 contract — a future refactor that drops the error
    // return reverts the silent-truncation hazard.
    expectedSig := regexp.MustCompile(`func\s+ExportPrivateKey\([^)]+\)\s+error\b`)
    if !expectedSig.MatchString(body) {
        t.Errorf("export.go must declare ExportPrivateKey with an error return (F-ERR-005); current declaration must match the regex %q", expectedSig.String())
    }
}

// TestExportPrivateKey_OsCreateErrorBlock_Shape pins the wallet-file-create
// error block to the F-ERR-005 contract: print to stdout (defence-in-depth
// breadcrumb for CLI users) AND return a wrapped error so the caller can
// react. Drift in either is a regression.
//
// v4.0.1 (audit cycle 2026-05-04, F-SEC-002): the create call uses
// `os.OpenFile(FileName, O_CREATE|O_WRONLY|O_TRUNC, 0600)` (owner-only).
// v4.0.1 (audit cycle 2026-05-04, F-ERR-005): the bare `return` was
// replaced with `return fmt.Errorf("failed to create export file %q: %w", ...)`.
func TestExportPrivateKey_OsCreateErrorBlock_Shape(t *testing.T) {
    src, err := os.ReadFile("export.go")
    if err != nil {
        t.Fatalf("failed to read export.go: %v", err)
    }
    body := string(src)

    // Pattern: os.OpenFile with explicit mode bits, followed by an
    // if-err block that prints to stdout with the "Error: " prefix and
    // returns a wrapped error. Pattern accepts either `0o600` (Go 1.13+
    // literal) or `0600` (legacy).
    pattern := regexp.MustCompile(
        `OutputFile,\s*err\s*:=\s*os\.OpenFile\(FileName,\s*os\.O_CREATE\|os\.O_WRONLY\|os\.O_TRUNC,\s*0o?600\)\s*` +
            `\n\s*if\s+err\s*!=\s*nil\s*\{\s*` +
            `\n\s*fmt\.Println\("Error:\s+failed to create export file:",\s*err\)\s*` +
            `\n\s*return\s+fmt\.Errorf\(`,
    )
    if !pattern.MatchString(body) {
        t.Errorf("ExportPrivateKey wallet-file-create error block does not match the F-ERR-005 contract (print + wrapped error return) with the F-SEC-002 owner-only OpenFile form")
    }
}
