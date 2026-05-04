package keystore

import (
    "os"
    "regexp"
    "strings"
    "testing"
)

// TestExportPrivateKey_NoLogFatal is the regression guard for the KG-2 sibling
// pattern adoption in ExportPrivateKey. The function must never abort the
// process via log.Fatal/log.Fatalf/log.Panic/os.Exit when os.Create fails;
// it must print a sibling-pattern error to stdout and return gracefully so
// callers (e.g. SaveBitString) can continue or surface the failure.
//
// Phase 10 (REQ-31, v4.0.0): moved verbatim from
// Elliptic/ExportPrivateKey_errpath_test.go alongside ExportPrivateKey's
// move to keystore/. The source-text target was retargeted from
// "KeyGeneration.go" to "export.go" (the Phase-10 home of the function).
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
            t.Errorf("export.go must not contain %q (process-terminating call); KG-2 sibling pattern requires print + return", needle)
        }
    }

    // The "log" import must be absent now that no log.* call remains.
    // Match either a bare `"log"` import line or an aliased form.
    logImport := regexp.MustCompile(`(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"log"\s*$`)
    if logImport.MatchString(body) {
        t.Errorf("export.go must not import \"log\" (no log.* usages remain post-T1.3); go vet would also flag this")
    }

    // Positive assertion: the sibling pattern message for the os.Create
    // error path is present. This pins the wording so a future refactor
    // cannot silently regress to log.Fatal or to a non-sibling shape.
    expected := `fmt.Println("Error: failed to create export file:", err)`
    if !strings.Contains(body, expected) {
        t.Errorf("export.go must contain the KG-2 sibling-pattern error print %q for the os.Create failure path", expected)
    }
}

// TestExportPrivateKey_OsCreateErrorBlock_Shape pins the exact 4-line shape
// of the wallet-file-create error block to the sibling pattern used in the
// same function. Drift in shape is a regression.
//
// v4.0.1 (audit cycle 2026-05-04, F-SEC-002): the create call switched
// from `os.Create(FileName)` (mode 0644, world-readable on POSIX) to
// `os.OpenFile(FileName, O_CREATE|O_WRONLY|O_TRUNC, 0600)` (owner-only).
// The pattern below matches the new form while preserving the sibling-
// pattern intent (print-then-return, no log.Fatal).
func TestExportPrivateKey_OsCreateErrorBlock_Shape(t *testing.T) {
    src, err := os.ReadFile("export.go")
    if err != nil {
        t.Fatalf("failed to read export.go: %v", err)
    }
    body := string(src)

    // Sibling-shape: os.OpenFile with explicit mode bits, followed by an
    // if-err block that prints to stdout with the "Error: " prefix and
    // returns. Pattern uses arbitrary whitespace for indentation tolerance
    // and accepts either `0o600` (Go 1.13+ literal) or `0600` (legacy).
    pattern := regexp.MustCompile(
        `OutputFile,\s*err\s*:=\s*os\.OpenFile\(FileName,\s*os\.O_CREATE\|os\.O_WRONLY\|os\.O_TRUNC,\s*0o?600\)\s*` +
            `\n\s*if\s+err\s*!=\s*nil\s*\{\s*` +
            `\n\s*fmt\.Println\("Error:\s+failed to create export file:",\s*err\)\s*` +
            `\n\s*return\s*` +
            `\n\s*\}`,
    )
    if !pattern.MatchString(body) {
        t.Errorf("ExportPrivateKey wallet-file-create error block does not match the KG-2 sibling pattern shape (print-then-return) with the F-SEC-002 owner-only OpenFile form")
    }
}
