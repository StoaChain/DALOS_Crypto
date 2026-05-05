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
// v4.0.3 (audit cycle 2026-05-04, F-LOW-014): O_TRUNC swapped for
// O_EXCL — collision now rejected rather than silently overwriting.
// New `os.IsExist(err)` branch precedes the generic-error branch and
// surfaces a distinct user-actionable message. Both branches must
// preserve the F-ERR-005 contract (print + wrapped error return).
func TestExportPrivateKey_OsCreateErrorBlock_Shape(t *testing.T) {
    src, err := os.ReadFile("export.go")
    if err != nil {
        t.Fatalf("failed to read export.go: %v", err)
    }
    body := string(src)

    // Pattern A: the OpenFile call must use O_EXCL (F-LOW-014) with
    // owner-only 0600 mode (F-SEC-002). Both `0o600` and `0600` accepted.
    openPattern := regexp.MustCompile(
        `OutputFile,\s*err\s*:=\s*os\.OpenFile\(FileName,\s*os\.O_CREATE\|os\.O_WRONLY\|os\.O_EXCL,\s*0o?600\)`,
    )
    if !openPattern.MatchString(body) {
        t.Errorf("ExportPrivateKey OpenFile call must use O_CREATE|O_WRONLY|O_EXCL with mode 0o600 (F-SEC-002 owner-only + F-LOW-014 collision protection); shape does not match")
    }

    // Pattern B: the EEXIST branch (F-LOW-014) — `if os.IsExist(err)`
    // must precede the generic-error branch, print a user-actionable
    // message, and return a wrapped error.
    eexistPattern := regexp.MustCompile(
        `if\s+os\.IsExist\(err\)\s*\{[^}]*` +
            `fmt\.Printf\("Error:\s+wallet file %q already exists[^"]*"` +
            `[^}]*return\s+fmt\.Errorf\(`,
    )
    if !eexistPattern.MatchString(body) {
        t.Errorf("ExportPrivateKey EEXIST branch must surface a distinct collision-protection error per F-LOW-014 (print 'wallet file already exists' + wrapped error return)")
    }

    // Pattern C: the generic-error branch (F-ERR-005) must remain — print
    // 'failed to create export file' breadcrumb + wrapped error return.
    // This catches non-EEXIST OpenFile failures (permission denied, disk
    // full, parent-dir-missing, etc.).
    genericPattern := regexp.MustCompile(
        `fmt\.Println\("Error:\s+failed to create export file:",\s*err\)\s*` +
            `\n\s*return\s+fmt\.Errorf\(`,
    )
    if !genericPattern.MatchString(body) {
        t.Errorf("ExportPrivateKey generic OpenFile-error branch must preserve the F-ERR-005 contract (print 'failed to create export file' + wrapped error return)")
    }
}
