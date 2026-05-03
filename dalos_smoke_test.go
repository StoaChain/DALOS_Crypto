package main

import (
    "context"
    "os/exec"
    "strings"
    "testing"
    "time"
)

// TestCLI_InvalidIntegerFlag_ExitsNonZeroWithError is the integrated-driver
// regression guard for the empty-string-sentinel + caller-update contract
// across ProcessIntegerFlag and Dalos.go's base-10 integer call site
// (CLI flag -i10, internally named intaFlag). It spawns the compiled binary
// as a subprocess via `go run` and asserts:
//
//   1. The subprocess exits non-zero (caller hit os.Exit(1) after observing
//      the empty-string sentinel from ProcessIntegerFlag).
//   2. Combined stdout+stderr contains "Error: Invalid private key." — the
//      diagnostic emitted by ProcessIntegerFlag itself.
//   3. Combined stdout+stderr contains "Aborting -i10 base-10 key generation."
//      — the per-call-site message emitted by Dalos.go BEFORE os.Exit(1).
//      The "-i10" token references the actual user-facing flag (matches
//      the input the user typed). This proves the caller-update landed
//      and the sentinel check is wired.
//
// A 30-second deadline gates the worst-case failure mode: if the caller
// update accidentally allows downstream flow to reach SaveBitString's
// fmt.Scanln password prompt, the subprocess would block on stdin forever.
// CommandContext + DeadlineExceeded converts that hang into a clean test
// diagnostic instead of stalling the entire `go test` run.
//
// The test invokes `go run .` (Phase 10 v4.0.0 cutover from
// `go run Dalos.go` — the carve-out splits package main across Dalos.go
// + print.go + process.go, so the single-file compile no longer resolves
// the relocated free functions ProcessIntegerFlag / ProcessKeyGeneration
// / etc.). CI environments and local dev shells both have `go` on PATH;
// no separate build artifact is managed.
func TestCLI_InvalidIntegerFlag_ExitsNonZeroWithError(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "go", "run", ".", "-g", "-i10", "not_an_integer", "-p", "test")
    out, err := cmd.CombinedOutput()

    if ctx.Err() == context.DeadlineExceeded {
        t.Fatalf("subprocess timed out after 30s — likely hanging on fmt.Scanln; the -i10 caller-update may not be short-circuiting before SaveBitString. Output: %s", string(out))
    }

    if err == nil {
        t.Fatalf("expected non-zero exit from subprocess, got nil error; output: %s", string(out))
    }
    if _, isExitErr := err.(*exec.ExitError); !isExitErr {
        t.Fatalf("expected *exec.ExitError, got %T: %v; output: %s", err, err, string(out))
    }

    output := string(out)
    const wantInvalidPK = "Error: Invalid private key."
    if !strings.Contains(output, wantInvalidPK) {
        t.Errorf("subprocess output missing %q\n  got: %s", wantInvalidPK, output)
    }
    const wantAbort = "Aborting -i10 base-10 key generation."
    if !strings.Contains(output, wantAbort) {
        t.Errorf("subprocess output missing %q\n  got: %s", wantAbort, output)
    }
}
