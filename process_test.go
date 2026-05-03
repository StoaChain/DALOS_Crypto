package main

import (
    el "DALOS_Crypto/Elliptic"
    "testing"
)

// TestProcessIntegerFlag_InvalidInput_ReturnsEmptyString is the runtime
// behavioural regression guard for ProcessIntegerFlag's empty-string
// sentinel. Pre-fix the function called os.Exit(1) on any input that
// failed ValidatePrivateKey, terminating the test process. Post-fix the
// function prints "Error: Invalid private key." and returns "" so callers
// can detect failure and bail.
//
// The table below covers four classes of invalid input that all flow
// through the !isValid branch:
//
//   1. Non-numeric base-10 input — big.Int.SetString fails silently,
//      leaving PK=0; binaryKey="0", first-character check ('1') fails.
//   2. Non-numeric base-49 input — same path, base-49 parser rejects
//      punctuation; PK=0, binaryKey="0", first-character check fails.
//   3. Empty string — same path; SetString rejects, PK=0, binaryKey="0".
//   4. Out-of-range negative integer — SetString accepts the sign, PK<0,
//      Text(2) returns "-…", first character is '-' not '1', guard fails.
//
// Each case asserts the returned string is "" (the sentinel). The mere
// fact that the t.Errorf line is reachable proves the function did not
// terminate the process — the implicit half of the contract.
//
// Phase 10 (REQ-31, v4.0.0): moved verbatim from
// Elliptic/KeyGeneration_test.go alongside ProcessIntegerFlag. The
// receiver-form invocation `e.ProcessIntegerFlag(...)` is rewritten
// to the Phase-10 free-function form `ProcessIntegerFlag(&e, ...)`.
func TestProcessIntegerFlag_InvalidInput_ReturnsEmptyString(t *testing.T) {
    e := el.DalosEllipse()
    cases := []struct {
        name      string
        flagValue string
        isBase10  bool
    }{
        {"non_numeric_base10", "not_an_integer", true},
        {"non_numeric_base49", "!!!invalid49", false},
        {"empty_string_base10", "", true},
        {"negative_out_of_range_base10", "-1", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := ProcessIntegerFlag(&e, tc.flagValue, tc.isBase10)
            if got != "" {
                t.Errorf("ProcessIntegerFlag(%q, %v) = %q, want empty string", tc.flagValue, tc.isBase10, got)
            }
        })
    }
}
