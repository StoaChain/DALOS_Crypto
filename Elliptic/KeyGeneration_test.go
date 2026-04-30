package Elliptic

import (
    "bytes"
    "io"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestConvertHashToBitString(t *testing.T) {
    cases := []struct {
        name      string
        hash      []byte
        bitLength uint32
        want      string
    }{
        {"leading_zero_byte_aligned_16", []byte{0x00, 0xFF}, 16, "0000000011111111"},
        {"leading_zeros_byte_aligned_24", []byte{0x00, 0x00, 0x01}, 24, "000000000000000000000001"},
        {"truncate_branch", []byte{0xFF, 0xFF, 0xFF, 0xFF}, 24, "111111111111111111111111"},
        {"left_pad_branch", []byte{0xAB}, 12, "000010101011"},
        {"dalos_happy_path_1600", make200ByteAllFF(), 1600, strings1600AllOnes()},
        {"leading_zero_non_byte_aligned_15", []byte{0x00, 0xAB}, 15, "000000001010101"},
        {"empty_hash_all_pad_16", []byte{}, 16, "0000000000000000"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            e := &Ellipse{S: tc.bitLength}
            got := e.ConvertHashToBitString(tc.hash)
            if got != tc.want {
                t.Errorf("ConvertHashToBitString = %q, want %q", got, tc.want)
            }
        })
    }
}

func make200ByteAllFF() []byte {
    out := make([]byte, 200)
    for i := range out {
        out[i] = 0xFF
    }
    return out
}

func strings1600AllOnes() string {
    out := make([]byte, 1600)
    for i := range out {
        out[i] = '1'
    }
    return string(out)
}

// bs0001InputBitstring is the 1600-bit deterministic-RNG fixture from the
// frozen Genesis corpus (testvectors/v1_genesis.json, record bs-0001's
// "input_bitstring" field). Using a known-valid corpus vector guarantees
// that ExportPrivateKey's three preceding guards (AES.EncryptBitString,
// GenerateScalarFromBitString, ScalarToKeys) all succeed, so execution
// reaches the os.Create branch — which is the branch under test.
const bs0001InputBitstring = "0010010111000100101111000100101100000000101001110010101110010101010100010011000010000001001001111011011011000100010010001100000110001100001100101011000100000010110000111010011011110010101000010100101011111110110111101111101101101111101011110000110111000110101111000000110110100101100101011001100010010101101110011100001101100011001110110010101000111000000101111011011100100110101101001110110101010001100100100100000111011101011011010101101111110001011011111111111011010000110000111011010001111101100101101111000001010111101110111010101101001101000010001111010010100111000111101001001111111010010101111100100010110001111101111100100100001011100110101011111011101100110111100100110011100010110101011001110000011011110011100000000011111100110101101101010011110011001111001101110011001111011001111111100100011010010000001011000010001010010011010100000011111111000111111100100011001111000101101101110110100111111010010000011101101110001101110101110111101111001110101111110010011000110010101010110010001110011010010111000101100100001011100010101010111011101001111110011100000001101111111110001000001010100000010001000001010111011010001010000011011010100100110111111111111100110110110001011010001001010011001001100001001111101000111000010101000110001100011011111011100001000000111010011010100100101010100101100100111111100100100100101111101000000111111100000000100101100010011101101011011011100011011011011010010000110011001101001100110001000011101000101101011100010100111011100100110000000101101101110101111100101101011011100001000101101101000101111100000000010100010111010101011010110101000111011110001111"

// TestExportPrivateKey_FileCreateFailure_PrintsErrorAndReturns is the
// behavioural regression guard for KG-2 sibling-pattern adoption in
// ExportPrivateKey's os.Create error branch (KeyGeneration.go:548-551).
// Pre-fix the function called log.Fatal(err), terminating the test
// process. Post-fix the function prints
//
//     "Error: failed to create export file: <err>"
//
// to stdout and returns. This test reaches that branch by pre-creating
// a directory at the exact path os.Create would target, then captures
// stdout via the Go stdlib os.Pipe redirect idiom and asserts on the
// captured substring. If log.Fatal ever returns, the process dies before
// the assertion runs — so the assertion's mere execution is also part
// of the contract (process did not terminate).
//
// Stdout-capture pipe-redirect idiom (first use in this repo; precedent
// for future tests): save os.Stdout, swap in a pipe's write end, run the
// function, close the write end, drain the read end into a buffer, then
// restore os.Stdout via t.Cleanup (NOT bare defer — t.Cleanup runs even
// on t.Fatal). The error message is short, so a synchronous io.Copy
// after w.Close() stays well under the OS pipe buffer (~64 KiB).
func TestExportPrivateKey_FileCreateFailure_PrintsErrorAndReturns(t *testing.T) {
    // CWD-safe sandbox: run the export inside t.TempDir() so the
    // pre-created directory at the expected filename does not pollute
    // the repo root, and so any successful write (regression) lands in
    // a disposable location. Go 1.19 lacks t.Chdir; use os.Chdir with
    // a t.Cleanup-registered restore so CWD is reset even on t.Fatal.
    originalCwd, err := os.Getwd()
    if err != nil {
        t.Fatalf("failed to capture original cwd: %v", err)
    }
    sandbox := t.TempDir()
    if err := os.Chdir(sandbox); err != nil {
        t.Fatalf("failed to chdir to sandbox %q: %v", sandbox, err)
    }
    t.Cleanup(func() { _ = os.Chdir(originalCwd) })

    // Derive the public key the function would derive from the same
    // BitString, so we can pre-compute the exact filename os.Create
    // will target. Using DalosEllipse() (full curve params) is required
    // because GenerateScalarFromBitString validates the bit length
    // against e.S (1600 for the Genesis curve).
    e := DalosEllipse()
    scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
    if err != nil {
        t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
    }
    keyPair, err := e.ScalarToKeys(scalar)
    if err != nil {
        t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
    }
    expectedFilename := GenerateFilenameFromPublicKey(keyPair.PUBL)
    if expectedFilename == "" || expectedFilename == "InvalidPublicKey.txt" {
        t.Fatalf("unexpected derived filename %q from corpus public key %q", expectedFilename, keyPair.PUBL)
    }

    // Failure-trigger: create a directory at the exact path os.Create
    // will target. os.Create on a path that resolves to a directory
    // fails on every platform (POSIX: EISDIR; Windows: "Access is
    // denied."). This forces ExportPrivateKey down the post-T1.3 print
    // + return branch.
    triggerPath := filepath.Join(sandbox, expectedFilename)
    if err := os.MkdirAll(triggerPath, 0o755); err != nil {
        t.Fatalf("failed to pre-create trigger directory at %q: %v", triggerPath, err)
    }

    // Stdout-capture: swap os.Stdout for a pipe's write end. Restore
    // via t.Cleanup so a panic or t.Fatal inside the function under
    // test does not leave the test runner with a closed/leaked stdout.
    origStdout := os.Stdout
    r, w, err := os.Pipe()
    if err != nil {
        t.Fatalf("failed to create stdout-capture pipe: %v", err)
    }
    os.Stdout = w
    t.Cleanup(func() { os.Stdout = origStdout })

    // Invoke under capture. The password is irrelevant — the AES
    // encryption guard (line 520) succeeds for any non-empty password
    // against a valid bit string, and we never reach the file body.
    e.ExportPrivateKey(bs0001InputBitstring, "test-password")

    // Close the write end so the read end sees EOF, then drain.
    if err := w.Close(); err != nil {
        t.Fatalf("failed to close pipe write end: %v", err)
    }
    var captured bytes.Buffer
    if _, err := io.Copy(&captured, r); err != nil {
        t.Fatalf("failed to drain pipe read end: %v", err)
    }
    output := captured.String()

    // Substring is unique to T1.3's new error-message wording — it
    // cannot be produced by the AES, scalar, or keypair sibling guards
    // (which print "AES encryption failed", "invalid bit string", and
    // "failed to derive key pair" respectively). So matching this
    // substring proves the test reached line 548, not an earlier
    // branch.
    const wantSubstring = "Error: failed to create export file:"
    if !strings.Contains(output, wantSubstring) {
        t.Errorf("captured stdout missing expected error message\n  want substring: %q\n  got: %q", wantSubstring, output)
    }

    // Implicit-but-essential assertion: this line executing at all
    // proves ExportPrivateKey returned cleanly. Pre-T1.3 the function
    // would have called log.Fatal(err) and killed the test process
    // before this point.
}

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
func TestProcessIntegerFlag_InvalidInput_ReturnsEmptyString(t *testing.T) {
    e := DalosEllipse()
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
            got := e.ProcessIntegerFlag(tc.flagValue, tc.isBase10)
            if got != "" {
                t.Errorf("ProcessIntegerFlag(%q, %v) = %q, want empty string", tc.flagValue, tc.isBase10, got)
            }
        })
    }
}
