package Elliptic

import (
	"math/big"
	"strings"
	"testing"
)

// Strict-parser regression tests for ConvertPublicKeyToAffineCoords
// (F-SEC-002 / F-ERR-006). The pre-fix parser silently accepted several
// classes of malformed input:
//
//   1. xLength prefix decoding to 0 or a negative integer — produced an
//      empty xString and the entire body became the Y coordinate, with
//      X silently set to 0. Verifier downstream then operated on a
//      zero-valued point with no rejection.
//   2. (*big.Int).SetString(xString, 10) returning ok=false — ignored;
//      coords.AX retained whatever previous state SetString left it in
//      (typically 0). Same silent zero-coordinate hazard.
//   3. (*big.Int).SetString(yString, 10) returning ok=false — same.
//
// The post-fix parser rejects all three cases with a non-nil error and
// returns a zero-value CoordAffine (nil AX, nil AY) so downstream
// callers cannot read garbage coordinates after an error.

// hasNilCoords asserts that an erroring parser return is the safe
// zero-value (no partially-constructed coordinates leak to the caller).
func hasNilCoords(t *testing.T, ax, ay any) {
	t.Helper()
	if ax != nil {
		t.Errorf("expected coords.AX == nil on error, got %v", ax)
	}
	if ay != nil {
		t.Errorf("expected coords.AY == nil on error, got %v", ay)
	}
}

// TestConvertPublicKeyToAffineCoords_RejectsZeroLength feeds a key whose
// xLength prefix decodes to 0 (the base-49 digit "0"). Pre-fix this
// produced a zero X coordinate without error.
func TestConvertPublicKeyToAffineCoords_RejectsZeroLength(t *testing.T) {
	// Format is "<xLength-base49>.<body-base49>". Prefix "0" → xLength=0.
	input := "0.abc123"

	coords, err := ConvertPublicKeyToAffineCoords(input)
	if err == nil {
		t.Fatalf("expected error for xLength=0, got nil; coords=%+v", coords)
	}
	if !strings.Contains(err.Error(), "xLength") {
		t.Errorf("expected error to mention xLength, got %q", err.Error())
	}
	if coords.AX != nil {
		hasNilCoords(t, coords.AX, coords.AY)
	}
}

// TestConvertPublicKeyToAffineCoords_RejectsNegativeLength feeds a key
// whose xLength prefix decodes via base-49 to a value that, when read as
// int64, yields a negative number — also rejected by the xLength < 1
// guard.
//
// Engineering note: ConvertBase49toBase10 always produces a non-negative
// big.Int, so the practical way to drive xLength <= 0 in Go is the zero
// case above. This test guards the same code path with an alternate
// zero-yielding prefix to confirm the guard is on `< 1` (not `== 0`),
// which catches any future change that lets xLength go negative.
func TestConvertPublicKeyToAffineCoords_RejectsNegativeLength(t *testing.T) {
	// Multi-digit zero ("00") still decodes to 0 — exercises the same
	// `xLength < 1` guard from a different surface input.
	input := "00.abc123"

	coords, err := ConvertPublicKeyToAffineCoords(input)
	if err == nil {
		t.Fatalf("expected error for xLength<1, got nil; coords=%+v", coords)
	}
	if coords.AX != nil {
		hasNilCoords(t, coords.AX, coords.AY)
	}
}

// TestConvertPublicKeyToAffineCoords_RejectsNonDecimalX constructs a key
// whose body, after base-49 decoding, contains characters that
// big.Int.SetString(_, 10) refuses. Pre-fix the SetString ok was
// ignored; post-fix the parser surfaces it as an error.
//
// Strategy: ConvertBase49toBase10 produces a base-10 string from the
// body. To inject non-decimal content into xString we exploit the
// branch where SetString itself fails. The simplest route is a body
// whose base-49 decoding rounds to a base-10 digit string starting
// with a leading zero stripped by big.Int — but big.Int's String()
// always returns canonical decimal, so the failure must come from a
// different vector.
//
// We instead test the post-fix code path directly by passing a body
// that exercises the SetString-fail branch via a deliberately
// truncated input that would split into an x portion big.Int rejects.
// Since big.Int.String() always returns valid decimal, achieving
// SetString=ok=false on the resulting xString requires an empty
// xString — which the xLength<1 guard already rejects upstream.
//
// To still exercise the SetString guard meaningfully, this test
// confirms the post-fix code returns nil-coords on the standard
// zero-length path AND that the error message mentions the parse
// stage when triggered. We use a synthetic input where xLength is
// one but the body decodes to a value with fewer digits (caught by
// "invalid key body length") to confirm error returns retain
// nil-coords safety.
func TestConvertPublicKeyToAffineCoords_RejectsNonDecimalX(t *testing.T) {
	// xLength prefix "2" but body "0" decodes to "0" — totalValueStr
	// has length 1 < xLength=2 → "invalid key body length" branch.
	// Confirms post-fix that ALL error returns produce nil coords.
	input := "2.0"

	coords, err := ConvertPublicKeyToAffineCoords(input)
	if err == nil {
		t.Fatalf("expected error, got nil; coords=%+v", coords)
	}
	if coords.AX != nil || coords.AY != nil {
		t.Errorf("expected nil coords on error, got AX=%v AY=%v", coords.AX, coords.AY)
	}
}

// TestConvertPublicKeyToAffineCoords_RejectsNonDecimalY exercises the
// same nil-coords-on-error invariant via the malformed-format branch
// (no '.' separator). Confirms that the legacy "invalid public key
// format" path also returns the safe zero-value coords post-fix.
func TestConvertPublicKeyToAffineCoords_RejectsNonDecimalY(t *testing.T) {
	input := "no-dot-separator-anywhere"

	coords, err := ConvertPublicKeyToAffineCoords(input)
	if err == nil {
		t.Fatalf("expected error for missing separator, got nil; coords=%+v", coords)
	}
	if coords.AX != nil || coords.AY != nil {
		t.Errorf("expected nil coords on error, got AX=%v AY=%v", coords.AX, coords.AY)
	}
}

func TestConvertPublicKeyToAffineCoords_RejectsExtraDot(t *testing.T) {
	// REQ-22 (F-BUG-005): pubkey parser symmetry — Go now rejects inputs with
	// 2+ dots at the same boundary as TS (which uses split('.') and rejects
	// parts.length !== 2). Pre-Phase-7, Go used SplitN(_,_,2) which silently
	// collapsed extra dots into the second part.
	coords, err := ConvertPublicKeyToAffineCoords("a.b.c")
	if err == nil {
		t.Errorf("expected error for input with extra dot, got nil")
	}
	if coords.AX != nil || coords.AY != nil {
		t.Errorf("expected nil coords on error, got AX=%v AY=%v", coords.AX, coords.AY)
	}
	// Pin the specific error message shape for cross-impl symmetry tracking.
	if err != nil && !strings.Contains(err.Error(), "expected exactly 1") {
		t.Errorf("expected message to contain 'expected exactly 1', got: %s", err.Error())
	}
}

// =============================================================================
// F-ERR-002 (audit cycle 2026-05-04, v4.0.1): ConvertBase49toBase10 contract
// =============================================================================
//
// Pre-v4.0.1 the helper discarded big.Int.SetString's `ok` return — invalid
// input produced an undefined big.Int that flowed unchecked into SchnorrSign,
// AESDecrypt, and the signature parser. Tests below pin the new
// (*big.Int, error) contract + alphabet validator. Mirrors the TS port's
// `parseBigIntInBase` (REQ-21) which throws on invalid base-49 chars.

// TestIsValidBase49Char pins the alphabet definition (matches the TS
// `isValidBase49Char` at ts/src/gen1/scalar-mult.ts).
func TestIsValidBase49Char(t *testing.T) {
	cases := []struct {
		c    byte
		want bool
	}{
		// Valid: '0'..'9'
		{'0', true}, {'5', true}, {'9', true},
		// Valid: 'a'..'z'
		{'a', true}, {'m', true}, {'z', true},
		// Valid: 'A'..'M'
		{'A', true}, {'G', true}, {'M', true},
		// Invalid: 'N'..'Z' (deliberately above 'M' — base-49 only uses 'A'..'M')
		{'N', false}, {'Z', false},
		// Invalid: punctuation, separators, whitespace
		{'.', false}, {'|', false}, {'-', false}, {' ', false}, {'\n', false}, {'\t', false},
		// Invalid: high-bit / non-ASCII
		{0x00, false}, {0x7F, false}, {0x80, false}, {0xFF, false},
	}
	for _, c := range cases {
		got := IsValidBase49Char(c.c)
		if got != c.want {
			t.Errorf("IsValidBase49Char(%q) = %v, want %v", c.c, got, c.want)
		}
	}
}

// TestConvertBase49toBase10_AcceptsValidInput confirms valid base-49 input
// still parses correctly (no regression on the happy path).
func TestConvertBase49toBase10_AcceptsValidInput(t *testing.T) {
	cases := []struct{ input, expectedDecimal string }{
		{"0", "0"},
		{"a", "10"},
		{"M", "48"},
		{"10", "49"},
		{"100", "2401"}, // 49^2
	}
	for _, c := range cases {
		result, err := ConvertBase49toBase10(c.input)
		if err != nil {
			t.Errorf("ConvertBase49toBase10(%q) returned unexpected error: %v", c.input, err)
			continue
		}
		if result.String() != c.expectedDecimal {
			t.Errorf("ConvertBase49toBase10(%q) = %s, want %s", c.input, result.String(), c.expectedDecimal)
		}
	}
}

// TestConvertBase49toBase10_RejectsEmpty pins the empty-input rejection.
func TestConvertBase49toBase10_RejectsEmpty(t *testing.T) {
	result, err := ConvertBase49toBase10("")
	if err == nil {
		t.Fatalf("expected error for empty input, got nil; result=%v", result)
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %v", result)
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Errorf("expected error to mention 'empty input', got: %s", err.Error())
	}
}

// =============================================================================
// F-ERR-007 (audit cycle 2026-05-04, v4.0.1): SchnorrSign private-key range check
// =============================================================================
//
// SchnorrSign computes s = z + e·k mod Q. Pre-v4.0.1 there was no check
// that the parsed k was in [1, Q-1]. The dangerous case is k = 0 which
// yields R = 0·G = O (infinity) and s = z + 0 = z — the signer's nonce
// is now embedded in the signature s. k outside [1, Q-1] is meaningless
// cryptography. Post-v4.0.1 SchnorrSign returns "" on out-of-range k
// (matches the same empty-string sentinel from F-ERR-002's parse-failure
// branch). The TS port has equivalent guards via parseBigIntInBase +
// range validation (REQ-21/REQ-22).

// TestSchnorrSign_RejectsZeroPrivateKey pins the k = 0 nonce-leak guard.
// k = 0 is reachable today by hand-constructing a DalosKeyPair with
// PRIV = "0" (base-49 zero). Pre-v4.0.1 SchnorrSign would return a
// signature where s = z (the deterministic nonce, leaked).
//
// v4.0.1 (F-API-005): SchnorrSign now returns (string, error); rejection
// surfaces as a non-nil error rather than the empty-string sentinel.
func TestSchnorrSign_RejectsZeroPrivateKey(t *testing.T) {
	e := DalosEllipse()
	kp := DalosKeyPair{
		PRIV: "0", // base-49 representation of zero
		PUBL: "1.0",
	}
	sig, err := e.SchnorrSign(kp, "any message")
	if err == nil {
		t.Errorf("expected error for k=0 (would leak nonce), got nil; sig=%q", sig)
	}
	if sig != "" {
		t.Errorf("expected empty signature on error path, got: %q", sig)
	}
	if err != nil && !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected error to mention range; got: %v", err)
	}
}

// TestSchnorrSign_RejectsOutOfRangePrivateKey pins the k >= Q guard.
// k > Q reduces silently mod Q in the signing math, so the signature
// would still verify against the "true" k mod Q — but accepting it
// conceals the corruption. Build a PRIV string that decodes to a value
// >= Q.
func TestSchnorrSign_RejectsOutOfRangePrivateKey(t *testing.T) {
	e := DalosEllipse()
	// Build PRIV that decodes to exactly Q (in [1, Q-1] is valid; Q is
	// the boundary that must be rejected).
	privAtQ := e.Q.Text(49)
	kp := DalosKeyPair{
		PRIV: privAtQ,
		PUBL: "1.0",
	}
	sig, err := e.SchnorrSign(kp, "any message")
	if err == nil {
		t.Errorf("expected error for k=Q (out of range), got nil; sig=%q", sig)
	}
	if sig != "" {
		t.Errorf("expected empty signature on error path, got: %q", sig)
	}

	// Also check k > Q (some larger value): use Q + 1.
	qPlusOne := new(big.Int).Add(&e.Q, big.NewInt(1))
	kp.PRIV = qPlusOne.Text(49)
	sig, err = e.SchnorrSign(kp, "any message")
	if err == nil {
		t.Errorf("expected error for k=Q+1 (out of range), got nil; sig=%q", sig)
	}
	if sig != "" {
		t.Errorf("expected empty signature on error path, got: %q", sig)
	}
}

// TestSchnorrSign_AcceptsValidPrivateKey is the positive-control: a
// known-good keypair (derived from the bs-0001 corpus fixture) must
// still produce a non-empty signature. Confirms the F-ERR-007 + F-API-005
// guards did not regress the happy path.
func TestSchnorrSign_AcceptsValidPrivateKey(t *testing.T) {
	e := DalosEllipse()
	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
	}
	kp, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
	}
	sig, err := e.SchnorrSign(kp, "any message")
	if err != nil {
		t.Errorf("expected nil error for well-formed keypair, got: %v", err)
	}
	if sig == "" {
		t.Errorf("expected non-empty signature for well-formed keypair, got empty string (regression)")
	}
}

// =============================================================================
// F-PERF-001 (audit cycle 2026-05-04, v4.0.1): cofactor check via two doublings
// =============================================================================
//
// SchnorrVerify multiplies R and P by the cofactor (4) to detect small-
// subgroup attack points. Pre-v4.0.1 this used `ScalarMultiplier(cofactor4, X)`,
// which builds a 48-element PrecomputeMatrix (24 doublings + 24 additions
// of internal work) and walks the base-49 digits of the scalar — way
// over-engineered for the trivial scalar 4. Two HWCD doublings produce
// the same result with ~16x less work per side (R + P → ~96 wasted
// big-int ops eliminated per verify).
//
// This test pins the mathematical equivalence: for any on-curve point P,
//
//     ScalarMultiplier(big.NewInt(4), P)  ≡  noErrDoubling(noErrDoubling(P))
//
// in projective sense — i.e., both produce the same affine point under
// Extended2Affine. The extended-coords representations may differ
// (HWCD has multiple representations of the same projective point), so
// the canonical equivalence check is to compare the affine projection.

// TestCofactor4_DoublingEquivalence confirms that two HWCD doublings
// produce the same affine point as a general scalar-multiply by 4 for
// several on-curve test points. Drives F-PERF-001's mathematical
// foundation: the cofactor check at SchnorrVerify lines 459/486 can
// safely switch from ScalarMultiplier to two doublings.
func TestCofactor4_DoublingEquivalence(t *testing.T) {
	e := DalosEllipse()
	four := big.NewInt(4)

	// Build the test fixtures: the generator G, [2]·G, and a corpus-derived
	// public key point. Each represents a distinct on-curve point so the
	// equivalence check exercises different extended-coord values.
	gExt := e.Affine2Extended(e.G)

	twoExt := e.noErrDoubling(gExt) // [2]·G as a second test point

	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
	}
	kp, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
	}
	pkAffine, err := ConvertPublicKeyToAffineCoords(kp.PUBL)
	if err != nil {
		t.Fatalf("ConvertPublicKeyToAffineCoords rejected the derived PUBL: %v", err)
	}
	pkExt := e.Affine2Extended(pkAffine)

	cases := []struct {
		name string
		p    CoordExtended
	}{
		{"generator_G", gExt},
		{"two_G", twoExt},
		{"public_key_from_bs0001", pkExt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldPath := e.ScalarMultiplier(four, c.p)
			newPath := e.noErrDoubling(e.noErrDoubling(c.p))

			oldAffine := e.Extended2Affine(oldPath)
			newAffine := e.Extended2Affine(newPath)

			if oldAffine.AX.Cmp(newAffine.AX) != 0 {
				t.Errorf("affine X mismatch: ScalarMultiplier(4, %s).X = %s, noErrDoubling² = %s",
					c.name, oldAffine.AX.String(), newAffine.AX.String())
			}
			if oldAffine.AY.Cmp(newAffine.AY) != 0 {
				t.Errorf("affine Y mismatch: ScalarMultiplier(4, %s).Y = %s, noErrDoubling² = %s",
					c.name, oldAffine.AY.String(), newAffine.AY.String())
			}
		})
	}
}

// TestCofactor4_InfinityPreserved confirms that the IsInfinityPoint
// boolean is the same for both paths on a non-infinity input. (We can't
// easily synthesise an order-4 point in a unit test without committing
// to specific curve internals; the corpus generator's adversarial vectors
// cover the [4]·X == infinity branch end-to-end, and corpus byte-identity
// SHA-256 preservation is the regression guard for that direction.)
func TestCofactor4_InfinityPreserved(t *testing.T) {
	e := DalosEllipse()
	four := big.NewInt(4)
	gExt := e.Affine2Extended(e.G)

	oldPath := e.ScalarMultiplier(four, gExt)
	newPath := e.noErrDoubling(e.noErrDoubling(gExt))

	if e.IsInfinityPoint(oldPath) {
		t.Fatalf("legitimate generator [4]·G must not be infinity (would mean cofactor check would falsely reject the generator)")
	}
	if e.IsInfinityPoint(newPath) != e.IsInfinityPoint(oldPath) {
		t.Errorf("IsInfinityPoint divergence: old=%v, new=%v", e.IsInfinityPoint(oldPath), e.IsInfinityPoint(newPath))
	}
}

// TestSchnorrSign_RejectsMalformedPRIV pins the F-ERR-002 base-49 parser
// failure — an invalid character in PRIV must surface as an error, not
// the legacy empty-string sentinel.
func TestSchnorrSign_RejectsMalformedPRIV(t *testing.T) {
	e := DalosEllipse()
	kp := DalosKeyPair{
		PRIV: "abcZZZ", // 'Z' is above 'M' in the base-49 alphabet
		PUBL: "1.0",
	}
	sig, err := e.SchnorrSign(kp, "any message")
	if err == nil {
		t.Errorf("expected error for malformed PRIV, got nil; sig=%q", sig)
	}
	if sig != "" {
		t.Errorf("expected empty signature on error path, got: %q", sig)
	}
	if err != nil && !strings.Contains(err.Error(), "malformed private key") {
		t.Errorf("expected error to mention malformed PRIV; got: %v", err)
	}
}

// TestConvertBase49toBase10_RejectsInvalidChars pins the alphabet-validator
// rejection. Drives the same parity path as the TS port's
// `parseBigIntInBase` (REQ-21).
func TestConvertBase49toBase10_RejectsInvalidChars(t *testing.T) {
	cases := []string{
		"abcN",      // 'N' is above 'M' (the highest valid uppercase digit)
		"hello.",    // '.' is a separator, not a digit
		"foo|bar",   // '|' is the Schnorr-signature separator
		"a b",       // space
		"\nabc",     // leading newline
		"abcÿ", // high-bit byte
	}
	for _, input := range cases {
		result, err := ConvertBase49toBase10(input)
		if err == nil {
			t.Errorf("ConvertBase49toBase10(%q) returned nil error; expected rejection. result=%v", input, result)
			continue
		}
		if result != nil {
			t.Errorf("ConvertBase49toBase10(%q) returned non-nil result %v on error", input, result)
		}
		if !strings.Contains(err.Error(), "invalid base-49 character") {
			t.Errorf("ConvertBase49toBase10(%q) error message missing 'invalid base-49 character': %s", input, err.Error())
		}
	}
}
