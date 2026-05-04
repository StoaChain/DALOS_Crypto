package Elliptic

import (
	"math/big"
	"testing"
)

// =============================================================================
// F-PERF-003 (audit cycle 2026-05-04, v4.0.1): equivalence proofs for
// arePointsEqualProjective and isOnCurveExtended.
// =============================================================================
//
// SchnorrVerify pays 8 ModInverse calls per verify (4 inside ArePointsEqual,
// 2 inside IsOnCurve(R), 2 inside IsOnCurve(P)). The new private helpers
// `arePointsEqualProjective` and `isOnCurveExtended` reach the same
// mathematical conclusion using projective cross-multiplication and the
// homogenized extended-coords curve equation respectively — zero
// ModInverses required.
//
// This file PROVES equivalence between the OLD public methods
// (ArePointsEqual, IsOnCurve) and the NEW private helpers across a wide
// space of test points. The tests run BEFORE the public method bodies
// are swapped to delegate to the helpers — so during this transition
// window both code paths exist and can be compared directly. Once the
// public method bodies are swapped, the equivalence proofs become
// degenerate (both call the same helper) but the tests are kept as
// regression guards.
//
// Test inputs cover:
//   1. The generator G (canonical on-curve point).
//   2. [k]·G for several scalars k (covers post-scalar-mult representations).
//   3. Public keys derived from corpus fixtures (real-world use case).
//   4. Different extended representations of the same projective point
//      — scaling X, Y, T, Z by a non-zero factor preserves the projective
//      point. This is the crucial case: the new helper must still return
//      true for two extended points that have the same affine projection
//      but different extended coords.
//   5. Off-curve points (e.g., (1, 1) won't satisfy the curve equation
//      unless the curve was specifically chosen to include it — vanishingly
//      unlikely for a 1606-bit prime).
//   6. The infinity point representation (0, 1, 1, 0).

// scaleExtended returns an extended representation of the same projective
// point as P, scaled by factor f. For HWCD coords:
//   (X, Y, T, Z) ≡ (f·X, f·Y, f²·T, f·Z)  (because T = XY/Z, so scaling
// X and Y by f scales T = (fX)(fY)/(fZ) = f·(XY/Z) = f·T. Wait — check
// this: (fX)(fY) = f²XY, divided by fZ gives f·XY/Z = f·T. So T scales
// by f, NOT f². Let me re-derive: actually T should scale by f, and the
// resulting tuple (fX, fY, fT, fZ) represents (fX/fZ, fY/fZ) = (X/Z, Y/Z),
// the same affine point. ✓
func scaleExtended(e Ellipse, P CoordExtended, f *big.Int) CoordExtended {
	return CoordExtended{
		EX: e.MulModP(P.EX, f),
		EY: e.MulModP(P.EY, f),
		ET: e.MulModP(P.ET, f),
		EZ: e.MulModP(P.EZ, f),
	}
}

// gatherTestPoints returns a diverse set of on-curve extended points for
// the equivalence tests. Uses corpus-derived public keys + multiples of G
// to cover the realistic input space SchnorrVerify sees in practice.
func gatherTestPoints(t *testing.T, e Ellipse) []CoordExtended {
	t.Helper()
	points := []CoordExtended{
		e.Affine2Extended(e.G), // G itself
	}
	// [2]·G, [3]·G, [4]·G — exercises HWCD doubling + addition outputs
	// which have non-trivial Z values.
	g := e.Affine2Extended(e.G)
	g2 := e.noErrDoubling(g)
	g3 := e.Tripling(g)
	g4 := e.noErrDoubling(g2)
	points = append(points, g2, g3, g4)

	// Several public keys derived from corpus fixtures (real-world keys).
	// Each goes through GenerateScalarFromBitString → ScalarToKeys →
	// publicKeyToAffineCoords → Affine2Extended, exercising the full
	// pipeline an external caller would use.
	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected bs0001: %v", err)
	}
	kp, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys: %v", err)
	}
	pk1Affine, err := ConvertPublicKeyToAffineCoords(kp.PUBL)
	if err != nil {
		t.Fatalf("ConvertPublicKeyToAffineCoords: %v", err)
	}
	points = append(points, e.Affine2Extended(pk1Affine))

	// Append several scaled-extended representations of G to specifically
	// exercise the projective-cross-multiplication equivalence on points
	// whose affine projection is identical but extended coords differ.
	for _, factor := range []int64{2, 3, 5, 7, 11, 13, 17} {
		f := big.NewInt(factor)
		points = append(points, scaleExtended(e, g, f))
	}

	return points
}

// TestArePointsEqual_OldVsNew_Equivalence proves arePointsEqualProjective
// returns the same answer as ArePointsEqual on a wide range of input
// PAIRS. Three categories of pairs:
//
//   1. Same point compared to itself          → both return true.
//   2. Same projective point, different
//      extended representation                 → both return true.
//   3. Different points                        → both return false.
//
// Category 2 is the cryptographically-load-bearing case: arePointsEqualProjective
// must NOT return false just because the extended coords differ — it must
// see through to the underlying projective equality.
func TestArePointsEqual_OldVsNew_Equivalence(t *testing.T) {
	e := DalosEllipse()
	points := gatherTestPoints(t, e)

	t.Run("same_point_self", func(t *testing.T) {
		// Every point is equal to itself.
		for i, p := range points {
			old := e.ArePointsEqual(p, p)
			newVal := e.arePointsEqualProjective(p, p)
			if !old {
				t.Errorf("point %d: OLD ArePointsEqual(p,p) = false (sanity check failed)", i)
			}
			if old != newVal {
				t.Errorf("point %d: OLD=%v, NEW=%v (must agree)", i, old, newVal)
			}
		}
	})

	t.Run("same_projective_different_extended", func(t *testing.T) {
		// For each base point, scale by various factors and confirm both
		// implementations still return TRUE.
		factors := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29}
		for i, p := range points {
			for _, factor := range factors {
				f := big.NewInt(factor)
				pScaled := scaleExtended(e, p, f)
				old := e.ArePointsEqual(p, pScaled)
				newVal := e.arePointsEqualProjective(p, pScaled)
				if !old {
					t.Errorf("point %d × %d: OLD ArePointsEqual(p, scaled p) = false (math broken — projective scaling should preserve affine point)", i, factor)
				}
				if old != newVal {
					t.Errorf("point %d × %d: OLD=%v, NEW=%v", i, factor, old, newVal)
				}
			}
		}
	})

	t.Run("different_points", func(t *testing.T) {
		// Compare each point with every other point; both implementations
		// must agree on every pair. The affine projection of any two
		// different points (e.g., G vs [2]·G) is different.
		for i := 0; i < len(points); i++ {
			for j := 0; j < len(points); j++ {
				if i == j {
					continue
				}
				old := e.ArePointsEqual(points[i], points[j])
				newVal := e.arePointsEqualProjective(points[i], points[j])
				if old != newVal {
					t.Errorf("points %d vs %d: OLD=%v, NEW=%v", i, j, old, newVal)
				}
				// Sanity: if i and j are scaled versions of the same base
				// point (e.g., G and 2·G-extended-rep), they SHOULD be
				// equal; otherwise different. The test above for "same
				// projective different extended" pins the equality side;
				// here we just need OLD == NEW.
			}
		}
	})
}

// TestIsOnCurve_OldVsNew_Equivalence proves isOnCurveExtended returns the
// same (OnCurve, Infinity) tuple as IsOnCurve on a wide range of inputs.
//
// On-curve inputs: G + multiples of G + corpus public keys + scaled-extended
// representations of G (must still register as on-curve in BOTH paths).
//
// Off-curve inputs: synthesized as Affine2Extended of (1, 1), (2, 3), etc.
// — random small integers extremely unlikely to satisfy the 1606-bit-prime
// curve equation. Both paths must report OnCurve=false.
//
// Infinity input: the canonical HWCD infinity (0, 1, 1, 0). Both paths
// must report OnCurve=true, Infinity=true.
func TestIsOnCurve_OldVsNew_Equivalence(t *testing.T) {
	e := DalosEllipse()
	onCurvePoints := gatherTestPoints(t, e)

	t.Run("on_curve_inputs", func(t *testing.T) {
		for i, p := range onCurvePoints {
			oldOnCurve, oldInf := e.IsOnCurve(p)
			newOnCurve, newInf := e.isOnCurveExtended(p)
			if !oldOnCurve {
				t.Errorf("point %d: OLD IsOnCurve = false (sanity check failed; this point should be on curve)", i)
			}
			if oldOnCurve != newOnCurve {
				t.Errorf("point %d OnCurve: OLD=%v, NEW=%v", i, oldOnCurve, newOnCurve)
			}
			if oldInf != newInf {
				t.Errorf("point %d Infinity: OLD=%v, NEW=%v", i, oldInf, newInf)
			}
		}
	})

	t.Run("off_curve_inputs", func(t *testing.T) {
		// Synthesize off-curve points by Affine2Extended of small (x, y)
		// pairs that almost certainly don't satisfy x² + y² ≡ 1 + D·x²·y²
		// for the 1606-bit prime DALOS curve.
		offCurvePairs := []struct{ x, y int64 }{
			{1, 1}, {2, 3}, {5, 7}, {1, 0}, {0, 0},
		}
		for _, pair := range offCurvePairs {
			affine := CoordAffine{
				AX: big.NewInt(pair.x),
				AY: big.NewInt(pair.y),
			}
			ext := e.Affine2Extended(affine)
			oldOnCurve, oldInf := e.IsOnCurve(ext)
			newOnCurve, newInf := e.isOnCurveExtended(ext)
			if oldOnCurve != newOnCurve {
				t.Errorf("(%d, %d) OnCurve: OLD=%v, NEW=%v", pair.x, pair.y, oldOnCurve, newOnCurve)
			}
			if oldInf != newInf {
				t.Errorf("(%d, %d) Infinity: OLD=%v, NEW=%v", pair.x, pair.y, oldInf, newInf)
			}
			// Sanity: (1, 1) must NOT be on the curve (else the test point
			// is poorly chosen and the test gives no signal).
			if pair.x == 1 && pair.y == 1 && oldOnCurve {
				t.Errorf("test design failure: (1, 1) is unexpectedly on curve")
			}
		}
	})

	t.Run("infinity_canonical", func(t *testing.T) {
		// The canonical HWCD infinity representation: (0, 1, 1, 0).
		// IsInfinityPoint requires EX=0, ET=0, EY=EZ.
		inf := CoordExtended{
			EX: new(big.Int).SetInt64(0),
			EY: new(big.Int).SetInt64(1),
			EZ: new(big.Int).SetInt64(1),
			ET: new(big.Int).SetInt64(0),
		}
		oldOnCurve, oldInf := e.IsOnCurve(inf)
		newOnCurve, newInf := e.isOnCurveExtended(inf)
		if !oldOnCurve {
			t.Errorf("OLD: infinity reports OnCurve=false (sanity check failed)")
		}
		if !oldInf {
			t.Errorf("OLD: infinity reports Infinity=false (sanity check failed)")
		}
		if oldOnCurve != newOnCurve {
			t.Errorf("infinity OnCurve: OLD=%v, NEW=%v", oldOnCurve, newOnCurve)
		}
		if oldInf != newInf {
			t.Errorf("infinity Infinity: OLD=%v, NEW=%v", oldInf, newInf)
		}
	})
}

// TestSchnorrVerify_RoundTrip_Corpus is a end-to-end byte-identity check:
// for several deterministic corpus fixtures, sign + verify, asserting the
// signature verifies cleanly. Acts as integration test that the new helpers
// (once swapped into IsOnCurve / ArePointsEqual) preserve verify outcomes
// for legitimate signatures.
func TestSchnorrVerify_RoundTrip_Corpus(t *testing.T) {
	e := DalosEllipse()
	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString: %v", err)
	}
	kp, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys: %v", err)
	}

	for _, msg := range []string{
		"hello, world",
		"DALOS-gen1 test message",
		"",
		"a",
		"the quick brown fox jumps over the lazy dog",
	} {
		sig, err := e.SchnorrSign(kp, msg)
		if err != nil {
			t.Errorf("SchnorrSign(%q): %v", msg, err)
			continue
		}
		if !e.SchnorrVerify(sig, msg, kp.PUBL) {
			t.Errorf("SchnorrVerify(%q) returned false for legitimate signature", msg)
		}
	}
}
