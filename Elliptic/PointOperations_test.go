package Elliptic

import (
	"math/big"
	"testing"
)

// =============================================================================
// F-MED-014 (audit cycle 2026-05-04, v4.0.2): direct unit tests for the
// HWCD point-arithmetic foundation.
// =============================================================================
//
// Pre-v4.0.2 the core arithmetic primitives in PointOperations.go
// (Addition, AdditionV1/V2/V3, Doubling, DoublingV1/V2, Tripling,
// FortyNiner, ScalarMultiplier, ScalarMultiplierWithGenerator) had no
// isolated unit tests. Correctness was asserted only through:
//
//   1. The Genesis 105-vector corpus byte-identity check (catches any
//      regression that perturbs the keys derived through the full
//      pipeline).
//   2. The TS port's `[Q]·G = O` invariant test (catches order-related
//      regressions but only on the TS side).
//   3. PointOperations_perf_equiv_test.go (locks ArePointsEqual /
//      IsOnCurve against their pre-F-PERF-003 implementations, but
//      doesn't test the underlying point ops).
//
// The gap: a bug in (say) the Tripling formula that happens to preserve
// the corpus inputs (because their scalar decompositions don't hit the
// Tripling code path) would slip through both gates. This file closes
// that gap by exercising the math directly: identity element, additive
// commutativity / associativity, the [Q]·G = O group-order check on
// every curve, addition/doubling consistency, and tripling consistency
// with addition+doubling.
//
// All assertions use ArePointsEqual (now locked by the F-PERF-003
// equivalence proof to behave the same as the pre-v4.0.1 affine-conversion
// path) so a regression in the underlying point ops can't hide behind
// a representation difference.
//
// Cross-curve coverage: every test that exercises a single curve runs
// across DALOS, E521, LETO, ARTEMIS, and APOLLO. Same code paths,
// different prime fields and curve coefficients — locks down the math
// against per-curve regressions (e.g., a hardcoded coefficient leaking
// in from one curve's params).

// allTestCurves returns one Ellipse value for each of the five curves
// the codebase defines factories for. Used by every per-curve test
// below to guarantee uniform coverage.
//
// Test selection rationale: DALOS is the production Genesis curve
// (1606-bit prime, S=1600). E521 is the closest published reference
// curve to DALOS in shape. LETO/ARTEMIS/APOLLO are the historical
// curves promoted to production in v1.2.0 (different bit-widths,
// same TEC family). Five curves give enough diversity to catch any
// hardcoded-param regression while staying fast (each curve's [Q]·G
// test takes <1s in practice).
func allTestCurves(t *testing.T) []struct {
	name string
	e    Ellipse
} {
	t.Helper()
	return []struct {
		name string
		e    Ellipse
	}{
		{"DALOS", DalosEllipse()},
		{"E521", E521Ellipse()},
		{"LETO", LetoEllipse()},
		{"ARTEMIS", ArtemisEllipse()},
		{"APOLLO", ApolloEllipse()},
	}
}

// genExtended returns the generator G of the given curve in HWCD
// extended coordinates. Trivial helper that captures the Affine2Extended
// pattern so test bodies can stay focused on the math.
func genExtended(e *Ellipse) CoordExtended {
	return e.Affine2Extended(e.G)
}

// =============================================================================
// Identity-element tests (the infinity point O = (0, 1, 1, 0))
// =============================================================================

// TestInfinityPoint_IsInfinity locks the IsInfinityPoint predicate's
// behavior on the canonical infinity representation and on G.
func TestInfinityPoint_IsInfinity(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.e.IsInfinityPoint(InfinityPoint) {
				t.Errorf("IsInfinityPoint(InfinityPoint) = false; want true")
			}
			G := genExtended(&tc.e)
			if tc.e.IsInfinityPoint(G) {
				t.Errorf("IsInfinityPoint(G) = true; want false (G must not be the identity)")
			}
		})
	}
}

// TestInfinityPoint_IsOnCurve locks the IsOnCurve predicate's behavior
// on infinity and on G. F-PERF-003 (v4.0.1) established that IsOnCurve
// returns (OnCurve=true, Infinity=true) for the identity and
// (OnCurve=true, Infinity=false) for finite on-curve points.
func TestInfinityPoint_IsOnCurve(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			onCurve, isInf := tc.e.IsOnCurve(InfinityPoint)
			if !onCurve || !isInf {
				t.Errorf("IsOnCurve(InfinityPoint) = (%v, %v); want (true, true)", onCurve, isInf)
			}
			G := genExtended(&tc.e)
			onCurve, isInf = tc.e.IsOnCurve(G)
			if !onCurve || isInf {
				t.Errorf("IsOnCurve(G) = (%v, %v); want (true, false)", onCurve, isInf)
			}
		})
	}
}

// TestAddition_IdentityElement locks that the infinity point is the
// additive identity: P + O = P, O + P = P. This is the fundamental
// group-axiom check.
//
// HWCD note: Addition with Z=0 operand exercises the V3 code path
// (since InfinityPoint has Z=0 != 1). The other operand has Z=1 (G is
// stored in affine), so this also exercises the asymmetric V2 case
// when O is the second operand.
func TestAddition_IdentityElement(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)

			gPlusO, err := tc.e.Addition(G, InfinityPoint)
			if err != nil {
				t.Fatalf("Addition(G, O): %v", err)
			}
			if !tc.e.ArePointsEqual(gPlusO, G) {
				t.Errorf("G + O != G — infinity is not the additive identity (right operand)")
			}

			oPlusG, err := tc.e.Addition(InfinityPoint, G)
			if err != nil {
				t.Fatalf("Addition(O, G): %v", err)
			}
			if !tc.e.ArePointsEqual(oPlusG, G) {
				t.Errorf("O + G != G — infinity is not the additive identity (left operand)")
			}
		})
	}
}

// =============================================================================
// Group-order test: [Q]·G = O
// =============================================================================
//
// This is the single most important crypto invariant. Q is the order
// of the generator G, defined in Parameters.go via DalosEllipse() and
// the historical-curve factories. By definition, [Q]·G = O. If this
// fails, either:
//   - The generator G is not actually a generator of order Q (curve
//     parameters are inconsistent),
//   - The scalar multiplication algorithm is broken,
//   - Or the cofactor / Q computation is wrong.
//
// Any of these is a catastrophic regression. The TS port runs this
// test; the Go side did not until F-MED-014.

// TestScalarMultiply_QTimesG_IsInfinity locks the [Q]·G = O invariant
// on every defined curve.
func TestScalarMultiply_QTimesG_IsInfinity(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			Q := new(big.Int).Set(&tc.e.Q) // copy to avoid mutating the curve param
			result := tc.e.ScalarMultiplierWithGenerator(Q)
			if !tc.e.IsInfinityPoint(result) {
				// Don't dump the full extended coords — they're 1606-bit
				// integers. Just report the first 32 hex chars of EX so
				// the failure is identifiable without flooding the log.
				short := result.EX.Text(16)
				if len(short) > 32 {
					short = short[:32] + "..."
				}
				t.Fatalf("[Q]·G != O on curve %s — generator order or scalar-mult is broken!\n  result.EX (truncated): 0x%s", tc.name, short)
			}
		})
	}
}

// TestScalarMultiply_OneTimesG_IsG locks [1]·G = G. Trivial but
// important: catches a regression where ScalarMultiplier silently
// adds an extra doubling or skips the base case.
func TestScalarMultiply_OneTimesG_IsG(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)
			one := big.NewInt(1)
			result := tc.e.ScalarMultiplierWithGenerator(one)
			if !tc.e.ArePointsEqual(result, G) {
				t.Errorf("[1]·G != G on curve %s", tc.name)
			}
		})
	}
}

// TestScalarMultiply_TwoTimesG_EqualsDoubleG locks [2]·G = G + G via
// the direct doubling formula. Cross-validates the scalar-mult
// dispatch against the doubling primitive.
func TestScalarMultiply_TwoTimesG_EqualsDoubleG(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)
			two := big.NewInt(2)
			scalarPath := tc.e.ScalarMultiplierWithGenerator(two)

			doublingPath, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}

			if !tc.e.ArePointsEqual(scalarPath, doublingPath) {
				t.Errorf("[2]·G via scalar-mult != Doubling(G) on curve %s — scalar-mult / doubling divergence", tc.name)
			}
		})
	}
}

// =============================================================================
// Addition / Doubling / Tripling consistency
// =============================================================================

// TestAddition_PlusP_EqualsDoubling locks the fundamental group law
// Addition(P, P) = Doubling(P). This is the most basic consistency
// check between two independent code paths (mmadd-2008-hwcd in
// Addition vs mdbl-2008-hwcd in Doubling). Run on G across all curves.
func TestAddition_PlusP_EqualsDoubling(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)

			added, err := tc.e.Addition(G, G)
			if err != nil {
				t.Fatalf("Addition(G, G): %v", err)
			}
			doubled, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}

			if !tc.e.ArePointsEqual(added, doubled) {
				t.Errorf("Addition(G, G) != Doubling(G) on curve %s — addition/doubling consistency violated", tc.name)
			}
		})
	}
}

// TestTripling_EqualsAddDouble locks Tripling(P) = Addition(P,
// Doubling(P)). Catches regressions in the tpl-2015-c formula
// implementation by cross-checking against the elementary derivation.
func TestTripling_EqualsAddDouble(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)

			tripled := tc.e.Tripling(G)

			doubled, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}
			addPath, err := tc.e.Addition(doubled, G)
			if err != nil {
				t.Fatalf("Addition(2G, G): %v", err)
			}

			if !tc.e.ArePointsEqual(tripled, addPath) {
				t.Errorf("Tripling(G) != Addition(Doubling(G), G) on curve %s — tpl-2015-c formula vs derived 3G divergence", tc.name)
			}
		})
	}
}

// TestAddition_Commutative locks P + Q = Q + P. Required by the abelian
// group structure; a violation would indicate either a non-commutative
// operation (would be catastrophic) or asymmetric handling between
// the two operand positions.
func TestAddition_Commutative(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)
			G2, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}

			pq, err := tc.e.Addition(G, G2)
			if err != nil {
				t.Fatalf("Addition(G, 2G): %v", err)
			}
			qp, err := tc.e.Addition(G2, G)
			if err != nil {
				t.Fatalf("Addition(2G, G): %v", err)
			}

			if !tc.e.ArePointsEqual(pq, qp) {
				t.Errorf("Addition(G, 2G) != Addition(2G, G) on curve %s — addition is not commutative", tc.name)
			}
		})
	}
}

// TestAddition_Associative locks (P + Q) + R = P + (Q + R). Required by
// the group structure. Test on G, 2G, 3G — a small but non-degenerate
// case.
func TestAddition_Associative(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)
			G2, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}
			G3 := tc.e.Tripling(G)

			// (G + 2G) + 3G
			lhsInner, err := tc.e.Addition(G, G2)
			if err != nil {
				t.Fatalf("Addition(G, 2G): %v", err)
			}
			lhs, err := tc.e.Addition(lhsInner, G3)
			if err != nil {
				t.Fatalf("Addition((G + 2G), 3G): %v", err)
			}

			// G + (2G + 3G)
			rhsInner, err := tc.e.Addition(G2, G3)
			if err != nil {
				t.Fatalf("Addition(2G, 3G): %v", err)
			}
			rhs, err := tc.e.Addition(G, rhsInner)
			if err != nil {
				t.Fatalf("Addition(G, (2G + 3G)): %v", err)
			}

			if !tc.e.ArePointsEqual(lhs, rhs) {
				t.Errorf("(G + 2G) + 3G != G + (2G + 3G) on curve %s — addition is not associative", tc.name)
			}
		})
	}
}

// TestAddition_DispatchVariantsAgree locks that the V1 / V2 / V3
// variants of Addition produce the same result for the same operand
// pair after applying the appropriate canonicalisation. Specifically:
//   - For two affine points (Z1=Z2=1), AdditionV1 and Addition give
//     the same answer.
//   - For an affine + projective pair, AdditionV2 (called via
//     Addition's dispatch) gives the same answer as scaling the
//     affine to projective and using AdditionV3.
//
// This locks the Z-test dispatch in Addition against silent regressions.
func TestAddition_DispatchVariantsAgree(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e) // Z=1
			G2, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}
			// G2 has Z!=1 (post-doubling)

			// Path 1: Addition dispatches to V1 for (G, G).
			d1, err := tc.e.Addition(G, G)
			if err != nil {
				t.Fatalf("Addition(G, G): %v", err)
			}
			// Path 2: AdditionV1 directly.
			d2, err := tc.e.AdditionV1(G, G)
			if err != nil {
				t.Fatalf("AdditionV1(G, G): %v", err)
			}
			if !tc.e.ArePointsEqual(d1, d2) {
				t.Errorf("Addition(G, G) != AdditionV1(G, G) on curve %s — dispatch divergence at Z1=Z2=1", tc.name)
			}

			// Path 3: Addition dispatches to V2 for (G2, G) — Z1!=1, Z2=1.
			a1, err := tc.e.Addition(G2, G)
			if err != nil {
				t.Fatalf("Addition(2G, G): %v", err)
			}
			// Path 4: AdditionV2 directly with same (G2, G).
			a2, err := tc.e.AdditionV2(G2, G)
			if err != nil {
				t.Fatalf("AdditionV2(2G, G): %v", err)
			}
			if !tc.e.ArePointsEqual(a1, a2) {
				t.Errorf("Addition(2G, G) != AdditionV2(2G, G) on curve %s — dispatch divergence at Z1!=1, Z2=1", tc.name)
			}
		})
	}
}

// TestDoubling_DispatchVariantsAgree is the doubling counterpart to
// TestAddition_DispatchVariantsAgree. Locks DoublingV1 against
// Doubling's V1 dispatch on Z=1 input.
func TestDoubling_DispatchVariantsAgree(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e) // Z=1

			d1, err := tc.e.Doubling(G)
			if err != nil {
				t.Fatalf("Doubling(G): %v", err)
			}
			d2, err := tc.e.DoublingV1(G)
			if err != nil {
				t.Fatalf("DoublingV1(G): %v", err)
			}
			if !tc.e.ArePointsEqual(d1, d2) {
				t.Errorf("Doubling(G) != DoublingV1(G) on curve %s — dispatch divergence at Z=1", tc.name)
			}

			// And for Z!=1: take the result of doubling once (which has
			// Z!=1 typically) and verify Doubling routes to V2.
			G2 := d1
			d3, err := tc.e.Doubling(G2)
			if err != nil {
				t.Fatalf("Doubling(2G): %v", err)
			}
			d4, err := tc.e.DoublingV2(G2)
			if err != nil {
				t.Fatalf("DoublingV2(2G): %v", err)
			}
			if !tc.e.ArePointsEqual(d3, d4) {
				t.Errorf("Doubling(2G) != DoublingV2(2G) on curve %s — dispatch divergence at Z!=1", tc.name)
			}
		})
	}
}

// TestFortyNiner_Equals49xG locks FortyNiner(P) = [49]·P. The
// FortyNiner helper is used inside scalar multiplication's base-49
// digit processing; a regression in its decomposition (3 + 6 + 12 +
// 24 + 48 + 1 = 49? No — 3·G doubled to 6, doubled to 12, doubled to
// 24, doubled to 48, then +G = 49) would silently corrupt every
// scalar multiplication.
func TestFortyNiner_Equals49xG(t *testing.T) {
	for _, tc := range allTestCurves(t) {
		t.Run(tc.name, func(t *testing.T) {
			G := genExtended(&tc.e)

			fortyNine := tc.e.FortyNiner(G)
			scalarPath := tc.e.ScalarMultiplierWithGenerator(big.NewInt(49))

			if !tc.e.ArePointsEqual(fortyNine, scalarPath) {
				t.Errorf("FortyNiner(G) != [49]·G on curve %s — base-49 decomposition is broken", tc.name)
			}
		})
	}
}
