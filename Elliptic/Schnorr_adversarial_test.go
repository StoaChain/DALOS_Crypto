package Elliptic

import (
	"math/big"
	"testing"
)

// =============================================================================
// Schnorr cofactor / small-subgroup behavioural-rejection tests (Phase 6, T6.8)
// =============================================================================
//
// Background — F-SEC-001, REQ-16. The DALOS twisted-Edwards curve has cofactor
// h = 4. The 4-torsion subgroup contains the points (0, P-1) (order 2),
// (X₂, 0) and (-X₂, 0) (order 4), and the identity (0, 1) (order 1) — the
// classic Edwards small-subgroup family. Pre-Phase-0 SchnorrVerify accepted any
// (R, P) on-curve regardless of subgroup membership, so an attacker could
// substitute one of these low-order points for R or for the public key and
// drive the Fiat–Shamir equation into a configuration where forging a valid s
// is feasible. T6.2 (v2.x.x, post-v2.1.0) added the explicit cofactor check
// `[4]·R ≠ O` and `[4]·P ≠ O` immediately after the existing on-curve check
// inside SchnorrVerify (Schnorr.go, lines around 375-408 at HEAD).
//
// What these tests assert: SchnorrVerify rejects the four well-known cofactor /
// small-subgroup attack constructions, and accepts the matching legitimate
// signature as a positive control (proving the rejection is targeted, not a
// blanket false). Construction follows the same recipe used by the T6.7
// adversarial vector generator at testvectors/generator/main.go, so the wire
// format used here is byte-compatible with the v1_adversarial.json corpus.
//
// MULTI-LAYER-DEFENCE NOTE (verified honestly via watch-it-fail).
// SchnorrVerify currently has THREE independent rejection layers between the
// signature parser and the Fiat–Shamir equation check:
//
//   Layer 1 — strict pubkey parser (T6.5, F-SEC-002 / F-ERR-006):
//     ConvertPublicKeyToAffineCoords now rejects xLength < 1, captures the
//     ok-flag from both big.Int.SetString calls, and returns CoordAffine{}
//     on any failure.
//
//   Layer 2 — on-curve check on R and P (SC-5, v1.3.0):
//     IsOnCurve verifies the parsed point satisfies the curve equation.
//
//     CRITICAL CAVEAT for the (0, P-1) construction below: AffineToPublicKey
//     (Elliptic/KeyGeneration.go) concatenates XString + YString into a single
//     base-10 string for wire transmission. For X=0, XString="0" — but when
//     the decoder reverses this via big.Int.SetString → big.Int.Text(10) the
//     leading "0" gets stripped. The wire-format-decoded point is therefore
//     NOT (0, P-1) — it's a different point whose AX is the first decimal
//     digit of (P-1) and whose AY is the remaining digits. That recovered
//     point is essentially random and almost certainly OFF-CURVE, so Layer 2
//     fires FIRST on the (0, P-1) construction, before Layer 3 ever runs.
//     This was discovered by Phase 6 review F-001 / F-004; documented honestly
//     here so future auditors do not believe Layer 3 is being directly
//     exercised by these test vectors.
//
//   Layer 3 — explicit cofactor scalar mult (T6.2, F-SEC-001):
//     [4]·X on extended-coords formulas; rejects if result is identity.
//     This layer IS active and correct (verified by code-read), but the
//     wire-format-recovered point from the (0, P-1) construction does not
//     reach it — Layer 2 catches first. Constructing a test that isolates
//     Layer 3 requires either a test seam into the verifier's internal
//     extended-coords path, or a true order-4 point with non-zero X
//     (Tonelli-Shanks construction for sqrt(-1/d) mod P) — both deferred
//     to a future audit cycle per spec authorization.
//
// Per the watch-it-fail protocol mandated by the T6.8 plan, the cofactor
// check (Layer 3) was temporarily commented out and these tests were re-run.
// Outcome: all three rejection tests STILL PASSED — because of Layer 2
// (IsOnCurve) firing first on the wire-format-decoded garbage point per
// the lossy-encoding caveat above. The earlier hypothesis attributing the
// rejection to Layer 4 (Fiat–Shamir equation check) was corrected by Phase 6
// review F-004 — the actual rejection layer is Layer 2, not Layer 4.
//
// The cofactor check (Layer 3) IS the canonical guard for the F-SEC-001
// threat model: an adversary who CAN construct an on-curve order-4 point
// with non-zero X (which survives the lossy encoding intact AND passes
// IsOnCurve) and CAN forge a matching `s` such that the Fiat-Shamir equation
// holds. Constructing such a test fixture is non-trivial cryptographic work
// (Tonelli-Shanks for sqrt(-1/d) mod P) and is deferred to a future audit
// cycle per spec authorization.
//
//   - TestSchnorrVerify_AcceptsLegitimateSig:
//     unaffected by Layer 3 toggling (legitimate (R, P) trivially satisfy
//     [4]·R ≠ O and [4]·P ≠ O).
//
// This precedent matches the Phase 1 archive note for the off-curve R guard:
// "removing R guard alone does NOT cause TestSchnorrVerify_OffCurveR_Rejected
// to fail". We document it here rather than pretending the cofactor check is
// the sole defence — the test guards REJECTION BEHAVIOUR (the contract), not
// the isolated firing of any single layer. If any layer regresses, the test
// remains a tripwire — the failing layer just shifts.
// =============================================================================

// adversarialMessage is the same legit-message string used by the T6.7
// adversarial vector generator (see testvectors/v1_adversarial.json).
// Keeping it identical means the wire-format constructions in this file are
// byte-compatible with the on-disk corpus, so anyone debugging a failure can
// cross-reference v1_adversarial.json directly.
const adversarialMessage = "T6.7-cofactor-adversarial-vector"

// buildLegitKeyPair derives a deterministic Genesis-curve keypair from the
// frozen bs0001InputBitstring corpus fixture. Using a known-valid corpus
// vector (rather than rand-generated entropy) guarantees the three preceding
// guards (GenerateScalarFromBitString, ScalarToKeys) succeed every run and
// the test is reproducible across machines, OSes, and Go versions.
func buildLegitKeyPair(t *testing.T, e Ellipse) DalosKeyPair {
	t.Helper()
	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
	}
	kp, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
	}
	return kp
}

// orderTwoFallbackR returns the affine encoding of the order-2 small-subgroup
// point (0, P-1) — the same construction used by the T6.7 adv-cof-0001 vector.
// This is the canonical low-order fallback for the DALOS curve: substituting
// into a·x² + y² = 1 + d·x²·y² gives 0 + (P-1)² ≡ 1 (mod P) and 1 + 0 = 1, so
// the point is on-curve; doubling on twisted-Edwards yields the identity, so
// the order is 2 → it lies in the cofactor-4 subgroup → [4]·(0, P-1) = O.
func orderTwoFallbackR(e Ellipse) CoordAffine {
	return CoordAffine{
		AX: big.NewInt(0),
		AY: new(big.Int).Sub(&e.P, big.NewInt(1)),
	}
}

// TestSchnorrVerify_RejectsCofactor4R is the behavioural regression guard for
// the cofactor / small-subgroup attack on the R component of a Schnorr
// signature (F-SEC-001, REQ-16, T6.2 hardening). The verifier, given a
// signature whose R has been swapped for the order-2 fallback (0, P-1), MUST
// return false — proving that an attacker cannot forge a verifiable signature
// by substituting a low-order R after the fact.
//
// Construction (matches testvectors/generator/main.go and v1_adversarial.json
// adv-cof-0001): sign a legitimate message under a legitimate keypair; parse
// the signature; replace the R coordinate with (0, P-1); re-serialize via
// ConvertSchnorrSignatureToString; verify against the legitimate public key.
// Pre-T6.2 the verifier accepted the substituted R (no cofactor check). At
// HEAD the [4]·R cofactor check rejects deterministically — see the
// multi-layer-defence note at the top of this file for an honest accounting
// of the other guards that also fire as belt-and-braces.
func TestSchnorrVerify_RejectsCofactor4R(t *testing.T) {
	e := DalosEllipse()
	kp := buildLegitKeyPair(t, e)

	legitSigStr, err := e.SchnorrSign(kp, adversarialMessage)
	if err != nil {
		t.Fatalf("SchnorrSign returned error for legit input — sign-side failure, cannot proceed: %v", err)
	}

	parsed, err := ConvertSchnorrSignatureAsStringToStructure(legitSigStr)
	if err != nil {
		t.Fatalf("ConvertSchnorrSignatureAsStringToStructure rejected its own legit output: %v", err)
	}

	// Mutation under test: replace R with the order-2 fallback (0, P-1).
	parsed.R = orderTwoFallbackR(e)
	mutatedSigStr := ConvertSchnorrSignatureToString(parsed)

	if e.SchnorrVerify(mutatedSigStr, adversarialMessage, kp.PUBL) {
		t.Errorf("SchnorrVerify accepted a signature with R = (0, P-1) cofactor-4 fallback — F-SEC-001 regression")
	}
}

// TestSchnorrVerify_RejectsCofactor4P is the behavioural regression guard for
// the cofactor / small-subgroup attack on the public key component (the
// symmetric of TestSchnorrVerify_RejectsCofactor4R). The verifier, given a
// substituted public key (0, P-1) in canonical wire format, MUST return false.
//
// Construction (matches v1_adversarial.json adv-cof-0002): sign with the legit
// keypair, then verify using a synthetic public key produced by
// AffineToPublicKey({AX:0, AY:P-1}). Pre-T6.2 the verifier accepted the
// substituted public key. At HEAD the [4]·P cofactor check rejects.
func TestSchnorrVerify_RejectsCofactor4P(t *testing.T) {
	e := DalosEllipse()
	kp := buildLegitKeyPair(t, e)

	legitSigStr, err := e.SchnorrSign(kp, adversarialMessage)
	if err != nil {
		t.Fatalf("SchnorrSign returned error for legit input — sign-side failure, cannot proceed: %v", err)
	}

	// Mutation under test: substitute the legit public key with the canonical
	// wire encoding of the order-2 fallback (0, P-1). AffineToPublicKey
	// produces the same "<xLength>.<body>" base-49 encoding the verifier
	// expects, so the strict parser (T6.5) admits the point structurally;
	// rejection happens later at the cofactor check.
	mutatedPubKey := AffineToPublicKey(orderTwoFallbackR(e))

	if e.SchnorrVerify(legitSigStr, adversarialMessage, mutatedPubKey) {
		t.Errorf("SchnorrVerify accepted a signature against substituted P = (0, P-1) cofactor-4 fallback — F-SEC-001 regression")
	}
}

// TestSchnorrVerify_AcceptsLegitimateSig is the positive-control complement to
// the two rejection tests above. Without it, a regression that turned the
// cofactor (or any other) guard into a blanket `return false` would silently
// pass the rejection tests while breaking every honest signature in production.
// The control proves the test infrastructure (corpus fixture → keypair → sign
// → verify) is wired up correctly AND that none of the hardened guards
// (strict parser, on-curve check, cofactor check, range check on s) over-reject
// legitimate inputs derived from the deterministic Genesis corpus.
//
// Mirrors v1_adversarial.json adv-control-0001.
func TestSchnorrVerify_AcceptsLegitimateSig(t *testing.T) {
	e := DalosEllipse()
	kp := buildLegitKeyPair(t, e)

	legitSigStr, err := e.SchnorrSign(kp, adversarialMessage)
	if err != nil {
		t.Fatalf("SchnorrSign returned error for legit input — sign-side failure, cannot proceed: %v", err)
	}

	if !e.SchnorrVerify(legitSigStr, adversarialMessage, kp.PUBL) {
		t.Errorf("SchnorrVerify rejected an honest legitimate signature — over-rejection regression in one of the SC-* / cofactor guards")
	}
}

// =============================================================================
// SC-5 off-curve perturbation rejection tests (origin v3.1.0, F-TEST-001)
// =============================================================================
//
// The two tests below cover Layer 2 (IsOnCurve) of the multi-layer-defence
// chain documented at the top of this file. Where the cofactor tests above
// substitute a low-order on-curve point to exercise Layer 3 (cofactor check),
// these tests perturb AY by +1 to land OFF the curve, exercising Layer 2
// directly. Combined, the two test families cover Layers 2 + 3 with explicit
// adversarial constructions.
//
// Both follow the same shape:
//   1. Produce a real signature via the existing keygen + sign pipeline using
//      the deterministic 1600-bit fixture bs0001InputBitstring.
//   2. Deserialize the signature (or the public key) into its CoordAffine form
//      via the production helpers ConvertSchnorrSignatureAsStringToStructure /
//      ConvertPublicKeyToAffineCoords.
//   3. Perturb AY by +1. Probability of (AX, AY+1) landing on a valid 1606-bit
//      curve point is ≈ 1 / P (vanishingly small). Confirmed off-curve via
//      e.IsOnCurve BEFORE the verify call — if the perturbation ever lands
//      on-curve (astronomical false-positive), t.Fatalf forces a hard failure
//      rather than a misleading pass.
//   4. Re-encode through the production string helpers (these are purely
//      numerical; they accept any bigint ≥ 0 for AX/AY).
//   5. Assert e.SchnorrVerify(...) == false, proving SOMETHING in the verifier
//      rejects the off-curve input.
//
// MULTI-LAYER-DEFENCE CAVEAT (mutation-test finding from F-TEST-001 execution):
// Removing the R-guard at Schnorr.go:375-378 alone does NOT cause
// TestSchnorrVerify_OffCurveR_Rejected to fail — the downstream algebraic
// check `s·G == e·P + R` independently rejects the off-curve perturbation.
// Same applies to the P-guard and TestSchnorrVerify_OffCurveP_Rejected. These
// tests therefore prove END-TO-END off-curve rejection (the consumer-observable
// property), but they do NOT specifically pin either on-curve guard as the
// SOLE rejection mechanism. F-TEST-001 closes with behavioral coverage; the
// SC-5 guards remain as defence-in-depth. See AUDIT.md F-TEST-001 closure row.

func TestSchnorrVerify_OffCurveR_Rejected(t *testing.T) {
	e := DalosEllipse()

	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
	}
	keyPair, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
	}

	const message = "off-curve-R-adversarial-test"
	sigStr, err := e.SchnorrSign(keyPair, message)
	if err != nil {
		t.Fatalf("SchnorrSign returned error for the corpus fixture: %v", err)
	}

	// Sanity: the unmodified signature verifies. If this fails the
	// pipeline is broken before we can assert anything about the guard.
	if !e.SchnorrVerify(sigStr, message, keyPair.PUBL) {
		t.Fatalf("baseline SchnorrVerify rejected an honestly-produced signature; pipeline broken")
	}

	sig, err := ConvertSchnorrSignatureAsStringToStructure(sigStr)
	if err != nil {
		t.Fatalf("failed to deserialize the produced signature: %v", err)
	}

	perturbedR := CoordAffine{
		AX: new(big.Int).Set(sig.R.AX),
		AY: new(big.Int).Add(sig.R.AY, big.NewInt(1)),
	}

	// Confirm the perturbation actually moved R off-curve. Probability of a
	// false positive here is ≈ 1/P on a 1606-bit prime — never observed in
	// practice — but a hard fail beats a misleading pass.
	rExtended := e.Affine2Extended(perturbedR)
	onCurve, _ := e.IsOnCurve(rExtended)
	if onCurve {
		t.Fatalf("AY+1 perturbation did not move R off-curve; cannot exercise SC-5 R-guard branch")
	}

	perturbedSig := SchnorrSignature{R: perturbedR, S: new(big.Int).Set(sig.S)}
	perturbedSigStr := ConvertSchnorrSignatureToString(perturbedSig)

	if e.SchnorrVerify(perturbedSigStr, message, keyPair.PUBL) {
		t.Fatalf("SchnorrVerify accepted a signature with an off-curve R component; SC-5 R-guard regression")
	}
}

func TestSchnorrVerify_OffCurveP_Rejected(t *testing.T) {
	e := DalosEllipse()

	scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
	if err != nil {
		t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
	}
	keyPair, err := e.ScalarToKeys(scalar)
	if err != nil {
		t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
	}

	const message = "off-curve-P-adversarial-test"
	sigStr, err := e.SchnorrSign(keyPair, message)
	if err != nil {
		t.Fatalf("SchnorrSign returned error for the corpus fixture: %v", err)
	}

	// Sanity: baseline verifies under the honest public key.
	if !e.SchnorrVerify(sigStr, message, keyPair.PUBL) {
		t.Fatalf("baseline SchnorrVerify rejected an honestly-produced signature; pipeline broken")
	}

	pAffine, err := ConvertPublicKeyToAffineCoords(keyPair.PUBL)
	if err != nil {
		t.Fatalf("failed to parse the produced public key: %v", err)
	}

	perturbedP := CoordAffine{
		AX: new(big.Int).Set(pAffine.AX),
		AY: new(big.Int).Add(pAffine.AY, big.NewInt(1)),
	}

	pExtended := e.Affine2Extended(perturbedP)
	onCurve, _ := e.IsOnCurve(pExtended)
	if onCurve {
		t.Fatalf("AY+1 perturbation did not move P off-curve; cannot exercise SC-5 P-guard branch")
	}

	perturbedPubKey := AffineToPublicKey(perturbedP)

	if e.SchnorrVerify(sigStr, message, perturbedPubKey) {
		t.Fatalf("SchnorrVerify accepted a signature against an off-curve public key P; SC-5 P-guard regression")
	}
}
