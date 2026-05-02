package Elliptic

import (
    "math/big"
    "testing"
)

// Schnorr_adversarial_test.go pins the existing on-curve guards on
// SchnorrVerify's R component (Schnorr.go:372-378) and P component
// (Schnorr.go:391-398) with adversarial regression coverage. A future
// refactor that drops either guard fails CI before merging.
//
// Both tests follow the same shape:
//   1. Produce a real signature via the existing keygen + sign pipeline
//      using the deterministic 1600-bit fixture bs0001InputBitstring
//      (declared in KeyGeneration_test.go — shared across the package's
//      _test.go compile unit, do NOT redeclare here).
//   2. Deserialize the signature (or the public key) into its CoordAffine
//      form via the production helpers ConvertSchnorrSignatureAsString-
//      ToStructure / ConvertPublicKeyToAffineCoords.
//   3. Perturb AY by +1. The Genesis curve is a 1606-bit Edwards-form
//      field, so the probability that (AX, AY+1) lands on a valid curve
//      point is ≈ 1 / P (vanishingly small). Confirmed off-curve via
//      e.IsOnCurve BEFORE the verify call — if the perturbation ever
//      lands on-curve (astronomical false-positive), t.Fatalf forces
//      a hard test failure rather than a misleading pass.
//   4. Re-encode through ConvertSchnorrSignatureToString / Affine-
//      ToPublicKey (these helpers are purely numerical; they accept any
//      bigint ≥ 0 for AX/AY and produce syntactically-valid output).
//   5. Assert e.SchnorrVerify(...) == false, proving SOMETHING in the
//      verifier rejects the off-curve input.
//
// Multi-layer defence (mutation-test finding from T1.3 execution):
// Removing the R-guard at Schnorr.go:375-378 alone does NOT cause
// TestSchnorrVerify_OffCurveR_Rejected to fail — the downstream
// algebraic check `s·G == e·P + R` at Schnorr.go:418 (via
// e.ArePointsEqual) independently rejects the off-curve perturbation.
// Same applies to the P-guard at :395-398 and TestSchnorrVerify_OffCurveP_Rejected.
// These tests therefore prove END-TO-END off-curve rejection (the
// consumer-observable property), but they do NOT specifically pin
// either on-curve guard as the SOLE rejection mechanism. A future
// refactor that removes the on-curve guards would not flip these tests
// red — the algebraic check still rejects. F-TEST-001 closes with
// behavioral coverage; the SC-5 guards remain as defence-in-depth.
// See AUDIT.md F-TEST-001 closure row for the same disclosure.

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
    sigStr := e.SchnorrSign(keyPair, message)
    if sigStr == "" {
        t.Fatalf("SchnorrSign returned empty string for the corpus fixture")
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

    // Confirm the perturbation actually moved R off-curve. Probability
    // of a false positive here is ≈ 1/P on a 1606-bit prime — never
    // observed in practice — but a hard fail beats a misleading pass.
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
    sigStr := e.SchnorrSign(keyPair, message)
    if sigStr == "" {
        t.Fatalf("SchnorrSign returned empty string for the corpus fixture")
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
