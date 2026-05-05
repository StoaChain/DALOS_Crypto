// File internal_assertions.go — compile-time pin on internal helper
// method signatures that are NOT part of the public EllipseMethods
// interface but ARE load-bearing for the package's hot paths.
//
// The companion file `assertions.go` enforces that *Ellipse satisfies
// the public EllipseMethods interface. That assertion only catches
// drift in EXPORTED methods. This file fills the symmetric gap: pin
// the signatures of the package-private helpers that the addition /
// scalar-mult / Schnorr-verify pipelines invoke directly. A future
// refactor that accidentally drops, renames, or changes the signature
// of any of these helpers fails `go build ./Elliptic/...` here BEFORE
// it can corrupt the call sites.
//
// Audit trail: F-LOW-008 (audit cycle 2026-05-04, v4.0.3). Pre-v4.0.3
// the Phase 11 conformance assertion in assertions.go covered only
// the exported surface; the private helpers (noErrAddition,
// noErrDoubling, isOnCurveExtended, arePointsEqualProjective,
// schnorrHashFromAffine, cofactorCheckRejects) had no equivalent
// compile-time pin. They are all called from the Schnorr verify hot
// path and from the F-PERF-003 / F-MED-011 / F-MED-017 v4.0.x
// hardening; silent signature drift would manifest only at runtime
// (e.g., a panicking noErrAddition that no longer returns CoordExtended
// would corrupt SchnorrSign output, but would compile cleanly because
// the call sites would just fail-typecheck). This file makes that
// drift a build-time error.
//
// Filename note: this file is `internal_assertions.go` and NOT
// `_internal_assertions.go` because the Go build tool ignores files
// whose names start with `_` or `.`.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
package Elliptic

import "math/big"

// internalEllipseMethods is the package-private mirror of EllipseMethods
// — it lists the helper signatures that the hot paths call directly but
// that should NOT be exported through the public interface (they are
// performance-internal optimizations that public callers should never
// need to invoke directly; misuse risks breaking constant-time / on-curve
// invariants).
//
// The interface itself is never instantiated; the conformance assertion
// at the bottom of this file is the only consumer.
type internalEllipseMethods interface {
	// PO-3 fail-fast helpers (v2.1.0). Wrap Addition / Doubling for
	// internal call sites that pass operands guaranteed-on-curve by
	// construction; any error from the inner call is a programming
	// error and panics.
	noErrAddition(P1, P2 CoordExtended) CoordExtended
	noErrDoubling(P CoordExtended) CoordExtended

	// F-PERF-003 (v4.0.1) inversion-free helpers. Replace the
	// pre-v4.0.1 Extended2Affine-then-compare path with projective
	// arithmetic — eliminates 8 ModInverse calls per SchnorrVerify.
	// Equivalence proven by PointOperations_perf_equiv_test.go.
	isOnCurveExtended(InputP CoordExtended) (OnCurve bool, Infinity bool)
	arePointsEqualProjective(P1, P2 CoordExtended) bool

	// F-MED-011 (v4.0.2) pre-parsed-coords overload. Used by
	// SchnorrVerify which has already parsed PublicKey into PAffine
	// for its on-curve + cofactor checks. Skips the redundant
	// ConvertPublicKeyToAffineCoords parse.
	schnorrHashFromAffine(R *big.Int, PublicKeyAffine CoordAffine, Message string) *big.Int

	// F-MED-017 (v4.0.2) hybrid cofactor-check dispatch. h=4 fast
	// path (2 doublings) + general fallback via ScalarMultiplier.
	cofactorCheckRejects(X CoordExtended) bool
}

// Compile-time pin on the internal helper signatures. Any drift in any
// of the methods listed in internalEllipseMethods will fail the build
// HERE with a clear "*Ellipse does not implement internalEllipseMethods"
// error before reaching the call sites.
//
// Discard-named variable; never read at runtime; never allocates
// (typed nil).
var _ internalEllipseMethods = (*Ellipse)(nil)
