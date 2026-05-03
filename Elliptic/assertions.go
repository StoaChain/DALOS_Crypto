// File assertions.go — compile-time interface conformance assertions
// for the Elliptic package.
//
// This file exists solely to enforce, at compile time, that the
// concrete *Ellipse type satisfies the EllipseMethods interface
// declared in PointOperations.go. Any future drift in TYPE SIGNATURES
// (not parameter names — Go does not type-check parameter names)
// between the interface declaration and the *Ellipse method receivers
// will cause `go build ./Elliptic/...` to fail.
//
// Audit trail: F-ARCH-002 (Phase 11, v4.0.0, unified-audit-2026-04-29).
// Filename note: this file is `assertions.go` and NOT `_assertions.go`
// because the Go build tool ignores files whose names start with `_` or `.`.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
package Elliptic

// Compile-time interface conformance assertion. Discard-named variable;
// never read at runtime; never allocates (typed nil).
var _ EllipseMethods = (*Ellipse)(nil)
