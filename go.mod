module DALOS_Crypto

// F-MED-003 (audit cycle 2026-05-04, v4.0.2): bumped from go 1.19 (EOL
// August 2023) to go 1.22 (currently supported as of 2026-05). 1.19
// shipped multiple stdlib CVEs since EOL — CVE-2023-29406 (HTTP),
// CVE-2023-39325 (HTTP/2 rapid reset), CVE-2024-24783 (crypto/x509),
// CVE-2024-24784 (net/mail), CVE-2024-34156 (encoding/gob recursion).
// None of these CVEs touch the Genesis cryptographic primitives this
// package exposes (Blake3, AES, math/big, the curve operations are
// all stable across these toolchain releases) but the toolchain itself
// stops receiving security backports once it falls out of the
// supported window, so we move forward.
//
// 1.22 specifically (rather than 1.23+) for two reasons:
//   1. CI was already pinned to 1.22 (.github/workflows/go-ci.yml),
//      so the canonical-test-environment Go version is unchanged.
//   2. 1.22 is the lowest Go version still receiving security backports
//      as of this bump, giving the widest practical compat window for
//      future consumers.
//
// Genesis byte-identity is INDEPENDENT of Go version (verified via
// the corpus byte-identity gate on every CI run + locally before
// shipping this bump). Math primitives produce bit-identical output
// across Go 1.19 / 1.20 / 1.21 / 1.22 / 1.23.
//
// No external deps invariant preserved — `go.mod` still has zero
// `require` directives.
go 1.22
