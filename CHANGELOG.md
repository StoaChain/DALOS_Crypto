# Changelog

All notable changes to `StoaChain/DALOS_Crypto` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned

- TypeScript port (`ts/` subdirectory) — begin Phase 1 of [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md) (math foundation).
- Expand test-vector corpus from 85 → 500+ — edge cases (all-zero, all-ones, boundary scalars), invalid-input rejection vectors.
- `docs/SCHNORR_HARDENING.md` — detailed fix plan for the 7 Schnorr findings (Category B, applied in the TS port).
- Third-party cryptographic audit engagement.

---

## [1.1.1] — 2026-04-23

### Added

- **[`testvectors/VALIDATION_LOG.md`](testvectors/VALIDATION_LOG.md)** — verbatim output of the Go validation suite (`go vet`, `go build`, `gofmt -l`, generator run, determinism proof via diff). Canonical SHA-256 of the committed `v1_genesis.json` is `0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db`. Anyone can reproduce.

### Verified (again, after v1.1.0 shipped)

- `go vet ./...` — exit 0, no issues
- `go build ./...` — exit 0, self-contained compile
- Test-vector determinism: re-running the generator produces **byte-identical output for all 50 bitstring vectors and 15 seed-word vectors**; only timestamp + 20 Schnorr signatures vary (expected — Schnorr uses random nonce). 64 deterministic records × 2 runs = 100% match.

---

## [1.1.0] — 2026-04-23

**Self-containment release.** The Go reference is now self-contained (no external module dependencies) and ships with a reproducible test-vector corpus.

### Added

- **[`LICENSE`](LICENSE)** — Proprietary notice: Copyright © 2026 AncientHoldings GmbH. All rights reserved. Grants inspection, audit, verification-script-execution, and sanctioned-integration rights. Reserves redistribution, derivative works, and commercial-use rights.
- **`Blake3/`** — Blake3 XOF implementation inlined from [`StoaChain/Blake3`](https://github.com/StoaChain/Blake3) (was previously imported as `Cryptographic-Hash-Functions/Blake3`).
- **`AES/`** — AES-256-GCM wrapper with Blake3 KDF, inlined from the same sibling repo. Audit findings added to [`AUDIT.md`](AUDIT.md) (mode: GCM ✅, KDF: single-pass Blake3 ⚠️, error handling: needs hardening ⚠️).
- **[`testvectors/v1_genesis.json`](testvectors/v1_genesis.json)** — **85 reproducible input/output vectors**:
  - 50 bitstring → keypair → address vectors (deterministic `math/rand` seed `0xD4105C09702`)
  - 15 seed-word vectors spanning ASCII, Cyrillic, Greek, accented Latin
  - 20 Schnorr sign+self-verify vectors (all pass `verify == true`)
- **[`testvectors/generator/main.go`](testvectors/generator/main.go)** — deterministic Go generator, reproducible by any consumer via `go run testvectors/generator/main.go`.
- **[`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md)** — 12-phase TypeScript port plan (628 lines, moved in from the consumer-app docs).

### Changed

- `Elliptic/KeyGeneration.go`, `Elliptic/Schnorr.go`, `AES/AES.go` — import paths updated:
  - `"Cryptographic-Hash-Functions/Blake3"` → `"DALOS_Crypto/Blake3"`
  - `"Cryptographic-Hash-Functions/AES"` → `"DALOS_Crypto/AES"`
  
  These are **import-path changes only**. No cryptographic logic was modified. The Genesis key-generation path remains bit-for-bit identical to v1.0.0.
- [`README.md`](README.md) — added Blake3/AES/test-vectors entries to the repository structure and status table, updated licence section, linked to the now-local TS port plan.
- [`AUDIT.md`](AUDIT.md) — AES audit section now marked complete with findings.

### Verified

- `go build ./...` completes clean with no errors from the repo root
- All 85 test-vector generation operations succeed
- 20/20 Schnorr signatures self-verify

---

---

## [1.0.0] — 2026-04-23

**First versioned release.** Baseline audited Go reference implementation of DALOS Cryptography (Genesis).

### Added

- **[`AUDIT.md`](AUDIT.md)** — complete audit report:
  - Mathematical verification of curve parameters (7 tests, all PASS)
  - Per-file source audit (Auxilliary, Parameters, PointConverter, PointOperations, KeyGeneration, Schnorr, Dalos)
  - Categorisation of findings into output-preserving (Cat. A) and output-changing (Cat. B) fixes
  - Remediation roadmap
  - Confidence summary and sign-off
- **[`verification/`](verification/)** — reproducible mathematical verification suite:
  - [`verify_dalos_curve.py`](verification/verify_dalos_curve.py) — Python implementation (gmpy2 + sympy backed)
  - [`verify_dalos_curve.sage`](verification/verify_dalos_curve.sage) — Sage version (Pari/GP deterministic primality)
  - [`README.md`](verification/README.md) — usage guide
  - [`VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) — verbatim run output (2026-04-23)
- **[`README.md`](README.md)** — rewritten: project overview, security status, curve parameters, quick-verify guide, roadmap, related repositories, links to audits/tests.
- **[`CHANGELOG.md`](CHANGELOG.md)** — this file.

### Verified

- **P = 2^1605 + 2315** is prime (Miller–Rabin, 50 rounds, error probability ≤ 2⁻¹⁰⁰)
- **Q = 2^1603 + K** is prime (same)
- Cofactor **R = 4** (curve order = 4·Q divides cleanly)
- **d = −26 is a quadratic non-residue mod P** → Bernstein–Lange addition-law completeness
- Generator **G = (2, Y_G)** lies on the curve
- **[Q]·G = O** (G has prime order Q — computed via explicit projective scalar multiplication)
- Safe-scalar size **1600 ≤ log₂(Q) = 1604**

### Changed

- Nothing. All cryptographic code (`Elliptic/`, `Auxilliary/`, `Dalos.go`, `go.mod`) is unchanged from the pre-audit state. The audit explicitly **freezes** the Genesis key-generation path.

### Notes

- **No LICENSE file** in the repo yet. Licensing to be decided before first npm publish.
- The audit is an *internal review*. A third-party cryptographic audit by an accredited firm is recommended before:
  - DALOS Schnorr is used for on-chain authentication
  - DALOS primitives are used in multi-tenant / side-channel-sensitive environments
  - The TypeScript port is used to sign transactions with non-trivial financial consequences

---

## Pre-1.0.0 history (reconstructed)

Before this changelog was introduced, the repository went through these milestones (preserved in git history):

- **Initial Commit** — original DALOS_Crypto Go implementation by the StoaChain founder. Curve parameters, point operations, key generation, Schnorr, Blake3 integration. Runs on `go.ouronetwork.io` in production serving the Ouronet UI.
- README iterations — basic project description.

---

[Unreleased]: https://github.com/StoaChain/DALOS_Crypto/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/StoaChain/DALOS_Crypto/releases/tag/v1.0.0
