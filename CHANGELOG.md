# Changelog

All notable changes to `StoaChain/DALOS_Crypto` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned

- TypeScript port (`ts/` subdirectory) — 12-phase roadmap, see [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md) when added.
- Blake3 inline: merge [`StoaChain/Blake3`](https://github.com/StoaChain/Blake3) as a git submodule or vendored copy, make this repo self-contained.
- Test-vector corpus: 500+ input/output pairs generated from the Go reference, committed to `testvectors/`. Becomes the oracle for the TypeScript port.
- `AES/` audit — mode, IV handling, KDF.
- `docs/SCHNORR_HARDENING.md` — detailed fix plan for the 7 Schnorr findings.

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
