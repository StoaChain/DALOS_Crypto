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

## [2.2.0] — 2026-04-23

**Phase 0b landed — TypeScript build scaffold.** `ts/` subfolder now hosts the `@stoachain/dalos-crypto` package (at v0.0.1), ready for Phase 1 math code to land inside. Zero cryptographic logic yet — pure infrastructure.

### Added

- **`ts/`** subdirectory containing the full TypeScript scaffold:
  - `package.json` — `@stoachain/dalos-crypto@0.0.1`, ES modules, strict subpath exports (`.`, `./gen1`), author = Kjrekntolopon (AncientHoldings GmbH), npm `publishConfig` pointed at npmjs.org
  - `tsconfig.json` — TypeScript 5.7, target ES2022, strictest options (`noUncheckedIndexedAccess`, `verbatimModuleSyntax`, `isolatedModules`, all `strict*` flags)
  - `tsconfig.test.json` — test-only config with Vitest globals
  - `biome.json` — linter + formatter (2-space indent, single quotes, trailing commas, LF)
  - `vitest.config.ts` — Node environment, 30s timeout, tests in `tests/` and `src/`
  - `.gitignore` — dist, node_modules, coverage, tsbuildinfo
  - `src/index.ts` — scaffold placeholder exporting `SCAFFOLD_VERSION`
  - `tests/fixtures.ts` — typed loader for `../testvectors/v1_genesis.json` with interfaces `BitStringVector`, `SeedWordsVector`, `BitmapVector`, `SchnorrVector`, `VectorCorpus`
  - `tests/scaffold.test.ts` — 7 tests proving the corpus loader works and all 105 records are accessible
  - `README.md` — package overview, Genesis contract, architecture diagram, dev commands, licence reference
- **`.github/workflows/ts-ci.yml`** — CI matrix across Node 20, 22, 24 with lint + typecheck + build + test steps; uploads dist artifact on Node 24.

### Verified

- `npm install` → 58 packages in 7s (clean install)
- `npm run typecheck` → exit 0
- `npm run build` → exit 0 (dist/ produced with `.js` + `.d.ts` + source maps)
- `npm run lint` → exit 0 (clean after auto-fix of import ordering)
- `npm test` → 7/7 tests pass in 1.5s
- All 105 test-vector records accessible via the typed fixture loader

### Next

Phase 1 (TS math foundation) begins in the next push: `src/gen1/math.ts`, `coords.ts`, `curve.ts`, `point-ops.ts`. Every function will be validated byte-for-byte against the Go test-vector corpus.

---

## [2.1.0] — 2026-04-23

**Phase 0 finalised — all output-preserving Category-A hardening complete.** Every remaining finding from the v1.0.0 audit is now resolved, NOT-FIXED-BY-DESIGN (with rationale), or documented as a residual. No items remain in "deferred" state. All 105 test-vector records (50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr) are byte-identical to v2.0.0.

### Fixed

- **PO-3** — `noErrAddition` / `noErrDoubling` helpers added to `Elliptic/PointOperations.go`. Every internal call site in `FortyNiner`, `PrecomputeMatrix`, and `ScalarMultiplier` that previously discarded errors via `_` now routes through these helpers, which panic on any unexpected internal failure (fail-fast instead of silent garbage). No output change for any valid input.
- **KG-2** — `ProcessPrivateKeyConversion`, `ProcessKeyGeneration`, `ExportPrivateKey` (`Elliptic/KeyGeneration.go`) now handle error returns from `GenerateScalarFromBitString`, `ScalarToKeys`, and `AES.EncryptBitString`. Previously these cascaded silently into garbage output; now each error prints a diagnostic and the function returns early. CLI contract (void return) preserved.
- **KG-3** — `ZeroBytes(b []byte)` helper added to `AES/AES.go`. `MakeKeyFromPassword` now zeros the intermediate password-bytes buffer and the Blake3 output after copying. `EncryptBitString` / `DecryptBitString` use `defer ZeroBytes(Key)` to scrub the AES key on return, and zero intermediate plaintext byte slices. Best-effort within Go's memory model — documented residual: Go string immutability means the caller's password *string* cannot be scrubbed from inside this library.
- **AES-3** — `EncryptBitString` now returns `""` on any AES primitive failure (NewCipher, NewGCM, nonce generation) instead of `fmt.Println`-ing and continuing with garbage state. `DecryptBitString` returns typed `fmt.Errorf` errors on any failure instead of printing-and-returning-garbage. Callers treat `""` from encrypt as an error signal; decrypt already returned an error, now it's meaningful instead of stale.
- **AES-4** (cosmetic) — removed the pointless `hex.EncodeToString`/`hex.DecodeString` round-trip in `MakeKeyFromPassword`. Replaced with a direct slice copy. Output identical.

### Clarified (moved from "deferred" to "NOT-FIXED-BY-DESIGN")

- **PO-2** (per-Addition on-curve validation) — prohibitive runtime cost (~10×+ slowdown on key-gen for a ~0 security benefit, since internal `Addition` is never called with attacker-controlled input — external points enter through Schnorr's SC-5 boundary check first). Documented in `AUDIT.md` with rationale.
- **KG-1** (`ImportPrivateKey`) — already had proper error returns in v1.0.0. Re-reviewed in v2.1.0 audit pass; no changes needed. Marked closed.

### Verified

- `go build ./...` → exit 0
- `go vet ./...` → exit 0
- Generator produces 105/105 vectors
- Schnorr self-verify: 20/20
- **Byte-identity vs v2.0.0: all 50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr records are byte-for-byte identical.** Hardening is pure internal refactor — no user-observable output change.

### Final Phase-0 state

Every finding from the v1.0.0 audit is now:
- ✅ RESOLVED (applied, shipped, byte-identity verified where applicable), OR
- ❌ NOT-FIXED-BY-DESIGN (with explicit rationale in AUDIT.md — PO-2 full cost/benefit; AES-1/2 Genesis-file-format preservation; math/big out-of-scope)

**Phase 0 is complete. Next: Phase 0b (TypeScript build scaffold), then Phases 1-12 (TS port proper).**

---

## [2.0.0] — 2026-04-23

**Phase 0d landed — Schnorr v2 hardening (Cat-B).** Complete rewrite of the Schnorr sign/verify path with the three output-changing fixes (SC-1, SC-2, SC-3). Genesis key-generation output remains bit-for-bit identical to v1.0.0. Schnorr signature format breaks from pre-v2 — intentional, safe (no on-chain deps).

**Canonical SHA-256 of `testvectors/v1_genesis.json` at v2.0.0: `45c89ec36c30847a92dbd5b696b42d94159900dddb6ce7ad35fca58f4bba16f3`**

### Fixed

- **SC-1** — Length-prefixed Fiat–Shamir transcript. `SchnorrHash` now computes `Blake3(len32(tag) || tag || len32(r) || r || len32(P.x) || P.x || len32(P.y) || P.y || len32(m) || m) mod Q` with 4-byte big-endian length prefixes on every component. Eliminates the pre-v2 leading-zero ambiguity from `big.Int.Text(2)` concatenation.
- **SC-2** — RFC-6979-style deterministic nonces adapted for Blake3. The nonce `z` is now derived from `(private_key, Blake3(tag_msg || message))` via a tagged Blake3 KDF, not `crypto/rand`. Consequence: **`SchnorrSign(k, m)` is now fully deterministic** — same inputs produce byte-identical signatures across runs and across implementations. Eliminates the Sony-PS3 random-nonce-reuse attack family.
- **SC-3** — Domain-separation tags on both the challenge hash (`"DALOS-gen1/SchnorrHash/v1"`) and the nonce derivation (`"DALOS-gen1/SchnorrNonce/v1"`). Prevents hash collisions with any other Blake3-based protocol.
- **SC-4 (full)** — `s` is now reduced mod Q in `SchnorrSign`; `SchnorrVerify` rejects any signature with `s ≥ Q` or `s ≤ 0`. Canonical range `(0, Q)` enforced by both signer and verifier.

### Added

- [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) — normative specification of the v2 signature format. Implementers porting to other languages (TypeScript port, Rust, etc.) use this as their reference. Contains canonical encodings, signing/verification algorithms, determinism contract, security properties, known residuals, and the pre-v2 incompatibility note.

### Changed

- `Elliptic/Schnorr.go` — `SchnorrSign` and `SchnorrHash` fully rewritten. `SchnorrVerify`'s `s < Q` upper-bound check now active. `deterministicNonce` added as an internal helper.
- `testvectors/v1_genesis.json` — regenerated. All 20 Schnorr signatures now deterministic (stable across runs — verified by running generator twice, byte-identical Schnorr output on second run).

### Verified

- `go build ./...` → exit 0
- `go vet ./...` → exit 0
- Key-gen path: **all 85 deterministic records byte-identical to v1.3.0 and v1.2.0** (50 bitstring + 15 seed-words + 20 bitmap). Genesis preservation held.
- Schnorr self-verify: 20/20 signatures verify under the new `SchnorrVerify`.
- Schnorr determinism: 20/20 signatures produce byte-identical output when the generator runs twice with the same inputs.
- Schnorr format break: 20/20 signatures differ from pre-v2.0.0 signatures (expected — SC-1/SC-2/SC-3 all change the output).

### Incompatibility

v2.0.0 signatures fail to verify under pre-v2.0.0 code, and vice versa. No deployed consumer carries Schnorr signatures across this boundary.

### Documented known residual

Go's `math/big` is not constant-time at the CPU-instruction level. v1.3.0's PO-1 hardening closed the macro-level timing channel; v2.0.0 inherits that. Fully-constant-time signing would require a custom limb-oriented big-int implementation — out of scope for the Go reference. Applies only to signers (verifiers observe public inputs).

---

## [1.3.0] — 2026-04-23

**Phase 0c landed — Category-A hardening.** All output-preserving security fixes applied to the Go reference. The Genesis key-generation path (bitstring → scalar → public key → address) produces **bit-for-bit identical output** to v1.2.0 for all 85 deterministic test vectors. Schnorr signatures continue to self-verify 20/20.

### Changed (implementation hardening, output preserved)

- **PO-1 (constant-time scalar multiplication)** — `Elliptic/PointOperations.go:ScalarMultiplier` rewritten. The pre-v1.3.0 version was a 49-case switch on base-49 digit characters, creating a macro-level timing side channel where an attacker observing wall-clock time could learn scalar digits. The new version does a branch-free linear scan over all 48 precompute entries for every digit, so the sequence of Go-level operations is identical for every scalar of the same base-49 length. Per-iteration work is constant regardless of scalar content.

  **Byte-for-byte compatibility**: verified against the full 85-record deterministic corpus (50 bitstring + 15 seed-words + 20 bitmap). Zero byte drift. The new implementation is a drop-in replacement.

  **Known residual**: Go's `math/big` is not constant-time at the CPU-instruction level; individual `Add`/`Mul`/`Mod` operations may still leak timing through data-dependent limb counts. True constant-time would require a custom limb-oriented implementation (out of scope for the Go reference). The macro-level hardening in v1.3.0 closes the most-exploitable channel and raises attacker cost substantially.

- **SC-4 (partial, Schnorr range check)** — `SchnorrVerify` now rejects signatures with `s ≤ 0`. The stricter `s < Q` upper-bound check is deferred to v2.0.0 because the pre-v2.0.0 Schnorr produces `s = z + H(…)·k` without a mod-Q reduction; historically-valid signatures legitimately have `s ≥ Q`. Preserves backward compatibility for v1.3.0.

- **SC-5 (on-curve validation)** — `SchnorrVerify` now calls `IsOnCurve()` on both `R` (the nonce commitment) and `P` (the public key) before running the verification equation. An attacker-prepared off-curve point no longer interacts with addition formulas in undefined ways. Valid signatures with on-curve points are unaffected.

- **SC-6 (explicit error returns)** — `SchnorrVerify` now returns `false` cleanly on every error path: signature parse failure, nil internal components, public-key parse failure, nil Fiat–Shamir hash, or addition error. The pre-v1.3.0 code used an `if err == nil { … }` pattern that left downstream variables in undefined states, risking nil dereferences.

### Deferred to v1.3.x patches or v2.0.0

The remaining Category-A items are robustness improvements that do not affect output for valid inputs. They're scheduled for incremental patch releases to keep each change surgically reviewable:

- **PO-2** (on-curve validation on every Addition entry — expensive, deferred; already handled at Schnorr boundary)
- **PO-3** (sanity panics in internal paths — deferred)
- **KG-1, KG-2, KG-3** (better error returns + memory hygiene in KeyGeneration — deferred)
- **AES-3** (proper error propagation in AES wrapper — deferred)

### Verified

- `go build ./...` → exit 0
- `go vet ./...` → exit 0
- All 50 bitstring + 15 seed-words + 20 bitmap test vectors produce **byte-for-byte identical output** to v1.2.0
- 20/20 Schnorr signatures self-verify under the hardened `SchnorrVerify`

### The v1.3.0 canonical hash

A fresh regeneration of `testvectors/v1_genesis.json` at v1.3.0 produces a different SHA-256 from v1.2.0 because of the timestamp + random Schnorr nonces, but the deterministic-record content is identical. The canonical hash for the **committed** v1.3.0 JSON is recorded in `testvectors/VALIDATION_LOG.md`.

---

## [1.2.0] — 2026-04-23

**Phase 0a landed.** Adds the 40×40 black/white bitmap as the 6th key-generation input type to the Go reference, with 20 bitmap test vectors committed. Bit-for-bit equivalent to the existing bitstring path; pure input reshaping, no new cryptographic operations. This primes the TypeScript port (Phase 1 onward) with a Go-validated bitmap oracle.

### Added

- **[`Bitmap/Bitmap.go`](Bitmap/Bitmap.go)** — the `Bitmap` package:
  - `type Bitmap = [40][40]bool` with Genesis conventions **locked**: black pixel = 1, white pixel = 0, row-major TTB-LTR scan, strict pure-B/W (no greys accepted)
  - `BitmapToBitString(b)` — deterministic reshape to 1600-character bitstring
  - `BitStringToBitmapReveal(bitsReveal)` — visualisation inverse; parameter intentionally named to flag that the result IS a private key
  - `ValidateBitmap(b)`, `ParseAsciiBitmap(rows)`, `BitmapToAscii(b)`, `ParsePngFileToBitmap(path)`, `EqualBitmap(a,b)`
- **`(*Ellipse).GenerateFromBitmap(b Bitmap)`** in [`Elliptic/KeyGeneration.go`](Elliptic/KeyGeneration.go) — the 6th key-gen entry point. Under the hood: `BitmapToBitString` → existing `GenerateScalarFromBitString` → existing `ScalarToKeys`. Pure input reshape.
- **20 bitmap test vectors** in [`testvectors/v1_genesis.json`](testvectors/v1_genesis.json):
  - 16 hand-designed patterns (all-white, all-black, checkerboard both parities, horizontal+vertical stripes, border, center cross, top/left halves, both diagonals, center dot, four corners, top-left quadrant, concentric squares)
  - 4 deterministic random (RNG seeded with `0xB17A77`)
  - Cross-check assertion in the generator: `GenerateFromBitmap(b)` produces identical keys to `GenerateFromBitString(BitmapToBitString(b))` for all 20 fixtures
- **Updated generator** [`testvectors/generator/main.go`](testvectors/generator/main.go):
  - Generator version 1.2.0
  - Second RNG stream for bitmap randomness (fixed seed `0xB17A77`) so bitstring vectors are unaffected
  - New `BitmapVector` schema in the JSON corpus (id, pattern, ASCII rendering, derived bitstring, priv/pub/addresses)

### Changed

- **`testvectors/v1_genesis.json`** regenerated. Total vectors: **105** (was 85). Canonical SHA-256: `037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9`.
- [`testvectors/VALIDATION_LOG.md`](testvectors/VALIDATION_LOG.md) — new section for the 2026-04-23 v1.2.0 run; bitmap-path cross-check listed; determinism proof re-run (42 diff lines = exactly 2 timestamp + 40 Schnorr signatures; all 85 deterministic records byte-identical).
- [`AUDIT.md`](AUDIT.md) — new `Bitmap/Bitmap.go` section, no findings (pure reshape). Test-vector total updated to 105.
- [`README.md`](README.md) — version badge bumped to 1.2.0; 6 input paths listed (new §0); status table gains bitmap row; repo structure shows `Bitmap/` + `docs/FUTURE.md` + `testvectors/VALIDATION_LOG.md`.

### Verified

- `go build ./...` exit 0
- `go vet ./...` exit 0
- Generator produces 105 vectors, all 20 Schnorr sigs self-verify
- Determinism: all 85 deterministic records (50 bitstring + 15 seed-words + 20 bitmap) byte-identical across regeneration runs; only timestamp and Schnorr signatures vary
- Bitmap cross-check: 20/20 fixtures pass `fromBitmap == fromBitString(toBitString(bitmap))`

---

## [1.1.3] — 2026-04-23

### Added / Changed

- [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md) rewritten to v2 — comprehensive per-phase specification: Locked Decisions section (8 fixed design choices), Phase 0 marked DONE, Phase 0a + 0b added, Phase 4 updated for 6 input types, Phase 5 locked to AES as-is, Phase 6 enumerates the 7 Schnorr hardening items, cross-phase invariants + versioning policy + all 10 decision points. 14 phases total.

---

## [1.1.2] — 2026-04-23

### Added

- **[`docs/FUTURE.md`](docs/FUTURE.md)** — deferred research directions:
  - Post-quantum primitive families (priority: HIGH; bigger curves explicitly not pursued)
  - Bitmap scan-order variants (opt-in future feature, Genesis locked to row-major TTB-LTR)
  - Additional key-gen input types (audio, geolocation, handwriting — community-driven)
  - Bigger curves — **deliberately not on the roadmap**, with reasoning
  - Third-party audit candidates and budget notes
  - Hardware wallet integration (Ledger/Trezor)

### Changed

- **[`LICENSE`](LICENSE)** — author credit updated with explicit attribution:
  - Kjrekntolopon, Geschäftsführer of AncientHoldings GmbH
  - Contact: Kjrekntolopon@ancientholdings.eu
- **[`README.md`](README.md) Acknowledgements** — same attribution plus brief credit describing the original design and prime-search work on 32-thread Ryzen 5950X.
- **[`AUDIT.md`](AUDIT.md) Sign-off** — same author attribution added.

### Confirmed (design decisions)

- **AES stays as-is.** Single-pass Blake3 KDF, AES-256-GCM. Argon2id upgrade deferred — the AES wrapper is used only for standalone encrypted-key-file export (not by the Ouronet UI, which uses ouronet-core's codex encryption). Changing the KDF would break the encrypted-file format without affecting account addresses; the trade-off is not worth it for Genesis. Weak-KDF note remains in AUDIT.md as "user responsibility to choose strong password".
- **Bitmap conventions for Genesis** (locked):
  - 40 × 40 = 1600 pixels = 1600 bits
  - Black pixel = 1, White pixel = 0
  - Row-major top-to-bottom, left-to-right scan
  - Strict black/white (pure 0x000000 or 0xFFFFFF); reject any other pixel value

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
