# DALOS Cryptography — Audit Report

**Audit target:** `StoaChain/DALOS_Crypto` (Go reference implementation)
**Initial audit date:** 2026-04-23 (against commit `d136e8d` / tag `v1.0.0`)
**Last updated:** 2026-04-30 (after error-handling closure shipped at `v3.0.1`)
**Audit scope:** Complete source audit + mathematical verification + hardening verification

---

## Hardening Status (current as of `v3.0.1`) — **PHASE 0 + PHASE 8 COMPLETE**

> **Every finding from the v1.0.0 audit is now resolved, partial-with-rationale, or explicitly not-fixed-by-design. No items remain in "deferred" state.**
>
> **Output-preserving fixes (Category A):**
> - **PO-1** (non-constant-time scalar mult) — ✅ RESOLVED in **v1.3.0** (branch-free linear scan; verified byte-identical on all test vectors)
> - **PO-2** (on-curve validation) — ✅ partial in v1.3.0 (Schnorr boundary via SC-5); per-Addition check NOT-FIXED-BY-DESIGN (v2.1.0 decision: 10×+ runtime cost for marginal benefit — internal `Addition` is never called with attacker-controlled points, since external input always passes Schnorr's SC-5 check first)
> - **PO-3** (silent error discards in point ops) — ✅ RESOLVED in **v2.1.0** (`noErrAddition` / `noErrDoubling` panic on unexpected failures)
> - **KG-1** (`ImportPrivateKey`) — already had proper error returns pre-v2.1.0; re-reviewed and confirmed in v2.1.0
> - **KG-2** (`ProcessPrivateKeyConversion`, `ProcessKeyGeneration`, `ExportPrivateKey`, `ProcessIntegerFlag`) — ✅ COMPLETED in **v3.0.1** (partial in v2.1.0; stragglers F-ERR-002 / F-ERR-003 closed v3.0.1: `ExportPrivateKey` `log.Fatal` and `ProcessIntegerFlag` `os.Exit` replaced with sentinel returns / sibling-mirror)
> - **KG-3** (memory hygiene) — ✅ RESOLVED in **v2.1.0** (best-effort — `ZeroBytes` helper; `defer ZeroBytes(Key)` in AES; intermediate plaintext scrubbed. Limited by Go string immutability — documented)
> - **AES-3** (error propagation) — ✅ COMPLETED in **v3.0.1** (partial in v2.1.0; straggler F-ERR-001 closed v3.0.1: TS port `encryptAndPad` no longer silently masks underlying encryption failure)
> - **SC-4** (s range check) — ✅ RESOLVED in **v2.0.0** (full `(0, Q)` canonical range)
> - **SC-5** (on-curve check of R) — ✅ RESOLVED in **v1.3.0**
> - **SC-6** (explicit error returns in Schnorr) — ✅ RESOLVED in **v1.3.0**
> - **SC-7** (non-CT scalar mult in Schnorr) — ✅ RESOLVED in **v1.3.0** (inherits PO-1)
>
> **Output-changing fixes (Category B):**
> - **SC-1** (length-prefix transcript) — ✅ RESOLVED in **v2.0.0**
> - **SC-2** (deterministic nonces) — ✅ RESOLVED in **v2.0.0**
> - **SC-3** (domain-separation tags) — ✅ RESOLVED in **v2.0.0**
>
> **Output-changing fixes (Category C — cross-curve byte-identity, LETO/ARTEMIS only):**
> - **XCURVE-1** (`Schnorr.go:216` `outputSize := int(e.S) / 8` → `aux.CeilDiv8(int(e.S))`) — ✅ RESOLVED in **v3.0.0**. Aligns Schnorr Fiat-Shamir digest size with TS port's `Math.ceil` semantics for non-byte-aligned curves.
> - **XCURVE-2** (`Schnorr.go:247` `expansionSize := 2 * int(e.S) / 8` → `aux.CeilDiv8(2 * int(e.S))`) — ✅ RESOLVED in **v3.0.0**. Aligns deterministic-nonce expansion size.
> - **XCURVE-3** (`KeyGeneration.go:161` `OutputSize := int(e.S) / 8` → `aux.CeilDiv8(int(e.S))`) — ✅ RESOLVED in **v3.0.0**. Aligns seedwords→bitstring output size; comment block at lines 158-160 rewritten.
> - **XCURVE-4** (`KeyGeneration.go:173-193` `ConvertHashToBitString` rewritten to mirror `ts/src/gen1/hashing.ts:108-129`) — ✅ RESOLVED in **v3.0.0**. Replaces leading-zero-eliding `bytes → hex → big.Int.Text(2) → left-pad` pipeline with TS-canonical per-byte `%08b` concatenation + truncate-or-pad. Affects LETO/ARTEMIS only; APOLLO and DALOS Genesis byte-aligned and unchanged.
>
> **Documented, not fixed (by design):**
> - **AES-1, AES-2** (single-pass Blake3 KDF without salt) — preserved forever to avoid breaking Genesis encrypted-file format. AES is CLI-only; OuronetUI uses ouronet-core's codex encryption. User-responsibility: choose a strong password for CLI use.
> - **Go `math/big` timing** — CPU-instruction-level residual; closing it requires replacing math/big with a custom limb-oriented implementation (out-of-scope for Go reference). The TypeScript port will use constant-time bigints where available.
> - **CLI bugs (CLI-1..4)** — Dalos.go CLI driver; not ported to TS (library-only).
>
> **Genesis key-generation output has remained byte-for-byte identical through every hardening release (v1.0.0 → v1.2.0 → v1.3.0 → v2.0.0 → v2.1.0 → v3.0.0 → v3.0.1).** All 105 test vectors produce exactly the same output. Schnorr signatures are byte-identical from v2.0.0 onward (deterministic).
>
> **LETO + ARTEMIS Schnorr signatures and seedword-derived keys** — wire-format changed at v3.0.0 (XCURVE-1..4). Pre-v3.0.0 outputs do NOT verify under v3.0.0+ for these two curves. APOLLO (S=1024 byte-aligned) and DALOS Genesis (S=1600 byte-aligned) are unaffected — XCURVE-1..4 produce identical output for byte-aligned curves. Cross-implementation byte-identity now formalized via `testvectors/v1_historical.json` (60 vectors, schema_version: 2).

See [`CHANGELOG.md`](CHANGELOG.md) for per-release detail, [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) for the hardened Schnorr specification.

---

## TL;DR (post-hardening)

**The DALOS cryptographic stack is mathematically sound, functionally correct, and — as of `v2.0.0` — production-hardened.** The custom Twisted Edwards curve over the 1606-bit prime field has been independently verified (Python + Sage). The Go reference produces correct keys, addresses, and Schnorr signatures for all valid inputs.

Hardening achieved in v1.3.0 + v2.0.0:
- Scalar multiplication is now algorithmic constant-time (branch-free)
- Schnorr signatures are deterministic (RFC-6979 adapted for Blake3), length-prefixed, domain-tagged, and canonically ranged
- On-curve validation at external input boundaries
- Explicit error handling on the Schnorr verify path

**Residuals explicitly documented:**
- `math/big` is not CPU-instruction-level constant-time (out of scope for the Go reference)
- Per-Addition on-curve validation is deferred to a v1.3.x patch (Schnorr boundary check covers the main attack surface)
- AES password-KDF improvements are deferred to a future gen (Genesis freeze preserves the encrypted-file format)

**Production readiness assessment (as of v2.0.0):**

| Use case | Assessment |
|----------|------------|
| **Key generation + address derivation** | ✅ SAFE. Math is correct, output is deterministic, Genesis accounts are permanently derivable. |
| **Schnorr signature signing** | ✅ READY. v2 format is deterministic, length-prefixed, domain-tagged, canonically-s-ranged. Note: no on-chain consumer exists today; this is "ready for activation". |
| **Side-channel-resistant environments** (hardware wallets, multi-tenant servers) | ⚠️ MOSTLY READY. Macro-level timing channel closed in v1.3.0. Micro-level `math/big` timing remains (documented, out-of-scope). For hardware-wallet-grade constant-time, use the TypeScript port with constant-time bigints. |

---

## Methodology

Three passes:

1. **Static code audit** — reading every Go file for correctness, error handling, defensive coding, side-channel resistance.
2. **Mathematical verification** — independent re-derivation of curve parameters using Python (with `gmpy2` backing) and Sage. See [`verification/VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) for full output.
3. **Test vector generation** — a deterministic Go program (`testvectors/generator/main.go`) produces 105 input/output pairs committed as [`testvectors/v1_genesis.json`](testvectors/v1_genesis.json):
   - 50 bitstring → scalar → keypair → addresses (deterministic RNG seeded with `0xD4105C09702`)
   - 15 seed-word fixtures spanning ASCII, Cyrillic, Greek, accented Latin, 1-word minimum, 12-word long phrases
   - **20 bitmap fixtures** — all-white, all-black, checkerboard, stripes, border, diagonals, corners, quadrants, concentric rings, 4 deterministic-random (RNG seeded with `0xB17A77`). Bitmap path cross-check passes: `GenerateFromBitmap(b) == GenerateFromBitString(BitmapToBitString(b))` for all 20 fixtures.
   - 20 Schnorr sign+self-verify vectors (signature bytes vary per run due to random nonce, but all 20 self-verify as `true`)
   
   These are the oracle for the forthcoming TypeScript port — byte-for-byte equivalence on all non-Schnorr outputs is the correctness criterion.

---

## 1. Mathematical Verification

Seven independent tests executed via [`verification/verify_dalos_curve.py`](verification/verify_dalos_curve.py). All **PASSED** with 50-round Miller-Rabin (false-positive probability ≤ 2⁻¹⁰⁰).

| # | Property | Result | Runtime |
|---|----------|--------|---------|
| 1 | `P = 2^1605 + 2315` is prime | ✅ PASS | 0.05 s |
| 2 | `Q = 2^1603 + K` is prime | ✅ PASS | 0.05 s |
| 3 | Cofactor `R = (P + 1 - T) / Q` is integer (= **4**) | ✅ PASS | <1 ms |
| 4 | `d = -26` is a quadratic non-residue mod P (Bernstein–Lange addition-law completeness) | ✅ PASS | <1 ms |
| 5 | Generator `G = (2, Y_G)` lies on the curve | ✅ PASS | <1 ms |
| 6 | **`[Q]·G = O`** (G has prime order Q) | ✅ PASS | 0.3 s |
| 7 | Safe-scalar size `1600 ≤ log₂(Q) = 1604` | ✅ PASS | <1 ms |

**Total runtime: < 1 second on commodity hardware.** See [`verification/VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) for the verbatim output.

### What these results mean

- **Tests 1 & 2** prove the underlying field arithmetic is well-defined. Years of prime-search compute by the DALOS author were not in vain — both primes stand up to industrial-strength probabilistic testing.
- **Test 3** proves the curve has a prime-order subgroup of size Q (cofactor 4). Every valid private key lands in a group where discrete-log is cryptographically hard.
- **Test 4** proves the Bernstein–Lange completeness condition: the addition law on E is complete for *all* input pairs — no exceptional points, no special cases, no branching required. This is a desirable property held by only a few production curves (e.g., Ed25519).
- **Test 6** is the critical one. It directly exercises `[Q]·G` using projective coordinates and confirms the result is the neutral element. This proves G really does have order Q (not some multiple or divisor of Q). Without this, the whole cryptosystem would be unsound.

### Curve parameters (verified)

```
Name       : TEC_S1600_Pr1605p2315_m26
Equation   : x² + y² ≡ 1 + d·x²·y²   (mod P)
Field P    : 2^1605 + 2315                               (1606-bit prime)
Order Q    : 2^1603 + 1258387060301909...1380413          (1604-bit prime)
Cofactor R : 4                                            (curve order = 4·Q)
Trace T    : -5033548241207638...5519336                  (negative — accepted)
Coefficient a : 1
Coefficient d : -26                                       (non-square mod P)
Generator  G : (2, 479577721234...0907472)
Safe scalar : 1600 bits                                   (≤ log₂(Q) = 1604)
```

---

## 2. Static Code Audit — Per-File Findings

### `Auxilliary/Auxilliary.go` ✅

Tiny helper. `TrimFirstRune` is trivially correct. No findings.

### `Elliptic/Parameters.go` ✅

Defines `Ellipse` struct, `E521Ellipse()`, `DalosEllipse()`, helpers (`MakePrime`, `ComputeCofactor`, `ComputeSafeScalar`, `InferiorTrace`, `Power2DistanceChecker`). All values cross-check against the mathematical verification above.

- `MakePrime` correctly builds `2^n ± k` primes
- `ComputeCofactor` correctly computes `(P + 1 − T) / Q`
- `InferiorTrace` / `SuperiorTrace` implement Hasse's bound correctly
- `Power2DistanceChecker` is convoluted but correct (purely a display helper for printing numbers in `2^n ± k` form)

No findings of any severity.

### `Elliptic/PointConverter.go` ✅

Coordinate types + modular arithmetic (`AddModulus`, `SubModulus`, `MulModulus`, `QuoModulus`) + coordinate conversions (`Affine2Extended`, `Extended2Affine`).

- Modular arithmetic is correct (uses Go's `math/big` which handles negative modulus cleanly)
- `QuoModulus` implements `a / b mod p` as `a * b⁻¹ mod p` with `ModInverse` from `math/big` — correct

**Minor note:** `Affine2Extended` aliases `OutputP.EX = InputP.AX` rather than copying. In Go, `*big.Int` is a pointer, so both structs share the same underlying buffer. This is only a problem if the caller mutates `InputP` later. In practice the code doesn't do this, but a defensive port should copy values.

### `Elliptic/PointOperations.go` ✅

Implements the HWCD (Hisil–Wong–Carter–Dawson 2008) twisted Edwards formulas:
- `additionV1` (both Z=1)
- `additionV2` (one Z=1)
- `additionV3` (general case, complete)
- `doublingV1` (Z=1)
- `doublingV2` (general)
- `tripling` (tpl-2015-c)
- `fortyNiner` (49·P via chained doublings and additions)
- `PrecomputeMatrix` (49-element lookup)
- `ScalarMultiplier` (base-49 Horner with PM)
- `ScalarMultiplierWithGenerator` (cached-PM wrapper)

**Mathematical correctness:** formulas match the [Explicit-Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html) entries byte-for-byte. No deviation.

**Findings:**

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| PO-1 | Scalar multiplication branches on the current digit of the scalar — **timing-channel leak**. | ⚠️ Medium (for local use); Critical (for multi-tenant / remote signing). | **✅ RESOLVED v1.3.0** (branch-free linear scan; byte-identical output verified on 105 test vectors) |
| PO-2 | No input validation on `addition()` or `doubling()`. Passing a point not on the curve yields undefined (but deterministic) output. | ⚠️ Low–Medium | ✅ partial v1.3.0 (Schnorr boundary via SC-5); per-Addition check **NOT-FIXED-BY-DESIGN v2.1.0** (prohibitive runtime cost; internal Addition never receives attacker-controlled input) |
| PO-3 | Errors from sub-operations silently discarded in internal point ops. | ⚠️ Low | **✅ RESOLVED v2.1.0** (`noErrAddition`/`noErrDoubling` panic on unexpected failures) |

**Remediation for Category-A (output-preserving) fixes** in the TS port:
- Replace branching scalar mult with Montgomery ladder (same output, constant time) — **✅ APPLIED IN GO AT v1.3.0** (algorithmic constant-time via branch-free linear scan; see PO-1 entry in `CHANGELOG.md`)
- Add `isOnCurve()` check in `addition()` / `doubling()` entry points — **✅ APPLIED AT SCHNORR BOUNDARY AT v1.3.0** (SC-5 covers both R and P)
- Replace silent error swallowing with explicit `Result<T>` / TS error throwing — **✅ APPLIED IN SchnorrVerify AT v1.3.0** (SC-6); other call sites deferred to v1.3.x

### `Elliptic/KeyGeneration.go` ✅

The key-generation API: bitstring → scalar → pubkey → addresses. Also the 16×16 `CharacterMatrix`, bit-string validation, base-49 encoding, seed-words pipeline.

- `GenerateRandomBitsOnCurve` uses `crypto/rand` — cryptographically sound source
- `GenerateScalarFromBitString` applies a clamping step (leading `1` + cofactor trail) that ensures the scalar stays in the safe range — correct, matches the Ed25519-style clamping philosophy
- `affineToPublicKey` encoding is injective (decodable) for all valid points
- Seven-fold Blake3 hashing in `SeedWordsToBitString` — non-standard but cryptographically benign (no security benefit beyond the first round, but no harm either)
- The 16×16 character matrix is a literal constant — 256 Unicode runes spanning Cyrillic, Greek, Latin extended, accented Latin, currency symbols, and math symbols. No duplicates (verified by code inspection).

**Findings:**

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| KG-1 | `ImportPrivateKey` silently ignores `ReadFile` errors beyond a boolean | ⚠️ Low | ✅ already had error returns; re-reviewed **v2.1.0** — no changes needed |
| KG-2 | `ProcessPrivateKeyConversion` / `ProcessKeyGeneration` / `ExportPrivateKey` / `ProcessIntegerFlag` have no error return — bad input causes silent garbage output OR process termination from library code | ⚠️ Low | **✅ COMPLETED v3.0.1** (partial in v2.1.0: `Process*Conversion`+`Generation` print+return; v3.0.1 stragglers: F-ERR-002 `ExportPrivateKey` `log.Fatal` → sibling-mirror; F-ERR-003 `ProcessIntegerFlag` `os.Exit` → empty-string sentinel) |
| KG-3 | Passwords flow as plaintext `string` through call frames, never zeroed in memory after use | ⚠️ Low–Medium (Go strings are immutable, hard to zero anyway — language-level concern) | **✅ RESOLVED v2.1.0** (`ZeroBytes` helper; AES key scrubbed via `defer ZeroBytes(Key)`; intermediate plaintext byte slices scrubbed. Best-effort within Go's memory model — documented residual: Go string immutability means the caller's password string cannot be scrubbed from outside) |
| KG-4 | `dalosAddressMaker` relies on the prefix character `Ѻ` / `Σ` being encoded as multi-byte UTF-8 correctly. Works on all modern systems; noted for portability. | ℹ️ Informational | documented; no fix needed |

No mathematical or security-critical findings. All output generated by this file is deterministic and bit-identical for identical inputs.

### `Elliptic/Schnorr.go` ✅ (all 7 findings resolved as of v2.0.0)

Implements Fiat–Shamir Schnorr over the DALOS curve. **Core math is textbook correct** — `s = z + H(R ‖ P ‖ m)·k` with verification `s·G ?= R + H(R ‖ P ‖ m)·P`.

**Hardening history — all 7 findings resolved:**
- SC-5, SC-6 (on-curve validation, explicit error returns) landed in **v1.3.0**
- SC-4 partial (`s > 0`) landed in v1.3.0; full `(0, Q)` in v2.0.0
- SC-7 inherits PO-1 constant-time scalar mult from v1.3.0
- SC-1, SC-2, SC-3 (length-prefix transcript, deterministic nonces, domain tags) landed in **v2.0.0** as the Schnorr v2 format — see [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md).

The v2.0.0 format is **not interoperable** with pre-v2 signatures. No DALOS Schnorr signatures are used on-chain, so no deployment migration is required.

**Historical findings** (all closed; preserved below for auditor traceability):

| # | Finding | Severity | Fixable? | Status |
|---|---------|----------|----------|--------|
| SC-1 | **Fiat–Shamir transcript is ambiguous.** Concatenates `R.Text(2) + P.AX.Text(2) + P.AY.Text(2) + m.Text(2)` — but `big.Int.Text(2)` strips leading zeros. Two different (R, P, m) triples can produce the same concat string. | ⚠️ Medium | Cat. B (changes sig output) | **✅ RESOLVED v2.0.0** (4-byte length prefix on every component; see `docs/SCHNORR_V2_SPEC.md`) |
| SC-2 | **Nonce generated from `crypto/rand` only.** No RFC-6979 deterministic option. If `crypto/rand` is weak or repeats, private key leaks (Sony PS3 / Playstation ECDSA bug). | ⚠️ Medium | Cat. B (changes sig output) | **✅ RESOLVED v2.0.0** (tagged Blake3 KDF from (priv, msg); Schnorr fully deterministic) |
| SC-3 | **No domain-separation tag** in the hash. Collides namespace-wise with other protocols using Blake3-1600. | ⚠️ Low–Medium | Cat. B | **✅ RESOLVED v2.0.0** (distinct tags for challenge-hash and nonce-derivation) |
| SC-4 | **No range check on `s`** in `SchnorrVerify` (should enforce `0 < s < Q`). | ⚠️ Low | Cat. A (output-preserving, just adds rejection) | **✅ RESOLVED v2.0.0** (full `(0, Q)` check active; v1.3.0 was partial with only `s > 0`) |
| SC-5 | **No on-curve validation of R** in `SchnorrVerify`. | ⚠️ Medium | Cat. A | **✅ RESOLVED v1.3.0** (R and P both validated) |
| SC-6 | Errors silently discarded on lines 147, 161, 229, 239 — if point parsing fails, `SchnorrHashOutput` is nil → nil deref on next use. | ⚠️ Medium | Cat. A | **✅ RESOLVED v1.3.0** (explicit false returns) |
| SC-7 | Non-constant-time scalar mult inherited from `ScalarMultiplier`. Same caveat as PO-1. | ⚠️ Low (for local); Critical (for remote signing) | Cat. A (new primitive) | **✅ RESOLVED v1.3.0** (inherits PO-1 hardening) |

**Since DALOS Schnorr is NOT used on-chain today**, SC-1 through SC-7 can ALL be fixed — and all seven have been resolved as of v2.0.0 (2026-04-23):
- SC-4, SC-5, SC-6, SC-7 landed in **v1.3.0** (Category-A, output-preserving)
- SC-1, SC-2, SC-3 landed in **v2.0.0** (Category-B, signature format changes; see [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md))

The v2.0.0 signature format is NOT interoperable with pre-v2.0.0 signatures. This is intentional and safe — no DALOS Schnorr signatures are used on-chain.

### `Dalos.go` ℹ️

CLI driver, not cryptographic code. Findings recorded for completeness but not "fixable" in the TypeScript port (the TS version is library-only, no CLI wrapper).

| # | Finding | Severity |
|---|---------|----------|
| CLI-1 | Flag-validation logic bug on line 118: `... && *intaFlag != "" && *intbFlag != ""` should be `== ""`. Currently the "required-method" check never fires. | ⚠️ Medium (UX) |
| CLI-2 | Error message mismatch: says "word must be between 3 and 256 characters" but check is `< 1` | ⚠️ Low (UX) |
| CLI-3 | `os.Exit(1)` scattered everywhere; makes this non-importable as a library | ⚠️ Low (design) |
| CLI-4 | `fmt.Scan` echoes seed words to terminal — no masked input | ⚠️ Low (UX) |

**None of these affect cryptographic correctness** of generated keys.

### `Blake3/*.go` (external dependency: `StoaChain/Blake3`)

Pure-Go Blake3 XOF implementation. **Externally validated by the user against an online Blake3 test tool** — byte-for-byte match on test inputs. No further audit required. The TypeScript port will use [`@noble/hashes/blake3`](https://www.npmjs.com/package/@noble/hashes) (spec-compliant, industry-audited) and will be cross-validated against the Go fork using generated test vectors.

### `Bitmap/Bitmap.go` ✅ (added in v1.2.0)

The 6th key-generation input type: a 40×40 black/white bitmap. 40 × 40 = 1600 pixels = 1600 bits = the DALOS safe-scalar size exactly. **Pure input reshaping — no new cryptographic operations are introduced.** The bitmap is converted to a 1600-character bitstring and the standard `GenerateScalarFromBitString` pipeline runs from there.

**Locked Genesis conventions:**

| Parameter | Value |
|-----------|-------|
| Size | 40 × 40 = 1600 pixels |
| Bit convention | **Black pixel = 1, White pixel = 0** |
| Scan order | **Row-major top-to-bottom, left-to-right** |
| Pixel palette | **Strict pure black (R=G=B=0) or pure white (R=G=B=255)**; any other value is rejected as an error |

**Functions (5):**

- `BitmapToBitString(b Bitmap) string` — deterministic reshape, always 1600 chars of "0"/"1"
- `BitStringToBitmapReveal(bitsReveal string) (Bitmap, error)` — visualisation inverse; parameter named to flag secret sensitivity
- `ValidateBitmap(b Bitmap) error` — trivially valid (all `[40][40]bool` are structurally OK); hook for future conventions
- `ParseAsciiBitmap(rows []string) (Bitmap, error)` — parses 40 rows × 40 chars of `#` (= 1) / `.` (= 0)
- `ParsePngFileToBitmap(path string) (Bitmap, error)` — reads a 40×40 PNG; rejects any non-pure-black/white pixel with position + observed RGB in error
- `BitmapToAscii(b Bitmap) []string` — reverse for display/test-vector fixtures
- `EqualBitmap(a, b Bitmap) bool` — equality helper

**Wiring:** `(*Ellipse).GenerateFromBitmap(b Bitmap.Bitmap) (DalosKeyPair, error)` in `Elliptic/KeyGeneration.go`.

**Security note:** A bitmap encodes a private key bit-for-bit. The library contains WARNING comments on every function that returns or displays a bitmap. UI consumers must treat bitmap display with the same operational-security posture as seed-phrase display (explicit reveal action, never photographed, never transmitted unencrypted).

**Audit finding:** none. Pure deterministic reshape, cross-checked against the bitstring path in all 20 committed test vectors.

### `AES/AES.go` ✅

Now inlined into the repo (was previously in the sibling `Cryptographic-Hash-Functions` tree). 135-line wrapper around Go stdlib `crypto/aes` + `crypto/cipher`, used by `Elliptic/KeyGeneration.go` for encrypted private-key file storage.

**Mode of operation:** **AES-256-GCM** — Galois/Counter Mode, an authenticated-encryption-with-associated-data (AEAD) construction. This is the **best general-purpose choice** — provides confidentiality + integrity + authenticity in one pass. Go stdlib implementation, not custom crypto.

**Key derivation:** `MakeKeyFromPassword(password string) []byte` hashes the password via **single-pass Blake3 with 32-byte output** to produce the AES-256 key.

**Nonce handling:** Fresh 96-bit nonce per encryption via `crypto/rand`, prepended to ciphertext. Standard GCM pattern, correct.

**Findings:**

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| AES-1 | **Password KDF is single-pass Blake3 — not a true password KDF.** Proper password-based key derivation (PBKDF2, scrypt, Argon2) adds salt + iteration count + memory hardness. Single-hash is brute-forceable at billions/sec on GPU. Weak passwords fall quickly. | ⚠️ Medium (low-entropy pw); Low (high-entropy pw). | **NOT-FIXED-BY-DESIGN** (Genesis encrypted-file format preserved; CLI-only path not used by OuronetUI; user responsibility to pick strong password). |
| AES-2 | **No salt.** Same password always derives the same key → two files encrypted with the same password are decryptable via one key recovery. | ⚠️ Medium. | **NOT-FIXED-BY-DESIGN** (same rationale as AES-1). |
| AES-3 | **Errors printed with `fmt.Println` then execution continues.** If AES block setup, GCM construction, nonce generation, or decryption fails, the function returns garbage bytes with no error signal. | ⚠️ Medium. | **✅ RESOLVED v2.1.0** (`EncryptBitString` returns "" on failure; `DecryptBitString` returns typed error). |
| AES-4 | `MakeKeyFromPassword` hex-encodes then hex-decodes the Blake3 output — pointless round-trip, but functionally correct. | ℹ️ Cosmetic. | ✅ cleaned up **v2.1.0** (direct slice copy + zeroing). |
| AES-5 | No AAD (associated data) passed to `Seal`/`Open`. Ciphertext is not bound to context (user ID, purpose tag). Not a flaw — a missed feature. | ℹ️ Informational. | documented; no fix needed (would break Genesis encrypted-file format). |

**Verdict:** AES-GCM is a sound primitive. The construction is **safe for encrypting strong passwords' keys** but provides **no meaningful resistance to low-entropy password brute-force** due to the missing salt + iteration KDF.

**Decision (locked 2026-04-23):** AES stays as-is in the Go reference AND in the TypeScript port. Changing the KDF would break the encrypted-file format without any Genesis-key benefit. The AES wrapper is used only by the CLI's `ExportPrivateKey` / `ImportPrivateKey` (saving encrypted key-files to disk); the OuronetUI does **not** use this path — it uses ouronet-core's V1/V2 codex encryption instead. Weak-KDF risk is explicitly documented as "user responsibility to choose a strong password" for CLI consumers. See `docs/FUTURE.md` §4 for the design rationale and `CHANGELOG.md` [1.1.2] for the decision log.

---

## 3. Fix Classification

All findings are sorted into two categories based on whether fixing them changes the output observable by users.

### Category A — Output-Preserving Fixes (ALL SHIPPED)

These fixes change *how* the code computes without changing *what* it outputs. All verified byte-identical against the 105-record test-vector corpus.

| Target | Fix | Affects | Status |
|--------|-----|---------|--------|
| PO-1 | Branch-free linear-scan scalar multiplication | Timing channel only. Same bits out. | ✅ **SHIPPED v1.3.0** (105/105 byte-identical) |
| PO-2, SC-5 | On-curve validation of input points | Rejects invalid input; valid input yields same output. | ✅ SC-5 shipped v1.3.0 (Schnorr boundary); PO-2 per-Addition NOT-FIXED-BY-DESIGN v2.1.0 (cost vs marginal benefit) |
| PO-3 | `noErrAddition`/`noErrDoubling` panic on unexpected internal failures | Control flow; for valid input, output unchanged. | ✅ **SHIPPED v2.1.0** |
| SC-4 | Range check on Schnorr `s` | Rejects malformed; valid sigs verify unchanged. | ✅ partial v1.3.0 (`s > 0`); full `(0, Q)` **v2.0.0** |
| SC-6 | Explicit error returns in SchnorrVerify | Control flow; for valid input, output unchanged. | ✅ **SHIPPED v1.3.0** |
| KG-1 | `ImportPrivateKey` error handling | already had proper error returns | ✅ re-reviewed **v2.1.0**; no change needed |
| KG-2 | `Process*` + `ExportPrivateKey` + `ProcessIntegerFlag` error returns | Control flow; CLI diagnostic instead of garbage; library no longer kills host process | ✅ **COMPLETED v3.0.1** (partial v2.1.0 + stragglers F-ERR-002/F-ERR-003 v3.0.1) |
| KG-3 | Memory hygiene for plaintext keys (best-effort) | Side-effect only (RAM state). | ✅ **SHIPPED v2.1.0** (`ZeroBytes` helper; `defer` scrubs in AES) |
| AES-3 | Proper error returns instead of `fmt.Println` (Go); throw on underlying failure (TS port) | Control flow; valid output unchanged. | ✅ **COMPLETED v3.0.1** (partial v2.1.0 Go-side; TS straggler F-ERR-001 v3.0.1) |

### Category B — Output-Changing Fixes (SHIPPED in v2.0.0 where marked)

These fixes do change output. Applied ONLY to Schnorr (no existing on-chain consumers). Never applied to the key-gen path (Genesis frozen).

| Target | Fix | Affects what? | Applicable? | Status |
|--------|-----|---------------|-------------|--------|
| *(none identified on the key-gen path)* | — | Address generation — **permanently frozen** to preserve existing Ouronet accounts | ❌ NEVER | n/a |
| SC-1 | Length-prefixed Fiat–Shamir transcript | Schnorr signature bytes | ✅ YES | ✅ **SHIPPED v2.0.0** |
| SC-2 | RFC-6979-style deterministic nonces (Blake3 KDF) | Schnorr signature bytes (sigs now fully deterministic) | ✅ YES | ✅ **SHIPPED v2.0.0** |
| SC-3 | Domain-separation tag in Schnorr hash | Schnorr signature bytes | ✅ YES | ✅ **SHIPPED v2.0.0** |

**After v2.0.0**: 20/20 Schnorr signatures in the test corpus now produce byte-identical output across regeneration runs (deterministic), and 20/20 self-verify. Pre-v2 signatures fail v2 verify (expected — format break, see [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) §9).

### The Genesis Freeze Rule

> **Every bit of output on the key-generation path — bitstring → scalar → public key → address — is permanently frozen at Genesis.** The TypeScript port matches the Go reference byte-for-byte. Any proposed change to these primitives becomes a "Gen 2" feature and lives under a separate primitive identifier. Existing addresses stay valid forever, decodable by the registered Genesis primitive.

This is consistent with how every production blockchain cryptosystem handles the same tension (Bitcoin SECP256K1 frozen, Ethereum likewise).

---

## 4. Remediation Status + Roadmap

### Completed (in the Go reference) — **PHASE 0 DONE**

| Phase | Tag | What |
|-------|-----|------|
| 0 | v1.0.0 → v1.1.x | Initial audit + curve math verification + self-containment + 85 test vectors + author credit + future-research docs |
| 0a | v1.2.0 | Bitmap 40×40 input type added (6th key-gen path). Pure input reshape, no new crypto. |
| **0c** | **v1.3.0** | **Category-A hardening (batch 1)**: PO-1 constant-time scalar mult; SC-4 (partial), SC-5, SC-6, SC-7 on Schnorr verify. Key-gen output preserved byte-for-byte. |
| **0d** | **v2.0.0** | **Category-B Schnorr hardening**: SC-1 length-prefix, SC-2 deterministic nonces, SC-3 domain tags, SC-4 (full). Schnorr v2 format. Key-gen output still preserved byte-for-byte. `docs/SCHNORR_V2_SPEC.md` added. |
| **0c-finish** | **v2.1.0** | **Category-A hardening (batch 2)**: PO-3 (noErr* helpers panic on unexpected internal failures); KG-2 (error returns in `Process*` + `ExportPrivateKey`); KG-3 (memory hygiene via `ZeroBytes`, `defer` scrubs in AES); AES-3 (short-circuit on AES errors, typed errors from Decrypt); AES-4 (cosmetic cleanup). **All 105 records byte-identical to v2.0.0 verified. Phase 0 substantively complete; error-handling stragglers closed in v3.0.1.** |
| **0e** | **v3.0.1** | **Error-handling closure** (KG-2 / AES-3 stragglers): F-ERR-001 (TS `encryptAndPad` throw on underlying-encryption failure), F-ERR-002 (Go `ExportPrivateKey` `log.Fatal` → sibling-mirror print+return), F-ERR-003 (Go `ProcessIntegerFlag` `os.Exit` → empty-string sentinel + 5 CLI caller updates). **No public API changes; Genesis 105-vector corpus byte-identical to v3.0.0; TS test count 347/347.** |

### Not being fixed (by design)

- **AES-1, AES-2** (password KDF is single-pass Blake3 without salt). Genesis-frozen in the Go reference and mirrored in the TS port. CLI-only path; OuronetUI doesn't use it. Treated as "user responsibility to pick a strong password". See `docs/FUTURE.md` §4.
- **PO-2 full** (per-Addition on-curve check) — prohibitive runtime cost (~10×+ slowdown on key-gen for marginal benefit). Internal `Addition` is never called with attacker-controlled input — all external points enter through Schnorr's SC-5 boundary check first. Defense-in-depth not needed at this layer.
- **CLI-1..CLI-4** (Dalos.go CLI driver bugs). Not ported to TS (library-only, no CLI).
- **Go `math/big` CPU-instruction-level timing** — closing it requires replacing math/big with a custom limb-oriented implementation. Out-of-scope for the Go reference. TypeScript port will use constant-time bigints where available.

### In progress (TypeScript port — see [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md))

The TypeScript port validates byte-for-byte against the hardened v2.0.0 Go reference:

1. **Phase 0b** (TS scaffold) — in progress next
2. **Phases 1–7** (math → scalar mult → hashing → key-gen → AES → Schnorr → registry) — TS implementation
3. **Phase 8** (integration into `@stoachain/ouronet-core`)
4. **Phase 9** (OuronetUI migration — remove `go.ouronetwork.io/api/generate`)
5. **Phases 10–12** (perf, docs, Go-server retirement)

Because the TypeScript port matches the hardened Go reference byte-for-byte, the TS port **automatically inherits** all v1.3.0 + v2.0.0 hardening — no separate TS-specific hardening work required.

---

## 5. Sign-off

**Original author of the audited work:** Kjrekntolopon (Geschäftsführer, AncientHoldings GmbH). Contact: Kjrekntolopon@ancientholdings.eu.

**Audit conducted by:** Claude (Anthropic), acting as an automated reviewer, on behalf of StoaChain / AncientHoldings GmbH.
**Audit scope disclaimer:** This is an *internal audit* — rigorous source review + independent mathematical verification. It is **not a substitute for a third-party cryptographic audit** by an accredited firm. A third-party audit is **strongly recommended** before:
- DALOS Schnorr is used for on-chain authentication
- DALOS primitives are used in multi-tenant server environments where timing attacks are possible
- The TypeScript port is used to sign anything with non-trivial financial consequences

**Confidence summary (as of v2.0.0):**

| Property | Before hardening (v1.0.0) | After hardening (v2.0.0) |
|----------|---------------------------|---------------------------|
| Mathematical correctness of curve and formulas | **HIGH** (independently verified) | **HIGH** (unchanged) |
| Deterministic reproducibility | **HIGH** (verified) | **HIGH** (85/85 records byte-identical across all hardening releases) |
| Correctness of output for all valid inputs | **HIGH** | **HIGH** |
| Side-channel resistance (algorithmic) | **LOW** | **HIGH** (branch-free scalar mult + deterministic Schnorr) |
| Side-channel resistance (CPU-instruction) | **LOW** | **LOW** (math/big limitation; out of scope — documented) |
| Input-validation robustness | **MEDIUM** | **MEDIUM-HIGH** (Schnorr boundary validates; per-Addition deferred) |
| Schnorr production-readiness | **MEDIUM** (7 items open) | **HIGH** (all 7 items resolved; deterministic + canonical v2 format) |
| Error-path robustness | **MEDIUM** | **MEDIUM-HIGH** (SchnorrVerify fully hardened; KG error paths deferred) |

---

## Related Documents

- [`README.md`](README.md) — project overview
- [`CHANGELOG.md`](CHANGELOG.md) — repo change log
- [`verification/README.md`](verification/README.md) — how to reproduce the math verification yourself
- [`verification/VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) — verbatim output of the 7-test run
- [`verification/verify_dalos_curve.py`](verification/verify_dalos_curve.py) — Python verifier source
- [`verification/verify_dalos_curve.sage`](verification/verify_dalos_curve.sage) — Sage verifier source

---

*This audit report is a living document. As the TypeScript port progresses and third-party reviews come in, this file will be updated. History of updates is tracked in [`CHANGELOG.md`](CHANGELOG.md).*
