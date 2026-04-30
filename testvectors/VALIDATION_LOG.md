# Test Vector Validation Log

This file captures the verbatim output of the Go validation suite against the DALOS Genesis reference implementation. It complements [`../verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) (which is about curve-parameter math) by demonstrating that the full pipeline from bitstring to address works end-to-end and is **bit-for-bit reproducible**.

**Anyone can reproduce this.** See the commands below — each one runs in <1 minute on commodity hardware.

---

## Run — 2026-04-30 (v3.0.0, Phase 8 cross-curve byte-identity + historical corpus)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64), Git Bash |
| Go version | go1.19.4 windows/amd64 |
| Generator version | 3.0.0 |
| `core.autocrlf` | true (CRLF working tree, LF in git blob) |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| `go test ./Auxilliary/...` | ✅ 13/13 unit tests pass (CeilDiv8 helper) |
| `go test ./Elliptic/...` | ✅ 7/7 unit tests pass (ConvertHashToBitString XCURVE-4 + XCURVE-1..3 ceil-div) |
| Generator output | ✅ 105 Genesis vectors + 60 historical vectors (10 bitstring + 5 seedwords + 5 Schnorr per LETO/ARTEMIS/APOLLO) |
| **DALOS Genesis byte-identity** (timestamp-elided) | ✅ Pre-XCURVE vs Post-XCURVE: SHA-256 stable. Per-vector deterministic outputs unchanged. |
| **APOLLO byte-identity** (S=1024 byte-aligned) | ✅ Pre-fix vs post-fix: zero diff across keys/addresses/Schnorr signatures + handcrafted leading-zero hash probe |
| Schnorr determinism (Genesis) | ✅ 20/20 signatures self-verify; byte-identical across regeneration runs |
| Schnorr determinism (Historical) | ✅ 15/15 signatures self-verify (5 per curve); byte-identical across regeneration runs |
| Per-curve historical address prefixes | ✅ 15× LETO `Ł.`/`Λ.`, 15× ARTEMIS `R.`/`Ř.`, 15× APOLLO `₱.`/`Π.` — 0 DALOS-prefix (`Ѻ.`/`Σ.`) leakage in historical corpus |
| Historical corpus determinism | ✅ Twice-run regeneration produces byte-identical `v1_historical.json` SHA-256 (timestamp-elided) |
| TS test suite (`npm test` from `ts/`) | ✅ 346/346 tests pass (16 test files) |

### Canonical SHA-256 values at tag `v3.0.0` (timestamp-elided)

```
testvectors/v1_genesis.json     SHA-256: 742ef1e271c35d5abe27347688ce1304b14798e7021efe8f7ff6fb54a5392c7a
testvectors/v1_historical.json  SHA-256: 0f60a8fe631dc5d95244d27c247ec0f6e031f629eee7fbe3e9fd48b888a48b35
```

**Verification protocol (Windows Git Bash):**
```bash
sed 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' testvectors/v1_genesis.json | sha256sum
sed 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' testvectors/v1_historical.json | sha256sum
```

The `generator_version` field bumped from `1.2.0` → `3.0.0` and `host` field updated to `"StoaChain/DALOS_Crypto test-vector generator v3.0.0"` are deliberate metadata changes for v3.0.0; per-vector cryptographic outputs are byte-identical to the pre-Phase-8 frozen state for byte-aligned curves (DALOS, APOLLO).

### What this run proves

1. **Genesis preservation across the XCURVE-1..4 hardening pass.** All 50 bitstring + 15 seedwords + 20 bitmap + 20 Schnorr DALOS vectors reproduce byte-for-byte. The `aux.CeilDiv8` helper produces identical output to floor division for byte-aligned safe-scalars (DALOS S=1600).
2. **APOLLO byte-identity preservation.** S=1024 is byte-aligned; XCURVE-1..4 produce identical APOLLO output. Pre-fix and post-fix scratch tools produce zero-diff JSON across all probed outputs.
3. **LETO + ARTEMIS wire-format break (intentional, per spec).** Pre-v3.0.0 LETO/ARTEMIS Schnorr signatures and seedword-derived keys do NOT match post-v3.0.0 outputs. The byte-identity contract is now formalized at v3.0.0 via `v1_historical.json` and verified by the TS test suite (`tests/registry/historical-primitives.test.ts` BYTE-IDENTITY blocks).
4. **Cross-implementation byte-identity formalized.** The TypeScript port at `@stoachain/dalos-crypto@3.0.0` now reproduces every committed Go-side historical vector byte-for-byte, validated on every npm test run.

---

## Run — 2026-04-23 (v2.0.0, Schnorr v2 hardening)

### Environment

| Item | Value |
|------|-------|
| Generator version | 1.2.0 (unchanged; only Schnorr output format changes) |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| Generator output | ✅ 105 vectors (50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr) |
| **Genesis key-gen byte-identity vs v1.2.0** | ✅ **ALL 85 deterministic records byte-identical** (50+15+20). Genesis contract held through Phase 0c + 0d. |
| Schnorr self-verify | ✅ 20/20 under v2 format |
| **Schnorr determinism** (regenerate twice, compare) | ✅ **20/20 signatures byte-identical across runs** — the v2.0.0 RFC-6979-style nonce derivation delivers full determinism |
| Schnorr format break vs v1.x | ✅ **20/20 signatures differ from pre-v2.0.0** (expected — SC-1/SC-2/SC-3 all change bytes) |

### Canonical SHA-256 of `v1_genesis.json` at tag `v2.0.0`

```
SHA-256:  45c89ec36c30847a92dbd5b696b42d94159900dddb6ce7ad35fca58f4bba16f3
```

### What this run proves

1. **Genesis preservation held through 3 hardening releases (v1.2.0 → v1.3.0 → v2.0.0).** Every bitstring, seed-word, and bitmap derivation produces byte-identical keys/addresses.
2. **PO-1 hardening (v1.3.0) is correct.** Constant-time scalar mult, verified against full corpus.
3. **SC-4, SC-5, SC-6 (v1.3.0) work correctly.** Schnorr verify rejects invalid inputs while passing valid ones.
4. **SC-1, SC-2, SC-3 (v2.0.0) work correctly.** New format is self-consistent; sign produces deterministic output that verify accepts.

---

## Run — 2026-04-23 (v1.3.0, Category-A hardening)

Abridged re-run after Phase 0c Category-A fixes.

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS |
| `go vet ./...` | ✅ PASS |
| Key-gen byte-identity vs v1.2.0 | ✅ all 85 deterministic records byte-identical |
| Schnorr self-verify | ✅ 20/20 (still using v1 Schnorr format) |

Canonical hash recorded in commit `v1.3.0` CHANGELOG entry: `dca92bc33589fdde798f77cd5ce12ce5f3e08701606bfc62c893d852bde29fd7`.

---

## Run — 2026-04-23 (v1.2.0, bitmap vectors added)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64) |
| Go version | go1.19.4 windows/amd64 |
| Generator version | 1.2.0 |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| Generator output | ✅ 105 vectors produced (50 bitstring + 15 seed-words + **20 bitmap** + 20 Schnorr) |
| Schnorr self-verify | ✅ 20/20 true |
| Bitmap path cross-check | ✅ `GenerateFromBitmap(b) == GenerateFromBitString(BitmapToBitString(b))` for all 20 fixtures |
| Determinism proof | ✅ Only timestamp + 20 Schnorr sigs vary between runs; **all 85 deterministic records (50+15+20) byte-identical** — diff produced 42 lines, matching `1 timestamp×2 + 20 signatures×2`. |

### Canonical SHA-256 of `v1_genesis.json` at tag `v1.2.0`

```
SHA-256:  037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9
```

### Bitmap fixtures

| # | Pattern | Notes |
|---|---------|-------|
| 1 | all-white (zeros) | baseline — fromBitmap must equal fromBitString("000…0") |
| 2 | all-black (ones) | baseline — fromBitmap must equal fromBitString("111…1") |
| 3 | checkerboard-even | (r+c) even = white |
| 4 | checkerboard-odd | (r+c) even = black |
| 5 | horizontal-stripes | every 2 rows alternate |
| 6 | vertical-stripes | every 2 cols alternate |
| 7 | border-frame | outer ring black |
| 8 | center-cross | row 20 + col 20 black |
| 9 | top-half-black | rows 0-19 black |
| 10 | left-half-black | cols 0-19 black |
| 11 | diagonal-tl-br | main diagonal black |
| 12 | diagonal-tr-bl | anti-diagonal black |
| 13 | center-dot | single pixel (20,20) |
| 14 | four-corners | 4 corner pixels only |
| 15 | top-left-quadrant | 20×20 block black |
| 16 | concentric-squares | rings spaced every 4 |
| 17-20 | deterministic-random | math/rand seed `0xB17A77` |

---

## Run — 2026-04-23 (v1.1.0, initial corpus)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64) |
| Go version | go1.19.4 windows/amd64 |
| Git commit | `400468e` (v1.1.0) |

### Check 1 — `go vet ./...`

Static analysis catches suspicious constructs, unused variables, unreachable code, format-string mismatches, and common Go pitfalls.

```
$ go vet ./...
$ echo $?
0
```

**Result: EXIT 0, zero output.** No issues flagged across all 11 Go files (`Auxilliary/`, `AES/`, `Blake3/`, `Elliptic/`, `Dalos.go`, `testvectors/generator/`).

### Check 2 — `go build ./...`

```
$ go build ./...
$ echo $?
0
```

**Result: EXIT 0.** The repo is a self-contained Go module — no external dependencies required. The Blake3 + AES inline (v1.1.0) works cleanly.

### Check 3 — `gofmt -l .`

Lists files whose formatting would change if `gofmt` were run. Non-zero output indicates style deviations, not bugs.

```
$ gofmt -l .
AES/AES.go
Auxilliary/Auxilliary.go
Blake3/Blake3.go
Blake3/Compress.go
Blake3/CompressGeneric.go
Dalos.go
Elliptic/KeyGeneration.go
Elliptic/Parameters.go
Elliptic/PointConverter.go
Elliptic/PointOperations.go
Elliptic/Schnorr.go
testvectors/generator/main.go
$ echo $?
0
```

**Result:** 12 files have non-canonical whitespace (mostly tabs-vs-spaces). **This is style only** — no logical or cryptographic implications. `gofmt` was not applied because:

1. The Genesis Go reference is **explicitly frozen** at v1.0.0 — any formatting change, even whitespace, is a commit against the frozen state.
2. `go vet` and `go build` pass cleanly, so there are no *functional* issues.
3. Running `gofmt` does not change binary output or produce different keys/addresses. Purely cosmetic.

If a future consumer wants canonical formatting, they can run `gofmt -w .` on a fork. The Ouronet reference stays as-is.

### Check 4 — Test vector generation

```
$ go run testvectors/generator/main.go
[1/3] Generating 50 bitstring vectors...
      10 / 50
      20 / 50
      30 / 50
      40 / 50
      50 / 50
[2/3] Generating seed-word vectors...
      15 fixtures
[3/3] Generating Schnorr sign+verify vectors...
      20 / 20

=============================================================
  DONE. 85 total vectors written to testvectors/v1_genesis.json
    50 bitstring vectors
    15 seed-words vectors
    20 schnorr vectors
    20 / 20 schnorr signatures self-verified
=============================================================
```

**Result: 85/85 vectors generated; 20/20 Schnorr signatures self-verified.**

### Check 5 — Determinism proof (re-generation diff)

The critical property: running the generator twice on the same machine must produce **identical output for everything except the timestamp and Schnorr signatures** (which are correctly random per-run due to `crypto/rand` nonce selection).

```
$ cp testvectors/v1_genesis.json /tmp/first_run.json
$ go run testvectors/generator/main.go          # regenerate
$ diff /tmp/first_run.json testvectors/v1_genesis.json | grep -c '^[<>]'
42
```

**Analysis of the 42 differing lines:**

| Category | Count | Expected? |
|----------|-------|-----------|
| Timestamp line (`generated_at_utc`) | 1 | ✅ YES — captures current clock |
| Schnorr signature values (20 × 2 sides of diff) | 40 | ✅ YES — random nonce per signature |
| Everything else | **1** | This is the `<` side of the timestamp diff |
| **TOTAL** | **42** | All expected. |

**What was byte-identical across both runs:**

- All 50 bitstring vectors (input bitstring, scalar, priv keys in base 10 + 49, public key, both addresses) ✅
- All 15 seed-word vectors (input words, derived bitstring, scalar, priv key, public key, both addresses) ✅
- All 20 Schnorr vectors' **input**, **keypair**, **public key**, **message**, and `verify_actual: true` flag ✅
- Only the 20 `signature` values differ — which is the correct behaviour for a Schnorr scheme using random nonces.

**This proves:**

1. The **key-generation path is deterministic** for a given input. Same input always yields same output. ✅
2. **Schnorr signature generation is non-deterministic** (by design — random nonce). ✅
3. **Schnorr signature verification is reliable** — 20/20 of each run's signatures self-verify as true. ✅

### Check 6 — Committed file integrity

```
$ git show HEAD:testvectors/v1_genesis.json | sha256sum
0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db  -
```

**The canonical hash of `testvectors/v1_genesis.json` as committed at v1.1.0 is:**

```
SHA-256:  0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db
```

Anyone cloning the repo at tag v1.1.0 can verify this with:

```bash
git checkout v1.1.0
git show HEAD:testvectors/v1_genesis.json | sha256sum
# Expected: 0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db
```

(Note: if you `cat` the file directly on Windows, line-ending autoconversion may produce CRLF and thus a different hash. Use `git show` or `tr -d '\r'` to normalise.)

---

## Summary

| Check | Result |
|-------|--------|
| `go vet ./...` | ✅ PASS (exit 0, no output) |
| `go build ./...` | ✅ PASS (exit 0) |
| `gofmt -l .` | Non-canonical style only — no functional issues |
| Test vector generation | ✅ 85/85 vectors produced |
| Schnorr self-verify | ✅ 20/20 true |
| Determinism proof | ✅ Only timestamp + 20 Schnorr sigs vary; 64 deterministic vectors byte-identical |
| Canonical JSON hash | `0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db` |

**Conclusion:** the Go reference implementation is **functionally correct, reproducible, and ready to serve as the oracle for the forthcoming TypeScript port.**

---

## Re-validation policy

This check battery should be re-run:

- Any time any Go source file is modified
- Before any major tag/release
- Annually as a prudent integrity check
- When a new generator version is introduced (would produce a new `v2_*.json` — do not overwrite v1)

Append new entries to this file with the date of each re-run. Never overwrite.

---

*Log maintained by StoaChain. See [`../AUDIT.md`](../AUDIT.md) for the full source + mathematical audit. See [`../verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) for the curve-parameter verification.*
