# CHANGELOG-v4.0.1-draft.md

> **Purpose:** Running changelog for the next release tag (`ts-v4.0.1`).
> Accumulates audit-cycle-2026-05-04 fixes one-by-one as they land on
> `main`. When the audit triage is complete, this file gets folded into
> `CHANGELOG.md` as the canonical `[4.0.1]` section, then this draft is
> deleted. Pollinate (`/bee:pollinate`) reads `CHANGELOG.md`, not this
> draft — final-step move is mandatory before tag push.

---

## [4.0.1] — 2026-05-04 (DRAFT — in progress)

**Patch release.** Closes the `audit-2026-05-04` cycle's CRITICAL + HIGH
findings: hardening of error-handling, library-API contracts, and CLI
input validation. Genesis 105-vector corpus byte-identity preserved at
extended-elided SHA-256 = `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae`
(unchanged since v3.0.0); historical SHA-256 = `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b`
(unchanged since v3.0.0).

**Audit context:** the pre-v4.0.1 audit cycle (after v4.0.0 shipped)
returned 60 substantive findings (2 CRITICAL, 16 HIGH, 23 MEDIUM, 20 LOW)
plus 3 NEEDS CONTEXT, with 0 false positives. v4.0.1 closes the CRITICAL
+ HIGH band; MEDIUM and LOW findings deferred to future cycles per the
"Critical + High mandatory, Medium triage, Low informational" policy
adopted during this triage session.

### Why a patch release?

Every fix here is either:
- A bug fix with no API surface change (Go-side panic-on-malformed-input
  for previously silent-corruption code paths — F-ERR-003), OR
- A **Go-side library signature widening** (function gains an `error`
  return). Pure additions — existing single-return-value callers fail
  to compile but the fix is mechanical and the only known consumer is
  this repo's own CLI + test suite. The published TypeScript port
  `@stoachain/dalos-crypto` is not affected by Go-side signatures.
- A CLI-only diagnostic improvement (F-CRIT-002, F-API-002, F-ERR-001).
- A TS-public-surface no-op (this release does not change any TS
  public exports; the npm package's wire format and behaviour are
  byte-identical to v4.0.0).

Per SemVer the Go signature changes would normally push to v5.0.0, but
this project's `lifecycle.tag_pattern` is `ts-v{version}` and the version
field in `ts/package.json` represents the **TypeScript package version**.
TS surface is unchanged → patch bump is correct for the tag-driven
release flow. The Go-side breaking changes are documented below for
anyone embedding the Go reference directly.

### Repository hygiene

#### F-CRIT-001 — Stray wallet artifact removed from repo root

Commit `844905a`. Real DALOS wallet file `9G.2idxjKM...fatDK0u.txt`
committed since the initial commit deleted from tracking. `.gitignore`
extended with `*...*.txt` glob (matches the
`{first7_pubkey}...{last7_pubkey}.txt` convention of
`keystore.GenerateFilenameFromPublicKey`) so future stray wallets in
the working directory don't get tracked.

Not a security compromise (the file holds an AES-256-GCM-encrypted
private key plus the public key + addresses, all of which are intended
to be public for the latter two and require password compromise for
the former), but cleaner not to ship a stray wallet bundle at repo
root.

### CLI fixes (`Dalos.go`)

#### F-CRIT-002 — `-g` validation guard inverted condition

Commit `b72e588`. The check at `Dalos.go:119` had inverted operators
on the last two operands: `*intaFlag != "" && *intbFlag != ""` should
have been `== "" && == ""`. The boolean expression could only be true
if BOTH `-i10` AND `-i49` were supplied, the opposite of what the
error message says. As a result `dalos -g -p mypassword` (omitting any
input flag) would silently exit 0 with no key generated and no error.

Fix: invert the two `!=` to `==`. Smoke test added at
`dalos_smoke_test.go::TestCLI_GenerateWithoutInputMethod_ExitsWithError`.
`AUDIT.md` CLI-1 row marked **FIXED**.

#### F-ERR-001 — `SaveBitString` infinite-loop hang on stdin EOF

Commit `3274d98`. Password-confirmation loop in `process.go:152-178`
discarded `fmt.Scanln`'s error. On closed stdin (CI, redirected
`</dev/null`, broken pipe, daemonised invocation), `Scanln` returned
`(0, io.EOF)` repeatedly; the empty `P2` never matched the password;
the `for {}` loop spun burning a CPU core indefinitely.
`dalos_smoke_test.go:27-31` already documented this hang, mitigated
only by a 30s context deadline in the test harness — production had
no guard.

Fix: check the `Scanln` error — `n == 0 && err != nil` triggers stderr
"stdin closed before password confirmation" + `os.Exit(1)`. Cap retries
at 3 to bound the human-typo case as well.

#### F-API-002 — Seed-word length error message wording

Commit `51aad47`. Validator at `Dalos.go:149-153` accepted words of
length 1-256 but the user-facing error message claimed "between 3 and
256" — the function lied about its own contract. Documented in
`AUDIT.md:247` (CLI-2). The actual contract (also in `README.md:71`)
is: 4-256 words, each 1-256 characters.

Fix: message corrected to "between 1 and 256". Smoke test added at
`dalos_smoke_test.go::TestCLI_SeedWord_TooLong_ExitsWithError` with
forbid-list assertion catching any future regression to the wrong
wording. `AUDIT.md` CLI-2 row marked **FIXED**.

### Filesystem / wallet hardening (`keystore/`)

#### F-SEC-002 — Wallet files now written `0600` instead of `0644`

Commit `2e27fca`. `os.Create` always uses mode 0644 (`rw-r--r--` on
POSIX), making exported wallet files world-readable on Linux/macOS.
The file contains the AES-256-GCM-encrypted private key plus the
matching public key — enough material for an offline brute-force
oracle if the password is weak.

Fix: `os.Create(FileName)` → `os.OpenFile(FileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)`.
Owner-only on POSIX. Windows ignores POSIX mode bits (NTFS uses ACLs)
so behaviour there is unchanged.

#### F-ERR-005 — `ExportPrivateKey` returns error, no silent wallet truncation

Commit `f9ef84b`. **Go-side breaking change** (function signature gains
an `error` return).

Pre-v4.0.1 the function discarded every error from the 11× `fmt.Fprintln`
+ 1× `fmt.Fprint` calls plus the deferred `OutputFile.Close`. If the
disk filled mid-write, the network FS disconnected, or the I/O quota
was hit between any two lines, the file ended up TRUNCATED — early
lines (encrypted private key, public key) present, tail (smart/standard
addresses, footer) missing — and the function returned with no signal.
The matching `ImportPrivateKey` requires `len(lines) == 12` exactly,
so a truncated wallet → unimportable with a generic "invalid file
format" message → user with no recourse and may not realise the
failure happened until later recovery attempts. Worst possible failure
mode for a wallet-export operation.

Fix:
- Build the entire 12-line payload in a `strings.Builder` before
  touching the file (atomic in-memory construction, no intermediate
  write points where partial state can land).
- Single all-or-nothing `OutputFile.WriteString(payload)`. On failure:
  `Close` + `os.Remove(FileName)` + return wrapped error.
- Explicit `OutputFile.Sync()` (flush kernel buffers to durable
  storage), then explicit `OutputFile.Close()` with errors checked.
- Function signature: `func(...)` → `func(...) error`.

CLI caller in `process.go::SaveBitString` updated to print to stderr +
`os.Exit(1)` on failure. Tests
(`TestExportPrivateKey_NoLogFatal`, `TestExportPrivateKey_OsCreateErrorBlock_Shape`,
`TestExportPrivateKey_FileCreateFailure_ReturnsError`) updated to pin
the new error-returning shape.

#### F-API-003 — `GenerateFilenameFromPublicKey` returns `(string, error)`

Commit `ee92a1b`. **Go-side breaking change**.

Pre-v4.0.1 the function had two contract violations for a public
library function in the v4.0.0-carved-out `keystore` package:
1. `fmt.Println("Invalid public key format. No dot found.")` from
   inside a library helper — a side-effect that breaks callers running
   in non-CLI contexts (server, GUI, JSON pipe).
2. Returned the magic sentinel string `"InvalidPublicKey.txt"` instead
   of a Go-idiomatic error. Consumers couldn't distinguish a real
   wallet someone deliberately named that from a programming error,
   and `ExportPrivateKey` would have silently produced a wallet file
   literally named `"InvalidPublicKey.txt"`, with multiple failed
   exports colliding on that filename.

Fix: signature changed from `func(string) string` to
`func(string) (string, error)`. Drop the `fmt.Println`. Return a
wrapped error on the no-separator path. Propagate at the one
production caller (`keystore/export.go:72` inside `ExportPrivateKey`).
3 new tests added at `keystore/filename_test.go`.

#### F-API-004 — Wallet parser: header-anchored, CRLF-tolerant, no oracle

Commit `9ed4751`. Pre-v4.0.1 `ImportPrivateKey` split the file content
on `"\n"` and demanded EXACTLY 12 elements, then trusted `lines[2]`
(encrypted PK) and `lines[5]` (public key) by positional index. Two
brittleness vectors:

1. **CRLF normalisation** (Windows clipboard, email transport, git's
   `core.autocrlf=true`) replaced `"\n"` with `"\r\n"`, leaving each
   split part `\r`-terminated. Combined with any tool that "ensures
   final newline" the count drifted off 12 → import rejected with the
   generic "invalid file format" message → cross-platform recovery
   broken for non-trivial reasons.

2. **No header content validation** — a malicious 12-line file (no
   need for valid headers) could be fed to `ImportPrivateKey` to
   attempt password decrypt against `lines[2]`. AES would bail with
   "incorrect password or decryption failed", turning the import
   surface into a brute-force oracle.

Also reported as F-DB-001 by the database-auditor — same bug, two
auditor lenses.

Fix: header-anchored parsing.
- Strip `\r` per-line; trim surrounding whitespace per-line.
- Walk lines to locate canonical headers by content
  (`headerEncryptedPrivateKey`, `headerPublicKey` package constants),
  take the first non-empty subsequent line as the body.
- Headers must match exactly — non-wallet files rejected at the parse
  stage rather than at AES (closes the oracle vector).

5 new tests at `keystore/import_test.go`: round-trip, CRLF tolerance,
trailing-newline tolerance, non-wallet rejection (with explicit
forbid-list assertion catching the AES-fallthrough oracle vector if
ever re-introduced), missing-second-header rejection.

### Library API honesty (`Bitmap/`)

#### F-API-006 — `Bitmap.ValidateBitmap` Godoc no longer claims work it doesn't do

Commit `624d71b`. **Documentation-only fix, no behavior change.**

Pre-v4.0.1 the Godoc summary line read "performs structural validation
of a Bitmap" — misleading, since the function body is `return nil`. A
consumer reading the Godoc would believe the bitmap was being inspected
and might skip their own checks.

The honest body comment was already there ("currently always returns
nil. It exists for API symmetry … and as a hook for future conventions"),
but only Godoc summary lines surface in IDE tooltips and the
`go doc` listing — readers don't see the body.

Fix: rewrite the summary line to make the no-op nature explicit
("ValidateBitmap is a NO-OP that always returns nil"). Expand the body
documentation to explain *why* it's a no-op and stays a no-op:
- The Go type system already enforces the structural invariants
  (`[40][40]bool` cannot be wrong-shape or nil).
- Real "is this a valid DALOS bitmap" checks would have to be
  CURVE-SPECIFIC (DALOS=40×40=1600 bits, APOLLO=32×32=1024 bits,
  LETO=different again). Per-curve dimension checks belong on the
  receiving Ellipse, not on the Bitmap helper.
- Cross-impl note added: TS port's `validateBitmap` returns
  `{ valid: boolean; reason?: string }` and DOES perform structural
  checks because TS lacks Go's compile-time type guarantees. The Go
  side intentionally diverges here.

The single in-repo caller (`GenerateFromBitmap` in
`Elliptic/KeyGeneration.go`) gets a comment noting the call is kept as
a forward-compat anchor — any future real check added to ValidateBitmap
will fire automatically without a downstream API change.

Option A (remove the function entirely) and Option B (mirror TS and
make it real) were considered and rejected: removal would break any
external consumer using the symbol; making it real would require
curve-specific dimension parameters that don't belong at this layer.

### Test infrastructure

#### F-TEST-003 — `keystore.AESDecrypt` + `ImportPrivateKey` direct tests + flaky-roundtrip fix

Commit `f906556`. **Test additions + a fix for pre-existing flakiness in F-API-004's roundTripFixture. No production code changes. No byte-identity risk.**

Pre-v4.0.1 the keystore package's public `AESDecrypt` function had ZERO direct tests; it was exercised transitively via `ImportPrivateKey`'s round-trip tests. Specific failure modes (wrong password, malformed ciphertext, post-F-ERR-002 base-49 validation, empty input, too-short ciphertext) weren't pinned. `ImportPrivateKey` itself had round-trip + parser-rejection coverage from F-API-004 but lacked file-not-found and wrong-password unhappy-path tests.

**Test additions (NEW `keystore/aesdecrypt_test.go`):**
- `TestAESDecrypt_RoundTrip` — happy path, 4 sub-cases (short bitstring, Unicode password, long password, corpus bs0001 fixture).
- `TestAESDecrypt_RejectsWrongPassword` — AES-GCM auth-tag-mismatch path.
- `TestAESDecrypt_RejectsMalformedBase49` — F-ERR-002 alphabet-validator rejection at the keystore wrapper layer (`"malformed base-49 ciphertext"` prefix), 4 sub-cases.
- `TestAESDecrypt_RejectsEmpty` — empty-input branch.
- `TestAESDecrypt_RejectsTooShortCiphertext` — AES-side rejection of too-short payloads.
- `TestImportPrivateKey_RejectsFileNotFound` — `os.ReadFile` error propagation.
- `TestImportPrivateKey_RejectsWrongPassword` — canonical `"incorrect password or decryption failed"` wording for end-to-end import.

**Bonus fix: stabilised pre-existing flake in `roundTripFixture` (used by F-API-004 tests).** The `ExportPrivateKey → AES.EncryptBitString → big.Int.Text(2)` path is **lossy whenever the encrypted blob's most-significant byte has its high nibble close to zero** — documented Go-era edge case (CLAUDE.md "Hardening catalogue" / AUDIT.md AES-1+AES-2, NOT-FIXED-BY-DESIGN). The TS port sidesteps this by constraining the IV's high nibble to be non-zero; the Go side accepts the ~1/16 round-trip failure rate per encryption. F-API-004's `TestImportPrivateKey_AcceptsTrailingNewline` (and the other roundTripFixture-dependent tests) had been latently flaky at ~10-30% failure rate since they shipped.

Both `roundTripFixture` (in `import_test.go`) and the new `encryptForTest` helper (in `aesdecrypt_test.go`) now use a verify-on-success retry pattern: encrypt, attempt the inverse decrypt, retry on failure. Statistically O(1) expected attempts; max attempts capped at 100 (probability of all failing ~ 1e-117).

**Verification:**
- 10/10 consecutive `go test ./keystore/` runs all green (vs 7/10 before the retry-loop fix).
- Full Go suite passes; corpus byte-identity preserved (`v1_genesis.json` SHA `082f7a40...`).
- TS suite unaffected (no TS source touched).

#### F-TEST-002 — Bitmap package: scope docs + comprehensive unit tests

Commit `7ffb43e`. **Doc-only change to source files + new test file. No behavior change. No byte-identity risk.**

Pre-v4.0.1 the Go `Bitmap/` package had ZERO direct unit tests. Correctness rode on the 20 bitmap vectors in `testvectors/v1_genesis.json` end-to-end byte-identity. That catches macroscopic regressions but doesn't cover validators, error-message contracts, roundtrip properties, or the row-major scan-order convention.

Initial proposal was to also refactor the package to support per-curve bitmap dimensions (e.g., APOLLO 32×32 → 1024 bits) since the current code is hardcoded 40×40 → 1600 bits (DALOS-only). Investigation revealed OuronetUI v0.30.12 already solved this with consumer-side dimensioning in `OuronetUI/src/lib/dalos/bitmap-local.ts` — explicitly chosen architectural decision per its docstring: *"Rather than split the core's tight DALOS format, we do the dimension-generic conversions here in the UI layer and feed the results to core's `generateFromBitString`."* Centralizing the dimensioning into this package would have:
- Broken OuronetUI's `import type { Bitmap }` if the type shape changed.
- Broken OuronetCore's Go-side consumers of `Bitmap.Bitmap` as a value type.
- Made `bitmap-local.ts` redundant or silently divergent.
- Forced an npm v4 → v5 major bump for a capability consumers already had at the right layer.

The right boundary is: this package = curve-agnostic crypto math; consumers = curve-aware UX. F-TEST-002 respects that boundary.

**Fix:**

1. **Updated package docstrings on both Go (`Bitmap/Bitmap.go`) and TS (`ts/src/gen1/bitmap.ts`) sides.** New SCOPE NOTE block explicitly documents:
   - The DALOS-only nature of `Bitmap` / `fromBitmap` / `GenerateFromBitmap`.
   - That non-square or non-1600 curves return length-validation errors from downstream `fromBitString`.
   - The reference consumer-side pattern: paint an appropriately-sized grid, convert to a flat row-major bitstring, call `fromBitString` directly. Cross-references `OuronetUI/src/lib/dalos/bitmap-local.ts` as the canonical example.
   - Maintains the existing Genesis-frozen conventions block (bit convention, scan order, greyscale strictness, OPSEC note).

2. **NEW `Bitmap/Bitmap_test.go`** with 9 test functions covering 30+ sub-cases across the public surface:
   - **`TestBitmapToBitString_LengthIsAlwaysBits`** — output is always 1600 chars of `0`/`1`. (3 sub-cases: all-zero, all-one, alternating.)
   - **`TestBitmapToBitString_RowMajorTopLeftFirst`** — single `true` at `[0][1]` produces `"01" + 1598 zeros`. Catches column-major / row-inversion / column-inversion bugs explicitly.
   - **`TestBitmapToBitString_AllZeroAllOne`** — boundary pin against `strings.Repeat("0", 1600)` and the all-ones equivalent.
   - **`TestBitmapToBitString_BitStringToBitmapReveal_RoundTrip`** — bitmap → bits → bitmap is identity. (4 sub-cases including corner pixels.)
   - **`TestBitStringToBitmapReveal_RejectsWrongLength`** — empty / 1599 / 1601 / way-short all rejected with "must be exactly" wording.
   - **`TestBitStringToBitmapReveal_RejectsBadChars`** — `x`/space/`2`/newline at various positions rejected with "invalid char at position" wording.
   - **`TestParseAsciiBitmap_HappyPath`** — checkerboard pattern parses correctly.
   - **`TestParseAsciiBitmap_RejectsMalformedInput`** — table-driven across 7 malformed cases (too-few rows, too-many rows, row-too-short, row-too-long, uppercase invalid char, space invalid char, newline invalid char). Each must mention either "expected 40 rows" or "row N" or "invalid char" in the error.
   - **`TestBitmapToAscii_RoundTripWithParse`** — `ParseAsciiBitmap(BitmapToAscii(b)) == b` for all-zero, all-one, alternating.
   - **`TestEqualBitmap_TrueOnSameFalseOnSinglePixelDiff`** — equality semantics including a single-pixel-different counter-case.

   `ParsePngFileToBitmap` is NOT tested here — requires committing PNG fixture binaries which is a separate spec.

**Verification:**
- `go test ./Bitmap/` clean: 30+ sub-cases all pass in ~10ms.
- Full Go suite still green; corpus byte-identity preserved (`v1_genesis.json` SHA `082f7a40...` unchanged) since no source-code logic was touched.

#### F-TEST-001 — Add Go-side CI workflow + add "adding new primitives" playbook

Commit `efd0fe6`. **CI infrastructure addition + new contributor documentation. No code changes. No byte-identity risk.**

Pre-v4.0.1 the Go reference (the canonical implementation per `CLAUDE.md`) had **no CI automation at all**. The TS port has had `ts-ci.yml` since v3.x; the Go side relied entirely on developers remembering to run `go test` and diff the corpus locally before pushing. A Go-side regression that broke Genesis byte-identity wouldn't be caught until the next manual regen — or, worse, until the TypeScript port's byte-identity tests later failed with a misleading "TS broken" error when actually Go had drifted.

Fix has two pieces:

**(1) NEW workflow `.github/workflows/go-ci.yml`** with 4 gates running on every push to `main` and every PR touching Go code or `testvectors/`:
1. `go build ./...` — compile check
2. `go vet ./...` — static analysis
3. `go test -timeout 120s ./...` — full unit suite
4. **Corpus byte-identity check** — regenerates the three frozen v1_*.json files and asserts their elided SHA-256 matches the canonical baseline:
   - `v1_genesis.json`     `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae`
   - `v1_historical.json`  `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b`
   - `v1_adversarial.json` `b9f228943106e1293c52a7e3d741520e58940b78816a2eeed7aa7332314b9d93`

The byte-identity check is structured so that adding a new primitive's frozen baseline is a one-line edit to a bash associative array — see the playbook below for the procedure. On gate failure, the workflow prints the offending file, expected vs actual SHA, and the first 60 lines of the diff between committed and regenerated content (so a human can debug from the CI log alone).

**(2) NEW document `docs/ADDING_NEW_PRIMITIVES.md`** — the canonical playbook for adding new cryptographic primitives without tripping the byte-identity gate. Sections:

- TL;DR: the 5 rules in one place.
- What the frozen contract actually is (which SHAs, what they cover, what the elision recipe is).
- Invariants you must NOT break (Schnorr v2 wire format, `a=1`, base-49 alphabet, AES KDF, seven-fold Blake3, scalar sizes per curve).
- How CI enforces the contract.
- The 8-step playbook for adding a new primitive: implement Go → add separate generator path → verify Gen-1 still matches → implement TS mirror → cross-validate → freeze + add CI pin → document → register.
- Naming convention for new corpus files.
- "What to do if the SHA gate fires red" — 4-step diagnosis covering the common failure modes (intentional Gen-1 change, shared-helper drift, mixed generator paths, other).
- Related-documents pointers + an "AI agents" section with discipline notes.

**(3) `CLAUDE.md` updated** with a new top-level section pointing to the playbook, so any AI agent loading project context on a future session sees the rules immediately.

**Forward-compat design:** the workflow's `BASELINES` array is the only thing that needs updating when a new primitive is frozen. Adding a future post-quantum primitive (e.g., Dilithium) is one new line in the array + one new file in `testvectors/`. The existing v1 pins stay forever.

### Release pipeline (`.github/workflows/`)

#### F-INT-002 — `ts-publish.yml` race conditions hardened

Commit `a4739d4`. **CI/release-pipeline change. No code changes. No byte-identity risk.**

The TS release pipeline had two real race conditions, one of which you observed during the v4.0.0 release:

1. **Tag-and-merge race.** Pushing a commit to `main` started `ts-ci` across Node 20/22/24 (~2-3 minutes). Pushing the release tag immediately after started `ts-publish` on Node 24 only. If `ts-publish` finished first AND the Node-20 CI build later failed, **a broken-on-Node-20 version was already on npm** with no rollback. Pre-fix `ts-publish` had no dependency on `ts-ci` and only tested Node 24.

2. **Rapid-fire tag re-push.** Force-pushing a tag could spawn parallel `ts-publish` runs that raced on `npm publish` — npm rejected the duplicate but CI minutes were wasted and the GitHub Release page could end up half-formed. Pre-fix `ts-publish` had no `concurrency:` block.

Fix (in `ts-publish.yml`):

1. **Workflow-level `concurrency:` block** — `group: ts-publish-${{ github.ref }}` + `cancel-in-progress: false`. Serialises per-tag runs: a second push waits for the first to complete. `cancel-in-progress: false` is intentional — never cancel a publish mid-flight (half-published packages are worse than a delayed second attempt).

2. **NEW `gates` job with Node 20/22/24 matrix.** Mirrors `ts-ci.yml` exactly: lint + typecheck + build + test + docs:check on each Node version. Runs ON THE TAGGED SHA before the publish job is allowed to start. The `publish` job has `needs: gates`, so a single matrix-cell failure on Node 20 (or 22, or 24) blocks the npm publish + Release creation entirely.

3. **`publish` job de-duplicated.** Since `gates` already runs lint/typecheck/test on all 3 Node versions, the publish job's redundant copies of those steps were removed; only `npm run build` is kept (to produce the artifact for `npm publish`). Net change: faster publish job + same correctness guarantee.

**Bonus fix (closes F-INT-004 as a side effect):** the backfill list at the bottom of the workflow was missing `ts-v4.0.0`. Now includes it. Future tags should be added to the list each release (the audit's F-INT-004 finding noted this drift; addressed inline here rather than as a separate change).

**Verification:**
- YAML structure verified via indent-anchored grep: top-level `name`, `on`, `concurrency`, `permissions`, `jobs` at column 0; `gates` and `publish` at column 2 inside `jobs`; `needs: gates` at column 4 inside `publish`. No tabs, consistent 2-space indent.
- `actionlint` not run (not installed in this environment); the GitHub Actions parser will validate on next push. If it rejects the YAML, fix is mechanical and obvious.

**Real-world impact:** the next release will:
- Block on a Node-20-only test failure before publishing (closes F-INT-002 #1).
- Queue rather than race when re-pushing a tag (closes F-INT-002 #2).
- Backfill `ts-v4.0.0` to GitHub Releases on the next publish run (closes F-INT-004).

### Performance — Schnorr verify hot path

#### F-PERF-001 — Cofactor `[4]·R` and `[4]·P` via two HWCD doublings instead of `ScalarMultiplier(4, _)`

Commit `67d7a35`. **Real perf win, no behavior change, byte-identity preserved.**

Inside `SchnorrVerify` (and its TS twin in both sync + async forms),
the cofactor security check multiplies `R` and `P` by 4 to confirm
they're not in the small (order-4) subgroup. Pre-v4.0.1 this used
`ScalarMultiplier(big.NewInt(4), X)` (Go) / `scalarMultiplier(e.r, X, e)`
(TS), which builds a 48-element PrecomputeMatrix (24 doublings + 24
additions of internal work) and walks the base-49 digits of the
scalar — way over-engineered for the trivial scalar 4.

Mathematical equivalence: `[4]·X = [2·2]·X = doubling(doubling(X))`
holds for any abelian group, including this Twisted Edwards curve.
Both paths produce the same projective point; the `IsInfinityPoint`
boolean fires on the same condition.

Fix: replace at 6 sites total.
- Go (`Elliptic/Schnorr.go`):
  - Line 459 (cofactor check on R): `e.ScalarMultiplier(cofactor4, RExtend)` →
    `e.noErrDoubling(e.noErrDoubling(RExtend))`.
  - Line 486 (cofactor check on P): same pattern on `PExtend`.
  - The package-level `var cofactor4 = big.NewInt(4)` becomes dead
    code and is removed; the explanatory doc-comment block is rewritten
    in-place to document the new doubling-based approach + reference
    the equivalence test.
- TypeScript (`ts/src/gen1/schnorr.ts`):
  - Line 45 (imports): add `doubling` to the existing `point-ops.js`
    import.
  - Line 410 (sync verify, cofactor on R): `scalarMultiplier(e.r, rExtended, e)` →
    `doubling(doubling(rExtended, e), e)`.
  - Line 430 (sync verify, cofactor on P): same pattern.
  - Line 567 (async verify, cofactor on R): same pattern. Note:
    `doubling` is fast and synchronous — no `await` needed even on
    the async path.
  - Line 586 (async verify, cofactor on P): same pattern.

Perf impact: roughly 16× less big-int work per cofactor step. With R
+ P combined, ~96 wasted big-int ops eliminated per Schnorr verify.
Stacks with F-PERF-003 (8 wasted ModInverses) for ~30-50% expected
reduction in Schnorr verify wall-clock once both land.

Tests added (Go-side, `Elliptic/Schnorr_strict_parser_test.go`):
- `TestCofactor4_DoublingEquivalence` — table-driven, asserts the
  AFFINE projection of `ScalarMultiplier(4, X)` and
  `noErrDoubling(noErrDoubling(X))` matches for 3 distinct on-curve
  points: the generator G, [2]·G, and a corpus-derived public key
  point. Affine equivalence is the canonical check (extended HWCD
  has multiple representations of the same projective point).
- `TestCofactor4_InfinityPreserved` — confirms `IsInfinityPoint` is
  invariant across both paths on a non-infinity input. The
  infinity-side of the check (small-subgroup attack vectors) is
  exercised end-to-end by the corpus generator's adversarial vectors;
  Genesis SHA-256 byte-identity preservation IS the regression guard
  for that direction.

TS-side: no new tests; the TS suite already cross-checks every
deterministic vector against the Go-produced corpus. If the TS
cofactor change diverged behaviorally from Go, the existing byte-identity
assertions in `ts/tests/` would catch it on the next `npm test` run.

Verification:
- `go build ./...` + `go vet ./...` clean.
- Full Go test suite passes (5 packages green).
- Genesis 105-vector corpus byte-identity preserved (the adversarial
  cofactor vectors in `v1_genesis.json` exercise the infinity branch
  end-to-end):
    `v1_genesis.json`     `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae`
    `v1_historical.json`  `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b`
- TS-side typecheck not run in this environment (npm not on shell
  PATH); user should run `npm run typecheck && npm test` from `ts/`
  before pollinate.

#### F-PERF-003 / F-PERF-004 — `ArePointsEqual` + `IsOnCurve` rewritten on extended coords (Go + TS)

Commit `d8a76d8`. **Real perf win in the Schnorr verify hot path. No behavior change. End-to-end byte-identity preserved across the genesis + historical + adversarial corpora; cross-impl byte-identity confirmed by 426/426 TS tests.**

`SchnorrVerify` was paying **8 modular inverses per verify**:
- `IsOnCurve(R)` → `Extended2Affine` → 2 `ModInverse` calls (one for AX = EX/EZ, one for AY = EY/EZ on the same denominator).
- `IsOnCurve(P)` → same 2 `ModInverse` calls.
- `ArePointsEqual(LeftTerm, RightTerm)` → `Extended2Affine` on BOTH points → 4 `ModInverse` calls total.

Modular inverse is the most expensive single big.Int operation in this codebase (Extended Euclidean Algorithm against a 1606-bit prime; orders of magnitude slower than `Mul`/`Add`/`Mod`). Eliminating 8 per verify is a meaningful hot-path win.

**The math:**

DALOS Twisted Edwards has parameter `a = 1` (verified across all 5 curve definitions in `Parameters.go`), so the affine equation is `x² + y² = 1 + d·x²·y²`. With `x = X/Z`, `y = Y/Z`, `T = XY/Z`, multiplying by `Z²` and using `x²·y² = T²/Z²` (since `T² = X²Y²/Z²`) gives the homogenized extended-coords curve equation:

    X² + Y² ≡ Z² + d·T² (mod p)

(Or for general `a`: `a·X² + Y² ≡ Z² + d·T²`.)

For point equality, two extended points represent the same affine point iff:

    X1·Z2 ≡ X2·Z1 (mod p)  AND  Y1·Z2 ≡ Y2·Z1 (mod p)

(Cross-multiply the affine equality `X1/Z1 == X2/Z2` and `Y1/Z1 == Y2/Z2` by `Z1·Z2`.)

**Cost comparison:**

| Operation | OLD (via `Extended2Affine`) | NEW (projective) | Win |
|---|---|---|---|
| `ArePointsEqual` | 4 `ModInverse` + 4 `Mul` | 4 `Mul` + 2 `Cmp` | **-4 inversions** |
| `IsOnCurve`      | 2 `ModInverse` + ~5 `Mul` + 2 `Add` | 5 `Mul` + 2 `Add` + 1 `Cmp` | **-2 inversions** |
| Per Schnorr verify (R + P + LHS==RHS) | 8 `ModInverse` | 0 `ModInverse` | **-8 inversions** |

**Implementation strategy (proof-first):**

1. Added private helpers `arePointsEqualProjective` + `isOnCurveExtended` to `Elliptic/PointOperations.go` alongside the unchanged public methods.
2. Added an extensive equivalence test suite in NEW file `Elliptic/PointOperations_perf_equiv_test.go`:
   - **`TestArePointsEqual_OldVsNew_Equivalence`** (3 sub-tests):
     - `same_point_self`: every point compares equal to itself in BOTH paths.
     - `same_projective_different_extended`: the cryptographically load-bearing case. Each base point is rescaled by 10 different non-zero factors (2, 3, 5, 7, 11, 13, 17, 19, 23, 29); each scaled extended representation projects to the same affine point. Both paths must return TRUE for the rescaled-vs-original pairs. Pre-fix this would have broken if `arePointsEqualProjective` failed to see through the Z-scaling. ✓ All passed.
     - `different_points`: full N×N cross-pair consistency check on 12 distinct on-curve points (G, [2]·G, [3]·G, [4]·G, a corpus-derived public key, and 7 scaled-G representations). Both paths return identical booleans on every pair. ✓
   - **`TestIsOnCurve_OldVsNew_Equivalence`** (3 sub-tests):
     - `on_curve_inputs`: 12 on-curve inputs; both paths return `(true, false)`. ✓
     - `off_curve_inputs`: 5 off-curve inputs `(1,1), (2,3), (5,7), (1,0), (0,0)`; both return `(false, false)`. ✓
     - `infinity_canonical`: HWCD canonical infinity `(0, 1, 1, 0)`; both return `(true, true)`. ✓
   - **`TestSchnorrVerify_RoundTrip_Corpus`**: end-to-end sign+verify on 5 messages including empty-string and a long phrase. ✓
3. Once equivalence proven on synthetic + corpus-derived inputs, swapped the public method bodies (`ArePointsEqual`, `IsOnCurve`) to delegate to the new helpers.
4. Re-ran full Go test suite **3 consecutive times** — all packages pass. ✓
5. Re-ran the corpus generator and verified **byte-identity SHA-256 preserved** on all three corpora:
   - `v1_genesis.json`     `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae` (unchanged since v3.0.0)
   - `v1_historical.json`  `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b` (unchanged since v3.0.0)
   - `v1_adversarial.json` `b9f228943106e1293c52a7e3d741520e58940b78816a2eeed7aa7332314b9d93` (matches committed baseline byte-for-byte)
6. Applied the same fix to TS port (`ts/src/gen1/curve.ts`): rewrote `isOnCurve` and `arePointsEqual` with the projective formulas. Note: TS keeps `m.mul(e.a, x2)` (vs Go's implicit `a=1`) because `e.a` is a curve parameter potentially varying across LETO/ARTEMIS/APOLLO; for DALOS `e.a === 1n` so the multiplication reduces to identity at runtime. TS `isInverseOnCurve` (separate from the Schnorr verify hot path) was deliberately NOT touched — same scope discipline as F-PERF-001.

**Critical security note: adversarial cofactor vectors STILL get rejected.** The `v1_adversarial.json` corpus contains 5 vectors:
- 4 with `expected_verify_result: false` (small-subgroup attack vectors that MUST be rejected by the cofactor + on-curve checks).
- 1 with `expected_verify_result: true` (legitimate control).

The corpus generator runs `SchnorrVerify` on each vector and writes both `expected_verify_result` (the spec) and `verify_actual` (what verify said). If F-PERF-003 had introduced any behavioral divergence — e.g., the new `IsOnCurve` accepting an off-curve point that the old one rejected — `verify_actual` would have flipped for at least one vector and the elided SHA-256 would have diverged from the committed baseline. **The fact that the elided SHA matches byte-for-byte is the strongest possible end-to-end empirical proof: the new helpers produce identical verify outcomes across every adversarial vector in the corpus.**

**Files touched:**
- `Elliptic/PointOperations.go`: added `arePointsEqualProjective` + `isOnCurveExtended` helpers; rewrote `ArePointsEqual` + `IsOnCurve` bodies to delegate to them.
- `Elliptic/PointOperations_perf_equiv_test.go`: NEW file. ~240 lines of equivalence proofs.
- `ts/src/gen1/curve.ts`: rewrote `arePointsEqual` + `isOnCurve` bodies. Comments updated.

**TS-side full validation passed:**
- `npm run typecheck` (tsc --noEmit): clean, no errors.
- `npm test` (vitest): **all 426 tests pass across 19 test files.**
- Critical cross-impl byte-identity assertions all green:
  - `schnorrSign (BYTE-IDENTITY vs Go corpus)`: all 20 Schnorr vectors produce byte-identical signatures.
  - `schnorrVerify — accepts all 20 committed signatures`: ✓
  - `schnorrSignAsync / schnorrVerifyAsync — equivalence with sync`: async path byte-identical to sync.
  - `fromBitString / fromSeedWords / fromBitmap (BYTE-IDENTITY END-TO-END vs Go corpus)`: all 50 + 15 + 20 deterministic vectors reproduce.
  - `BYTE-IDENTITY: APOLLO historical corpus`: all 5 APOLLO Schnorr vectors reproduce signature byte-for-byte and verify true.

This is the strongest possible cross-impl proof: the TS port — with the F-PERF-001 cofactor doublings AND the F-PERF-003 projective `arePointsEqual` + `isOnCurve` rewrites — produces byte-identical Schnorr signatures and verify results matching the Go-produced corpus across all 105 + 30 + 5 = 140 deterministic vectors. If either Go or TS had drifted behaviourally on the optimized paths, these byte-identity assertions would have failed immediately.

**Per-test latency observation:** the post-fix TS Schnorr verify suite (`schnorrVerify — accepts all 20 committed signatures`) ran in 4618ms (~230ms/verify on this machine). Pre-fix baseline isn't recorded but the perf delta is in the right direction; future benchmarks could quantify the speed-up explicitly.

### Library API hardening (`Elliptic/`)

#### F-ERR-002 — `ConvertBase49toBase10` alphabet validator + error return

Commit `efa59ec`. **Go-side breaking change**.

Pre-v4.0.1 the helper discarded `(*big.Int).SetString`'s `ok` return.
Per Go docs, the value of the result is *undefined* on parse failure
but the pointer is still returned, producing garbage that flowed
unchecked into `SchnorrSign`, `AESDecrypt`, and the Schnorr signature
parser.

Cross-impl parity gap: the TS port's `parseBigIntInBase`
(`ts/src/gen1/hashing.ts`) was hardened in REQ-21 to throw on invalid
base-49 chars. The Go side never received the matching fix until now.

Fix:
1. Add `IsValidBase49Char(c byte) bool` exported helper in
   `Elliptic/PointOperations.go` (mirrors TS `isValidBase49Char`).
2. Refactor `ConvertBase49toBase10` to return `(*big.Int, error)`:
   - empty input → error
   - any byte outside base-49 alphabet → error (names offending byte)
   - SetString failure → error (defense-in-depth)
3. Propagate at 4 production call sites with existing error returns
   (Schnorr.go:103, 143, 147; keystore/decrypt.go:18). The 5th call
   site in `SchnorrSign` initially used the empty-string sentinel
   pattern; that branch was refactored to a proper error in F-API-005.

4 new tests added at `Elliptic/Schnorr_strict_parser_test.go`.

#### F-ERR-003 — `PublicKeyToAddress` + `AffineToPublicKey` panic on malformed input

Commit `f04dae9`. Two latent crash/silent-corruption vectors in the
address-derivation helpers, sister functions to F-ERR-002:

`PublicKeyToAddress` (`Elliptic/KeyGeneration.go:44-54`):
1. `SplitString[1]` without length check → obscure index-out-of-range
   panic on input lacking the dot separator.
2. `(*big.Int).SetString(_, 49)` discarded the ok return → malformed
   base-49 input silently produced an undefined `*big.Int` that flowed
   through the seven-fold Blake3 chain into a "valid-looking" 160-char
   address bearing no relation to any real key.

`AffineToPublicKey` (`Elliptic/KeyGeneration.go:91-105`):
3. Nil `AX`/`AY` (zero-value `CoordAffine` reaching the function) →
   obscure "runtime error: invalid memory address or nil pointer
   dereference" on the first `.String()` call.

Fix: panic-at-entry with explicit messages naming the function and
offending field/condition. Matches the FP-001 / PO-3 / KG-3 fail-fast
convention and the TS port's throw-on-malformed-input behaviour.
Panic chosen over error-return because `DalosAddressMaker` has 11+
production callers (CLI flow + corpus generator) and changing the
return signature would ripple widely.

`PublicKeyToAddress` now uses the new `ConvertBase49toBase10` from
F-ERR-002 — closes the v4.0.1 hardening cluster end-to-end. 4 new
tests added (table-driven for the `AffineToPublicKey` nil cases).

#### F-ERR-007 — `SchnorrSign` range-check parsed private key

Commit `2d25469`. `SchnorrSign` computes `s = z + e·k mod Q`. Pre-v4.0.1
there was no check that the parsed `k` was in `[1, Q-1]`. The dangerous
case is `k = 0`:

  R = 0·G = O (point at infinity)
  s = z + e·0 mod Q = z

Result: a structurally-valid signature is emitted where R is infinity
and s == z — the signer's deterministic nonce is now public, embedded
in the signature.

Cross-impl parity: TS `schnorrSign` at `ts/src/gen1/schnorr.ts:317-360`
has equivalent guards via `parseBigIntInBase` + range validation
(REQ-21 + REQ-22).

Fix: 3-line range check immediately after the F-ERR-002 parse:

    if k.Sign() <= 0 || k.Cmp(&e.Q) >= 0 {
        return ""
    }

The `return ""` was later refactored to a proper error in F-API-005.
3 new tests (k=0, k=Q, k=Q+1, plus a happy-path positive control).

#### F-API-005 — `SchnorrSign` returns `(string, error)`

Commit `3dfc186`. **Go-side breaking change.**

Pre-v4.0.1 `SchnorrSign` returned `string`. Three internal-failure
conditions silently returned `""`:
- Malformed PRIV (added in F-ERR-002)
- `k` out of `[1, Q-1]` (added in F-ERR-007)
- Nil Fiat-Shamir challenge (original)

The CLI driver at `Dalos.go:284` printed the empty string under a
"Your Signature is:" banner with no detection. Pipe consumers
(`dalos -sign ... > sig.txt`) silently got an empty file.

Cross-language divergence: TS `schnorrSign` (`ts/src/gen1/schnorr.ts`)
throws `SchnorrSignError` on the same conditions. Go was the lone
surface still using a magic-empty-string sentinel.

Fix: signature changed to `(string, error)`. All three internal
failures now return descriptive errors via `fmt.Errorf`. Updated:
- `EllipseMethods` interface in `Elliptic/PointOperations.go:59`
  (Phase 11 compile-time conformance assertion).
- CLI caller `Dalos.go:284` → stderr + `os.Exit(1)`.
- 3 corpus-generator call sites in `testvectors/generator/main.go` →
  `must(err, ...)` (build-time tool; failing there is correct).
- 5 adversarial-test call sites + 4 strict-parser test call sites
  updated to handle the new return type.

1 new test (`TestSchnorrSign_RejectsMalformedPRIV`) added; the 3
existing F-ERR-007 tests updated to assert on `err != nil` instead of
the legacy empty-string sentinel.

---

### Verification

For every fix in this draft:
- `go build ./...` and `go vet ./...` clean.
- Full test suite passes (5 Go packages green).
- Genesis 105-vector corpus byte-identity preserved at extended-elided
  SHA-256:
  - `v1_genesis.json`     `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae`
  - `v1_historical.json`  `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b`

### Migration notes (Go-reference consumers only)

If you embed the Go reference directly (`import "DALOS_Crypto/Elliptic"`
or `"DALOS_Crypto/keystore"`), update call sites for the signature
changes:

```go
// v4.0.0
filename := keystore.GenerateFilenameFromPublicKey(publicKey)
err := keystore.ExportPrivateKey(e, bitString, password) // was: no return
sig := e.SchnorrSign(keyPair, message)
bigVal := el.ConvertBase49toBase10(s)

// v4.0.1
filename, err := keystore.GenerateFilenameFromPublicKey(publicKey)
if err != nil { /* handle malformed PUBL */ }

if err := keystore.ExportPrivateKey(e, bitString, password); err != nil {
    /* handle disk-full / partial-write / sync / close failure */
}

sig, err := e.SchnorrSign(keyPair, message)
if err != nil { /* handle malformed PRIV / k out-of-range / etc. */ }

bigVal, err := el.ConvertBase49toBase10(s)
if err != nil { /* handle malformed base-49 input */ }
```

The TypeScript package `@stoachain/dalos-crypto` is unaffected — no TS
public surface changed in v4.0.1.

---

### Outstanding from audit-cycle 2026-05-04

This draft covers fixes 1-13 of the audit triage session. Remaining
HIGH findings under triage (not yet decided):

- F-API-007 — `keystore.ExportPrivateKey` already-known-and-fixed-via-F-ERR-005? (validator overlap)
- F-API-008 — TS `from*` API entry points throw bare `Error`
- F-API-009 — `keystore.ImportPrivateKey` writes "DALOS Keys are being opened!" to stdout
- F-INT-002 — `ts-publish.yml` race + concurrency (FIXED, see below)
- F-INT-004 — Backfill list missing `ts-v4.0.0` (FIXED as side effect of F-INT-002)
- F-TEST-001 — No Go-side CI workflow (FIXED, see below)
- F-TEST-002 — `Bitmap/` package zero tests + scope ambiguity (FIXED, see below)
- F-TEST-003 — `keystore.AESDecrypt` + `ImportPrivateKey` direct tests + flaky-roundtrip fix (FIXED, see below)
- F-INT-002 — ts-publish.yml race vs ts-ci.yml + missing concurrency
- F-INT-003 — same as F-INT-002 (validator overlap)
- F-TEST-001 — No Go-side CI workflow
- F-TEST-002 — `Bitmap/` package zero tests
- F-TEST-003 — `keystore.AESDecrypt` + `keystore.ImportPrivateKey` zero direct tests

20 MEDIUMs and 20 LOWs not yet triaged. 3 NEEDS-CONTEXT findings
pending user judgment.

---

### Cumulative commit list

| Commit  | Finding   | Title (one line)                                                                |
|---------|-----------|---------------------------------------------------------------------------------|
| 844905a | F-CRIT-001 | Remove stray wallet artifact from repo root + ignore wallet-pattern .txt files |
| b72e588 | F-CRIT-002 | Invert -g validation guard at Dalos.go:119                                     |
| 2e27fca | F-SEC-002  | Wallet files written 0600 instead of 0644                                      |
| 3274d98 | F-ERR-001  | Bound SaveBitString password-confirm loop, exit on stdin EOF                   |
| efa59ec | F-ERR-002  | ConvertBase49toBase10 alphabet validator + error return                        |
| f04dae9 | F-ERR-003  | PublicKeyToAddress + AffineToPublicKey panic on malformed input                |
| f9ef84b | F-ERR-005  | ExportPrivateKey returns error, no silent wallet truncation                    |
| 2d25469 | F-ERR-007  | SchnorrSign range-check parsed private key                                     |
| 51aad47 | F-API-002  | Correct seed-word length error message wording                                 |
| ee92a1b | F-API-003  | GenerateFilenameFromPublicKey returns (string, error)                          |
| 9ed4751 | F-API-004  | Header-anchored wallet parser, CRLF-tolerant, no oracle                        |
| 3dfc186 | F-API-005  | SchnorrSign returns (string, error) + add v4.0.1 draft changelog               |
| 1af9394 | (meta)     | Backfill F-API-005 commit hash in this draft                                   |
| 12f7918 | (meta)     | Backfill cumulative table for F-API-005 + meta entry                           |
| 624d71b | F-API-006  | Bitmap.ValidateBitmap Godoc no longer claims work it doesn't do                |
| 2ed2a94 | (meta)     | Backfill F-API-006 commit hash                                                 |
| 67d7a35 | F-PERF-001 | Cofactor [4]·R/[4]·P via two HWCD doublings (Go + TS sync + TS async)          |
| 46e3c2e | (meta)     | Backfill F-PERF-001 commit hash                                                |
| d8a76d8 | F-PERF-003/004 | ArePointsEqual + IsOnCurve via projective coords (Go + TS) — proof-tested  |
| 8ea2c82 | (meta)     | Backfill F-PERF-003 commit hash                                                |
| a4739d4 | F-INT-002+004 | ts-publish.yml: concurrency guard + Node 20/22/24 matrix gates + ts-v4.0.0 backfill |
| 46c318e | (meta)     | Backfill F-INT-002 commit hash                                                 |
| efd0fe6 | F-TEST-001 | Add Go-side CI workflow + ADDING_NEW_PRIMITIVES.md playbook + CLAUDE.md pointer  |
| 32eb2c0 | (meta)     | Backfill F-TEST-001 commit hash                                                |
| 7ffb43e | F-TEST-002 | Bitmap package: scope docs (Go+TS) + Bitmap_test.go (9 tests, 30+ sub-cases)   |
| 23efdbf | (meta)     | Backfill F-TEST-002 commit hash                                                |
| f906556 | F-TEST-003 | keystore.AESDecrypt + ImportPrivateKey tests + roundTripFixture flake fix      |

---

**Pollinate handoff:** when triage is complete, copy the relevant
content above into `CHANGELOG.md` as a new `## [4.0.1] — YYYY-MM-DD`
section, bump `ts/package.json` version to `4.0.1`, run
`npm install --package-lock-only` to update `ts/package-lock.json`,
update README badges + tests count, then `/bee:pollinate`. The pollinate
preflight will refuse if `CHANGELOG.md` doesn't have the matching
section, so this draft → final-CHANGELOG.md move is mandatory before
the tag push.
