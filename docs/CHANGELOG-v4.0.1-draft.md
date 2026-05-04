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
- F-PERF-001 — Cofactor [4]·R / [4]·P rebuilds 48-element PrecomputeMatrix
- F-PERF-003 — Extended2Affine 4 ModInverses per Schnorr verify
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

---

**Pollinate handoff:** when triage is complete, copy the relevant
content above into `CHANGELOG.md` as a new `## [4.0.1] — YYYY-MM-DD`
section, bump `ts/package.json` version to `4.0.1`, run
`npm install --package-lock-only` to update `ts/package-lock.json`,
update README badges + tests count, then `/bee:pollinate`. The pollinate
preflight will refuse if `CHANGELOG.md` doesn't have the matching
section, so this draft → final-CHANGELOG.md move is mandatory before
the tag push.
