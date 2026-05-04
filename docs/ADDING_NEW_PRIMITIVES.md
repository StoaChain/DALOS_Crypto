# Adding new cryptographic primitives to DALOS_Crypto

> **Audience:** human contributors AND AI agents adding new cryptographic
> primitives to this codebase. Read this before touching any code that
> generates test vectors.

## TL;DR (the rules)

1. **Never change byte outputs of existing v1 corpus files.** `v1_genesis.json`, `v1_historical.json`, and `v1_adversarial.json` are the **frozen cryptographic contract**. CI fails if their SHA-256 changes.
2. **New primitives go in NEW corpus files.** Don't extend existing files; create `v2_<primitive_name>.json` (or similar — see naming below).
3. **New primitives implement BOTH Go and TypeScript** before merging. The TS port validates byte-identity against the Go-produced corpus on every test run; landing one without the other breaks the cross-impl invariant.
4. **Pin the new corpus's SHA-256 in `.github/workflows/go-ci.yml`** the moment you freeze it (i.e., when its outputs are stable and you're committing to never changing them).
5. **Use the registry pattern** for cross-language symmetry: implement the Go side as a separate package, expose via the `CryptographicPrimitive` adapter in `ts/src/registry/`.

If you follow those five rules, the existing CI gates will let your new primitive through cleanly. Skip any of them and CI will fire red — see the troubleshooting section at the end.

---

## What the frozen contract actually is

**Gen-1 = the original DALOS Genesis primitive.** Frozen at v1.0.0 (commit `d136e8d`). Three files define it byte-for-byte:

| File | Vectors | Frozen SHA-256 (extended-elided) |
|---|---|---|
| `testvectors/v1_genesis.json` | 50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr = 105 | `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae` |
| `testvectors/v1_historical.json` | 30 (LETO + ARTEMIS + APOLLO Schnorr + key-gen) | `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b` |
| `testvectors/v1_adversarial.json` | 5 (4 small-subgroup attacks + 1 control) | `b9f228943106e1293c52a7e3d741520e58940b78816a2eeed7aa7332314b9d93` |

The "extended-elided" SHA-256 is computed after running this `sed` recipe (documented in [`testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md)):

```bash
sed -e 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' \
    -e 's/"generator_version": "[^"]*"/"generator_version": "ELIDED"/' \
    -e 's/"host": "[^"]*"/"host": "ELIDED"/' \
    testvectors/v1_genesis.json | sha256sum
```

The three elided fields are metadata that legitimately drifts every regen (timestamp, generator-tool version string, hostname) without affecting the cryptographic content. Everything else must reproduce byte-for-byte forever.

### Invariants you must NOT break

These are the rules underpinning Gen-1. Violating any one of them perturbs the corpus and trips the CI gate:

1. **Schnorr v2 wire format** — length-prefixed Fiat-Shamir transcript, RFC-6979 deterministic nonces, domain tags `DALOS-gen1/SchnorrHash/v1` and `DALOS-gen1/SchnorrNonce/v1`. Defined in [`docs/SCHNORR_V2_SPEC.md`](SCHNORR_V2_SPEC.md).
2. **Twisted Edwards curve parameter `a = 1`** for DALOS, E521, LETO, ARTEMIS, APOLLO. Defined in `Elliptic/Parameters.go`.
3. **Base-49 alphabet:** `0-9, a-z, A-M`. Defined in `Elliptic/PointOperations.go::digitValueBase49` (Go) and `ts/src/gen1/scalar-mult.ts::BASE49_ALPHABET` (TS).
4. **AES-256-GCM with single-pass Blake3 KDF** for wallet encryption. Defined in `AES/AES.go`.
5. **TS-only deviation: AES IV high-nibble non-zero** — the TS port deliberately constrains the IV to sidestep a Go-era big.Int round-trip edge case. Documented in `README.md` "Hardening catalogue" and the source.
6. **Seven-fold Blake3 chain** for address derivation. Defined in `Elliptic/KeyGeneration.go::DalosAddressComputer`.
7. **40×40 = 1600-bit safe-scalar size** for DALOS Genesis. (Other curves have different scalar sizes — APOLLO is 32×32=1024; LETO is non-byte-aligned 545; ARTEMIS is 1023. Don't hard-code 1600 in shared helpers.)

If your new primitive needs to change any of these for the Gen-1 path, **stop**. Either you're not adding a new primitive (you're modifying Gen-1, which means you're forking the chain), or the existing primitive needs a different code path. New primitives use new files.

---

## How CI enforces this

[`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) runs on every push to `main` and every PR that touches Go code or `testvectors/`. The four gates:

1. `go build ./...` — compile check.
2. `go vet ./...` — static analysis.
3. `go test -timeout 120s ./...` — full unit suite.
4. **Corpus byte-identity check** — regenerate the three v1_*.json files and assert their elided SHA-256 matches the frozen baseline. **This is the cryptographic contract gate.**

The byte-identity check uses an associative array (`BASELINES`) at the top of the regen step. Adding a new primitive's frozen corpus is a one-line change to that array (see Step 6 below).

---

## The playbook: adding a new primitive

### Step 1: Implement the primitive in Go

- Create a new package under `Elliptic/` (or a new sibling package, depending on the primitive's domain). Example: `PostQuantum/Dilithium/`.
- Mirror the existing structure: separate `Parameters.go`, `KeyGeneration.go`, `Sign.go`, `Verify.go` files.
- **Do NOT modify any existing file in `Elliptic/`** that affects how Gen-1 vectors are produced. Helper functions used by Gen-1 (e.g., `MulModP`, `Blake3.SumCustom`, `digitValueBase49`) are off-limits unless you're adding a new helper alongside them.

### Step 2: Add a separate generator path

Edit [`testvectors/generator/main.go`](../testvectors/generator/main.go). Add a NEW function alongside the existing ones, e.g. `generateDilithiumCorpus()`. The function must:

- Write to a NEW file: `testvectors/v2_dilithium.json` (or whatever your naming convention is — see "Naming the new file" below).
- Use a NEW seeded RNG (don't share with `RNG_SEED_BITS` / `RNG_SEED_BITMAPS`; pick a new constant like `RNG_SEED_DILITHIUM = 0x... ` so the new vectors are deterministic but independent).
- Write the same metadata header structure: `schema_version`, `generated_at_utc`, `generator_version`, `host`, plus the primitive-specific vectors block.
- Include `expected_*` fields (e.g. `expected_verify_result: true|false` for adversarial vectors) so the corpus is self-validating.

Wire the new function into `main()` alongside the existing `generateDalosCorpus()` etc. Order doesn't matter — the existing functions still produce byte-identical output regardless of where in `main()` the new one goes.

### Step 3: Verify the existing CI gate STILL PASSES

Run locally:

```bash
go run testvectors/generator/main.go
sed -e 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' \
    -e 's/"generator_version": "[^"]*"/"generator_version": "ELIDED"/' \
    -e 's/"host": "[^"]*"/"host": "ELIDED"/' \
    testvectors/v1_genesis.json | sha256sum
```

Expected output: `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae`. If anything else, **you accidentally perturbed Gen-1**. Trace which shared helper your new code touched, and refactor to avoid the shared mutation.

Repeat for `v1_historical.json` (`80c93f4d...`) and `v1_adversarial.json` (`b9f228943106...`).

### Step 4: Implement the TypeScript port mirror

In `ts/src/`:

- New subpath module: `ts/src/dilithium/` (or whatever).
- Wire it into `ts/package.json::exports` as a new subpath: `"./dilithium": { ... }`.
- Re-export at top level from `ts/src/index.ts`.
- Implement byte-identical math against the Go reference. Use `@noble/hashes` or other audited primitives where available; vendor only if you must.

The TS port's tests (under `ts/tests/`) MUST include a byte-identity block that loads `testvectors/v2_dilithium.json` and asserts every vector reproduces. See `ts/tests/registry/historical-primitives.test.ts` for the existing pattern.

### Step 5: Cross-validate Go ↔ TS

Run `npm test` from `ts/`. Your new TS test file must pass — every vector in your new corpus reproduces exactly. If anything diverges, fix the TS implementation; the Go side is the canonical reference.

### Step 6: Freeze + add the CI gate

Once you're certain the new corpus is stable (i.e., its outputs are what you want for the rest of time), compute its frozen SHA-256:

```bash
sed -e 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' \
    -e 's/"generator_version": "[^"]*"/"generator_version": "ELIDED"/' \
    -e 's/"host": "[^"]*"/"host": "ELIDED"/' \
    testvectors/v2_dilithium.json | sha256sum
```

Edit `.github/workflows/go-ci.yml`. Find the `BASELINES` associative array. Add one line:

```yaml
declare -A BASELINES=(
  ["testvectors/v1_genesis.json"]="082f7a40..."
  ["testvectors/v1_historical.json"]="80c93f4d..."
  ["testvectors/v1_adversarial.json"]="b9f228943106..."
  ["testvectors/v2_dilithium.json"]="<your-new-sha-256>"   # ← NEW
)
```

That's the entire CI integration. From this point forward, any change that perturbs your new corpus fails CI just like Gen-1 changes do today.

### Step 7: Document the new primitive

- Update [`CLAUDE.md`](../CLAUDE.md) — add the new primitive to the "Architecture" section + the "Releases" section's invariants list (rule "vN [primitive_name] frozen at vX.Y.0").
- Update [`README.md`](../README.md) — add a new bullet under "Architecture" or "Cryptographic primitives".
- Update [`testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md) — add the new file's frozen hash + a one-line note ("v2_dilithium.json frozen at vX.Y.0, audit cycle YYYY-MM-DD").
- If the primitive has its own wire format spec (e.g., a Schnorr-v2-style spec doc), add it to `docs/`.

### Step 7.5 (CONDITIONAL): If your primitive uses a non-h=4 cofactor

The Schnorr verifier's cofactor check supports any cofactor `h` via the dispatch helper introduced in v4.0.2 (F-MED-017). However, **adding a non-h=4 curve requires more than just the dispatch — there are math-specific steps**: verifying `gcd(h, q) = 1`, hand-constructing h-torsion adversarial test vectors, mirroring the dispatch decision in TS, and updating the per-curve threat-model documentation.

**Read [`docs/COFACTOR_GENERALIZATION.md`](COFACTOR_GENERALIZATION.md) before adding any non-h=4 curve.** It covers the math (small-subgroup attacks, the cofactor-check derivation), the codebase locations that currently assume h=4, and the step-by-step playbook for adding a new-cofactor curve. The document includes a worked Ed25519 (h=8) example.

If your primitive uses `h = 4` (matching DALOS, LETO, ARTEMIS, APOLLO), no extra work — the existing fast path handles it. Skip this section.

### Step 8: Update the registry adapter (optional but recommended)

For cross-language symmetric usage, the project already has a registry pattern at `ts/src/registry/`. Existing entries: `genesis.ts`, `leto.ts`, `artemis.ts`, `apollo.ts`. Each adapts a primitive to the `CryptographicPrimitive` interface (defined in `ts/src/registry/primitive.ts`).

To add yours:
- New file `ts/src/registry/dilithium.ts` implementing the interface.
- Register in `ts/src/registry/index.ts`'s `CryptographicRegistry` constructor.
- Add tests under `ts/tests/registry/`.

The Go side currently has no equivalent registry layer (one of the audit's findings, not yet addressed). For now, the Go-side use is via direct package imports.

---

## Naming the new corpus file

Convention: `vN_<primitive_name>.json` where:
- `N` = the major-version generation. Currently `v1` is Gen-1 (DALOS Genesis + the historical curves + adversarial). New post-quantum primitives would be `v2`. New cipher primitives (e.g., a future hybrid scheme) would also be `v2` if introduced concurrently.
- `<primitive_name>` = lowercase, snake_case, no spaces. Examples: `dilithium`, `kyber`, `falcon`, `sphincs_plus`.

If you're not sure what generation number to use, ask in the PR description. The convention errs toward grouping (`v2_*` for several post-quantum primitives that ship in the same release cycle) rather than per-primitive versioning.

---

## What to do if the SHA gate fires red

The CI step prints the offending file, the expected SHA, the actual SHA, and the first 60 lines of the diff. Use that to diagnose:

### Diagnosis 1: did you intentionally change Gen-1 outputs?

If yes, **you probably shouldn't have**. Gen-1 is frozen forever. Either:
- You meant to add a new primitive but accidentally modified Gen-1's path → see "I touched a shared helper" below.
- You meant to fix a Gen-1 bug → this is allowed but rare; talk to the project maintainer first. Updating the SHA pin is a deliberate "I am breaking the cryptographic contract" act.

### Diagnosis 2: did you touch a shared helper?

Common culprits:
- `Blake3/Blake3.go` — every key-gen path uses it.
- `AES/AES.go` — wallet encryption.
- `Elliptic/Parameters.go` — curve parameters.
- `Elliptic/PointOperations.go::ScalarMultiplier` (and friends) — scalar mult.
- `Elliptic/PointConverter.go::QuoModulus`, `MulModulus`, etc. — modular arithmetic.
- `Elliptic/KeyGeneration.go::DalosAddressComputer` — address derivation.

Trace which call sites in the existing v1 generators feed into your changed function. If your new primitive needed a slight tweak to one of these, **don't tweak the existing function**. Add a sibling function (e.g., `MulModulusV2`) and have the new primitive's code call the new sibling. Gen-1 keeps using the original.

### Diagnosis 3: did test vector generator paths get mixed up?

Check `testvectors/generator/main.go`:
- Does your new function share an RNG with the existing functions? If yes, your new primitive's seeded RNG calls would shift the byte stream the existing functions consume → Gen-1 vectors drift.
- Does your new function write to one of the v1_*.json files instead of its own new file? Likely a copy-paste error.

### Diagnosis 4: nothing of the above applies

Read the diff line-by-line. The CI step prints up to 60 lines. If the diff is in metadata fields that should be elided, the elision recipe might need updating (rare). If the diff is in cryptographic content (scalars, public keys, signatures, addresses), trace the change to its source.

If you're truly stuck, revert your change locally, regenerate the corpus, confirm SHA matches, then re-apply your change one piece at a time (`git add -p`) regenerating between each piece until you find the line that flips the SHA.

---

## Related documents

- [`CLAUDE.md`](../CLAUDE.md) — project orientation, invariants list.
- [`testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md) — per-release SHA-256 history + elision recipe specification.
- [`docs/SCHNORR_V2_SPEC.md`](SCHNORR_V2_SPEC.md) — Schnorr v2 wire format (frozen at v2.0.0).
- [`docs/HISTORICAL_CURVES.md`](HISTORICAL_CURVES.md) — LETO/ARTEMIS/APOLLO parameters.
- [`docs/CHANGELOG-v4.0.1-draft.md`](CHANGELOG-v4.0.1-draft.md) — running changelog of the audit-2026-05-04 cycle's fixes (will be folded into `CHANGELOG.md` at release).
- [`README.md`](../README.md) — public-facing project intro.

---

## For AI agents

If you're an AI agent working on this codebase:

- **Read this entire document before adding a new primitive.** The TL;DR at the top + the playbook section is enough for routine additions; the troubleshooting section is for when the CI gate fires red.
- **Always run the corpus byte-identity check locally before pushing.** The CI gate is the safety net; running locally is the discipline.
- **Never modify the BASELINES array in `.github/workflows/go-ci.yml` to "fix" a failing gate.** The gate failing means you broke something. Updating the pin masks the breakage. The only legitimate reason to update an existing pin is when the project maintainer has explicitly authorized a contract break (rare).
- **The byte-identity assertions in `ts/tests/` are authoritative for cross-impl correctness.** If TS reproduces the corpus, the implementations agree. If TS diverges, fix TS to match Go (Go is the reference).
