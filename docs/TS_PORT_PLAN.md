# DALOS Cryptography — TypeScript Port Plan (v2)

> Canonical roadmap for porting the Genesis Go reference to TypeScript,
> removing the `go.ouronetwork.io/api/generate` dependency from the
> Ouronet UI, and publishing DALOS as a usable standalone library.
>
> **Plan version:** v2 (2026-04-23). Supersedes v1 by incorporating the
> 40×40 bitmap input type, locked Genesis conventions, and current
> repository state.

---

## Vision

1. **End reliance on `go.ouronetwork.io/api/generate`.** Every Ouronet address today is generated on a remote Go server; private keys briefly traverse HTTPS. **Move all of this into the browser/client.**
2. **Port the whole DALOS crypto stack to TypeScript** — self-contained, auditable, consumable by any JavaScript/TypeScript project.
3. **Modular primitive registry.** Genesis = `dalos-gen-1`. Future generations register alongside without breaking Gen-1 addresses.
4. **Expose publicly.** Documented API, npm-published, usable by third parties under the AncientHoldings GmbH proprietary licence.
5. **Preserve bit-identity with the Go reference.** Every existing Ouronet account must remain valid and re-derivable from the same inputs.

---

## Locked Decisions (do not churn mid-port)

These decisions are fixed. Revisiting them requires an explicit re-planning pass and a new plan version.

| Area | Locked to | Rationale |
|------|-----------|-----------|
| **Package architecture** | 3 layers: `@stoachain/dalos-blake3` → `@stoachain/dalos-crypto` → `@stoachain/ouronet-core` | Each layer independently auditable + publishable |
| **Genesis curve** | 1606-bit TE curve, A=1, D=-26, unchanged from Go | Mathematical verification passed all 7 tests; 1600 bits is ample |
| **Key-gen input types** | 6: random, bitstring, int base-10, int base-49, seed words, 40×40 bitmap | Covers all UX cases |
| **Bitmap convention** | 40×40 pixels, **black = 1, white = 0**, **row-major top-to-bottom, left-to-right**, **strict pure B/W** | Simplest, universal, no scan-order ambiguity |
| **AES wrapper** | Keep as-is: AES-256-GCM with single-pass Blake3 KDF | Changing KDF breaks encrypted-file format without affecting account strings |
| **Schnorr hardening** | Apply all 7 Category-B fixes in the TS port | No on-chain Schnorr signatures exist, so no user impact |
| **Genesis freeze** | `Ѻ.` / `Σ.` addresses derived via `dalos-gen-1` are permanent and never change bit-for-bit | Preserves every existing Ouronet account |
| **Blake3 implementation** | `@noble/hashes/blake3` (spec-compliant, audited), cross-verified against Go fork | User externally validated Blake3 spec match |
| **Post-quantum direction** | NOT bigger curves. Research PQ primitives separately (see `FUTURE.md`) | Shor breaks any ECC; curve size is irrelevant |
| **Licence** | Proprietary, AncientHoldings GmbH, Kjrekntolopon as author | Per [`LICENSE`](../LICENSE) |

---

## Scope

**In scope:**

- All 6 key-gen input types including the new 40×40 bitmap (Phase 0a adds this to the Go reference first)
- Twisted Edwards point arithmetic (HWCD formulas)
- Seven-fold Blake3 + 16×16 character matrix address encoding
- AES-256-GCM wrapper for encrypted-file export (bit-identical to Go)
- Schnorr sign/verify with 7 Category-B hardening items
- Modular `CryptographicPrimitive` interface + registry
- Integration with `@stoachain/ouronet-core`'s `Codex` class
- Browser UI migration to remove `go.ouronetwork.io` call
- Reproducibility: every TS output validated byte-for-byte against Go test vectors

**Out of scope for this plan:**

- DALOS Schnorr activated as on-chain authentication (requires Pact / chain-side work)
- Third-party cryptographic audit (recommended, budgeted separately)
- WASM compilation (Phase 10 decides if perf demands it)
- Hardware wallet integration (`FUTURE.md`)
- Post-quantum primitives (`FUTURE.md`)
- Bigger curves (`FUTURE.md` — explicitly NOT pursued)

---

## Source-code inventory

| Repo / subpath | Lines | What |
|---|---|---|
| `StoaChain/DALOS_Crypto/Auxilliary/` | 8 | `TrimFirstRune` helper |
| `StoaChain/DALOS_Crypto/Elliptic/Parameters.go` | 224 | Ellipse struct, curve definitions |
| `StoaChain/DALOS_Crypto/Elliptic/PointConverter.go` | 103 | Coord types + modular arithmetic |
| `StoaChain/DALOS_Crypto/Elliptic/PointOperations.go` | 734 | HWCD + scalar mult |
| `StoaChain/DALOS_Crypto/Elliptic/KeyGeneration.go` | 921 | Keygen API + character matrix |
| `StoaChain/DALOS_Crypto/Elliptic/Schnorr.go` | 256 | Sign + verify |
| `StoaChain/DALOS_Crypto/Blake3/` | 451 | Blake3 XOF (inlined v1.1.0) |
| `StoaChain/DALOS_Crypto/AES/` | 135 | AES-256-GCM + Blake3 KDF (inlined v1.1.0) |
| `StoaChain/DALOS_Crypto/Dalos.go` | 288 | CLI driver (not ported) |
| **Total crypto-relevant** | **~2832** | (excluding CLI driver) |

Plus, to be added in Phase 0a:

| Path | Est. lines | What |
|------|-----------|------|
| `StoaChain/DALOS_Crypto/Bitmap/Bitmap.go` | ~150 | 40×40 → bitstring + validation |

---

## Package architecture (target state)

```
┌───────────────────────────────────┐
│  StoaChain/OuronetUI              │
│  • React app                      │
│  • No direct DALOS code           │
│  • Uses: @stoachain/ouronet-core  │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│  StoaChain/OuronetCore            │
│  npm: @stoachain/ouronet-core     │
│  • Codex, pact, signing, etc.     │
│  • Uses: @stoachain/dalos-crypto  │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│  StoaChain/DALOS_Crypto/ts/       │
│  npm: @stoachain/dalos-crypto     │
│  • All Genesis primitives         │
│  • CryptographicRegistry          │
│  • Uses: @stoachain/dalos-blake3  │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│  StoaChain/Blake3/ts/             │
│  npm: @stoachain/dalos-blake3     │
│  • Blake3 + XOF + seven-fold      │
│  • Wraps @noble/hashes/blake3     │
└───────────────────────────────────┘
```

Each package has its own version cadence. The three-layer split means third parties can consume `@stoachain/dalos-crypto` without the blockchain weight of `ouronet-core`.

---

## Cross-phase invariants (enforced on every commit)

1. **`go build ./...` in `StoaChain/DALOS_Crypto/` must remain clean.** `go vet ./...` likewise.
2. **Every TypeScript output must match the Go test-vector corpus byte-for-byte** for all deterministic paths (bitstring, integer, seed words, bitmap). Schnorr signatures may differ (random nonce in Genesis mode) but must self-verify 100%.
3. **The canonical SHA-256 of `testvectors/v1_genesis.json`** must be documented in `CHANGELOG.md` at every release that regenerates it.
4. **Every new feature updates `CHANGELOG.md`**. Every release gets a git tag (`v<major>.<minor>.<patch>`).
5. **Genesis key-gen path never changes output.** Any proposed change becomes a Gen-2 feature, registered under a new primitive ID.
6. **No secrets in commits** — no real private keys in examples, only synthetic test vectors.
7. **CI (when set up in Phase 0b)** runs: Go build + vet + test-vector regeneration (determinism check) + TS build + TS tests + lint.

---

## Versioning policy

Semantic versioning, pinned to Genesis freeze:

- **Patch bump (1.x.Y)** — documentation, tests, audit findings, verification scripts
- **Minor bump (1.Y.0)** — new features that preserve Genesis freeze (bitmap input, new primitive in the registry, TS port milestones)
- **Major bump (X.0.0)** — reserved for breaking changes that would NOT be backward-compatible. Expected to be rare. Post-quantum primitive lands as a **new primitive ID**, not a major version bump, since existing Gen-1 accounts remain valid.

**Current version:** `v1.1.2` (as of 2026-04-23).

---

# Phases

## Status overview

| # | Phase | State | Effort | Key deliverable |
|---|-------|-------|--------|-----------------|
| 0 | Audit + Math Verification + Self-Containment | ✅ DONE | 1 wk | `v1.0.0` … `v1.1.2` |
| 0a | Bitmap Input to Go Reference | ✅ DONE (v1.2.0) | 2-3 d | `Bitmap/Bitmap.go` + 20 bitmap test vectors |
| 0c | Go Category-A Hardening | ✅ DONE (v1.3.0) | 5-7 d | PO-1 constant-time scalar mult + SC-4/5/6/7 Schnorr verify hardening |
| 0d | Go Schnorr Category-B Hardening | ✅ DONE (v2.0.0) | 3 d | SC-1/2/3 (length-prefix, RFC-6979 nonces, domain tag); `docs/SCHNORR_V2_SPEC.md` |
| 0b | TypeScript Build Scaffold | ✅ DONE (v2.2.0) | 1-2 d | `ts/` with package.json (0.0.1), TypeScript 5.7, Vitest 2.1, Biome 1.9, CI across Node 20/22/24. 7/7 scaffold tests pass. |
| 1 | TS Math Foundation | ⏳ | 2 wk | `ts/src/gen1/math+coords+curve+point-ops.ts` |
| 2 | TS Scalar Multiplication | ⏳ | 1 wk | `ts/src/gen1/scalar-mult.ts` |
| 3 | TS Hashing + `@stoachain/dalos-blake3` | ⏳ | 2-3 d | Two packages tagged |
| 4 | TS Key Generation API (all 6 inputs) | ⏳ | 1 wk | `ts/src/gen1/key-gen.ts` |
| 5 | TS AES Encryption Port (as-is) | ⏳ | 3-5 d | `ts/src/gen1/aes.ts` |
| 6 | TS Schnorr Hardened | ⏳ | 1 wk | `ts/src/gen1/schnorr.ts` |
| 7 | TS Modular Primitive Registry | ⏳ | 1 wk | `ts/src/registry/` |
| 8 | Integration into `@stoachain/ouronet-core` | ⏳ | 1 wk | Core uses registry |
| 9 | OuronetUI Migration | ⏳ | 3-5 d | `go.ouronetwork.io` call removed |
| 10 | Performance Optimisation (conditional) | ⏳ | 1-2 wk | Web Worker + maybe WASM |
| 11 | Documentation + Public npm Publish | ⏳ | 1 wk | `@stoachain/dalos-crypto@1.0.0` live |
| 12 | Go Server Retirement (optional) | ⏳ | 1 wk | Post 4-week soak |

**Total for remaining phases: 11–14 weeks of focused work.**

---

## Phase 0 — Audit + Verification + Self-Containment ✅ DONE

**Delivered in v1.0.0, v1.1.0, v1.1.1, v1.1.2** (2026-04-23):

- Full source audit of all Go files with findings catalogued in [`AUDIT.md`](../AUDIT.md)
- Mathematical verification via 7 independent tests (Python + Sage), all PASS — see [`verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md)
- AES-256-GCM confirmed as the Go reference cipher
- Blake3 + AES inlined from `StoaChain/Blake3`, repo now self-contained
- 85 deterministic test vectors committed at [`testvectors/v1_genesis.json`](../testvectors/v1_genesis.json), SHA-256: `0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db`
- Test-vector validation log at [`testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md)
- Author credit: Kjrekntolopon@ancientholdings.eu
- Future R&D directions documented in [`docs/FUTURE.md`](FUTURE.md)
- `v1.0.0` git tag marks the permanent Genesis reference commit

---

## Phase 0a — Bitmap Input to Go Reference ✅ DONE (v1.2.0, 2026-04-23)

**Goal:** Add the 40×40 bitmap as a 6th key-gen input path to the Go reference, generate bitmap test vectors, release `v1.2.0`. The TypeScript port (Phase 4) then has Go-validated bitmap vectors to match against.

**Why do this in Go first?** The invariant "Go is always the reference" holds only if every input type has a Go implementation to match. Adding bitmap to TS without Go would be a port without an oracle.

**Inputs:**

- Locked bitmap convention: 40×40, black=1, white=0, row-major TTB-LTR, strict pure B/W

**Steps:**

1. **Create `StoaChain/DALOS_Crypto/Bitmap/Bitmap.go`** with:
   - `type Bitmap = [40][40]bool` (or `[1600]bool`, TBD by Go aesthetics)
   - `func BitmapToBitString(b Bitmap) string` — 1600-char "01..." string
   - `func BitStringToBitmap(s string) (Bitmap, error)` — reverse for visualisation (public-safe: only a bitstring input; deriving bitmap from a bitstring reveals the key and is ONLY exposed as a diagnostic/visualisation function with an explicit "I know this reveals the key" argument name)
   - `func ValidateBitmap(b Bitmap) error` — trivial; any [40][40]bool is valid
   - `func ParsePngFileToBitmap(path string) (Bitmap, error)` — reads a PNG, asserts 40×40, thresholds pure black/white, errors on any grey pixel
   - `func ParseAsciiBitmap(rows []string) (Bitmap, error)` — reads 40 rows × 40 chars each, `#` = 1, `.` = 0
2. **Wire into KeyGeneration:**
   - `func (e *Ellipse) GenerateFromBitmap(b Bitmap) (DalosKeyPair, error)` in `Elliptic/KeyGeneration.go` — calls `BitmapToBitString` then existing `GenerateScalarFromBitString` path. No new crypto; pure input reshape.
3. **Add CLI flag** `-bitmap <path>` in `Dalos.go` (optional, low priority — CLI isn't being ported)
4. **Extend `testvectors/generator/main.go`** with:
   - 10× all-zero bitmap, all-ones bitmap, checkerboard, stripes, concentric squares, diagonal line, "smiley" pattern, random patterns (deterministic RNG) — each with the derived bitstring, scalar, priv, pubkey, addresses
5. **Regenerate `testvectors/v1_genesis.json`.** New canonical SHA-256 logged in CHANGELOG and VALIDATION_LOG.
6. **Update docs:**
   - `README.md` — note 6 input types
   - `AUDIT.md` — bitmap section (input reshape only, no crypto change)
   - `FUTURE.md` — confirm scan-order variants remain future work

**Deliverables:**

- `Bitmap/Bitmap.go` with the 5 functions above
- `Bitmap/Bitmap_test.go` with basic roundtrips (optional; Go test harness would be a departure from current style)
- Integration into `Elliptic/KeyGeneration.go`
- ~15 new bitmap test vectors in `v1_genesis.json`
- Updated `VALIDATION_LOG.md` with new canonical hash
- `v1.2.0` tag + CHANGELOG entry

**Exit criteria:**

- `go build ./...` clean
- `go vet ./...` clean
- New bitmap test vectors pass determinism check (regenerate → byte-identical)
- `GenerateFromBitmap(all-zero) = GenerateFromBitString("000...0")` — proves the reshape is equivalent

**Effort:** 2-3 days.

**Risks:**

- PNG parsing complexity on Windows (cross-platform file paths) — mitigated by keeping the primary input as ASCII strings (`#` / `.`) and treating PNG as a nice-to-have.
- Bit packing subtlety (how exactly do 1600 bits map to base-49 integer?) — answer: identical to bitstring path since we convert to bitstring first. Zero ambiguity.

---

## Phase 0b — TypeScript Build Scaffold (1-2 days)

**Goal:** Stand up `ts/` subdirectory with complete tooling so Phase 1 can begin coding.

**Toolchain decisions (locked):**

| Component | Choice | Why |
|-----------|--------|-----|
| Language | TypeScript 5.x, target ES2022 | Current, BigInt native |
| Package manager | npm | Matches ouronet-core |
| Build | `tsc` only (no bundler) | Library, not app. Consumers bundle |
| Tests | Vitest | Fast, native ESM, TS-first |
| Lint/format | Biome | One tool for both; fast |
| Fixtures | Load `../testvectors/v1_genesis.json` via Vitest `setup.ts` | One source of truth |

**Steps:**

1. **Create `StoaChain/DALOS_Crypto/ts/`** directory
2. **`ts/package.json`:**
   ```json
   {
     "name": "@stoachain/dalos-crypto",
     "version": "0.0.1",
     "description": "DALOS Cryptography — Genesis TypeScript port",
     "type": "module",
     "main": "./dist/index.js",
     "types": "./dist/index.d.ts",
     "exports": { /* subpath exports */ },
     "scripts": {
       "build": "tsc",
       "test": "vitest run",
       "test:watch": "vitest",
       "lint": "biome check src",
       "format": "biome format --write src"
     },
     "devDependencies": { /* TypeScript, Vitest, Biome */ },
     "dependencies": { "@stoachain/dalos-blake3": "^0.0.1" },
     "publishConfig": { "access": "public", "registry": "https://registry.npmjs.org" }
   }
   ```
3. **`ts/tsconfig.json`** — strict, ES2022 target, declaration output
4. **`ts/biome.json`** — formatter + linter rules
5. **`ts/vitest.config.ts`** — points at `src/**/*.test.ts`, loads Go test vectors in setup
6. **`ts/src/index.ts`** — placeholder `export {}` so `tsc` runs
7. **`ts/tests/fixtures.ts`** — loads & parses `../testvectors/v1_genesis.json` once, exposes typed vectors
8. **`.github/workflows/ts-ci.yml`** — on push: lint, build, test
9. **Update root `README.md`** with the new `ts/` entry in the repo structure
10. **Sibling work: create `StoaChain/Blake3/ts/`** with identical scaffold, package name `@stoachain/dalos-blake3`, version `0.0.1`, single dep on `@noble/hashes`. Stub `src/index.ts` exports `blake3` and `blake3XOF` re-exports for now.

**Deliverables:**

- Working `npm install && npm run build && npm test` (test suite empty, must still pass with 0/0)
- CI workflow on GitHub
- Blake3 scaffold in sibling repo
- `v1.3.0` tag

**Exit criteria:**

- `ts/dist/index.js` exists after build (empty but valid)
- CI green on main
- `@stoachain/dalos-blake3@0.0.1` ready to publish (not published yet — published in Phase 3 when it has content)

**Effort:** 1-2 days.

**Risks:** Minimal. Standard TypeScript project setup.

---

## Phase 1 — TypeScript Math Foundation ✅ DONE (v2.3.0, 2026-04-23)

**Landed:** `ts/src/gen1/math.ts` (Modular class + byte/bigint helpers), `coords.ts` (4 coord types + INFINITY_POINT_EXTENDED), `curve.ts` (DALOS_ELLIPSE constant + affine↔extended conversions + on-curve / infinity / equality predicates), `point-ops.ts` (HWCD addition V1/V2/V3, doubling V1/V2, tripling, fortyNiner, precomputeMatrix).

**Verified:** 63/63 tests pass. Algebraic identity checks confirm line-by-line port:
- `addition(G, G) === doubling(G)`
- `tripling(G) === addition(G, doubling(G)) === addition(addition(G, G), G)`
- `fortyNiner(G) === 48 chained additions of G`
- `precomputeMatrix[i][j]` at every slot equals `(i·7 + j + 1)·G` computed via the naive chain

Ready for Phase 2 (base-49 Horner scalar multiplication).

---

## Phase 1 — TypeScript Math Foundation (pre-landing spec; kept for reference) (2 weeks)

**Goal:** Port the pure-arithmetic layer. Every function validated against Go test vectors.

**Subpath:** `@stoachain/dalos-crypto/gen1/` (Genesis)

**Files to create:**

- `ts/src/gen1/math.ts` — modular arithmetic
- `ts/src/gen1/coords.ts` — 4 coord types
- `ts/src/gen1/curve.ts` — `DALOS_ELLIPSE` constant + predicates
- `ts/src/gen1/point-ops.ts` — HWCD formulas
- `ts/tests/gen1/math.test.ts`, `coords.test.ts`, `curve.test.ts`, `point-ops.test.ts`

**Detailed steps:**

1. **Modular class** (`math.ts`):
   ```ts
   export class Modular {
     constructor(public readonly p: bigint);
     add(a: bigint, b: bigint): bigint;
     sub(a: bigint, b: bigint): bigint;
     mul(a: bigint, b: bigint): bigint;
     inv(a: bigint): bigint;                   // via pow(a, -1, p), native since TS 5.x
     div(a: bigint, b: bigint): bigint;        // a * inv(b)
     exp(a: bigint, e: bigint): bigint;
     neg(a: bigint): bigint;                   // -a mod p, always in [0, p)
   }
   ```
2. **Coord types** (`coords.ts`):
   ```ts
   export interface CoordAffine    { ax: bigint; ay: bigint; }
   export interface CoordExtended  { ex: bigint; ey: bigint; ez: bigint; et: bigint; }
   export interface CoordInverted  { ix: bigint; iy: bigint; iz: bigint; }
   export interface CoordProjective{ px: bigint; py: bigint; pz: bigint; }
   ```
3. **Ellipse constant** (`curve.ts`):
   ```ts
   export interface Ellipse {
     readonly name: string;
     readonly p: bigint;
     readonly q: bigint;
     readonly t: bigint;
     readonly r: bigint;
     readonly s: number;       // 1600
     readonly a: bigint;       // 1
     readonly d: bigint;       // -26
     readonly g: CoordAffine;
   }
   export const DALOS_ELLIPSE: Ellipse = { /* literal values from Parameters.go */ };
   ```
4. **Predicates:**
   ```ts
   isInfinityPoint(p: CoordExtended): boolean;
   isOnCurve(p: CoordAffine): boolean;
   arePointsEqual(p1: CoordExtended, p2: CoordExtended): boolean;
   ```
5. **Coordinate conversions:**
   ```ts
   affine2Extended(p: CoordAffine): CoordExtended;
   extended2Affine(p: CoordExtended): CoordAffine;
   ```
6. **Point operations** (all from hyperelliptic.org EFD, port line-by-line):
   - `additionV1(p1, p2)` = `mmadd-2008-hwcd`
   - `additionV2(p1, p2)` = `madd-2008-hwcd-2`
   - `additionV3(p1, p2)` = `add-2008-hwcd` (general)
   - `addition(p1, p2)` — dispatcher with V1/V2/V3 selection
   - `doublingV1(p)` = `mdbl-2008-hwcd`
   - `doublingV2(p)` = `dbl-2008-hwcd`
   - `doubling(p)` — dispatcher
   - `tripling(p)` = `tpl-2015-c`
   - `fortyNiner(p)` — `49·P` via chained operations

**Testing strategy:**

- Cross-port Go `TestPointOperations_*` tests if they exist; otherwise, synthesise:
  - `addition(G, G) === doubling(G)`
  - `addition(G, infinity) === G`
  - `doubling(G) === additionV1(G, G)` (match both formula families)
  - `tripling(G) === addition(G, doubling(G))`
  - `fortyNiner(G)` matches `scalar_mult(49, G)` from a hand computation
- From test vectors: compute `49·G` — should match Go output byte-exact at the level of affine (X, Y) big-decimal strings.

**Deliverables:**

- 4 `.ts` files, each with exported API + JSDoc
- 80–100 passing tests
- Benchmarks documenting ms/operation for each op on CPython-vs-Node-comparable hardware

**Exit criteria:**

- All tests green
- `49·G` computed in TS matches the first test vector's computation path (we can synthesise this via the existing Go generator by adding a Phase-1-check output)

**Effort:** 2 weeks.

**Risks:**

- HWCD formula variants — there are multiple in the EFD; the Go code picks specific ones. Port must match exactly. Mitigation: read `PointOperations.go` line-by-line, match opcode-for-opcode.
- Big-int performance for 1606-bit operands in Node — probably slow first pass. Phase 10 optimises if needed.

---

## Phase 2 — TypeScript Scalar Multiplication ✅ DONE (v2.4.0, 2026-04-23)

**Landed:** `ts/src/gen1/scalar-mult.ts` with `BASE49_ALPHABET`, `digitValueBase49`, `bigIntToBase49`, `scalarMultiplier`, `scalarMultiplierWithGenerator`.

**Verified:** 92/92 tests pass. **Critical `[Q]·G = O` test passed in ~800 ms** — a full 1604-bit scalar multiplication producing the identity element, proving end-to-end correctness of both the Phase 2 algorithm and all Phase 1 point operations.

Ready for Phase 3 (hashing + `@stoachain/dalos-blake3`).

---

## Phase 2 — TypeScript Scalar Multiplication (pre-landing spec; kept for reference) (1 week)

**Goal:** Port `PrecomputeMatrix` and `ScalarMultiplier` — base-49 Horner evaluator — plus a constant-time Montgomery ladder variant.

**Files:**

- `ts/src/gen1/scalar-mult.ts`
- `ts/tests/gen1/scalar-mult.test.ts`

**Steps:**

1. **PrecomputeMatrix:**
   ```ts
   export function precomputeMatrix(p: CoordExtended): CoordExtended[] {
     // Returns [1·P, 2·P, 3·P, ..., 49·P]
     // Built via alternating double + add, matching Go's construction
   }
   ```
2. **Base-49 alphabet:** must match Go's `big.Int.Text(49)` exactly: `"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"` (10 + 26 + 13 = 49).
3. **ScalarMultiplier** (branching, matches Go byte-for-byte):
   ```ts
   export function scalarMultiplier(k: bigint, p: CoordExtended): CoordExtended {
     const pm = precomputeMatrix(p);
     const digits = toBase49(k);    // most-significant-first
     let acc: CoordExtended = INFINITY;
     for (let i = 0; i < digits.length; i++) {
       const d = digits[i];
       if (d > 0) acc = addition(acc, pm[d - 1]);  // pm[0] = 1·P
       if (i < digits.length - 1) acc = fortyNiner(acc);
     }
     return acc;
   }
   ```
4. **ScalarMultiplierWithGenerator** — cached PM for the ellipse generator G. Called once during module init.
5. **Montgomery ladder (constant-time variant):**
   ```ts
   export function scalarMultiplierCT(k: bigint, p: CoordExtended): CoordExtended {
     // Constant-time binary ladder. Output same as scalarMultiplier.
     // For future use where timing side channels matter.
   }
   ```

**Testing:**

- `scalarMultiplier(1, G) === G`
- `scalarMultiplier(2, G) === doubling(G)`
- `scalarMultiplier(0, G) === INFINITY`
- **`scalarMultiplier(Q, G) === INFINITY`** — critical; verifies G has order Q (already proven by Python; this double-checks the TS port)
- Against 50 test-vector scalars: bit-identical affine X/Y output to Go
- `scalarMultiplierCT(k, G) === scalarMultiplier(k, G)` for 50 random k

**Deliverables:**

- 1 `.ts` file
- 100+ tests
- Benchmark: ms per `scalarMultiplier(Q, G)`

**Exit criteria:**

- All tests green
- Critical `[Q]·G = INFINITY` test passes

**Effort:** 1 week.

---

## Phase 3 — TypeScript Hashing + Blake3 wrapper ✅ DONE (v2.5.0, 2026-04-23)

**Landed:** `ts/src/dalos-blake3/index.ts` (Blake3 XOF + seven-fold via `@noble/hashes@2.2.0`), `ts/src/gen1/character-matrix.ts` (256-rune 16×16 matrix), `ts/src/gen1/hashing.ts` (seed-words → bitstring, public-key format, character-matrix address encoding).

**🎯 FIRST BYTE-IDENTITY GATE PASSED:**
- 15/15 seed-words vectors: `seedWordsToBitString` output matches Go's `derived_bitstring` byte-for-byte
- 85/85 address-bearing vectors × 2 prefixes = **170 address byte-identity matches** vs Go corpus
- 105/105 public-key round-trips preserved

**Verified:** 142/142 tests pass in 2.7s.

Ready for Phase 4 (key-generation API + full end-to-end byte-identity).

---

## Phase 3 — TypeScript Hashing + `@stoachain/dalos-blake3` (pre-landing spec; kept for reference) (2-3 days)

**Goal:** Ship `@stoachain/dalos-blake3` v1.0.0 to npm, port the hashing pipeline (seven-fold Blake3 + character-matrix encoding), confirm bit-identity against Go test vectors.

**Work spans two repositories:**

### `StoaChain/Blake3/ts/` → npm `@stoachain/dalos-blake3`

**Files:**

- `Blake3/ts/src/index.ts` — re-exports from `@noble/hashes/blake3`
- `Blake3/ts/src/xof.ts` — `blake3XOF(input, outputBytes): Uint8Array` wrapping `@noble/hashes/blake3`'s streaming API
- `Blake3/ts/src/seven-fold.ts` — `sevenFoldBlake3(input, outputBytes)` = applies XOF seven times
- `Blake3/ts/tests/*.test.ts` — cross-validate against Go fork by running the Go generator and matching outputs

**Deliverable:** `@stoachain/dalos-blake3@1.0.0` published.

### `StoaChain/DALOS_Crypto/ts/src/gen1/hashing.ts`

**Files:**

- `ts/src/gen1/hashing.ts` — seed-words pipeline + address encoding
- `ts/src/gen1/character-matrix.ts` — the 16×16 matrix as a literal constant
- `ts/tests/gen1/hashing.test.ts`

**Functions:**

```ts
// In @stoachain/dalos-blake3
export function blake3XOF(input: Uint8Array, outBytes: number): Uint8Array;
export function sevenFoldBlake3(input: Uint8Array, outBytes: number): Uint8Array;

// In dalos-crypto gen1/hashing.ts
export function seedWordsToBitString(words: string[]): string;
export function convertHashToBitString(hash: Uint8Array, bitLength: number): string;
export function affineToPublicKey(p: CoordAffine): string;
export function publicKeyToAddress(pk: string): string;
export function dalosAddressMaker(pk: string, isSmart: boolean): string;
```

**Steps:**

1. Implement `blake3XOF` as a thin wrapper: call `@noble/hashes/blake3` in stream mode, read N bytes.
2. Implement `sevenFoldBlake3` — trivial loop, 7 iterations.
3. Port `SeedWordsToBitString` from Go: join with space, UTF-8 encode, seven-fold Blake3 with output size 200 bytes (= 1600 bits), convert to binary string.
4. Port `ConvertHashToBitString`: hex → BigInt → binary → pad to desired length.
5. Port `AffineToPublicKey`: X string + len(X) in base 49 + XY string in base 49.
6. Port `PublicKeyToAddress`: strip prefix, seven-fold Blake3 at 160-byte output, lookup through 16×16 matrix → 160-char string.
7. Port `DalosAddressMaker`: `Ѻ.` or `Σ.` + address.
8. Port `CharacterMatrix` as a frozen `readonly [readonly string[]][]` constant. **Cross-check every rune against the Go source** — UTF-8 byte-identical.

**Testing:**

- Every test vector's `derived_bitstring` field must match `seedWordsToBitString(input_words)` byte-for-byte
- Every test vector's `standard_address` and `smart_address` fields must match `dalosAddressMaker(public_key, false/true)` byte-for-byte

**Deliverables:**

- `@stoachain/dalos-blake3@1.0.0` on npm
- `ts/src/gen1/hashing.ts` + `character-matrix.ts`
- 200+ tests, all green

**Exit criteria:**

- All 15 seed-words test vectors produce identical addresses in TS vs committed JSON
- All 50 bitstring vectors' derived addresses identical

**Effort:** 2-3 days (reduced from 1 week because Blake3 is externally validated).

---

## Phase 4 — TypeScript Key Generation API ✅ DONE (v2.6.0, 2026-04-23)

**Landed:** `ts/src/gen1/bitmap.ts` (40×40 Bitmap utilities), `ts/src/gen1/key-gen.ts` (6 input entry points + validators + core pipeline).

**🎯 END-TO-END BYTE-IDENTITY GATE CLEARED.** All 85 address-bearing vectors (50 bitstring + 15 seed-words + 20 bitmap) plus 20 Schnorr-vector public keys reproduce byte-for-byte through the full TypeScript pipeline:

| Path | Vectors | Fields validated byte-identical |
|------|---------|---------------------------------|
| `fromBitString` | 50 | scalar_int10, priv_int10, priv_int49, public_key, standard_address, smart_address |
| `fromIntegerBase10` | 50 | bitString, priv_int49, public_key, both addresses |
| `fromIntegerBase49` | 85 (50 + 15 + 20) | Same 5-6 fields |
| `fromSeedWords` | 15 | All fields (Cyrillic, Greek, accented Latin included) |
| `fromBitmap` | 20 | All fields (hand-designed + random patterns) |
| `validatePrivateKey` | 105 | Extracted core bitString matches |

**Verified:** 182/182 tests pass in 27s. TypeScript port is a functionally complete drop-in replacement for the Go `go.ouronetwork.io/api/generate` service.

Ready for Phase 5 (AES Encryption Port).

---

## Phase 4 — TypeScript Key Generation API (pre-landing spec; kept for reference) (1 week)

**Goal:** The public key-gen API — all **6 input paths** including the new bitmap.

**Files:**

- `ts/src/gen1/key-gen.ts`
- `ts/src/gen1/bitmap.ts`
- `ts/src/gen1/validate.ts`
- `ts/tests/gen1/key-gen.test.ts`, `bitmap.test.ts`, `validate.test.ts`

**The 6 input types:**

```ts
export interface DalosKeyGen {
  // (1) Cryptographically secure random bits
  fromRandom(): Promise<KeyPair>;

  // (2) User-provided 1600-bit string "0101..."
  fromBitString(bits: string): KeyPair;

  // (3) User-provided base-10 integer representation
  fromIntegerBase10(n: string): KeyPair;

  // (4) User-provided base-49 integer representation
  fromIntegerBase49(n: string): KeyPair;

  // (5) Seed words (UTF-8, 1+ words)
  fromSeedWords(words: string[]): KeyPair;

  // (6) 40×40 black/white bitmap (new in v1.2.0)
  fromBitmap(bitmap: Bitmap): KeyPair;

  // Validators
  validateBitString(bits: string): ValidationResult;
  validatePrivateKey(key: string, base: 10 | 49): ValidationResult;
  validateBitmap(b: Bitmap): ValidationResult;

  // Low-level primitives (exposed for advanced users)
  generateScalarFromBitString(bits: string): bigint;
  scalarToKeyPair(scalar: bigint): KeyPair;
  scalarToPublicKey(scalar: bigint): string;
  scalarToPrivateKey(scalar: bigint): DalosPrivateKey;

  // Bitmap utilities
  bitmapToBitString(b: Bitmap): string;
  bitStringToBitmap(bits: string): Bitmap;    // diagnostic; reveals the key
  bitmapFromAsciiRows(rows: string[]): Bitmap;
  bitmapFromCanvas(canvas: HTMLCanvasElement): Bitmap;
  bitmapFromImageData(data: ImageData): Bitmap;
}

export interface KeyPair {
  priv: string;      // base-49 encoded
  publ: string;      // prefixed base-49 "N.xxx"
}

export interface DalosPrivateKey {
  bitString: string; // 1600-bit "01..." (trimmed, pre-clamp)
  int10: string;     // base-10 integer
  int49: string;     // base-49 integer
}

export type Bitmap = boolean[][];   // 40 rows × 40 cols, [row][col] = true/false
```

**Steps:**

1. Build `bitmap.ts`:
   - `bitmapToBitString`: for row 0..39, for col 0..39, emit `true ? "1" : "0"`. Concatenate = 1600 chars.
   - `bitStringToBitmap`: reverse (for visualisation).
   - `bitmapFromAsciiRows`: parse `#` / `.`.
   - `bitmapFromImageData`: read each pixel, threshold by luminance (Y = 0.299·R + 0.587·G + 0.114·B), require pure 0 or 255 (strict).
   - `bitmapFromCanvas`: `getContext('2d').getImageData` → `bitmapFromImageData`.
2. Build `validate.ts`:
   - Existing validators
   - `validateBitmap`: dimensions 40×40, each cell boolean (trivially true for `boolean[][]`)
3. Build `key-gen.ts`:
   - `fromRandom`: 200-byte `crypto.getRandomValues(new Uint8Array(200))` → bitstring
   - `fromBitString`: validate → scalar → keypair
   - `fromIntegerBase10` / `fromIntegerBase49`: validate private key structure → extract bitstring → keypair (matches `ValidatePrivateKey` in Go)
   - `fromSeedWords`: `seedWordsToBitString` → keypair
   - `fromBitmap`: `bitmapToBitString` → keypair (identical to `fromBitString` after reshape)

**Testing:**

- All 50 bitstring test vectors: `fromBitString(input_bitstring)` produces byte-identical `priv_int49`, `public_key`, `standard_address`, `smart_address`
- All 15 seed-words vectors: `fromSeedWords(input_words)` matches
- All 15+ bitmap vectors (added in Phase 0a): `fromBitmap(parseBitmap)` matches
- `fromRandom()` produces a valid key that is parseable with `fromIntegerBase49(keyPair.priv)` and yields the same keypair
- Invalid inputs rejected with clear error types

**Deliverables:**

- 3 `.ts` files
- ~400 tests

**Exit criteria:**

- 100% of deterministic test vectors pass byte-for-byte match

**Effort:** 1 week.

---

## Phase 5 — TypeScript AES Encryption Port ✅ DONE (v2.7.0, 2026-04-23)

**Landed:** `ts/src/gen1/aes.ts` (AES-256-GCM + Blake3 KDF wrapper matching Go byte-for-byte), plus one TS-port robustness improvement: nonce generation constrains first byte to `>= 0x10` to eliminate a 6.25% latent roundtrip failure rate.

**Verified:** 208/208 tests pass. TS-produced ciphertexts always decrypt cleanly in Go. Ready for Phase 6 (hardened Schnorr — will land byte-identical to the Go v2 corpus).

---

## Phase 5 — TypeScript AES Encryption (pre-landing spec; kept for reference) (3-5 days)

**Goal:** Port the AES wrapper **as-is** — same mode, same KDF, same format. No security upgrade in the port (Argon2id etc. is deferred to future work).

**Files:**

- `ts/src/gen1/aes.ts`
- `ts/tests/gen1/aes.test.ts`

**Functions:**

```ts
// Matches AES/AES.go line-by-line
export async function encryptBitString(bits: string, password: string): Promise<string>;
export async function decryptBitString(ciphertextBits: string, password: string): Promise<string>;

// Internals
function makeKeyFromPassword(password: string): Promise<Uint8Array>;   // single Blake3 → 32 bytes
```

**Steps:**

1. `makeKeyFromPassword`: UTF-8 encode password → `blake3XOF(pw, 32)` → return 32-byte key.
2. `encryptBitString`:
   - Bitstring → BigInt → hex → `Uint8Array` (same as Go)
   - AES-256-GCM encrypt using Web Crypto API (`crypto.subtle.encrypt` with `{name: 'AES-GCM', iv: nonce}`)
   - Prepend nonce (12 bytes from `crypto.getRandomValues`) to ciphertext
   - Convert result bytes → hex → BigInt → binary string (same as Go)
3. `decryptBitString`: reverse.

**Testing:**

- Encrypt in TS → decrypt in TS (round-trip) for 20 random bitstrings
- Encrypt in Go → decrypt in TS for 5 vectors produced by the Go CLI
- Encrypt in TS → decrypt in Go for 5 vectors produced by TS
- Wrong password: `decrypt` throws (matches Go behaviour of producing garbage — TS gives a typed error)

**Deliverables:**

- 1 `.ts` file
- ~20 tests

**Exit criteria:**

- Round-trip Go ↔ TS works in both directions

**Effort:** 3-5 days.

**Note:** Ouronet UI does NOT use this AES (it uses ouronet-core's V1/V2 codex encryption). The AES port exists for CLI-encrypted-file compatibility. Keep scope narrow.

---

## Phase 6 — TypeScript Schnorr v2 ✅ DONE (v2.8.0, 2026-04-23)

**Landed:** `ts/src/gen1/schnorr.ts` with all seven audit items resolved.

**🎯 BYTE-IDENTITY GATE:** All 20 Schnorr test vectors' signatures match the Go corpus **byte-for-byte**. 234/234 tests pass.

Ready for Phase 7 (primitive registry).

---

## Phase 6 — TypeScript Schnorr Signatures, Hardened (pre-landing spec; kept for reference) (1 week)

**Goal:** Port Schnorr sign/verify **with all 7 Category-B hardening items applied**. The resulting signature format is INCOMPATIBLE with Go-generated signatures — but no on-chain Schnorr signatures exist, so no user is affected.

**Files:**

- `ts/src/gen1/schnorr.ts`
- `ts/tests/gen1/schnorr.test.ts`

**The 7 hardening items (from AUDIT.md):**

1. **Length-prefixed Fiat–Shamir transcript.** Concat becomes: `len(R)||R || len(P.X)||P.X || len(P.Y)||P.Y || len(m)||m`. Eliminates the leading-zero ambiguity.
2. **RFC-6979 deterministic nonces.** Nonce `k = HMAC-Blake3(priv, msg, …)` per RFC 6979 adapted for Blake3. Removes randomness dependency; same (priv, msg) always produces same signature.
3. **Domain-separation tag.** Prepend fixed string `"DALOS-gen1/SchnorrHash/v1"` before the transcript. Prevents hash-reuse across protocols.
4. **On-curve validation of R** in `verify`. Reject signatures where `R` is not on the curve.
5. **Range check `0 < s < Q`** in `verify`. Reject otherwise.
6. **Explicit error types** — `InvalidSignatureFormatError`, `InvalidPointError`, `SignatureRangeError`, etc. No silent nil-derefs.
7. **Constant-time scalar multiplication** for signing (uses the Phase-2 `scalarMultiplierCT`).

**Functions:**

```ts
export interface SchnorrSignature {
  readonly r: CoordAffine;
  readonly s: bigint;
}

export async function schnorrSign(
  privateKey: string,          // base-49 priv
  message: string | Uint8Array
): Promise<string>;             // "R-in-pubkey-format | s-in-base49" string form

export async function schnorrVerify(
  signature: string,
  message: string | Uint8Array,
  publicKey: string
): Promise<boolean>;

// Internal
function schnorrHash(r: bigint, pk: string, msg: Uint8Array): bigint;
```

**Testing:**

- 100 random sign → self-verify roundtrips (determinism: sign twice, same output)
- Tampered signatures fail verify
- Signatures from Go's test-vector corpus are recognised as "legacy Go format" (optional shim) OR rejected cleanly (decision: reject; users move to hardened signatures)
- Malformed inputs produce typed errors
- `schnorrVerify` rejects signatures where `R` is not on curve
- `schnorrVerify` rejects signatures where `s >= Q` or `s <= 0`

**Deliverables:**

- 1 `.ts` file
- 100+ tests

**Exit criteria:**

- All tests green, including self-verify roundtrips

**Effort:** 1 week.

---

## Phase 7 — Cryptographic Primitive Registry ✅ DONE (v2.9.0, 2026-04-23)

**Landed:** `ts/src/registry/*.ts` — full primitive + registry surface exposed as subpath `@stoachain/dalos-crypto/registry`. 34 new tests (268 total). Gen-2 primitives can now register cleanly.

Ready for Phase 8 (integration into `@stoachain/ouronet-core`).

---

## Phase 7 — TypeScript Modular Primitive Registry (pre-landing spec; kept for reference) (1 week)

**Goal:** Wrap everything in the registry pattern so Gen-2 can plug in later.

**Files:**

- `ts/src/registry/primitive.ts` — `CryptographicPrimitive` interface
- `ts/src/registry/registry.ts` — `CryptographicRegistry` class
- `ts/src/registry/genesis.ts` — `DalosGenesis` primitive instance
- `ts/src/registry/default.ts` — default registry factory
- `ts/src/index.ts` — re-exports

**`CryptographicPrimitive` interface (v2, includes all 6 input types):**

```ts
export interface CryptographicPrimitive {
  readonly id: string;
  readonly description: string;
  readonly version: number;
  readonly generation: string;

  readonly metadata: {
    curveName: string;
    primeField: bigint;
    order: bigint;
    cofactor: bigint;
    baseBitLength: number;
  };

  // Key generation
  generateRandom(): Promise<KeyPair>;
  generateFromBitString(bits: string): KeyPair;
  generateFromInteger(n: string, base: 10 | 49): KeyPair;
  generateFromSeedWords(words: string[]): KeyPair;
  generateFromBitmap(b: Bitmap): KeyPair;       // NEW

  // Address derivation
  publicKeyToAddress(pk: string, isSmart: boolean): string;
  detectGeneration(address: string): boolean;

  // Optional signing
  sign?(privateKey: string, message: string | Uint8Array): Promise<string>;
  verify?(signature: string, message: string | Uint8Array, publicKey: string): Promise<boolean>;
}
```

**`CryptographicRegistry` class:**

```ts
export class CryptographicRegistry {
  register(p: CryptographicPrimitive): void;
  unregister(id: string): void;
  get(id: string): CryptographicPrimitive | undefined;
  detect(address: string): CryptographicPrimitive | undefined;
  all(): readonly CryptographicPrimitive[];
  default(): CryptographicPrimitive;
  setDefault(id: string): void;
}

export function createDefaultRegistry(): CryptographicRegistry;  // with DalosGenesis pre-registered
```

**Steps:**

1. Define interface + KeyPair + Bitmap re-export
2. Implement registry as a simple Map-backed class
3. Build `DalosGenesis` by wiring Phase 1–6 exports through the interface
4. `createDefaultRegistry()` pre-registers Genesis + sets as default
5. Tests

**Deliverables:**

- 4 `.ts` files
- 50+ tests for registry behaviour (register, unregister, detect, default, duplicate ID rejection)

**Exit criteria:**

- Address `Ѻ.xxx...` correctly detected as Gen-1 via `registry.detect()`
- `registry.default().generateFromBitmap(b)` produces same keys as direct `gen1.fromBitmap(b)`

**Effort:** 1 week.

---

## Phase 8 — Integration into `@stoachain/ouronet-core` ⏸ BLOCKED ON NPMPUSHER SECRET

**Code landed** (2026-04-23):

- **`@stoachain/dalos-crypto`** side:
  - `ts/package.json` bumped to `1.0.0` (first production release).
  - `.github/workflows/ts-publish.yml` created, triggered by `ts-v*.*.*` tags. Mirrors OuronetCore's pattern (explicit `.npmrc` writing with `NPMPUSHER` secret). Includes a pre-flight secret-presence check with clear error message.
  - Tagged `ts-v1.0.0`. Workflow ran but failed at the publish step — `NPMPUSHER` secret is not configured on the `StoaChain/DALOS_Crypto` repo (it's on `StoaChain/OuronetCore`).

- **`@stoachain/ouronet-core`** side (via `file:../DALOS_Crypto/ts` dev-only dep):
  - `package.json` bumped to `1.3.0`.
  - New `./dalos` subpath export.
  - `src/dalos/index.ts` re-exports the full `CryptographicPrimitive` + `CryptographicRegistry` surface.
  - `src/dalos/account.ts` adds `createOuronetAccount(registry, options)` with a discriminated-union covering all 6 input modes.
  - `tests/dalos-integration.test.ts` — 9 integration tests all pass.
  - **Total: 295/295 tests pass locally** (286 existing + 9 new).

**To unblock npmjs publication:**

1. Add `NPMPUSHER` secret to `https://github.com/StoaChain/DALOS_Crypto/settings/secrets/actions` (same value as the one on OuronetCore — granular npm token with publish rights on the `@stoachain` scope).
2. Re-push the `ts-v1.0.0` tag:
   ```
   cd D:/_Claude/DALOS_Crypto
   git tag -d ts-v1.0.0
   git push origin :refs/tags/ts-v1.0.0
   git tag -a ts-v1.0.0 -m '@stoachain/dalos-crypto@1.0.0'
   git push origin ts-v1.0.0
   ```
3. In OuronetCore, swap `"@stoachain/dalos-crypto": "file:../DALOS_Crypto/ts"` → `"@stoachain/dalos-crypto": "^1.0.0"`, regenerate lockfile, commit + tag `v1.3.0` (or `v1.3.1` if v1.3.0 has been tagged already) → triggers OuronetCore's publish workflow.

After that, Phase 8 is complete on the npmjs side and Phase 9 (OuronetUI migration) can proceed using clean semver-ranged npm deps.

---

## Phase 8 — Integration into `@stoachain/ouronet-core` (pre-landing spec; kept for reference) (1 week)

**Goal:** Ouronet-core uses `@stoachain/dalos-crypto` via the registry for all DALOS operations.

**Steps:**

1. Add `@stoachain/dalos-crypto` as a `dependency` in ouronet-core's `package.json`
2. In `@stoachain/ouronet-core/crypto/`, add or extend:
   - Re-export the registry
   - Add a Codex-level method `createOuronetAccount({ mode, data, isSmart, primitiveId? })` which:
     - Picks the primitive from the registry (default if not specified)
     - Calls the appropriate `generateFrom*` method
     - Stores the result in the codex via `LocalStorageCodexAdapter`
3. Add `detectAccountGeneration(address)` utility on the Codex.
4. Integration tests: create account via Codex → read back via `codex.getAccount(addr)` → signs/verifies if Schnorr present.

**Deliverables:**

- Updated ouronet-core with registry integration
- Tests covering all 6 input types via the Codex API
- `@stoachain/ouronet-core` version bump (minor)

**Exit criteria:**

- Ouronet-core's test suite passes with registry wired in
- Existing codex files (V1/V2) still decrypt

**Effort:** 1 week.

---

## Phase 9 — OuronetUI Migration (3-5 days)

**Goal:** Remove the `go.ouronetwork.io/api/generate` call from OuronetUI. Browser-side key generation becomes the default.

**Steps:**

1. **Delete** the `generateOuronetAccount` function in `src/hooks/use-ouro-api.tsx`
2. **Replace callers** — `src/components/auth/CreateOuroAccount.tsx`, `src/context/auth-context.tsx` — with `codex.createOuronetAccount(...)` via `useWallet()`
3. **Add 40×40 bitmap UI component** at `src/components/auth/BitmapKeyInput.tsx`:
   - 40×40 grid of clickable cells
   - Black fill = 1, white fill = 0
   - "Clear", "Invert", "Fill random", "Import PNG" buttons
   - "Reveal" button that briefly shows the bitmap in full-screen for user review before confirm
4. **Add input-method selector** to the account creation flow — dropdown with all 6 options
5. **UX copy** — explain that local generation takes ~2 seconds; show a spinner + progress indicator
6. **Smoke tests (manual):**
   - Create an account with the same mnemonic previously used on the Go server → verify identical address produced
   - Go offline; create an account → succeeds
   - Import a codex with pre-existing accounts → unchanged
7. **Production rollout:** behind a feature flag for 1 week, then default-on

**Deliverables:**

- Code changes in OuronetUI
- Bitmap UI component tested cross-browser
- OuronetUI version bump

**Exit criteria:**

- No more calls to `go.ouronetwork.io/api/generate`
- Bitmap UI works on desktop + mobile
- All existing flows (swap, stake, transfer) continue to work with locally-generated accounts

**Effort:** 3-5 days.

---

## Phase 10 — Performance Optimisation (1-2 weeks, conditional)

**Trigger:** Phase 4 benchmarks show key-gen >3 seconds on commodity hardware.

**If <1 second:** skip Phase 10 entirely.

**If 1-3 seconds:** wrap key-gen in a Web Worker so the UI thread stays responsive. ~2 days work.

**If >3 seconds:** investigate WASM.

**WASM options:**

| Option | Effort | Pros | Cons |
|--------|--------|------|------|
| Rust port of critical path → `wasm-pack` | ~2 wk | Fastest | New language for the project |
| TinyGo: compile existing Go to WASM | ~1 wk | Reuses Go code | Larger binary, TinyGo has Go-stdlib limitations |
| AssemblyScript | ~1 wk | Familiar syntax | Modest speedup vs. JS |

**Deliverables (conditional):**

- Benchmark report
- Web Worker wrapper (always worth adding, low cost)
- WASM module (only if needed)

**Effort:** 1-2 weeks, conditional on benchmarks.

---

## Phase 11 — Documentation + Public npm Publish (1 week)

**Goal:** Publish `@stoachain/dalos-crypto@1.0.0` to npm. Make DALOS discoverable and usable by external developers.

**Steps:**

1. Write `ts/README.md` — package-specific quickstart
2. Generate API reference via TypeDoc → `ts/docs/api/`
3. Write `docs/DALOS_CRYPTO_GEN1.md` — high-level architectural overview (curve, hashing, encoding, security)
4. Quick-start guide with code examples for all 6 input types
5. Update the Ouronet Gitbook with a cross-link to DALOS crypto
6. Publish `@stoachain/dalos-crypto@1.0.0` to npm (access: public)
7. Publish `@stoachain/dalos-blake3@1.0.0` (already at 1.0.0 from Phase 3)

**Deliverables:**

- `ts/README.md`
- `ts/docs/api/` (TypeDoc-generated)
- `docs/DALOS_CRYPTO_GEN1.md`
- Gitbook updates
- npm packages live

**Exit criteria:**

- `npm install @stoachain/dalos-crypto` on a fresh machine yields a working install
- API docs render correctly

**Effort:** 1 week.

---

## Phase 12 — `go.ouronetwork.io` Retirement (optional, 1 week)

**Goal:** After production stability confirmed, shut down the Go server.

**Steps:**

1. Monitor Phase 9 deployment for ≥ 4 weeks — no regressions in account creation
2. Add deprecation header to `https://go.ouronetwork.io/api/generate` responses
3. 30-day deprecation window
4. Shut down the endpoint
5. Update any external documentation still referencing it

**This is entirely optional.** The Go server can also be kept indefinitely as a backup or for non-browser clients.

**Effort:** 1 week of coordination, most of it wall-clock soak time.

---

# Decision Points (all locked for the duration of this plan)

| # | Decision | Value |
|---|----------|-------|
| 1 | Phase 0 complete? | ✅ YES (v1.1.2 landed 2026-04-23) |
| 2 | Bitmap conventions for Genesis | 40×40, black=1, row-major TTB-LTR, strict pure B/W |
| 3 | Scan-order variants | Future feature (`FUTURE.md` §2) — not in Genesis |
| 4 | Argon2id KDF for AES | NO — keep single-pass Blake3 KDF (unchanged from Go) |
| 5 | Schnorr hardening in TS port | YES — all 7 items (SC-1..SC-7) |
| 6 | Third-party audit before Phase 6 | Optional; strongly recommended but not blocking |
| 7 | Bigger curves | NO — see `FUTURE.md` §4 |
| 8 | Post-quantum primitive | Separate track; `FUTURE.md` §1 |
| 9 | Standalone npm for dalos-crypto | YES — `@stoachain/dalos-crypto` |
| 10 | Licence | Proprietary, AncientHoldings GmbH |

---

# What starts next

**Phase 0a landed as v1.2.0 on 2026-04-23.**  105 test vectors live, bitmap cross-check passes.

**Phase 0c landed as v1.3.0 on 2026-04-23.**  Category-A hardening — constant-time scalar mult + Schnorr verify hardening. Key-gen output byte-identical to v1.0.0; 20/20 Schnorr still self-verify.

**Phase 0d landed as v2.0.0 on 2026-04-23.**  Schnorr v2 format — length-prefixed Fiat-Shamir, deterministic nonces, domain tags. Key-gen output still byte-identical to v1.0.0. Schnorr now fully deterministic (20/20 signatures stable across regeneration runs). Canonical test-vector hash: `45c89ec36c30847a92dbd5b696b42d94159900dddb6ce7ad35fca58f4bba16f3`.

**Next phase:** 0b — TypeScript Build Scaffold. TS port now targets the hardened v2.0.0 Go reference.

**Awaiting user:** `Exec: begin Phase 0b` to kick off.

**After Phase 0b lands:** Phase 1 (TS math foundation) — coding begins.

---

*Plan version: v2 (2026-04-23). Supersedes v1. History tracked in [`CHANGELOG.md`](../CHANGELOG.md).*
