# DALOS Cryptography Gen-1 — Architectural Overview

> Audit-facing architectural deep-dive for `@stoachain/dalos-crypto@1.1.0`
> and the matching Go reference. Intended to give cryptographic
> auditors, security reviewers, and downstream implementers a complete
> mental model of the Genesis primitive: curve, key-gen pipelines,
> hashing, encoding, signatures, encryption — and the threat surface
> each component is designed against.
>
> This document is the **single source of truth for the design
> rationale**. Line-level details live in the code + `AUDIT.md` +
> `SCHNORR_V2_SPEC.md`; this file explains *why*, not *how*.

**Version covered**: Go reference `v2.1.0` / TypeScript port `v1.1.0`.
Genesis output is frozen and every future additive change MUST preserve
byte-identity for existing inputs.

---

## 1. Design principles

1. **Single scalar, many inputs.** The DALOS private key is a 1600-bit
   integer in `[0, Q)` where `Q` is the prime subgroup order of the
   DALOS Ellipse. Every supported input path — random, bitstring,
   base-10 integer, base-49 integer, seed words, 40×40 bitmap — is
   a deterministic reshaping-or-hashing transformation onto that
   scalar. Once reshaped, the rest of the pipeline is identical.

2. **Byte-identity across languages.** The Go reference and the
   TypeScript port must produce **bit-for-bit identical** output for
   every input. This is continuously verified against a 105-vector
   canonical corpus (`testvectors/v1_genesis.json`). Deviations are
   bugs, not dialect differences.

3. **Genesis freeze.** The Gen-1 key-generation output is permanent.
   Existing Ouronet accounts must remain derivable from the same
   inputs for the life of the network. New input modes are only
   acceptable if they are pure reshaping (bitmap in v1.2.0 was
   acceptable because 40×40 = 1600 bits; the scalar derivation is
   unchanged). The curve, the character matrix, the address format,
   and the scalar-multiplication algorithm are all frozen.

4. **Branch-free secret paths.** Any code that touches the private
   scalar avoids data-dependent branching. The base-49 Horner
   scalar-multiplication does a linear scan over all 48 precompute
   entries; the selected point is chosen by equality mask, not by
   early-exit. Constant-time signature generation (Schnorr v2) is
   in-scope for future hardening but already complete for all secret
   comparisons and scalar adds.

5. **Registry-pluggable primitives.** A `CryptographicRegistry` holds
   N primitives, each with a `detect(address)` predicate. Genesis is
   one primitive among potentially many. This enables forward
   compatibility without touching Genesis code paths.

---

## 2. The DALOS Ellipse

### Equation

Twisted Edwards form:

$$a \cdot x^2 + y^2 \equiv 1 + d \cdot x^2 \cdot y^2 \pmod P$$

with `a = 1`, `d = -26`, over the prime field defined by:

$$P = 2^{1605} + 2315$$

### Full parameter set

| Symbol | Meaning | Value |
|---|---|---|
| `P` | Field prime | `2^1605 + 2315` (1606-bit) |
| `Q` | Prime subgroup order | `2^1603 + 1258387…1380413` (1604-bit) |
| `R` | Cofactor | `4` |
| `T` | Trace of Frobenius | `-5033548…5519336` |
| `a`, `d` | Curve coefficients | `1`, `-26` |
| `G` | Generator (affine) | `(2, 479577…907472)` |
| `S` | Safe scalar bit-width | `1600` |

### Mathematical audit

Seven independent tests confirm the parameters are sound
(`verification/verify_dalos_curve.py` and `.sage` — each runs in under
a minute):

1. `P` is prime (Miller-Rabin 50 rounds; error ≤ 2⁻¹⁰⁰).
2. `Q` is prime.
3. Cofactor identity: `(P + 1 - T) / Q = R` with zero remainder.
4. `d = -26` is a quadratic **non**-residue mod `P` — so the
   Bernstein-Lange addition law is complete; there are no exceptional
   points requiring branching in the addition formulas.
5. `G` satisfies the curve equation.
6. `[Q] · G = O` — the generator has order exactly `Q`. This is the
   strongest end-to-end consistency proof; if any of the 7 parameters
   were inconsistent, this test would fail.
7. `S ≤ log₂(Q)` — the safe scalar fits inside the subgroup order, so
   uniform scalars in `[0, 2^S)` are trivially unbiased modulo `Q`.

### Why these exact parameters

- **Prime form `2^k ± small`.** Fast reduction, unambiguous representation,
  small Selmer group to analyse for twist safety.
- **1606-bit prime.** Provides **2¹⁶⁰⁰ accounts**. Vastly beyond any
  cryptographic security margin. The large space is a design statement,
  not a security requirement — the practical attack bound is
  `O(sqrt(Q))` by Pollard rho, which is already > 2²⁵⁶ on the
  1604-bit subgroup.
- **Cofactor 4.** Standard Edwards-curve choice. Clears trivially by
  scalar-multiplying by 4 (i.e. two doublings) if subgroup-safety
  matters; we don't need this because our keys are generated modulo
  `Q`, never in the full curve group.
- **Negative `d`.** Combined with `-a = -1` being a non-square mod `P`,
  this is what gives us Bernstein-Lange **complete** addition — no
  identity-element or halving-point corner cases.

### Complete addition law

The HWCD formulas (Hisil-Wong-Carter-Dawson, ported from
`hyperelliptic.org/EFD`) produce the sum of two extended-coordinate
points in ≈ 9 field multiplications. Three variants are implemented:

- **V1**: strictly complete — handles all pairs including
  `INFINITY + INFINITY`.
- **V2**: Z-optimised for non-infinity inputs; ~20% faster but
  produces `Z = 0` on `INFINITY + INFINITY` (never exercised in
  practice; accumulators in scalar-mult are always non-infinity).
- **V3**: alternate form, kept for cross-verification.

Production scalar-mult uses V2 for interior adds and V1 for the
`fortyNiner` (forty-nine-squared multiplier) step.

---

## 3. The scalar derivation pipeline

### Goal

Given an input of one of six types, produce a uniform-looking private
scalar `k ∈ [0, Q)` such that scalar multiplication `k · G` yields the
public point. The mapping is deterministic; the **same input always
produces the same scalar**.

### Seven-fold Blake3

DALOS hashes arbitrary byte sequences through a **seven-fold Blake3
XOF**:

```
Let B0 = Blake3(input, 200 bytes of XOF output)
Let B1 = Blake3(B0,     200 bytes)
…
Let B6 = Blake3(B5,     200 bytes)
```

The final `B6` is 200 bytes = 1600 bits = the raw key material. This
is used in two places:

1. **Seed-word → bit-string** (input length variable; output fixed 200 bytes).
2. **Address derivation** (input: 201 bytes of raw key material; output: 160 bytes = 160 characters once mapped through the 16×16 matrix).

Why seven-fold: historical choice rooted in the author's original
Cryptoplasm research. The iteration count is a cryptographic black
box — every Blake3 call is its own PRF call, so seven rounds provide
no additional security over one round but also no meaningful cost,
and the construction's **determinism is what matters**. Freezing
it at Genesis.

### Bit-string → scalar

The 1600-bit string is interpreted as a big-endian unsigned integer,
then **reduced modulo Q** to produce the final scalar. Reduction
is a single modular subtraction if needed (the 1600-bit input is
never more than 4 × Q), avoiding statistical bias beyond the small
worst-case bound inherent in the reduction.

### Per-mode mapping

| Input mode | Transformation |
|---|---|
| `random` | `getRandomValues(200 bytes)` → interpret as 1600-bit → reduce mod Q |
| `bitString` | parse 1600 chars (any 0/1 pattern) → reduce mod Q |
| `integerBase10` | parse decimal string → reject if ≥ Q → done |
| `integerBase49` | parse base-49 string (alphabet: `0-9 a-z A-M`) → reject if ≥ Q → done |
| `seedWords` | concat words w/ space separator → seven-fold Blake3 → 1600 bits → reduce mod Q |
| `bitmap` | row-major read (1 = black, 0 = white; 40×40 = 1600 pixels) → 1600-bit string → reduce mod Q |

**Important**: `integerBase10` and `integerBase49` reject inputs ≥ Q
at the TypeScript API boundary. Every other mode clamps automatically
via reduction. "Any 1600-bit sequence qualifies" for `bitString` and
`bitmap` — there is no valid/invalid classification on those paths.

---

## 4. Public key & address derivation

### Public point

Standard: `publicPoint = scalar · G` using the base-49 Horner
scalar-multiplication (see §5 below).

### Address format

Addresses are **160 characters** from the 16×16 DALOS character matrix,
prefixed with the account type:

- **Standard Account** — `Ѻ.xxxxx…` (1 prefix char + 1 dot + 160 body chars = 162 total)
- **Smart Account** — `Σ.xxxxx…` (same shape, different prefix)

The 160 body characters encode 160 bytes of seven-fold Blake3 output
over the public-point coordinates:

```
1. Concat (publicPointX || publicPointY) — 200 bytes of prefixed base-49 form
2. Seven-fold Blake3 → 160 bytes
3. Each byte indexes the 256-rune character matrix: byte B → char at (B/16, B%16)
4. Prefix with 'Ѻ.' (standard) or 'Σ.' (smart)
```

### The character matrix

A **frozen 16×16 grid of 256 Unicode runes** spanning:

- Digits 0-9 + 6 currency signs
- Latin A-Z + a-z
- Latin-extended (Æ, Œ, Á, etc.)
- Greek capitals + lowercase
- Cyrillic capitals + lowercase

Any change to a single rune would produce different addresses for the
same keys — orphaning every existing account. **Never modify.**

### Detection

Given an arbitrary string, `registry.detect(address)` checks the
prefix and the 160-char body length to identify which primitive
minted it. Genesis accounts are detected on `Ѻ.` or `Σ.` followed by
exactly 160 characters drawn from the DALOS matrix.

---

## 5. Scalar multiplication — base-49 Horner

### Why base-49

The DALOS key scalar is processed in base 49: the scalar is converted
to a string of base-49 digits (49 = 7 × 7, so the algorithm does
seven-squared multiplier steps — hence `fortyNiner`). Each digit
contributes one `addition` and one `fortyNiner` step (= one `49 × P`
multiplication, i.e. six doublings + one addition + one tripling).

This is quite different from the traditional binary ladder, and was
selected in the Cryptoplasm research phase for:

- Balanced throughput/memory tradeoff (precompute matrix of 48 points)
- Avoiding the square-and-multiply side-channel fingerprint
- Being unique to the DALOS design (branding)

### Branch-free precompute lookup

The 48-entry precompute matrix is scanned in full for every digit.
The selected point is masked by equality, not chosen by early-exit:

```ts
let toAdd = INFINITY_POINT;
for (let idx = 1; idx <= 48; idx++) {
  if (value === idx) toAdd = precompute[...];
}
```

This ensures that the runtime and memory access pattern are
independent of the secret digit value. It's not as tight as true
constant-time assembly, but it's the closest high-level-TS can get
without dropping to WASM or SIMD.

### `[Q]·G = O` — end-to-end proof

The single strongest validation of the scalar-mult implementation is
computing `[Q]·G` and checking the result is the identity point.
Takes ~30 seconds on DALOS (1600-bit scalar) and ~100ms on the
smaller historical curves. Runs as a standing test.

---

## 6. Schnorr v2 signatures

See [`SCHNORR_V2_SPEC.md`](./SCHNORR_V2_SPEC.md) for the full spec.
Summary of hardening items (SC-1 … SC-7), all resolved:

| Item | Mitigation |
|---|---|
| SC-1 — length-prefix Fiat-Shamir | Every input to the challenge hash is length-prefixed |
| SC-2 — deterministic nonces | RFC-6979 — nonce = HMAC-DRBG(privKey ‖ msgHash) |
| SC-3 — domain tag | `"dalos-schnorr-v2"` prefix separates from other Schnorr variants |
| SC-4 — canonical s range | Signatures where `s ≥ Q` are rejected (reduced-s is canonical) |
| SC-5 — on-curve checks | Public keys parsed from wire are verified on-curve before use |
| SC-6 — error returns | Explicit `VerifyResult` with reason codes; no silent false-true |
| SC-7 — constant-time | Scalar-mult already branch-free; constant-time byte comparisons for signature equality |

Signatures are `(R, s)` where `R` is a curve point and `s` is a scalar.
Binary encoding: `serialize(R) ‖ serialize(s)` — sizes determined by
the curve (typically ~400 bytes for DALOS).

---

## 7. AES-256-GCM encryption

### Use case

Encrypts private-key material for on-disk storage (Codex files, UI
persistence). NOT for ephemeral encryption — that role belongs to
`@stoachain/ouronet-core/crypto`'s V1/V2 format.

### Format

```
cipher = iv ‖ AES-256-GCM(password-derived-key, iv, plaintext)
```

Where `password-derived-key = Blake3(password, 32 bytes)`.
**Single-pass KDF** — no Argon2 / scrypt / PBKDF2. Rationale: the
keys encrypted here are themselves 1600-bit cryptographic primitives;
adding a 100 ms KDF delay at login time is out of scope for a
password strength of "whatever the user picked". Consumers worried
about password-cracking adversaries should use the UI's codex-wide
`smartEncrypt` path instead.

### The IV nibble quirk

The Go reference serialises IVs through a `big.Int → hex → bytes`
round trip that drops the high nibble when it's zero (≈6% of
random IVs). On those ~6%, a ciphertext produced in Go fails to
decrypt in Go (and vice versa if we naïvely ported the bug).

The TypeScript port **sidesteps this** by constraining generated IVs
to have a non-zero high nibble (`iv[0] & 0xf0 !== 0`). TS ciphertexts
always decrypt in both TS and Go. Ciphertexts produced by Go still
round-trip correctly in TS as long as the IV was in the 94% safe
range. Lost-ciphertext recovery is not in scope — this was a bug
in the Go reference that the TS port avoids without changing the
on-the-wire format.

---

## 8. The CryptographicRegistry

### Why a registry

DALOS Gen-1 is **one** cryptographic primitive. Future generations
(Gen-2, Gen-3, ...) may introduce entirely new curve families,
address formats, or post-quantum schemes. The registry pattern lets
consumers programmatically discover which primitive to use for a given
address without hard-coding.

### Interface

```ts
interface CryptographicPrimitive {
  readonly metadata: { readonly id: string; readonly version: string; ... };
  detect(address: string): boolean;       // is this my kind of address?
  sign?(keyPair, msg): Signature;
  verify?(sig, msg, publ): boolean;
}

interface DalosGenesisPrimitive extends CryptographicPrimitive {
  generateRandom(): FullKey;
  generateFromBitString(s: string): FullKey;
  generateFromInteger(s: string, base: 10 | 49): FullKey;
  generateFromSeedWords(words: readonly string[]): FullKey;
  generateFromBitmap(b: Bitmap): FullKey;
}
```

### Default registry

`createDefaultRegistry()` returns a registry with `DalosGenesis`
registered as the default primitive — what every OuronetUI /
AncientHoldings consumer uses today.

### Primitive vs. sub-path

Historical curves (LETO, ARTEMIS, APOLLO) are **NOT** registered as
primitives — they're raw `Ellipse` constants, usable only by calling
the exported point-ops / scalar-mult functions directly with the curve
as a parameter. This is deliberate: registering them would imply they
produce addresses, which they don't (no Genesis-compatible char-matrix
derivation exists for them, by design).

---

## 9. Threat model (summary)

| Adversary | Goal | Relevant mitigation |
|---|---|---|
| Passive network observer | Private key extraction from HTTP traffic | Browser-side key-gen — no HTTP dependency (Phase 9 of TS port) |
| Malicious seed-word recipient | Recover private key from published public key | `[Q]·G = O` proof of subgroup order; Pollard rho attack = `sqrt(Q) ≈ 2^802` — intractable |
| Signing-oracle side-channel (timing) | Key extraction via signing timing | Branch-free scalar-mult + deterministic nonces (RFC-6979) |
| Corrupted input (malformed base-10/49) | DoS / crash / exception abuse | Explicit `throw` on invalid input with descriptive error codes; no silent fallback |
| Address-substitution attack | Trick user into sending to attacker address | Genesis char-matrix is deterministic; UI should always display the derived address *after* key-gen, not input |
| Ciphertext downgrade (AES) | Read stored keys | AES-256-GCM with unique IV per ciphertext; GCM provides both confidentiality and integrity |
| Schnorr signature replay | Reuse a signed message | Application-level nonce (consumers include a counter / timestamp in the signed message; library does not prevent replay by itself) |

### Out of scope

- **Quantum adversaries.** DALOS is pre-quantum. Post-quantum migration
  is tracked in `docs/FUTURE.md` and would require a new Gen-N primitive.
- **Side-channel attacks on browser runtime.** Modern V8 / SpiderMonkey
  JITs are not constant-time environments. The library is best-effort
  branch-free at the TypeScript level; deep-defense against timing
  attacks running JS in shared-CPU contexts requires a WASM / native
  fallback that this library does not ship.
- **Key-file password strength.** Users are responsible for choosing
  strong passwords. The single-pass Blake3 KDF provides no
  brute-force resistance beyond what the password entropy itself
  carries.

---

## 10. Versioning + freeze policy

### What's frozen (permanent)

- DALOS Ellipse parameters (`curve.ts` / `Parameters.go` `DalosEllipse`)
- The 16×16 character matrix
- Seven-fold Blake3 iteration count (7)
- Base-49 alphabet (`0-9 a-z A-M`)
- Bitmap row-major convention (black = 1, row-major TTB-LTR, 40×40)
- The Schnorr v2 challenge construction (after v2.0.0 of the Go reference)
- AES-256-GCM + Blake3 KDF encryption format

### What's additive (non-breaking)

- New input modes that are pure reshaping to the existing 1600-bit
  scalar space (v1.2.0 bitmap is an example)
- New primitives registered alongside Genesis in future library versions
- Historical curves (LETO / ARTEMIS / APOLLO in v1.1.0)
- Hardening of secret-path branching (already complete at v1.0.0)
- Expanded test-vector corpus

### What would be breaking (never)

- Changing any frozen parameter
- Adding or removing a character from the matrix
- Changing the number of Blake3 rounds
- Reordering anything in the bit-string → scalar mapping
- Modifying the Schnorr domain tag

A breaking change to Genesis is unimaginable — it would orphan every
existing account. Future generations (Gen-2 etc.) will be introduced
as **new primitives** in the registry, not modifications of Gen-1.

---

## 11. Further reading

| Document | Purpose |
|---|---|
| [`../AUDIT.md`](../AUDIT.md) | Complete source + mathematical audit (line-level) |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Go-reference version history |
| [`TS_PORT_PLAN.md`](./TS_PORT_PLAN.md) | 14-phase TypeScript port roadmap + current status |
| [`SCHNORR_V2_SPEC.md`](./SCHNORR_V2_SPEC.md) | Schnorr signature construction details (SC-1..SC-7) |
| [`HISTORICAL_CURVES.md`](./HISTORICAL_CURVES.md) | LETO / ARTEMIS / APOLLO provenance + audit |
| [`FUTURE.md`](./FUTURE.md) | Deferred R&D (Gen-2 / post-quantum / scan-order variants) |
| [`../verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) | Reproducible Python / Sage mathematical verification |
| [`../testvectors/v1_genesis.json`](../testvectors/v1_genesis.json) | 105-vector canonical Genesis corpus |
| [`../testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md) | Corpus determinism + `go vet` proof |

---

*Copyright © 2026 AncientHoldings GmbH. All rights reserved.*
