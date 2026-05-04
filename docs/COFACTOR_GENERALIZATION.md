# Cofactor Generalization

> **Audience:** human contributors AND AI agents adding new elliptic-curve primitives
> with cofactor `h ≠ 4` to this codebase. Read this in addition to
> [`docs/ADDING_NEW_PRIMITIVES.md`](ADDING_NEW_PRIMITIVES.md) before touching any
> cryptographic code that depends on the cofactor.

## TL;DR

- **Current state:** all 4 production curves (DALOS, LETO, ARTEMIS, APOLLO) have cofactor `h = 4`. The Schnorr verifier's cofactor check uses a fast 2-doubling implementation.
- **Hybrid mode (v4.0.2, F-MED-017):** the dispatch helper `cofactorCheckRejects` (Go) / `cofactorCheckRejects` (TS) supports any `h`. The h=4 fast path is preserved byte-identically; h=2 and h=8 use the doubling chain; arbitrary h falls back to general scalar multiplication.
- **The code now supports any cofactor — but using a non-h=4 curve requires more than just adding it.** This document is the playbook for the rest of the work.

## What is a cofactor and why does it matter?

A Twisted Edwards curve `E(F_p)` (`a·x² + y² = 1 + d·x²·y²` over a prime field `F_p`) has a finite number of points. That number — the curve's *order* — factorizes as

```
#E(F_p) = h · q
```

where `q` is a large prime and `h` (the **cofactor**) is a small integer. For DALOS Genesis, `h = 4` and `q` is a 1604-bit prime. The "safe" subgroup we use for cryptography is the order-`q` subgroup; the cofactor `h` represents the small "leftover" structure.

The 4-torsion subgroup of DALOS contains exactly 4 points: the identity and three points of orders dividing 4. These are the **small-subgroup attack surface**. If a verifier accepts a public key or signature R-value that happens to lie in the small subgroup, an attacker can leak `log₂(h)` bits of the signer's private key per signature — a slow but exploitable side channel.

**The cofactor check `[h]·X != O`** rejects any point in the h-torsion subgroup:

- For a legitimate point `X = [k]·G` (where `G` has prime order `q` and `k ∈ [1, q-1]`), `[h]·X = [hk]·G`. Because `gcd(h, q) = 1` (a structural property of well-constructed curves), `hk mod q ≠ 0`, so `[h]·X ≠ O`. ✓
- For an attack point `X` in the h-torsion subgroup, `[h]·X = O` by definition of "h-torsion". ✗ (rejected)

This check is **load-bearing for Schnorr verification** in the DALOS protocol (REQ-16, F-SEC-001).

## How the cofactor influences implementation

Computing `[h]·X` for an arbitrary `h` is the same operation as any scalar multiplication, but for small `h` there are dramatically faster shortcuts:

| Cofactor h | Implementation | Cost (in HWCD point ops) | Used by |
|---|---|---|---|
| 1 | trivial — no check needed | 0 | Brainpool curves, NIST P-curves (not Twisted Edwards) |
| 2 | 1 doubling | ~5–7 big.Int ops | hypothetical |
| **4** | **2 chained doublings (FAST PATH)** | **~10–15 big.Int ops** | **DALOS, LETO, ARTEMIS, APOLLO** |
| 8 | 3 chained doublings | ~15–22 big.Int ops | Curve25519 / Ed25519 family |
| 16, 32, ... (2^k) | k chained doublings | ~5k–7k big.Int ops | rare |
| 6, 12, 24 (non-powers-of-2) | full `ScalarMultiplier(h, X)` fallback | ~96 big.Int ops | rare; FourQ uses h=392 |

**Why the doubling chain works for `h = 2^k`:** point doubling is the operation `[2]·P`, so `[2^k]·P = [2^(k-1)]·([2]·P) = ... = doubling(doubling(... k times ...(P)))`. This is a one-line proof by induction.

**Why doublings alone don't work for non-powers-of-2:** to compute `[6]·P` from doublings only you would need `[6]·P = [4]·P + [2]·P`, which requires both chained doublings AND a point addition. The general `ScalarMultiplier(h, P)` already handles this via base-49 digit decomposition — it's slower (~16x) but always correct.

## Small-subgroup attacks: the threat model in detail

An attacker who controls the public key `P` (or the verifier-side `R` for a forged signature) can mount a small-subgroup attack as follows:

1. **Construct a malicious public key** `P' = P + T` where `T` is a non-identity point in the h-torsion subgroup (`[h]·T = O`).
2. **Submit `(R, s)` for verification against `P'`.** The verification equation `s·G = R + e·P'` becomes `s·G = R + e·P + e·T`.
3. **The leakage term is `e·T`.** Since `T` has small order `d | h`, the values `[e]·T` for varying challenges `e` cycle through only `d` distinct values.
4. **Over many signatures**, the attacker observes which "bucket" each signature falls into and learns `k mod d`. Across multiple small-order elements (orders dividing `h`), the Chinese Remainder Theorem combines these to give `k mod h` — i.e., `log₂(h)` bits of the secret key per signature.

For h=4, this is 2 bits per signature. For h=8 (Curve25519), 3 bits. Recovering a full 256-bit private key takes ≈128 signatures for h=4, ≈86 for h=8 — well within practical attack budgets.

**The cofactor check fully closes this attack** by rejecting any point in the h-torsion subgroup at the protocol boundary. Combined with the on-curve check (which rejects points NOT in `E(F_p)` at all), it forms the **multi-layer defense** documented in CLAUDE.md and Phase 6 of the unified-audit-2026-04-29 spec.

## Implementation in this codebase

### The dispatch helper

**Go** (`Elliptic/Schnorr.go`, post-F-MED-017):

```go
func (e *Ellipse) cofactorCheckRejects(X CoordExtended) bool {
    h := e.R.Int64()
    k, isPow2 := isPowerOfTwo(h)

    if isPow2 {
        // k chained doublings produces [2^k]·X = [h]·X.
        Y := X
        for i := 0; i < k; i++ {
            Y = e.noErrDoubling(Y)
        }
        return e.IsInfinityPoint(Y)
    }

    // Non-power-of-2 cofactor — fallback to general scalar multiplication.
    hScalar := new(big.Int).Set(&e.R)
    Y := e.ScalarMultiplier(hScalar, X)
    return e.IsInfinityPoint(Y)
}
```

**TS** (`ts/src/gen1/schnorr.ts`, post-F-MED-017): mirrors the Go logic exactly. Uses `e.r` (BigInt) instead of `e.R`. The `log2OrMinusOne` helper is inlined. The fallback path uses `scalarMultiplier(h, x, e)`.

The dispatch is called from both `SchnorrVerify` (the cofactor check on `R`) and (the cofactor check on `P`), in both the sync and async TS variants. **All four call sites use the same helper** — no behavior duplication.

### Correctness proofs

The dispatch's mathematical equivalence is proven by tests in `Elliptic/Schnorr_strict_parser_test.go`:

- **`TestIsPowerOfTwo`** — pins the helper that decides "doubling chain" vs "fallback". 16 sub-cases including edges (0, negative, large powers of 2, primes).
- **`TestCofactorCheckRejects_DispatchEquivalence_h4`** — for the h=4 fast path on real DALOS points: dispatch result matches both explicit-2-doublings AND general `ScalarMultiplier(4, X)`. Proves byte-identity preservation for production curves.
- **`TestCofactorCheckRejects_DispatchEquivalence_h2_synthetic`** — synthesizes a "fake h=2 curve" (DALOS with `e.R = 2`) and verifies dispatch matches both explicit single-doubling AND `ScalarMultiplier(2, X)`.
- **`TestCofactorCheckRejects_DispatchEquivalence_h8_synthetic`** — same for h=8 (3-doubling path, Ed25519/Curve25519 cofactor).
- **`TestCofactorCheckRejects_DispatchEquivalence_h12_synthetic_fallback`** — verifies the non-power-of-2 fallback dispatches to general scalar multiplication.

The synthetic tests don't validate that the resulting fake-h=8 curve is cryptographically sound (it isn't — the DALOS Q is not coprime to 8 in the fake construction). They verify the **dispatch logic** picks the right strategy. Real-curve correctness is the responsibility of any future contributor adding such a curve, per the "preconditions" section below.

### Codebase locations that currently assume h=4

These files / lines have h=4 baked in beyond just `e.R = 4`:

| File | Lines | What's hardcoded |
|---|---|---|
| `Elliptic/Schnorr.go` | 39–55 (doc) | Original F-PERF-001 commentary describing the h=4 fast path |
| `Elliptic/Schnorr_strict_parser_test.go` | `TestCofactor4_*` | Test names mention h=4; tests still valid post-dispatch refactor |
| `Elliptic/Schnorr_adversarial_test.go` | full file | Adversarial test cases use the h=4 small subgroup of DALOS |
| `testvectors/generator/main.go` | ~707–750 | Generator code constructs adversarial vectors using `T₂ = (0, P-1)` — the order-2 point of DALOS, h=4-specific |
| `testvectors/v1_adversarial.json` | full file | Frozen 5-vector corpus of h=4 small-subgroup attacks + 1 control |
| `.github/workflows/go-ci.yml` | BASELINES dict | Pins the `v1_adversarial.json` SHA to its h=4 baseline |

A new-cofactor curve must NOT modify any of these — instead, it adds **new** files that mirror the structure (e.g., `v2_<curve>_adversarial.json` with vectors from the new curve's h-torsion).

## Adding a new-cofactor curve: the playbook

Follow this in addition to (not instead of) [`docs/ADDING_NEW_PRIMITIVES.md`](ADDING_NEW_PRIMITIVES.md). The general primitive playbook covers the *structure* (separate generator paths, separate corpus files, frozen SHAs); this doc covers the *cofactor-specific math*.

### Step 1 — Verify the cofactor is supportable

Check the new curve's parameters against these preconditions:

1. **`gcd(h, q) = 1`** must hold, where `h` is the cofactor and `q` is the prime order of the base point. If `h` and `q` share a factor, the cofactor check has false positives (legitimate points are wrongly rejected). Compute via `gcd(h, q) == 1` in any big-integer library.

2. **`h` must be a positive integer.** Negative or zero cofactors are nonsensical.

3. **For best performance, `h` should be a power of 2.** Non-power-of-2 cofactors fall back to general `ScalarMultiplier`, which is ~16x slower per verify.

4. **The curve must be Twisted Edwards.** The `cofactorCheckRejects` dispatch assumes the curve uses HWCD extended coordinates and Twisted Edwards point doubling. Other curve forms (Weierstrass, Montgomery) need different code (out of scope for this doc).

If any of these fail, **do not add the curve.** Either fix the curve's parameters (Step 1.1: change the prime, Step 1.4: convert via isomorphism) or use a different verifier.

### Step 2 — Compute the curve's h-torsion subgroup

You need the explicit coordinates of every point in `E[h]` (the h-torsion subgroup) for two reasons:
- To construct adversarial test vectors that the cofactor check must reject.
- To verify your cofactor-check implementation matches your math (sanity check).

For `h = 4`:
- The 4-torsion subgroup has 4 points.
- The identity `O` (extended coords `(0, 1, 1, 0)`).
- The order-2 point: solve `2·P = O` on the curve. For Twisted Edwards `a·x² + y² = 1 + d·x²·y²`, the order-2 point is `(0, -1) = (0, p-1) mod p`.
- Two order-4 points: solve `4·P = O` but `2·P ≠ O`. These come from `y² = 1/(a + d)` (when `a + d` is a quadratic residue mod p) — see `testvectors/generator/main.go` lines 700–730 for the DALOS construction.

For `h = 8`:
- 8 points total. The 4 above PLUS 4 more order-8 points.
- Construction is curve-specific. For Curve25519 specifically, see RFC 7748 / the Curve25519 paper for the 8-torsion coordinates.

For `h > 8`:
- Use Tonelli-Shanks or Cantor-Zassenhaus to find roots; consult a CAS like SageMath.

### Step 3 — Construct adversarial vectors

For each non-identity point `T ∈ E[h]`:
1. Pick a legitimate keypair `(k, P)` where `P = [k]·G`.
2. Construct the malicious public key `P' = P + T`. (Or for an R-side attack: construct `R'` similarly.)
3. Compute a Schnorr signature `(R, s)` using the legitimate key and any message `m`.
4. Verify the signature against the malicious key `P'`. **It must fail** at the cofactor check (because `[h]·P' = [h]·P + [h]·T = [h]·P + O = [h]·P`, but `P' = P + T` is not the public key the signer signed for).
5. Wait — actually the better attack vector is: construct `P' = T` directly (P' is itself a small-subgroup point). The cofactor check `[h]·P' = [h]·T = O` rejects.
6. Add the test vector to `testvectors/v<N>_<curve>_adversarial.json` with `expected_verify_result: false`.

For the **legitimate control vector**: pick `(k, P)` where `P = [k]·G` legitimately, sign a message, verify with the real `P` — must succeed (`expected_verify_result: true`).

The DALOS h=4 corpus has 4 adversarial + 1 control = 5 vectors. An h=8 curve would need at least 7 adversarial (for the 7 non-identity h-torsion points) + 1 control.

### Step 4 — Wire the new corpus into the CI gate

Per [`docs/ADDING_NEW_PRIMITIVES.md`](ADDING_NEW_PRIMITIVES.md) Step 6: add a new line to the `BASELINES` associative array in `.github/workflows/go-ci.yml`:

```yaml
declare -A BASELINES=(
  ["testvectors/v1_genesis.json"]="082f7a40..."
  ["testvectors/v1_historical.json"]="80c93f4d..."
  ["testvectors/v1_adversarial.json"]="b9f228943106..."
  ["testvectors/v2_<curve>_adversarial.json"]="<your-new-frozen-sha>"  # ← NEW
)
```

This ensures any future change that perturbs your corpus fails CI.

### Step 5 — TS port mirror

The Go-side `cofactorCheckRejects` dispatch handles any `h` automatically once `e.R` is set correctly. The TS-side `cofactorCheckRejects` (in `ts/src/gen1/schnorr.ts`) does the same — it reads `e.r` (BigInt) and dispatches.

For a new curve to use the TS verifier:
1. Add the curve definition under `ts/src/historical/<curve>.ts` or `ts/src/gen2/<curve>.ts` (depending on whether it's a historical curve or a new generation).
2. Set `r` to the BigInt cofactor (e.g., `r: 8n` for h=8).
3. Add a TS-side test loading `v<N>_<curve>_adversarial.json` and asserting all vectors verify as expected.
4. Wire the curve into the registry adapter (`ts/src/registry/`) for cross-curve API access.

### Step 6 — Documentation

Update these in addition to per-`ADDING_NEW_PRIMITIVES.md` Step 7:

- **CLAUDE.md** invariants list: add the new curve's cofactor and a one-line note about its small-subgroup attack profile.
- **`docs/COFACTOR_GENERALIZATION.md`** (this file): add an entry to the "Codebase locations that currently assume h=4" table listing any NEW h=8 (or h=N) assumptions you introduced.
- **`docs/SCHNORR_V2_SPEC.md`**: if your curve uses the v2 Schnorr wire format, no changes needed (the format is cofactor-agnostic). If it uses a new wire format, write a separate spec doc.
- **`docs/HISTORICAL_CURVES.md`** or a new per-curve doc: per-curve parameters, threat model, performance characteristics.

## Worked example: adding Ed25519 (h=8) support

Suppose a future contributor wants to add Ed25519 (h=8, q=2^252 + 27742317777372353535851937790883648493) to the codebase. Step-by-step:

### Pre-flight (Step 1)
- Verify `gcd(8, q) = 1`. For Ed25519 q (an odd prime, since 2^252 + (odd) is odd), `gcd(8, q) = 1`. ✓
- Curve is Twisted Edwards. ✓
- h=8 is a power of 2 (3 doublings, fast path). ✓
- → Cofactor is supportable.

### h-torsion construction (Step 2)
- E[8] has 8 points. RFC 7748 (Curve25519) lists them explicitly: `O`, the order-2 point, two order-4 points, four order-8 points.
- For verification of the implementation: compute `[8]·P` for each — should yield `O` for all 8.

### Curve definition
- Add `Elliptic/EdwardsCurves/Ed25519.go` (NEW package or sub-package).
- Define `e.R = big.NewInt(8)`.
- Define `e.A`, `e.D`, `e.P`, `e.Q`, `e.G` per RFC 7748.

### Schnorr verifier — no changes needed
- `cofactorCheckRejects` already dispatches `e.R = 8` to the 3-doubling path.
- No changes to `Schnorr.go` or `schnorr.ts`.

### Adversarial corpus (Step 3)
- Construct 7 non-identity h-torsion points as adversarial keypairs.
- Construct 1 legitimate control.
- Generator code: add a new function to `testvectors/generator/main.go` (e.g., `generateEd25519AdversarialCorpus`).
- Output to `testvectors/v2_ed25519_adversarial.json`.

### CI gate (Step 4)
- Compute the elided SHA-256 of `v2_ed25519_adversarial.json`.
- Add to `BASELINES` in `.github/workflows/go-ci.yml`.

### TS mirror (Step 5)
- Add `ts/src/historical/ed25519.ts` (or `ts/src/gen2/ed25519.ts`).
- Set `r: 8n`.
- Add cross-impl byte-identity test against the new adversarial corpus.

### Documentation (Step 6)
- Update CLAUDE.md, ADDING_NEW_PRIMITIVES.md, this doc.

### Verification
- Run `go test ./...` — all green, including new dispatch tests.
- Run `npm test` from `ts/` — all green, including new byte-identity assertions.
- Run the corpus generator + check all 4 SHAs (genesis, historical, adversarial, ed25519_adversarial) match committed baselines.

## Performance considerations

Schnorr verification is the hot path for any chain validating signatures at scale. Cofactor-check costs are:

| Cofactor h | Big.Int ops per verify (R + P combined) | Penalty vs h=4 |
|---|---|---|
| 1 | 0 | -100% (trivial) |
| 2 | ~10–14 | ~30% lower |
| **4 (DALOS family)** | **~20–30** | **baseline** |
| 8 (Curve25519 family) | ~30–44 | ~50% higher |
| 16 | ~40–58 | ~100% higher |
| 12 (non-power-of-2) | ~192 | ~700% higher |

The doubling chain scales linearly in `log₂(h)`. Non-power-of-2 cofactors take a step function increase due to the `ScalarMultiplier` PrecomputeMatrix construction.

For most realistic curves (h ≤ 8), the cost stays trivial relative to the surrounding signature math (Schnorr verify itself is several hundred big.Int ops total). Adding an h=12 curve would be a noticeable hot-path regression — consider whether the curve choice is justified.

## When you might NEED to bypass the dispatch

The dispatch helper is the right answer for **standard small-subgroup checks**. There are a few edge cases where a curve might need different handling:

1. **Curves with no small-subgroup attack vector (h=1).** The cofactor check is trivially `[1]·X != O`, equivalent to "X is not the identity". Our `IsInfinityPoint` check on parsed points already handles this; the cofactor check becomes redundant. If you have a confirmed h=1 curve and want to skip the cofactor check entirely for performance, document it explicitly — but don't disable the upstream `IsInfinityPoint` check.

2. **Curves with composite-cofactor partial-rejection.** Some protocols want to reject only certain orders (e.g., reject the 4-torsion but accept order-8 points). Our dispatch rejects the full h-torsion. If you need finer-grained rejection, write a custom check; don't modify the dispatch.

3. **Curves using a non-Twisted-Edwards form.** Weierstrass, Montgomery, and Hessian curves have different cofactor-check math (and often different attack vectors). The dispatch helper is Twisted-Edwards-only.

These edge cases are rare. If you think you need them, the right move is to write a separate verifier that doesn't share `Elliptic/Schnorr.go` — don't shoehorn into the dispatch.

## Cross-references

- [`docs/ADDING_NEW_PRIMITIVES.md`](ADDING_NEW_PRIMITIVES.md) — general primitive-addition playbook (this doc is the cofactor-specific addendum).
- [`docs/SCHNORR_V2_SPEC.md`](SCHNORR_V2_SPEC.md) — Schnorr v2 wire format (cofactor-agnostic).
- [`CLAUDE.md`](../CLAUDE.md) — project invariants.
- [`AUDIT.md`](../AUDIT.md) — known issues and remediation history.
- [`testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md) — per-release SHA pinning.
- `Elliptic/Schnorr.go` — Go-side dispatch + verifier.
- `ts/src/gen1/schnorr.ts` — TS-side dispatch + verifier.
- `Elliptic/Schnorr_strict_parser_test.go` — dispatch equivalence proofs.

## For AI agents

If you're an AI agent adding a new-cofactor curve:

1. **Read this entire document plus [`docs/ADDING_NEW_PRIMITIVES.md`](ADDING_NEW_PRIMITIVES.md) before writing any code.** The dispatch helper is necessary but not sufficient. Adversarial vector construction is the load-bearing step you cannot skip.

2. **Verify `gcd(h, q) = 1` programmatically.** Add a one-time runtime assertion in the curve definition (e.g., a `func init()` block in the curve's `*.go` file) that fails fast if the precondition doesn't hold. This is a defensive invariant — production code should never construct a curve where it fails.

3. **Hand-construct the h-torsion adversarial vectors using a trusted reference.** RFCs (7748 for Curve25519, 8032 for Ed25519, etc.) list torsion-point coordinates explicitly. SageMath can compute them for arbitrary curves. Do not invent coordinates from scratch unless you can prove they're correct.

4. **Run the full equivalence test suite for your new cofactor.** Add `TestCofactorCheckRejects_DispatchEquivalence_h<your-h>` mirroring the existing tests. Use synthetic curve points (mutating `e.R` on DALOS) to verify the dispatch logic; use real curve points after the curve is defined to verify end-to-end.

5. **The CI byte-identity gate is your safety net.** If your changes accidentally perturb any existing corpus (DALOS, LETO, ARTEMIS, APOLLO h=4 vectors), CI fails red and you should investigate before forcing through.

6. **Never modify the BASELINES array in `.github/workflows/go-ci.yml` to "fix" a failing gate.** A red gate means you've broken something else; updating the pin masks the breakage. The only legitimate update is when you're explicitly adding a new pin for a new corpus you've just frozen.

7. **Cross-impl byte-identity is the strongest correctness proof.** The TS suite asserts byte-identity against Go-produced corpus on every test run. If your TS implementation diverges from Go, this fails immediately. Treat any TS-side byte-identity failure as a bug to fix, not a corpus to update.

The math is the math — but the playbook ensures you don't accidentally ship a curve that's mathematically sound but operationally vulnerable (because the adversarial vectors are missing, or the corpus pin is wrong, or the TS port silently disagrees with Go).
