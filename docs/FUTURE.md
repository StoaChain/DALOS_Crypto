# DALOS Cryptography — Future Directions

Ideas deferred from the Genesis implementation. Recorded here so they're not lost. None of these are blocking the current roadmap; they are exploratory R&D for later.

---

## 1. Post-Quantum Research (priority: HIGH, long-horizon)

**Motivation.** A sufficiently powerful cryptanalytically-relevant quantum computer (CRQC) using Shor's algorithm breaks **any** elliptic-curve system — including DALOS — in polynomial time. The 1600-bit DALOS curve is ~2²⁴ times harder than SECP256K1 classically, but **under Shor's algorithm the curve bit-length is largely irrelevant** — both fall. Going to a 2500-bit or 3000-bit curve does not meaningfully change the quantum timeline; it only buys ~log₂ factors.

**Strategic implication.** If DALOS is to remain secure against CRQC-enabled adversaries, the answer is **not** a bigger curve. The answer is a **different family of primitives** — ones based on hardness assumptions Shor does not break.

**Candidate primitive families for a future "DALOS Gen-2" or distinct quantum-resistant track:**

| Family | Hardness assumption | Examples |
|--------|--------------------|----------|
| Lattice-based (module-LWE) | Learning With Errors | Kyber (KEM), Dilithium (sig) — NIST-standardised 2024 |
| Hash-based signatures | Preimage resistance of hash | SPHINCS+, XMSS |
| Code-based | Syndrome decoding | Classic McEliece |
| Isogeny-based | Supersingular isogeny walks | (SIDH broken 2022 — SIKE not recommended; **CSIDH** still under research) |
| Multivariate quadratic | MQ problem | Rainbow (broken) — wait for next generation |

**Practical roadmap.**

- **Do not pursue bigger curves.** Prime searches for a 2500-bit (or larger) DALOS-equivalent would consume enormous CPU with negligible quantum-era benefit.
- **Monitor the NIST PQC standardisation** through rounds 4–5 and beyond.
- **Consider publishing a `@stoachain/dalos-pq` primitive** that registers alongside `dalos-gen-1` via the cryptographic primitive registry. Users get to choose per-account which primitive to use for new accounts.
- **Hybrid approach (recommended before full PQC migration):** sign with both DALOS-Genesis AND a PQ primitive. Signature valid only if both verify. Gives "breaks only if BOTH primitives are broken" guarantee. Classical overhead is small.
- **Address length.** If a PQ primitive is adopted, PQ account addresses will be longer (PQ public keys are 1–100 KB for most schemes, compared to DALOS's ~1000 chars). A new prefix character (e.g., `Q.` for Quantum accounts) would distinguish them from Genesis accounts.

**Decision point.** Do NOT begin PQ work until there's a compelling event (NIST finalisation of a small-public-key scheme, credible CRQC announcement, regulatory mandate). Currently: monitor, don't invest.

---

## 2. Bitmap Scan-Order Variants (priority: LOW-MEDIUM, short-horizon)

**Current Genesis convention.**

| Parameter | Value |
|-----------|-------|
| Bit value | Black pixel = 1, White pixel = 0 |
| Scan order | Row-major, top-to-bottom, left-to-right |
| Greyscale handling | Strict — pure 0x000000 or 0xFFFFFF only; reject other pixel values |
| Bitmap size | 40 × 40 = 1600 pixels = 1600 bits = DALOS safe-scalar size |

**Proposed future variants (opt-in, registered as named primitives):**

### 2.1 Alternative scan orders

Same 40×40 bitmap, but the 1600 bits are read in a different order. Produces a different bitstring → different scalar → different account.

Known "naturally memorable" variants:

- Row-major RTL-TTB (reading direction for Arabic / Hebrew users)
- Column-major TTB-LTR
- Column-major TTB-RTL
- Zigzag row-major (boustrophedon)
- Spiral, inward from top-left
- Spiral, outward from centre
- Hilbert curve (fractal space-filling, 2 rotations × 2 reflections = 4 variants)
- Peano curve (fractal, 2 rotations × 2 reflections = 4 variants)
- Diagonal scans (zigzag across diagonals, like JPEG zig-zag)

Total "natural" variants: ~30–50 → ~5–6 bits of entropy.

### 2.2 Pseudo-random scan order from a user-selected seed

The user picks a 32- or 64-bit seed; the bitmap is scanned in a deterministic permutation seeded by it.

- 32-bit seed → 2³² ≈ 4 × 10⁹ variants → 32 bits of entropy
- 64-bit seed → 2⁶⁴ ≈ 10¹⁹ variants → 64 bits of entropy

**Caveat.** The seed becomes a second secret the user must remember. Losing it is equivalent to losing the key.

### 2.3 Security analysis

- Bitmap alone already has 1600 bits of entropy — no practical cryptographic need for more.
- Scan-order variants add **defence-against-casual-leakage**: someone photographing your paper bitmap doesn't have the key without also knowing the scan order.
- Against a targeted attacker who knows the account holder's habits, this provides little extra.

**Recommendation.** Do not rush this. If demand arises, the cleanest way to ship it is as a separately-registered primitive `dalos-gen-1-bitmap-v2` with an explicit scan-order parameter in the address-derivation. Genesis addresses stay Genesis.

---

## 3. Additional Key-Generation Input Types (priority: LOW, community-driven)

The Genesis TS port will expose 6 key-gen paths (5 original + bitmap). Additional inputs could be registered as extensions:

- **Audio waveform** — hash a recorded voice sample to derive 1600 bits
- **Geolocation** — hash lat/long pairs for place-based keys (risky: low entropy)
- **Handwriting vector** — sample a drawn signature's stroke path
- **Graph-structured input** — user-designed node/edge graph serialised deterministically

None of these are as safe as the existing 5 for mainstream users. They're creative demos for showcasing DALOS's flexibility. **Never use low-entropy inputs (geolocation, short audio clips) without extensive stretching**.

---

## 4. Bigger Curves (priority: VERY LOW — explicitly not pursuing)

**Original idea (from the DALOS author's design notes):**

> A churning script that uses computing power to search for the next prime number that would result in a bigger ellipse. E.g., a 2500-bit-capable curve would use a 50×50-pixel bitmap (2500 bits).

**Why this is NOT on the roadmap:**

1. **Does not defeat quantum attacks.** Shor's algorithm breaks ECDLP in polynomial time regardless of curve size. A 2500-bit curve falls to a CRQC in not-much-more time than a 1600-bit curve. So the defensive benefit is marginal — post-quantum primitives (Section 1) dominate.

2. **Compute cost of prime search is enormous.** The original 2¹⁶⁰⁵ + 2315 search was run on a 32-thread Ryzen 5950X for days. A 2500-bit prime search is similarly expensive; a 3000-bit search is an order of magnitude more. No corresponding benefit.

3. **Bigger curve = slower keygen, slower signing.** A 2500-bit bitstring means 2500-bit scalar multiplication. Roughly 2-3× slower than 1600-bit. User-facing latency would get worse.

4. **1600 bits is already far beyond current need.** 2¹⁶⁰⁰ is ~10⁴⁸¹ — there are ~10⁸⁰ atoms in the observable universe. The classical security margin is already comical.

**Verdict.** The DALOS-Genesis 1600-bit curve stays. Future cryptographic advancement should target primitive-level innovation (Section 1), not curve-size scaling.

---

## 5. Sagemath-Based Advanced Verification (priority: LOW)

Current verification (`../verification/verify_dalos_curve.py`) establishes soundness of the 7 core properties. Possible extensions if full Sage is available:

- Compute the Cremona / Atkin–Elkies–Schoof point-counting algorithm to independently derive the curve order (currently trusted from the recorded trace T)
- Compute the discriminant and j-invariant
- Test for known "weak curve" classes (singular, anomalous trace, low embedding degree)
- Generate a one-shot formal proof certificate

None of these would change the Genesis conclusion, but would strengthen the audit with extra independent derivations.

---

## 6. Third-Party Security Audit (priority: MEDIUM, time-sensitive)

Strongly recommended before:

- DALOS Schnorr is activated for on-chain authentication
- DALOS primitives are used in multi-tenant or time-attack-sensitive environments  
- The TypeScript port is used to sign transactions with significant financial consequences

**Candidate auditors** (for the Go and forthcoming TS code):

- **Trail of Bits** — strong ECC and Go expertise
- **Kudelski Security** — cryptographic audits
- **Quarkslab** — low-level crypto and blockchain
- **Dedaub** — smart-contract + crypto primitive expertise
- **Sigma Prime** — blockchain-specific

A typical engagement is 4–8 weeks of auditor time, $30k–$100k. Budget and scope TBD by AncientHoldings GmbH.

---

## 7. Hardware Wallet Integration (priority: LOW)

If DALOS Schnorr ever becomes on-chain primary authentication, hardware-wallet support becomes critical. Options:

- **Ledger** — a DALOS app would require porting to the BOLOS OS's constrained environment (no Blake3 primitive built-in; would need ~10 KB of code and careful memory management)
- **Trezor** — similar porting effort
- **Custom hardware** — a dedicated StoaChain device (ambitious; probably 2–3 years out)

Discussion only; no work planned.

---

*This document is an idea park, not a commitment. Items here are researched and scoped when the time comes.*

*See [`../AUDIT.md`](../AUDIT.md) for what has been audited, [`../CHANGELOG.md`](../CHANGELOG.md) for what has shipped, and [`TS_PORT_PLAN.md`](TS_PORT_PLAN.md) for what is actively underway.*
