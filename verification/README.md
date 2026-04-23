# DALOS Curve Parameter Verification

Mathematical soundness checks for the DALOS Twisted Edwards curve
parameters in `../Elliptic/Parameters.go`. Run these **before** starting
the TypeScript port.

## What we verify

| # | Check | Why |
|---|-------|-----|
| 1 | `P = 2^1605 + 2315` is prime | Field F_P must be a proper field |
| 2 | `Q = 2^1603 + K` is prime | Base-point order must be prime |
| 3 | `R = (P + 1 - T) / Q` is an integer | Cofactor must divide cleanly |
| 4 | `d = -26` is a non-square mod P | Required for Bernstein-Lange complete addition |
| 5 | `G = (2, Y_G)` lies on the curve | Generator must satisfy the curve equation |
| 6 | `[Q] * G = O` | Generator must have order exactly Q |
| 7 | `1600 <= log2(Q)` | Safe-scalar size claim is sound |

## Pick one: Python OR Sage

### Option A — Python (simpler, no install beyond pip)

```bash
pip install gmpy2 sympy
python verify_dalos_curve.py
```

If gmpy2 won't build on Windows (needs C compiler), `sympy` alone works —
just slower.

Expected runtime:
- **with gmpy2** : ~30 seconds total
- **without gmpy2** : a few minutes (sympy's BPSW is thorough but slow)

### Option B — Sage (canonical tool for this kind of verification)

**No install needed** — paste the whole file into the free online
runner: https://sagecell.sagemath.org/  → click "Evaluate".

**Or install locally:**
- Windows: `winget install sagemath.sagemath` (or WSL + `apt install sagemath`)
- Mac:    `brew install --cask sage`
- Linux:  `apt install sagemath` / `dnf install sagemath`

Then:
```bash
sage verify_dalos_curve.sage
```

**Or clone the Sage repo and build from source** (overkill — Sage is a
huge project, builds take hours):
```bash
git clone https://github.com/sagemath/sage.git
cd sage && make configure && ./configure && make
```

> You do **not** need to build Sage from source just to run a 50-line
> verification script. Use the Sage Cell Server for zero-setup.

## Why two scripts?

- **`verify_dalos_curve.py`** — maximum portability, runs on any Python
  3.8+, uses only well-known packages. You can share this with anyone.
- **`verify_dalos_curve.sage`** — cleaner math notation, uses Sage's
  built-in `is_prime()` (Pari/GP-backed, APR-CL deterministic),
  native `GF(p)` field operations. Better for peer review by
  cryptographers.

Both do the same 7 tests; both should agree 100%. If one passes and the
other fails, that's a bug somewhere — investigate before porting.

## Independence note

If you want maximum assurance, have **two independent parties** run the
scripts. The verification is deterministic (modulo the probabilistic
primality test with 2^-100 error rate); identical inputs yield identical
outputs.
