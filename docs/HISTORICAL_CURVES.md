# Historical Curves — LETO, ARTEMIS, APOLLO

> Three novel twisted-Edwards ellipses discovered during Kjrekntolopon's
> original **Cryptoplasm** research — the very first iteration of what
> would eventually become DALOS. Shipped in `@stoachain/dalos-crypto`
> starting at **v1.1.0** under the `./historical` subpath and in the Go
> reference at `Elliptic/Parameters.go` as `LetoEllipse()`,
> `ArtemisEllipse()`, `ApolloEllipse()`.

## Why these names

**DALOS** is a stylization of **Delos** — the sacred Aegean island of
Greek mythology where Apollo and Artemis were born, with their mother
Leto arriving first to give birth. The naming of the historical curves
mirrors that myth:

- **LETO** — the mother, smaller, arrived first (a 545-bit curve; the
  "introduction" to the family).
- **ARTEMIS** — the twin sister, born first of the twins (1023-bit).
- **APOLLO** — the twin brother, born moments after (1024-bit). Shares
  the same prime P with ARTEMIS; the two differ only in the curve
  coefficient `d` and consequently in the subgroup order Q.

Genesis (the production curve used by every Ouronet address) remains
**DALOS** — Delos itself, the island where the whole family meets.

## Quick facts

| Curve | Safe-scalar (S) | Prime P | Cofactor | D | Keyspace |
|---|---|---|---|---|---|
| `LETO` | **545 bits** | `2^551 + 335` | 4 | −1874 | 2⁵⁴⁵ ≈ 1.15 × 10¹⁶⁴ |
| `ARTEMIS` | **1023 bits** | `2^1029 + 639` | 4 | −200 | 2¹⁰²³ ≈ 9.0 × 10³⁰⁷ |
| `APOLLO` | **1024 bits** | `2^1029 + 639` | 4 | −729 | 2¹⁰²⁴ ≈ 1.8 × 10³⁰⁸ |
| DALOS (Genesis) | 1600 bits | `2^1605 + 2315` | 4 | −26 | 2¹⁶⁰⁰ ≈ 4.1 × 10⁴⁸¹ |

For context: Bitcoin / Ethereum / Solana all sit at 2²⁵⁶ (≈ 10⁷⁷). Even
the smallest curve here has a key-space ~10⁸⁷ × larger. DALOS Genesis
is in its own stratosphere.

## Audit status — all three pass

Each curve was subjected to the same 7-test mathematical audit that
DALOS Genesis underwent in Phase 0 of the TypeScript port. All 21
checks passed (7 tests × 3 curves). See
[`verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md)
for the reproducible run.

| Test | LETO | ARTEMIS | APOLLO |
|---|---|---|---|
| P is prime (Miller–Rabin 50 rounds) | ✅ | ✅ | ✅ |
| Q is prime | ✅ | ✅ | ✅ |
| Cofactor R = (P + 1 − T) / Q = 4 | ✅ | ✅ | ✅ |
| d is a quadratic non-residue mod P (addition-law completeness) | ✅ | ✅ | ✅ |
| G is on the curve | ✅ | ✅ | ✅ |
| **[Q]·G = O** (G has prime order Q) | ✅ | ✅ | ✅ |
| S ≤ log₂(Q) (scalar unbiased) | ✅ | ✅ | ✅ |

The TypeScript port additionally runs 33 in-source tests
(`tests/historical/historical-curves.test.ts`) that re-verify these
properties in JS-land against the exported constants.

## Why these three, and not the others

The Cryptoplasm research produced a **catalogue of 13 curves** — three
Montgomery-form, ten twisted-Edwards-form — spanning bit sizes from 10
(a toy curve) up to 1605 (what became DALOS Genesis). Only the three
above made it into `@stoachain/dalos-crypto@1.1.0`. The filter:

1. **Same structural family as DALOS_ELLIPSE.** Twisted Edwards form
   `y² + x² = 1 + d·x²·y²`, cofactor 4, negative `d`. The gen-1
   arithmetic engine (HWCD point ops + base-49 Horner scalar-mult)
   was written for this exact shape — no code modifications needed.
2. **Math works unchanged.** Cofactor-8 variants (`TEC_S1021`,
   `Curve41417`) would require generalising the cofactor-clearing
   step. The Montgomery curves (`M383`, `Curve383187`, `M511`) would
   require a second parallel arithmetic engine (XZ-coordinate
   Montgomery ladder). `Goldilocks`/Ed448 uses a specific isogeny
   presentation. All out of scope for a "historical preservation" port.
3. **E521 is intentionally excluded** even though it's twisted
   Edwards with cofactor 4 — its parameters would require audit paths
   that don't apply to DALOS, and it was only ever a unit-testing
   scaffold during the Go-era research, not production material.

## Origin story

These curves were searched by brute-force over the prime neighbourhoods
`2^(k) ± small` for various `k`, with each candidate `(P, d)` pair
vetted for:
- `P` prime (Miller–Rabin)
- `#E(F_P) = h · q` with `q` prime and `h = 4`
- Twisted-Edwards completeness (`−a` non-square mod P, so the addition
  law is complete and no corner-case branching is needed)
- Resistance to the usual MOV / CM-discriminant / Weil descent attacks

The CPU time invested is considerable. They have sentimental value to
the author beyond their technical merit. The inclusion of this subpath
in the library is an act of preservation, not a recommendation for use.

## Usage

```ts
import { LETO, ARTEMIS, APOLLO } from '@stoachain/dalos-crypto/historical';
import {
  Modular,
  affine2Extended,
  isOnCurve,
  scalarMultiplierWithGenerator,
} from '@stoachain/dalos-crypto/gen1';

const curve = LETO;
const field = new Modular(curve.p);

// Sanity check: G is on the curve
const [onCurve] = isOnCurve(affine2Extended(curve.g, field), curve, field);
console.log(onCurve); // true

// Derive a public point from a random scalar
const scalar = 42n; // in practice, something much larger
const pubPoint = scalarMultiplierWithGenerator(scalar, curve, field);
```

In Go:

```go
import "DALOS_Crypto/Elliptic"

curve := Elliptic.LetoEllipse()   // or ArtemisEllipse() / ApolloEllipse()
_ = curve.S                        // 545 — max scalar bit-width
_ = curve.G                        // affine generator
```

## What they are NOT

- **NOT production primitives.** They are not registered in the
  `CryptographicRegistry`. You cannot mint Ouronet accounts from them.
- **NOT Schnorr-ready.** The signature layer (`@stoachain/dalos-crypto`
  Schnorr v2) is hard-coded to DALOS_ELLIPSE. Using these curves for
  signatures requires writing that layer yourself.
- **NOT a suggested upgrade path.** DALOS Genesis is frozen
  permanently; there is no Gen-2 / Gen-3 migration plan that would
  replace it with a smaller curve.

## Tests

### Python (repo-level, Phase 0-style)

`verification/verify_historical_curves.py` runs the 7-test audit on
all three curves end-to-end. See
[`VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) for the
captured run.

### TypeScript (in-source)

`tests/historical/historical-curves.test.ts` runs five integrity
checks per curve:

1. Name matches upstream Go identifier
2. Bit widths (P, Q) match expected
3. Coefficients `a = 1` and `d` match expected
4. Cofactor identity: `(P + 1 − T) mod Q = 0` and `(P + 1 − T) / Q = R`
5. Generator `G` satisfies the curve equation
6. **`[Q]·G = O`** — the end-to-end math consistency proof: our
   parameterised HWCD + base-49 scalar-mult produces the group
   identity on the correct order. This is the single strongest
   evidence that the arithmetic engine generalises to each curve.

All 33 tests (11 per curve × 3 curves) pass in ~135 ms on a consumer
laptop.

## Status

| Curve | TS port | Go port | Python audit | Byte-identity | Production-ready |
|---|---|---|---|---|---|
| DALOS_ELLIPSE | ✅ v1.0.0 | ✅ | ✅ Phase 0 + ongoing | ✅ 85 Go vectors | ✅ Yes (Genesis) |
| LETO | ✅ v1.1.0 | ✅ | ✅ v1.1.0 audit | n/a (no test corpus) | No (historical only) |
| ARTEMIS | ✅ v1.1.0 | ✅ | ✅ v1.1.0 audit | n/a | No (historical only) |
| APOLLO | ✅ v1.1.0 | ✅ | ✅ v1.1.0 audit | n/a | No (historical only) |

---

*Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.*
