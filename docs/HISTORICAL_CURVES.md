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

## Production-ready as of v1.2.0

Each historical curve now has a **full `CryptographicPrimitive` wrapper**
exported from `@stoachain/dalos-crypto/registry`. Every one supports:

- 5 key-generation input paths (random / bitString / integerBase10 /
  integerBase49 / seedWords) — same API as DalosGenesis
- Schnorr v2 sign + verify — curve-agnostic, byte-determined by the
  curve parameters
- `detectGeneration(address)` routing via unique prefix pairs
- Full registry interoperation — register alongside DalosGenesis, the
  registry dispatches correctly per-curve

The 40×40 bitmap input path is **intentionally not supported** by the
historical primitives — it's tied to DALOS's 1600-bit safe-scalar
design. The other five paths cover every programmable use case.

### Address prefix pairs (all in the DALOS 256-rune matrix)

| Primitive | Standard | Smart | Example |
|---|---|---|---|
| `DalosGenesis` | `Ѻ` | `Σ` | `Ѻ.xxxxx…` (unchanged Ouronet behaviour) |
| `Leto` | `Ł` | `Λ` | `Ł.xxxxx…` / `Λ.xxxxx…` |
| `Artemis` | `R` | `Ř` | `R.xxxxx…` / `Ř.xxxxx…` |
| `Apollo` | `₱` | `Π` | `₱.xxxxx…` / `Π.xxxxx…` |

Every prefix character is a rune already present in the DALOS character
matrix, so addresses render natively in every downstream tool.

## Usage

### As first-class registry primitives (v1.2.0+)

```ts
import {
  createDefaultRegistry,
  CryptographicRegistry,
  DalosGenesis,
  Leto,
  Artemis,
  Apollo,
} from '@stoachain/dalos-crypto/registry';

// Default registry is DalosGenesis-only (Ouronet behaviour).
const def = createDefaultRegistry();
console.log(def.size()); // 1 — DalosGenesis only

// To use the historical primitives, build your own registry:
const r = new CryptographicRegistry();
r.register(DalosGenesis);
r.register(Leto);
r.register(Artemis);
r.register(Apollo);

// Mint accounts on any primitive:
const letoKey = Leto.generateRandom();
console.log(letoKey.standardAddress); // "Ł.xxxxx…"

// Sign + verify:
const sig = Leto.sign!(letoKey.keyPair, 'hello world');
const ok = Leto.verify!(sig, 'hello world', letoKey.keyPair.publ);
console.log(ok); // true

// Registry detect() routes by address prefix:
console.log(r.detect(letoKey.standardAddress)?.id); // "dalos-leto"
```

### Low-level direct use (pre-v1.2.0 API, still supported)

```ts
import { LETO } from '@stoachain/dalos-crypto/historical';
import { scalarToKeyPair, schnorrSign, schnorrVerify } from '@stoachain/dalos-crypto/gen1';

const kp = scalarToKeyPair(42n, LETO);
const sig = schnorrSign(kp, 'hello', LETO);
const ok = schnorrVerify(sig, 'hello', kp.publ, LETO);
```

### In Go

```go
import "DALOS_Crypto/Elliptic"

curve := Elliptic.LetoEllipse()   // or ArtemisEllipse() / ApolloEllipse()
_ = curve.S                        // 545 — max scalar bit-width
_ = curve.G                        // affine generator
```

## Ouronet remains DALOS-only

The default registry registers only `DalosGenesis`. OuronetUI and
AncientHoldings HUB use the default registry — they never touch
historical primitives. The historical curves are exposed by the package
for third-party cryptographic consumers; Ouronet's own address space
stays `Ѻ.` / `Σ.`.

## What they are NOT

- **NOT a suggested upgrade path for Ouronet.** DALOS Genesis is
  frozen permanently; Ouronet will not migrate off it. The historical
  primitives coexist as additional options, never as replacements.
- **NOT byte-identical with any Go test-vector corpus.** DALOS Genesis
  has 105 canonical test vectors from the Go reference; the historical
  curves don't have such a corpus. Their assurance comes from:
  mathematical soundness of curve parameters (7-test Python audit per
  curve, all passing), Schnorr round-trip self-consistency in CI, and
  `[Q]·G = O` verification in both TS and Go.
- **NOT third-party audited.** Only DALOS Genesis has undergone
  external cryptographic review. The historical curves' math is the
  same family and same engine, but external auditors have not
  specifically reviewed them. Use accordingly.

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

| Curve | TS port | Go port | Python audit | Byte-identity vs Go corpus | Registry primitive | Third-party audit |
|---|---|---|---|---|---|---|
| DALOS_ELLIPSE | ✅ v1.0.0 | ✅ | ✅ Phase 0 + ongoing | ✅ 105 vectors | ✅ `DalosGenesis` (default) | ✅ complete |
| LETO | ✅ v1.1.0 | ✅ | ✅ 7/7 passing | n/a (no corpus yet) | ✅ `Leto` (v1.2.0+) | ❌ not yet |
| ARTEMIS | ✅ v1.1.0 | ✅ | ✅ 7/7 passing | n/a | ✅ `Artemis` (v1.2.0+) | ❌ not yet |
| APOLLO | ✅ v1.1.0 | ✅ | ✅ 7/7 passing | n/a | ✅ `Apollo` (v1.2.0+) | ❌ not yet |

---

*Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.*
