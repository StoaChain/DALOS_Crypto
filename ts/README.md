# @stoachain/dalos-crypto

> TypeScript port of the DALOS Genesis cryptographic primitive — Ouronet's
> custom 1606-bit Twisted Edwards curve with six key-generation input
> paths, Schnorr v2 signatures, AES-256-GCM encryption, and a pluggable
> `CryptographicRegistry` for multi-generation forward compatibility.

[![npm](https://img.shields.io/npm/v/@stoachain/dalos-crypto.svg)](https://www.npmjs.com/package/@stoachain/dalos-crypto)
[![tests](https://img.shields.io/badge/tests-346%20passing-brightgreen.svg)](#verification)
[![license](https://img.shields.io/badge/license-UNLICENSED-blue.svg)](https://github.com/StoaChain/DALOS_Crypto)

---

## Install

```bash
npm install @stoachain/dalos-crypto
# or
yarn add @stoachain/dalos-crypto
```

Requires **Node ≥ 20** (uses native `BigInt` + `globalThis.crypto.getRandomValues`).
Runs in the browser without polyfills on any modern evergreen target.

---

## What you get

### Genesis curve — `DALOS_ELLIPSE`

A custom Twisted Edwards curve over `P = 2^1605 + 2315` (a 1606-bit
prime), with safe-scalar bit width **S = 1600**. Private key space =
**2¹⁶⁰⁰ ≈ 4 × 10⁴⁸¹** — roughly 10⁴⁰⁴ × larger than Bitcoin's.

| Parameter | Value |
|---|---|
| Name | `TEC_S1600_Pr1605p2315_m26` |
| Field prime `P` | `2^1605 + 2315` (1606-bit) |
| Subgroup order `Q` | `2^1603 + 1258387…1380413` (1604-bit prime) |
| Cofactor `R` | `4` |
| Coefficients `(a, d)` | `(1, -26)` |
| Generator `G` | `(2, 479577…907472)` |
| Safe scalar `S` | 1600 bits |

Independently audited and verified — see the main repo's
[`AUDIT.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/AUDIT.md)
and [`verification/VERIFICATION_LOG.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/verification/VERIFICATION_LOG.md).

### Six key-generation input paths — one scalar

All six paths produce **byte-for-byte identical** output with the Go
reference's [105-vector test corpus](https://github.com/StoaChain/DALOS_Crypto/blob/main/testvectors/v1_genesis.json).

| Mode | Input | Typical use |
|---|---|---|
| `random` | OS randomness | one-click account spawning |
| `bitString` | 1600-bit `0`/`1` string | research, direct scalar, paper wallets |
| `integerBase10` | decimal integer (< Q) | numeric private keys |
| `integerBase49` | base-49 string (< Q) | DALOS-native compact integer form |
| `seedWords` | array of UTF-8 words | BIP-39-style mnemonics (12 / 24 / 4–256 custom) |
| `bitmap` | 40×40 `Bitmap` | hand-painted entropy (1600 pixels = 1600 bits) |

### Schnorr v2 signatures

Full hardened Schnorr implementation with RFC-6979 deterministic nonces,
length-prefixed Fiat-Shamir challenge, and domain-tag separation.
See [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md).

### AES-256-GCM with Blake3 KDF

Matches the Go reference's key-file encryption format exactly — the TS
port additionally constrains the IV nibble to avoid a latent Go-side
edge case (≈6% failure rate in Go; 0% in TS).

### Historical curves (since `v1.1.0`)

Three extra curves from the author's original Cryptoplasm research phase,
named after the Delian family. Same structural family as DALOS (Twisted
Edwards, cofactor 4, negative `d`), smaller primes for research /
pedagogy / benchmarking. **Not production primitives** — the registry
never exposes them.

| Curve | Safe-scalar `S` | Prime `P` | Keyspace |
|---|---|---|---|
| `LETO` | 545 bits | `2^551 + 335` | 2⁵⁴⁵ ≈ 1.15 × 10¹⁶⁴ |
| `ARTEMIS` | 1023 bits | `2^1029 + 639` | 2¹⁰²³ ≈ 9.0 × 10³⁰⁷ |
| `APOLLO` | 1024 bits | `2^1029 + 639` | 2¹⁰²⁴ ≈ 1.8 × 10³⁰⁸ |

See [`docs/HISTORICAL_CURVES.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/HISTORICAL_CURVES.md)
for the full provenance, audit log, and usage.

---

## Quick start

### Mint an Ouronet account (every mode)

```ts
import { type Bitmap } from "@stoachain/dalos-crypto/gen1";
import { DalosGenesis } from "@stoachain/dalos-crypto/registry";

// 1 — OS randomness (simplest)
const a = DalosGenesis.generateRandom();

// 2 — from a custom seed phrase (any language, 4–256 words)
const b = DalosGenesis.generateFromSeedWords([
  "mountain", "whisper", "aurora", "eternal", "signal", "zen",
]);

// 3 — from a 1600-bit binary string (any sequence qualifies)
const bits1600 = "1".repeat(800) + "0".repeat(800);
const c = DalosGenesis.generateFromBitString(bits1600);

// 4 — from a base-10 integer (must be in curve range; core throws if not)
const d = DalosGenesis.generateFromInteger("123456789012345", 10);

// 5 — from a base-49 integer (DALOS alphabet, 0-9 a-z A-M)
const e = DalosGenesis.generateFromInteger("hello42", 49);

// 6 — from a 40×40 bitmap (row-major, true = black, false = white)
const bitmap: Bitmap = Array.from({ length: 40 }, () => Array<boolean>(40).fill(false));
const f = DalosGenesis.generateFromBitmap(bitmap);

// Every `FullKey` has:
console.log(f.keyPair.priv);          // base-49 private key
console.log(f.keyPair.publ);          // base-49 prefixed public key
console.log(f.privateKey.bitString);  // 1600-char binary
console.log(f.privateKey.int10);      // base-10 representation
console.log(f.privateKey.int49);      // base-49 representation
console.log(f.standardAddress);       // Ѻ.xxxxx…   (160 chars)
console.log(f.smartAddress);          // Σ.xxxxx…   (160 chars)

// All six paths feed the same Genesis pipeline; here are their addresses.
const accounts = [a, b, c, d, e, f];
console.log(`Generated ${accounts.length} accounts via 6 different input paths.`);
console.log(accounts.map((acc) => acc.standardAddress));
```

### Sign + verify (Schnorr v2)

```ts
import { sign, verify } from "@stoachain/dalos-crypto/gen1";
import { DalosGenesis } from "@stoachain/dalos-crypto/registry";

const account = DalosGenesis.generateRandom();
const sig = sign(account.keyPair, "hello world");
console.log(verify(sig, "hello world", account.keyPair.publ)); // true
```

### AES encryption (Genesis-compatible key-file format)

```ts
import { decrypt, encrypt } from "@stoachain/dalos-crypto/gen1";

const cipher = await encrypt("secret message", "strong-password");
const recovered = await decrypt(cipher, "strong-password");
console.log(recovered === "secret message"); // true
```

### Detect which primitive minted an address

```ts
import { createDefaultRegistry, DalosGenesis } from "@stoachain/dalos-crypto/registry";

const registry = createDefaultRegistry();
const account = DalosGenesis.generateRandom();
const detected = registry.detect(account.standardAddress);
if (detected) console.log(detected.id); // "dalos-gen-1"
```

---

## Subpaths

```ts
// Per-subpath narrow imports (recommended for tree-shaking).
import { fromRandom } from "@stoachain/dalos-crypto/gen1";
import { createDefaultRegistry, DalosGenesis } from "@stoachain/dalos-crypto/registry";
import { LETO } from "@stoachain/dalos-crypto/historical";
import { blake3SumCustom } from "@stoachain/dalos-crypto/dalos-blake3";

// All four subpaths exist; pick whichever surface area you need.
console.log(typeof fromRandom, typeof DalosGenesis, typeof createDefaultRegistry, typeof LETO, typeof blake3SumCustom);
```

Every subpath has first-class TypeScript types.

---

## Byte-identity with Go reference

Core value proposition: **the same input produces the same output as the
Go service at `go.ouronetwork.io/api/generate`**. The port is validated
against 105 canonical test vectors:

- 50 bitstring → keys → addresses
- 15 seed-word fixtures (ASCII + Unicode)
- 20 bitmap fixtures (hand-designed + deterministic-random)
- 20 Schnorr sign + self-verify

Plus `[Q]·G = O` end-to-end verification per curve. Run locally:

```bash
npm test   # 301 tests, ~27s
```

See the Go-reference corpus: [`testvectors/v1_genesis.json`](https://github.com/StoaChain/DALOS_Crypto/blob/main/testvectors/v1_genesis.json).

---

## Security notes

- **No console leakage.** The library never logs key material.
- **Constant-time where it matters.** The base-49 Horner scalar-mult
  uses a branch-free linear scan over the precompute matrix (SC-7).
  See `src/gen1/scalar-mult.ts` + [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md).
- **Genesis freeze.** Key-generation output is permanently frozen at
  v1.0.0. Any future additions (new input modes, new curves) MUST
  preserve byte-identity for existing inputs. The historical curves
  added in v1.1.0 are additive and do not alter Genesis behaviour.
- **Schnorr v2 deterministic nonces** — signatures are reproducible
  from `(message, privateKey)`; there is no randomness dependency and
  no nonce-reuse attack surface.
- **AES-256-GCM IV constraint** — TS port rejects IVs whose high
  nibble is zero, eliminating a latent round-trip failure present in
  the Go reference (~6% of randomly-generated IVs). Ciphertexts
  produced by the TS port decrypt cleanly on both TS and Go sides.

---

## Licence

Proprietary — Copyright © 2026 AncientHoldings GmbH. All rights reserved.
See [`../LICENSE`](https://github.com/StoaChain/DALOS_Crypto/blob/main/LICENSE).

---

## Links

- Main repo: [github.com/StoaChain/DALOS_Crypto](https://github.com/StoaChain/DALOS_Crypto)
- Architecture deep-dive: [`docs/DALOS_CRYPTO_GEN1.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/DALOS_CRYPTO_GEN1.md)
- TS port phase tracker: [`docs/TS_PORT_PLAN.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/TS_PORT_PLAN.md)
- Historical curves: [`docs/HISTORICAL_CURVES.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/HISTORICAL_CURVES.md)
- Schnorr spec: [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md)
- Gitbook: [demiourgos-holdings-tm.gitbook.io](https://demiourgos-holdings-tm.gitbook.io/kadena/ouro-network-cryptography)
