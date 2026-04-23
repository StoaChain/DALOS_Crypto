# @stoachain/dalos-crypto

TypeScript port of the DALOS Genesis cryptographic primitive — Ouronet's custom 1606-bit Twisted Edwards curve, Schnorr signatures, and six key-generation input paths (random, bitstring, integer base-10, integer base-49, seed words, 40×40 bitmap).

**Current status: v0.0.1 scaffold. Real exports land in Phase 1 onward.** See [`../docs/TS_PORT_PLAN.md`](../docs/TS_PORT_PLAN.md).

## Why this package exists

The Go reference at [`StoaChain/DALOS_Crypto`](https://github.com/StoaChain/DALOS_Crypto) runs today on `go.ouronetwork.io/api/generate` — every Ouronet `Ѻ.` / `Σ.` account is produced by that server. This TypeScript port moves all of it into the browser / client, eliminating the remote dependency.

## Genesis contract

Every function in this package is validated byte-for-byte against the Go reference's test-vector corpus at [`../testvectors/v1_genesis.json`](../testvectors/v1_genesis.json). Any deviation is a bug.

- 50 bitstring → keys → addresses
- 15 seed-word fixtures (ASCII + Unicode)
- 20 bitmap fixtures (hand-designed + deterministic-random)
- 20 Schnorr sign + self-verify

Canonical corpus SHA-256 at Go reference v2.1.0 is recorded in [`../testvectors/VALIDATION_LOG.md`](../testvectors/VALIDATION_LOG.md).

## Architecture

```
@stoachain/dalos-blake3   ← Blake3 XOF + seven-fold (published from StoaChain/Blake3)
        ↑ dep
@stoachain/dalos-crypto   ← THIS PACKAGE
        ↑ dep
@stoachain/ouronet-core   ← blockchain, codex, Pact, signing
        ↑ dep
OuronetUI / AncientHoldings Hub / etc.
```

## Development

```bash
npm install       # install devDeps
npm run build     # tsc → dist/
npm test          # vitest run
npm run lint      # biome check
npm run format    # biome format --write
```

## Licence

Proprietary — Copyright © 2026 AncientHoldings GmbH. All rights reserved. See [`../LICENSE`](../LICENSE) for the full terms.
