# CLAUDE.md — DALOS_Crypto

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## New Claude session? Start here.

This project is linked to **Claudstermind** at `../Claudstermind/`. Run the cluster-load skill:

> Read `../Claudstermind/README.md` and load context for this project.

See [`../Claudstermind/skills/load-cluster.md`](../Claudstermind/skills/load-cluster.md) for the full procedure. Claudstermind holds this project's onboarding, current state, architecture, conventions, and accumulated learnings — always check there before re-briefing Claude.

The knowledge base lives at [`../Claudstermind/projects/DALOS_Crypto/`](../Claudstermind/projects/DALOS_Crypto/).

## Cluster context at a glance

DALOS_Crypto is the cryptographic foundation of the Ouro-Network. Every `Ѻ.` / `Σ.` account anywhere in the Ancient-Holdings suite was produced by this code (Go reference) or the `go.ouronetwork.io/api/generate` service running it. Genesis key-gen output is **permanently frozen** at commit `d136e8d` (tag `v1.0.0`); the 105-vector corpus in `testvectors/v1_genesis.json` is the contract every future language port must satisfy byte-for-byte (canonical SHA-256 at v1.2.0: `037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9`).

Current state: Go reference at `v2.1.0`, **Phase 0 COMPLETE**. All v1.0.0 audit findings are now resolved or NOT-FIXED-BY-DESIGN (with rationale). Hardening history: Phase 0c (v1.3.0) = Cat-A batch 1 (constant-time scalar mult + Schnorr verify hardening); Phase 0d (v2.0.0) = Cat-B Schnorr v2 (length-prefix, deterministic nonces, domain tags); Phase 0c-finish (v2.1.0) = Cat-A batch 2 (PO-3 noErr helpers, KG-2 error propagation, KG-3 memory hygiene, AES-3 short-circuit). Key-gen output preserved bit-for-bit through every release. 105-vector test corpus (50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr). TypeScript port planned across 14 phases in `docs/TS_PORT_PLAN.md` v2 — next action is `Exec: begin Phase 0b` (TypeScript build scaffold, targeting hardened v2.1.0 Go reference).

Claudstermind's KB has the full picture; read it before making changes here.
