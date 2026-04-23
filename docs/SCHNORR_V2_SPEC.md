# DALOS Schnorr v2.0.0 — Signature Format Specification

**Status:** normative.  Implemented in `StoaChain/DALOS_Crypto` at tag `v2.0.0`.

This document is the reference for implementers porting DALOS Schnorr to
other languages (TypeScript, Rust, etc.). Signatures produced and
verified by any conforming implementation must interoperate bit-for-bit.

---

## 1. Overview

DALOS Schnorr v2 is a Fiat–Shamir Schnorr signature scheme over the
DALOS 1606-bit Twisted Edwards curve. v2.0.0 supersedes the pre-v2.0.0
Schnorr with three security upgrades (audit findings SC-1, SC-2, SC-3):

- **Length-prefixed Fiat–Shamir transcript** (SC-1) — eliminates
  leading-zero ambiguity.
- **RFC-6979-style deterministic nonce derivation** adapted for Blake3
  (SC-2) — eliminates random-nonce-reuse attacks.
- **Domain-separation tags** on both the challenge hash and the nonce
  derivation (SC-3) — isolates this signature from any other protocol
  using Blake3.

As a consequence of these changes, v2 signatures are **not
interoperable with pre-v2 signatures**. This is intentional and safe:
no DALOS Schnorr signatures were ever used on-chain, so no deployed
verifier requires the pre-v2 format.

---

## 2. Curve parameters (unchanged from Genesis)

Defined by `DalosEllipse()` in `Elliptic/Parameters.go`.

| Symbol | Value |
|--------|-------|
| P | 2^1605 + 2315 |
| Q | 2^1603 + 1258387…1380413 |
| cofactor | 4 |
| a | 1 |
| d | −26 |
| G | (2, 479577…907472) |
| S (safe-scalar bits) | 1600 |

---

## 3. Canonical encodings

### 3.1 `canonical(x)` — big.Int to canonical bytes

```
canonical(x):
    if x == nil or x == 0: return [0x00]
    else:                  return x.to_bytes_big_endian()  // no leading zeros
```

### 3.2 `len32(b)` — 4-byte big-endian length

```
len32(b):
    return uint32_big_endian(len(b)) ++ b
```

The 4-byte fixed-width length prefix is what makes the transcript
unambiguous across all inputs.

### 3.3 Domain tags (ASCII, no null terminator)

```
TAG_HASH  = "DALOS-gen1/SchnorrHash/v1"        (25 bytes)
TAG_NONCE = "DALOS-gen1/SchnorrNonce/v1"       (26 bytes)
TAG_MSG   = "DALOS-gen1/SchnorrNonce/v1/msg"   (30 bytes)
```

Tags are UTF-8 ASCII; conforming implementations must treat them as
opaque byte strings.

---

## 4. Signing algorithm

Input: private key `k ∈ [1, Q−1]` (decoded from base-49), message `m`
(arbitrary bytes).

Output: signature `(R, s)` where `R` is an affine curve point and
`s ∈ [0, Q−1]`.

```
SchnorrSign(k, m):
    # Message digest for nonce derivation (separate from Fiat–Shamir challenge).
    msgHash = Blake3_XOF(TAG_MSG || m, 64 bytes)

    # Deterministic nonce (RFC-6979 adapted for Blake3).
    seed = TAG_NONCE || 0x00 || canonical(k) || msgHash
    expansion = Blake3_XOF(seed, 2 * S / 8)         # 400 bytes
    z = bigint(expansion) mod Q
    if z == 0: z = 1                                # negligibly rare

    # Nonce commitment
    R = z · G                                       # extended TE
    R_affine = to_affine(R)
    r = R_affine.x

    # Fiat–Shamir challenge
    transcript = len32(TAG_HASH) || TAG_HASH
              || len32(canonical(r))        || canonical(r)
              || len32(canonical(P.x))      || canonical(P.x)
              || len32(canonical(P.y))      || canonical(P.y)
              || len32(m)                   || m
    e = bigint(Blake3_XOF(transcript, S / 8)) mod Q

    # Response scalar
    s = (z + e * k) mod Q

    return (R_affine, s)
```

Where `P = k · G` is the signer's public key.

### Serialisation

The signature serialises as `R_affine_as_public_key_string | s_base49`:

```
"<prefix-len-base49>.<base49-body>|<s-base49>"
```

Example:
```
9H.abc...|def...
```

(See `ConvertSchnorrSignatureToString` in `Elliptic/Schnorr.go`.)

---

## 5. Verification algorithm

Input: signature string, message `m`, public key string.

Output: boolean — `true` iff the signature is valid.

```
SchnorrVerify(sig_string, m, pubkey_string):
    # Parse — any parse error → false
    (R_affine, s) = ParseSignature(sig_string)

    # Range check (SC-4)
    if s <= 0 or s >= Q: return false

    # On-curve check of R (SC-5)
    if not IsOnCurve(R_affine): return false

    # Parse & on-curve check of P (SC-5)
    P_affine = ParsePublicKey(pubkey_string)
    if not IsOnCurve(P_affine): return false

    # Recompute Fiat–Shamir challenge
    r = R_affine.x
    transcript = (same as in sign)
    e = bigint(Blake3_XOF(transcript, S / 8)) mod Q

    # Verification equation: s·G ?= R + e·P
    left  = s · G
    right = R + (e · P)
    return PointsEqual(left, right)
```

---

## 6. Determinism

v2 Schnorr is **fully deterministic**: for fixed `(k, m)`, `SchnorrSign`
produces byte-identical output on every invocation. This property is
testable — the DALOS test-vector corpus (`testvectors/v1_genesis.json`)
contains 20 Schnorr vectors whose `signature` field is stable across
regeneration runs at tag `v2.0.0`.

---

## 7. Security properties

| Property | Guarantee |
|----------|-----------|
| EUF-CMA under ECDLP | Standard Schnorr reduction; no known sub-exponential attack on the DALOS curve |
| Nonce-reuse attack resistance | Deterministic nonces eliminate the Sony-PS3 attack family |
| Transcript ambiguity | Eliminated by fixed-width 4-byte length prefixes |
| Protocol-collision resistance | Tags ensure hashes do not collide with other Blake3-based protocols |
| On-curve input enforcement | Both R and P are validated; off-curve attacks rejected at the boundary |
| Canonical `s` | Enforced in `(0, Q)`; non-canonical signatures rejected |

### Known residual (not fixed in v2.0.0)

- **Go `math/big` is not constant-time** at the CPU-instruction level.
  `SchnorrSign` uses the algorithmic-constant-time `ScalarMultiplier`
  from v1.3.0, but individual big-int arithmetic can still leak timing.
  Applies only to signers; verifiers observe public inputs only.
  Documented trade-off — full constant-time Go requires a custom
  limb-oriented big-int implementation.

---

## 8. Test vectors

20 Schnorr test vectors are committed as the `schnorr_vectors` array
in `testvectors/v1_genesis.json`. Each entry contains:

- `input_bitstring` — 1600-bit private-key source
- `priv_int49` — private key in base-49
- `public_key` — `k·G` in DALOS public-key format
- `message` — the message signed
- `signature` — the serialised v2 signature
- `verify_expected` — always `true`
- `verify_actual` — result of running `SchnorrVerify` on the above

Conforming implementations must:

1. Produce byte-identical `signature` values given the same inputs.
2. Return `verify_actual = true` for all 20 committed vectors.
3. Return `false` for any signature where `s ≥ Q` or `s ≤ 0` or
   R is not on the curve.

---

## 9. Format incompatibility with pre-v2.0.0

Pre-v2 signatures fail `SchnorrVerify` under v2 (length-prefix
mismatch, domain-tag mismatch, possibly `s ≥ Q`). v2 signatures fail
under pre-v2 verify (same reasons, reversed). This is intentional:
the v2 format break is a one-way upgrade, clean and auditable.

No deployment path carries Schnorr signatures across the boundary.
Genesis **key-generation** output is preserved forever, independent of
the Schnorr format.

---

## 10. Revision history

| Version | Date | Change |
|---------|------|--------|
| v1 | 2026-04-23 | Initial v2.0.0 specification, matching `StoaChain/DALOS_Crypto` commit at tag `v2.0.0` |

---

*Document maintained in `docs/SCHNORR_V2_SPEC.md`. Any change to
`Elliptic/Schnorr.go` that affects signature bytes must bump this
document's revision and the corresponding test vectors.*
