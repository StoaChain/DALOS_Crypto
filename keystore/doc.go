// Package keystore implements the AES-backed Export/Import file format
// for DALOS private keys. It owns the on-disk wallet artifact: a UTF-8
// text file containing the encrypted bitstring, the decryption headers,
// and the public-key reference field.
//
// This package is a v4.0.0 carve-out from the historical Elliptic/
// package (REQ-31, F-ARCH-001). Consumers of v3.x who used
// `el.ExportPrivateKey(...)` etc. update to `keystore.ExportPrivateKey(e, ...)`
// form. See ../.bee/specs/2026-05-02-unified-audit-2026-04-29/phases/
// 10-elliptic-package-carve-out/MIGRATION.md for the full migration table.
//
// Package surface (4 free functions):
//
//   - ExportPrivateKey(e *el.Ellipse, BitString, Password string)
//     Serialize a Genesis private key to the canonical wallet file
//     using AES-256-GCM with a Blake3-derived key.
//   - ImportPrivateKey(e *el.Ellipse, PathWithName, Password string) (el.DalosKeyPair, error)
//     Inverse of ExportPrivateKey. Reads the wallet file, decrypts
//     the bitstring, and re-derives the keypair through the Genesis
//     pipeline so the returned PUBL is recomputed (not trusted) from
//     the recovered scalar.
//   - AESDecrypt(encryptedPrivateKeyBase49, password string) (string, error)
//     Decrypt the base-49-encoded ciphertext extracted from a wallet
//     file. Used internally by ImportPrivateKey; exposed for tooling.
//   - GenerateFilenameFromPublicKey(publicKey string) string
//     Compute the canonical wallet-file basename from a DALOS public
//     key (`<prefix>.<first7>...<last7>.txt`).
//
// Dependency direction: keystore -> Elliptic (one-way). Elliptic does
// NOT import keystore. AES is consumed for the symmetric primitive.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
package keystore
