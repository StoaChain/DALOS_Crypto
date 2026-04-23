/**
 * `@stoachain/dalos-crypto/registry` — the primitive abstraction layer.
 *
 * Phase 7 of the TS port. No new cryptography; this is the architecture
 * that lets future Gen-2 primitives register alongside Gen-1 without
 * breaking existing Ouronet accounts.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

export type {
  KeyPair,
  PrivateKeyForms,
  FullKey,
  PrimitiveMetadata,
  CryptographicPrimitive,
  DalosGenesisPrimitive,
} from './primitive.js';
export { isDalosGenesisPrimitive } from './primitive.js';

export { DalosGenesis } from './genesis.js';

export { CryptographicRegistry, createDefaultRegistry } from './registry.js';
