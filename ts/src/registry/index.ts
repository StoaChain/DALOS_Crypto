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

// Historical-curve primitives (production-ready since v1.2.0). NOT
// included in the default registry — import + register explicitly.
export { Leto } from './leto.js';
export { Artemis } from './artemis.js';
export { Apollo } from './apollo.js';

// Factory for building Gen-1-family primitives from arbitrary
// `Ellipse` + prefix-pair configs. Useful if you want to expose a
// custom curve in the same infrastructure.
export { createGen1Primitive } from './gen1-factory.js';
export type { Gen1PrimitiveConfig } from './gen1-factory.js';

// Address-prefix typing — re-exported so consumers can construct
// their own `AddressPrefixPair`s for custom primitives.
export type { AddressPrefixPair } from '../gen1/hashing.js';
export { DALOS_PREFIXES } from '../gen1/hashing.js';

export { CryptographicRegistry, createDefaultRegistry } from './registry.js';
