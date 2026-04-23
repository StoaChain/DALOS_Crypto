/**
 * `CryptographicRegistry` — the dispatcher.
 *
 * Holds a collection of `CryptographicPrimitive` instances keyed by
 * their `id`. Exposes:
 *   - `register` / `unregister` — lifecycle
 *   - `get` — look up by id
 *   - `detect` — find the primitive that claims ownership of an address
 *   - `all` — iterate
 *   - `default` / `setDefault` — which primitive mints new accounts
 *
 * By convention, the default primitive is the CURRENT Genesis of
 * Ouronet. When a Gen-2 primitive is introduced, consumers can either:
 *   - Register Gen-2 alongside Gen-1 (both become available)
 *   - Call `setDefault('dalos-gen-2')` so new accounts use Gen-2
 *   - Existing `Ѻ.` / `Σ.` addresses still resolve to Gen-1 via `detect`
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { DalosGenesis } from './genesis.js';
import type { CryptographicPrimitive } from './primitive.js';

/**
 * Mutable registry of cryptographic primitives. Each registry instance
 * is independent — consumers that need different default primitives
 * can own their own instance.
 */
export class CryptographicRegistry {
  private readonly primitives = new Map<string, CryptographicPrimitive>();
  private defaultId: string | undefined;

  /**
   * Register a new primitive. Throws if `p.id` is already registered.
   * The first registered primitive becomes the default.
   */
  register(p: CryptographicPrimitive): void {
    if (this.primitives.has(p.id)) {
      throw new Error(`CryptographicRegistry.register: id "${p.id}" is already registered`);
    }
    this.primitives.set(p.id, p);
    if (this.defaultId === undefined) {
      this.defaultId = p.id;
    }
  }

  /**
   * Remove a primitive. Throws if no such id is registered.
   *
   * If the removed primitive was the default, the default is
   * reassigned to the first remaining primitive (insertion order),
   * or cleared if the registry is now empty.
   */
  unregister(id: string): void {
    if (!this.primitives.has(id)) {
      throw new Error(`CryptographicRegistry.unregister: no such id "${id}"`);
    }
    this.primitives.delete(id);
    if (this.defaultId === id) {
      if (this.primitives.size > 0) {
        // Pick the first remaining entry (Map preserves insertion order).
        const first = this.primitives.keys().next();
        this.defaultId = first.value;
      } else {
        this.defaultId = undefined;
      }
    }
  }

  /**
   * Look up a primitive by its stable `id`. Returns `undefined` if
   * not registered.
   */
  get(id: string): CryptographicPrimitive | undefined {
    return this.primitives.get(id);
  }

  /**
   * Find the primitive whose `detectGeneration(address)` returns `true`.
   * If multiple primitives match (shouldn't happen with unique prefixes
   * per generation), returns the first one in insertion order.
   */
  detect(address: string): CryptographicPrimitive | undefined {
    for (const p of this.primitives.values()) {
      if (p.detectGeneration(address)) return p;
    }
    return undefined;
  }

  /**
   * Snapshot of all registered primitives in insertion order.
   */
  all(): readonly CryptographicPrimitive[] {
    return [...this.primitives.values()];
  }

  /**
   * The default primitive — used when creating NEW accounts without
   * specifying an explicit generation. Throws if the registry is empty.
   */
  default(): CryptographicPrimitive {
    if (this.defaultId === undefined) {
      throw new Error('CryptographicRegistry.default: registry is empty');
    }
    const p = this.primitives.get(this.defaultId);
    if (p === undefined) {
      // Should be unreachable given the register/unregister invariants
      throw new Error(
        `CryptographicRegistry.default: internal state error — defaultId "${this.defaultId}" not in map`,
      );
    }
    return p;
  }

  /**
   * Change which primitive is the default. Throws if the id isn't
   * registered.
   */
  setDefault(id: string): void {
    if (!this.primitives.has(id)) {
      throw new Error(`CryptographicRegistry.setDefault: no such id "${id}"`);
    }
    this.defaultId = id;
  }

  /** Number of registered primitives. */
  size(): number {
    return this.primitives.size;
  }

  /** Is this id registered? */
  has(id: string): boolean {
    return this.primitives.has(id);
  }

  /** The id of the default primitive, or undefined if registry is empty. */
  defaultIdOf(): string | undefined {
    return this.defaultId;
  }
}

/**
 * Create a new registry pre-populated with `DalosGenesis`.
 *
 * This is the idiomatic starting point for most consumers. If you need
 * a different primitive set, construct a `CryptographicRegistry`
 * directly and register what you want.
 */
export function createDefaultRegistry(): CryptographicRegistry {
  const r = new CryptographicRegistry();
  r.register(DalosGenesis);
  return r;
}
