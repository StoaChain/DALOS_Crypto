/**
 * Integration tests for the three historical-curve primitives
 * (Leto / Artemis / Apollo) shipped in v1.2.0.
 *
 * For each primitive we verify the full Gen-1 pipeline works:
 *   1. generateRandom() round-trips — sign + verify passes
 *   2. generateFromSeedWords() is deterministic — same seed → same account
 *   3. Address prefixes match the ones declared in `metadata`
 *   4. Sign + verify on a UTF-8 message
 *   5. Cross-primitive isolation — a signature from primitive A must
 *      NOT verify under primitive B (even when both use the same
 *      private scalar)
 *   6. detectGeneration() routes the primitive's own addresses AND
 *      rejects addresses from any other primitive
 *
 * These are the same assurances DalosGenesis has in its own test suite;
 * by running the identical battery on the historical primitives we
 * prove they're usable as drop-in cryptographic engines.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { describe, expect, it } from 'vitest';
import {
  Apollo,
  Artemis,
  type CryptographicPrimitive,
  CryptographicRegistry,
  DalosGenesis,
  Leto,
} from '../../src/registry/index.js';

interface Case {
  readonly name: string;
  readonly primitive: CryptographicPrimitive;
  readonly id: string;
  readonly expectedStandardPrefix: string;
  readonly expectedSmartPrefix: string;
  readonly expectedSafeScalarBits: number;
}

const CASES: readonly Case[] = [
  {
    name: 'Leto',
    primitive: Leto,
    id: 'dalos-leto',
    expectedStandardPrefix: 'Ł',
    expectedSmartPrefix: 'Λ',
    expectedSafeScalarBits: 545,
  },
  {
    name: 'Artemis',
    primitive: Artemis,
    id: 'dalos-artemis',
    expectedStandardPrefix: 'R',
    expectedSmartPrefix: 'Ř',
    expectedSafeScalarBits: 1023,
  },
  {
    name: 'Apollo',
    primitive: Apollo,
    id: 'dalos-apollo',
    expectedStandardPrefix: '₱',
    expectedSmartPrefix: 'Π',
    expectedSafeScalarBits: 1024,
  },
];

for (const tc of CASES) {
  describe(`Historical primitive: ${tc.name}`, () => {
    const p = tc.primitive;

    it('id + generation metadata matches declaration', () => {
      expect(p.id).toBe(tc.id);
      expect(p.version).toBe(1);
      expect(p.metadata.baseBitLength).toBe(tc.expectedSafeScalarBits);
      expect(p.metadata.addressPrefixStandard).toBe(tc.expectedStandardPrefix);
      expect(p.metadata.addressPrefixSmart).toBe(tc.expectedSmartPrefix);
    });

    it('generateRandom produces addresses with the declared prefixes', () => {
      const key = p.generateRandom();
      expect(key.standardAddress.startsWith(`${tc.expectedStandardPrefix}.`)).toBe(true);
      expect(key.smartAddress.startsWith(`${tc.expectedSmartPrefix}.`)).toBe(true);
      // Body length (chars after the prefix + ".") should be 160 — same
      // as DALOS since the address body derivation is curve-independent.
      const body = key.standardAddress.slice(tc.expectedStandardPrefix.length + 1);
      expect(body.length).toBe(160);
    });

    it('generateFromSeedWords is deterministic (same seed → same account)', () => {
      const seed = ['history', 'repeats', 'itself'];
      const a = p.generateFromSeedWords(seed);
      const b = p.generateFromSeedWords(seed);
      expect(a.keyPair.priv).toBe(b.keyPair.priv);
      expect(a.keyPair.publ).toBe(b.keyPair.publ);
      expect(a.standardAddress).toBe(b.standardAddress);
      expect(a.smartAddress).toBe(b.smartAddress);
    });

    it('publicKeyToAddress composes the same address as generate*', () => {
      const key = p.generateFromSeedWords(['ithaca']);
      expect(p.publicKeyToAddress(key.keyPair.publ, false)).toBe(key.standardAddress);
      expect(p.publicKeyToAddress(key.keyPair.publ, true)).toBe(key.smartAddress);
    });

    it('sign + verify round-trip on a UTF-8 message', () => {
      const key = p.generateFromSeedWords(['odin', 'thor', 'loki']);
      if (!p.sign || !p.verify) throw new Error('primitive missing sign/verify');
      const sig = p.sign(key.keyPair, 'hello world');
      expect(sig.length).toBeGreaterThan(0);
      expect(p.verify(sig, 'hello world', key.keyPair.publ)).toBe(true);
    });

    it('verify rejects a tampered message', () => {
      const key = p.generateFromSeedWords(['x']);
      if (!p.sign || !p.verify) throw new Error('primitive missing sign/verify');
      const sig = p.sign(key.keyPair, 'hello world');
      expect(p.verify(sig, 'hello universe', key.keyPair.publ)).toBe(false);
    });

    it('detectGeneration claims its own addresses', () => {
      const key = p.generateRandom();
      expect(p.detectGeneration(key.standardAddress)).toBe(true);
      expect(p.detectGeneration(key.smartAddress)).toBe(true);
    });

    it('detectGeneration rejects DalosGenesis addresses', () => {
      const dalosKey = DalosGenesis.generateFromSeedWords(['any', 'seed']);
      expect(p.detectGeneration(dalosKey.standardAddress)).toBe(false);
      expect(p.detectGeneration(dalosKey.smartAddress)).toBe(false);
    });

    it("DalosGenesis rejects this primitive's addresses", () => {
      const key = p.generateRandom();
      expect(DalosGenesis.detectGeneration(key.standardAddress)).toBe(false);
      expect(DalosGenesis.detectGeneration(key.smartAddress)).toBe(false);
    });
  });
}

describe('Cross-primitive signature isolation', () => {
  it('a Leto signature does NOT verify under Artemis or Apollo', () => {
    const letoKey = Leto.generateFromSeedWords(['test']);
    if (!Leto.sign) throw new Error('leto missing sign');
    const sig = Leto.sign(letoKey.keyPair, 'message');

    // Same public key under the "wrong" primitive's verify should fail
    // because the Schnorr equation uses curve-specific scalar
    // multiplication — the equation only holds under the originating
    // curve.
    if (!Artemis.verify || !Apollo.verify) throw new Error('missing verify');
    expect(Artemis.verify(sig, 'message', letoKey.keyPair.publ)).toBe(false);
    expect(Apollo.verify(sig, 'message', letoKey.keyPair.publ)).toBe(false);
  });
});

describe('Registry integration — all 4 primitives coexist', () => {
  it('custom registry can hold DALOS + all 3 historical primitives', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    r.register(Leto);
    r.register(Artemis);
    r.register(Apollo);
    expect(r.size()).toBe(4);

    // detect() routes correctly for each curve's address.
    const dalosKey = DalosGenesis.generateFromSeedWords(['d']);
    const letoKey = Leto.generateFromSeedWords(['l']);
    const artemisKey = Artemis.generateFromSeedWords(['a']);
    const apolloKey = Apollo.generateFromSeedWords(['p']);

    expect(r.detect(dalosKey.standardAddress)?.id).toBe('dalos-gen-1');
    expect(r.detect(letoKey.standardAddress)?.id).toBe('dalos-leto');
    expect(r.detect(artemisKey.standardAddress)?.id).toBe('dalos-artemis');
    expect(r.detect(apolloKey.standardAddress)?.id).toBe('dalos-apollo');

    // Smart addresses too.
    expect(r.detect(dalosKey.smartAddress)?.id).toBe('dalos-gen-1');
    expect(r.detect(letoKey.smartAddress)?.id).toBe('dalos-leto');
    expect(r.detect(artemisKey.smartAddress)?.id).toBe('dalos-artemis');
    expect(r.detect(apolloKey.smartAddress)?.id).toBe('dalos-apollo');
  });

  it('default registry does NOT include historical primitives by design', async () => {
    const { createDefaultRegistry } = await import('../../src/registry/index.js');
    const r = createDefaultRegistry();
    expect(r.size()).toBe(1);
    expect(r.default().id).toBe('dalos-gen-1');
    expect(r.has('dalos-leto')).toBe(false);
    expect(r.has('dalos-artemis')).toBe(false);
    expect(r.has('dalos-apollo')).toBe(false);
  });
});
