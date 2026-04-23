/**
 * Phase 7 tests — CryptographicRegistry + DalosGenesis primitive.
 *
 * Tests cover two concerns:
 *   1. Registry lifecycle semantics (register, unregister, default,
 *      detect, error paths).
 *   2. DalosGenesis behaviour through the primitive surface — smoke
 *      tests that the thin adapters reach the underlying Gen-1
 *      implementation correctly. Byte-identity with the Go corpus is
 *      already covered by Phase 3/4/6 tests; here we just verify
 *      the registry-level contract.
 */

import { describe, expect, it } from 'vitest';
import { parseAsciiBitmap } from '../../src/gen1/bitmap.js';
import {
  type CryptographicPrimitive,
  CryptographicRegistry,
  DalosGenesis,
  createDefaultRegistry,
  isDalosGenesisPrimitive,
} from '../../src/registry/index.js';
import { bitmapVectors, bitstringVectors, schnorrVectors, seedWordsVectors } from '../fixtures.js';

// ============================================================================
// DalosGenesis — smoke tests (byte-identity already proven in Phase 3/4/6)
// ============================================================================

describe('DalosGenesis primitive — identity + metadata', () => {
  it('has id "dalos-gen-1"', () => {
    expect(DalosGenesis.id).toBe('dalos-gen-1');
  });

  it('is version 1 of generation "genesis"', () => {
    expect(DalosGenesis.version).toBe(1);
    expect(DalosGenesis.generation).toBe('genesis');
  });

  it('metadata includes curve parameters', () => {
    const m = DalosGenesis.metadata;
    expect(m.curveName).toBe('TEC_S1600_Pr1605p2315_m26');
    expect(m.baseBitLength).toBe(1600);
    expect(m.cofactor).toBe(4n);
    expect(m.primeField).toBe((1n << 1605n) + 2315n);
    expect(m.addressPrefixStandard).toBe('Ѻ');
    expect(m.addressPrefixSmart).toBe('Σ');
  });

  it('is a DalosGenesisPrimitive (type guard)', () => {
    expect(isDalosGenesisPrimitive(DalosGenesis)).toBe(true);
  });
});

describe('DalosGenesis primitive — key generation paths', () => {
  it('generateFromBitString reproduces Go corpus', () => {
    for (const v of bitstringVectors().slice(0, 5)) {
      const k = DalosGenesis.generateFromBitString(v.input_bitstring);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  });

  it('generateFromInteger(priv, 10) reproduces Go corpus', () => {
    const v = bitstringVectors()[0]!;
    const k = DalosGenesis.generateFromInteger(v.priv_int10, 10);
    expect(k.keyPair.publ).toBe(v.public_key);
    expect(k.standardAddress).toBe(v.standard_address);
  });

  it('generateFromInteger(priv, 49) reproduces Go corpus', () => {
    const v = bitstringVectors()[0]!;
    const k = DalosGenesis.generateFromInteger(v.priv_int49, 49);
    expect(k.keyPair.publ).toBe(v.public_key);
    expect(k.standardAddress).toBe(v.standard_address);
  });

  it('generateFromSeedWords reproduces Go corpus', () => {
    for (const v of seedWordsVectors().slice(0, 3)) {
      const k = DalosGenesis.generateFromSeedWords(v.input_words);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
    }
  });

  it('generateFromBitmap reproduces Go corpus', () => {
    const v = bitmapVectors()[0]!;
    const bmp = parseAsciiBitmap(v.bitmap_ascii);
    const k = DalosGenesis.generateFromBitmap(bmp);
    expect(k.keyPair.publ).toBe(v.public_key);
    expect(k.standardAddress).toBe(v.standard_address);
  });

  it('generateRandom produces a well-formed, verifiable key', () => {
    const k = DalosGenesis.generateRandom();
    expect(k.keyPair.priv.length).toBeGreaterThan(0);
    expect(k.keyPair.publ).toContain('.');
    expect(k.standardAddress.startsWith('Ѻ.')).toBe(true);
    expect(k.smartAddress.startsWith('Σ.')).toBe(true);
    // Round-trip: the generated priv should regenerate the same keypair
    const kAgain = DalosGenesis.generateFromInteger(k.keyPair.priv, 49);
    expect(kAgain.keyPair.publ).toBe(k.keyPair.publ);
    expect(kAgain.standardAddress).toBe(k.standardAddress);
  });
});

describe('DalosGenesis primitive — address ownership', () => {
  it('detectGeneration returns true for Ѻ. addresses', () => {
    for (const v of bitstringVectors().slice(0, 3)) {
      expect(DalosGenesis.detectGeneration(v.standard_address)).toBe(true);
    }
  });

  it('detectGeneration returns true for Σ. addresses', () => {
    for (const v of bitstringVectors().slice(0, 3)) {
      expect(DalosGenesis.detectGeneration(v.smart_address)).toBe(true);
    }
  });

  it('detectGeneration returns false for non-Genesis addresses', () => {
    expect(DalosGenesis.detectGeneration('XYZ.not-a-genesis-address')).toBe(false);
    expect(DalosGenesis.detectGeneration('')).toBe(false);
    expect(DalosGenesis.detectGeneration('0x1234abcd')).toBe(false); // ETH-style
  });

  it('publicKeyToAddress matches standard / smart prefix', () => {
    const v = bitstringVectors()[0]!;
    expect(DalosGenesis.publicKeyToAddress(v.public_key, false)).toBe(v.standard_address);
    expect(DalosGenesis.publicKeyToAddress(v.public_key, true)).toBe(v.smart_address);
  });
});

describe('DalosGenesis primitive — signing', () => {
  it('sign and verify are defined', () => {
    expect(typeof DalosGenesis.sign).toBe('function');
    expect(typeof DalosGenesis.verify).toBe('function');
  });

  it('sign produces byte-identical output to Go corpus', () => {
    const v = schnorrVectors()[0]!;
    const keyPair = {
      priv: v.priv_int49,
      publ: v.public_key,
    };
    const sig = DalosGenesis.sign!(keyPair, v.message);
    expect(sig).toBe(v.signature);
  });

  it('verify accepts committed signature', () => {
    const v = schnorrVectors()[0]!;
    expect(DalosGenesis.verify!(v.signature, v.message, v.public_key)).toBe(true);
  });

  it('verify rejects tampered signature', () => {
    const v = schnorrVectors()[0]!;
    expect(DalosGenesis.verify!(v.signature, `${v.message}-tampered`, v.public_key)).toBe(false);
  });
});

// ============================================================================
// CryptographicRegistry — lifecycle
// ============================================================================

describe('CryptographicRegistry — lifecycle', () => {
  it('starts empty', () => {
    const r = new CryptographicRegistry();
    expect(r.size()).toBe(0);
    expect(r.all()).toEqual([]);
    expect(r.defaultIdOf()).toBeUndefined();
  });

  it('register adds a primitive and sets first as default', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    expect(r.size()).toBe(1);
    expect(r.has('dalos-gen-1')).toBe(true);
    expect(r.get('dalos-gen-1')).toBe(DalosGenesis);
    expect(r.default()).toBe(DalosGenesis);
    expect(r.defaultIdOf()).toBe('dalos-gen-1');
  });

  it('register throws on duplicate id', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    expect(() => r.register(DalosGenesis)).toThrow(/already registered/);
  });

  it('unregister removes the primitive', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    r.unregister('dalos-gen-1');
    expect(r.size()).toBe(0);
    expect(r.get('dalos-gen-1')).toBeUndefined();
  });

  it('unregister throws on unknown id', () => {
    const r = new CryptographicRegistry();
    expect(() => r.unregister('never-registered')).toThrow(/no such id/);
  });

  it('unregister clears default when last primitive is removed', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    r.unregister('dalos-gen-1');
    expect(r.defaultIdOf()).toBeUndefined();
    expect(() => r.default()).toThrow(/empty/);
  });

  it('default() throws on empty registry', () => {
    const r = new CryptographicRegistry();
    expect(() => r.default()).toThrow(/empty/);
  });

  it('setDefault changes the default', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    const stub = makeStubPrimitive('gen-2-stub');
    r.register(stub);
    expect(r.default()).toBe(DalosGenesis); // still the first registered
    r.setDefault('gen-2-stub');
    expect(r.default()).toBe(stub);
    expect(r.defaultIdOf()).toBe('gen-2-stub');
  });

  it('setDefault throws on unknown id', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    expect(() => r.setDefault('nonexistent')).toThrow(/no such id/);
  });
});

// ============================================================================
// CryptographicRegistry — detect()
// ============================================================================

describe('CryptographicRegistry — detect()', () => {
  it('returns DalosGenesis for Ѻ. addresses', () => {
    const r = createDefaultRegistry();
    const v = bitstringVectors()[0]!;
    expect(r.detect(v.standard_address)).toBe(DalosGenesis);
  });

  it('returns DalosGenesis for Σ. addresses', () => {
    const r = createDefaultRegistry();
    const v = bitstringVectors()[0]!;
    expect(r.detect(v.smart_address)).toBe(DalosGenesis);
  });

  it('returns undefined for non-Genesis addresses', () => {
    const r = createDefaultRegistry();
    expect(r.detect('XYZ.not-a-DALOS-address')).toBeUndefined();
    expect(r.detect(`0x${'ab'.repeat(20)}`)).toBeUndefined();
  });

  it('routes to the correct primitive when multiple are registered', () => {
    const r = new CryptographicRegistry();
    r.register(DalosGenesis);
    const stub = makeStubPrimitive('gen-2-stub', (addr) => addr.startsWith('Ω.'));
    r.register(stub);
    const v = bitstringVectors()[0]!;
    expect(r.detect(v.standard_address)).toBe(DalosGenesis);
    expect(r.detect('Ω.future-address')).toBe(stub);
  });
});

// ============================================================================
// createDefaultRegistry
// ============================================================================

describe('createDefaultRegistry', () => {
  it('returns a registry with DalosGenesis pre-registered as default', () => {
    const r = createDefaultRegistry();
    expect(r.size()).toBe(1);
    expect(r.default()).toBe(DalosGenesis);
    expect(r.get('dalos-gen-1')).toBe(DalosGenesis);
  });

  it("returns independent instances (mutation doesn't leak)", () => {
    const r1 = createDefaultRegistry();
    const r2 = createDefaultRegistry();
    r1.unregister('dalos-gen-1');
    expect(r1.size()).toBe(0);
    expect(r2.size()).toBe(1);
  });
});

// ============================================================================
// End-to-end scenario: registry routes an account to Genesis
// ============================================================================

describe('registry — end-to-end account operations', () => {
  it('creates an account via default, then detects its generation and signs via that primitive', () => {
    const r = createDefaultRegistry();

    // 1. Create a new account using the default primitive.
    const account = r.default().generateRandom();
    expect(account.standardAddress.startsWith('Ѻ.')).toBe(true);

    // 2. Later, we have just the address — find the primitive that owns it.
    const primitive = r.detect(account.standardAddress);
    expect(primitive).toBe(DalosGenesis);

    // 3. Sign a message using that primitive.
    const msg = 'approve tx 12345';
    const sig = primitive!.sign!(account.keyPair, msg);
    expect(sig.length).toBeGreaterThan(0);

    // 4. Verify.
    expect(primitive!.verify!(sig, msg, account.keyPair.publ)).toBe(true);
    expect(primitive!.verify!(sig, 'approve tx 99999', account.keyPair.publ)).toBe(false);
  });
});

// ============================================================================
// Helper: minimal stub primitive for multi-primitive tests
// ============================================================================

/**
 * Build a minimal stub `CryptographicPrimitive` for testing registry
 * semantics. Not a real crypto implementation — methods throw except
 * where needed.
 */
function makeStubPrimitive(
  id: string,
  detector: (addr: string) => boolean = () => false,
): CryptographicPrimitive {
  return {
    id,
    description: `Stub primitive for testing: ${id}`,
    version: 1,
    generation: id,
    metadata: {
      curveName: 'stub',
      primeField: 0n,
      order: 0n,
      cofactor: 0n,
      baseBitLength: 0,
    },
    generateRandom: () => {
      throw new Error(`${id}: stub not implemented`);
    },
    generateFromBitString: () => {
      throw new Error(`${id}: stub not implemented`);
    },
    generateFromInteger: () => {
      throw new Error(`${id}: stub not implemented`);
    },
    generateFromSeedWords: () => {
      throw new Error(`${id}: stub not implemented`);
    },
    publicKeyToAddress: () => {
      throw new Error(`${id}: stub not implemented`);
    },
    detectGeneration: detector,
  };
}
