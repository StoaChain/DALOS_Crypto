/**
 * Scaffold sanity tests. Proves the TS build + Vitest + fixture loader
 * + root namespace re-exports are all wired up correctly. No
 * cryptographic logic tested here — Phase 1 onwards will add real math.
 */

import { describe, expect, it } from 'vitest';
import { blake3, historical } from '../src/index.js';
import {
  bitmapVectors,
  bitstringVectors,
  loadCorpus,
  schnorrVectors,
  seedWordsVectors,
} from './fixtures.js';

describe('scaffold', () => {
  it('exposes historical and blake3 namespaces from the package root', () => {
    expect(typeof historical).toBe('object');
    expect(typeof blake3).toBe('object');

    expect('LETO' in historical).toBe(true);
    expect('ARTEMIS' in historical).toBe(true);
    expect('APOLLO' in historical).toBe(true);

    expect(typeof blake3.blake3SumCustom).toBe('function');
    expect(typeof blake3.sevenFoldBlake3).toBe('function');

    const out = blake3.blake3SumCustom(new Uint8Array([0]), 8);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(8);

    expect(historical.LETO.name).toBe('LETO');
    expect(typeof historical.LETO.p).toBe('bigint');
    expect(typeof historical.LETO.s).toBe('number');

    expect(historical.ARTEMIS.name).toBe('ARTEMIS');
    expect(typeof historical.ARTEMIS.p).toBe('bigint');
    expect(typeof historical.ARTEMIS.s).toBe('number');

    expect(historical.APOLLO.name).toBe('APOLLO');
    expect(typeof historical.APOLLO.p).toBe('bigint');
    expect(typeof historical.APOLLO.s).toBe('number');
  });
});

describe('test-vector corpus loader', () => {
  it('loads the corpus from ../testvectors/v1_genesis.json', () => {
    const corpus = loadCorpus();
    expect(corpus.schema_version).toBe(1);
    expect(corpus.curve).toBe('TEC_S1600_Pr1605p2315_m26');
  });

  it('exposes all 50 bitstring vectors', () => {
    const vs = bitstringVectors();
    expect(vs).toHaveLength(50);
    expect(vs[0]?.id).toBe('bs-0001');
    expect(vs[0]?.input_bitstring).toHaveLength(1600);
  });

  it('exposes all 15 seed-words vectors', () => {
    const vs = seedWordsVectors();
    expect(vs).toHaveLength(15);
    expect(vs[0]?.id).toBe('sw-0001');
  });

  it('exposes all 20 bitmap vectors', () => {
    const vs = bitmapVectors();
    expect(vs).toHaveLength(20);
    expect(vs[0]?.id).toBe('bmp-0001');
    expect(vs[0]?.bitmap_ascii).toHaveLength(40);
    expect(vs[0]?.bitmap_ascii[0]).toHaveLength(40);
  });

  it('exposes all 20 Schnorr vectors, all self-verified', () => {
    const vs = schnorrVectors();
    expect(vs).toHaveLength(20);
    for (const v of vs) {
      expect(v.verify_expected).toBe(true);
      expect(v.verify_actual).toBe(true);
    }
  });

  it('total = 105 records', () => {
    const corpus = loadCorpus();
    const total =
      corpus.bitstring_vectors.length +
      corpus.seed_words_vectors.length +
      corpus.bitmap_vectors.length +
      corpus.schnorr_vectors.length;
    expect(total).toBe(105);
  });
});
