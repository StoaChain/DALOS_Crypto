/**
 * Scaffold sanity tests. Proves the TS build + Vitest + fixture loader
 * are all wired up correctly. No cryptographic logic tested here —
 * Phase 1 onwards will add real math.
 */

import { describe, expect, it } from 'vitest';
import { SCAFFOLD_VERSION } from '../src/index.js';
import {
  bitmapVectors,
  bitstringVectors,
  loadCorpus,
  schnorrVectors,
  seedWordsVectors,
} from './fixtures.js';

describe('scaffold', () => {
  it('exports SCAFFOLD_VERSION (bumped to 0.7.0 at Phase 7 landing)', () => {
    expect(SCAFFOLD_VERSION).toBe('0.7.0');
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
