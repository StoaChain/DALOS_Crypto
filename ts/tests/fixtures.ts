/**
 * Test-vector loader. Reads the Go-reference-produced corpus at
 * ../testvectors/v1_genesis.json and exposes typed accessors.
 *
 * Every TypeScript port function must produce byte-identical output
 * to the corresponding Go function on every deterministic record.
 * Schnorr signatures are byte-identical too (v2 deterministic).
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(here, '..', '..', 'testvectors', 'v1_genesis.json');

export interface BitStringVector {
  readonly id: string;
  readonly source: string;
  readonly input_bitstring: string;
  readonly scalar_int10: string;
  readonly priv_int10: string;
  readonly priv_int49: string;
  readonly public_key: string;
  readonly standard_address: string;
  readonly smart_address: string;
}

export interface SeedWordsVector {
  readonly id: string;
  readonly input_words: readonly string[];
  readonly derived_bitstring: string;
  readonly scalar_int10: string;
  readonly priv_int49: string;
  readonly public_key: string;
  readonly standard_address: string;
  readonly smart_address: string;
}

export interface BitmapVector {
  readonly id: string;
  readonly pattern: string;
  readonly bitmap_ascii: readonly string[];
  readonly derived_bitstring: string;
  readonly scalar_int10: string;
  readonly priv_int49: string;
  readonly public_key: string;
  readonly standard_address: string;
  readonly smart_address: string;
}

export interface SchnorrVector {
  readonly id: string;
  readonly input_bitstring: string;
  readonly priv_int49: string;
  readonly public_key: string;
  readonly message: string;
  readonly signature: string;
  readonly verify_expected: boolean;
  readonly verify_actual: boolean;
}

export interface VectorCorpus {
  readonly schema_version: number;
  readonly generator_version: string;
  readonly curve: string;
  readonly curve_field_p_bits: number;
  readonly curve_order_q_bits: number;
  readonly curve_cofactor: string;
  readonly rng_seed_bits: string;
  readonly rng_seed_bitmaps: string;
  readonly generated_at_utc: string;
  readonly host: string;
  readonly bitstring_vectors: readonly BitStringVector[];
  readonly seed_words_vectors: readonly SeedWordsVector[];
  readonly bitmap_vectors: readonly BitmapVector[];
  readonly schnorr_vectors: readonly SchnorrVector[];
}

let cachedCorpus: VectorCorpus | undefined;

/**
 * Load the Go-reference test vector corpus. Cached after first call.
 */
export function loadCorpus(): VectorCorpus {
  if (cachedCorpus === undefined) {
    const raw = readFileSync(corpusPath, 'utf-8');
    cachedCorpus = JSON.parse(raw) as VectorCorpus;
  }
  return cachedCorpus;
}

/**
 * Convenience: just the bitstring vectors.
 */
export function bitstringVectors(): readonly BitStringVector[] {
  return loadCorpus().bitstring_vectors;
}

export function seedWordsVectors(): readonly SeedWordsVector[] {
  return loadCorpus().seed_words_vectors;
}

export function bitmapVectors(): readonly BitmapVector[] {
  return loadCorpus().bitmap_vectors;
}

export function schnorrVectors(): readonly SchnorrVector[] {
  return loadCorpus().schnorr_vectors;
}
