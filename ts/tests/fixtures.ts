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
const historicalCorpusPath = resolve(here, '..', '..', 'testvectors', 'v1_historical.json');
const adversarialCorpusPath = resolve(here, '..', '..', 'testvectors', 'v1_adversarial.json');

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

export interface HistoricalSeedWordsVector {
  readonly id: string;
  readonly input_words: readonly string[];
  readonly derived_bitstring: string;
  readonly scalar_int10: string;
  readonly priv_int10: string;
  readonly priv_int49: string;
  readonly public_key: string;
  readonly standard_address: string;
  readonly smart_address: string;
}

export interface HistoricalCurveBlock {
  readonly curve: string;
  readonly curve_field_p_bits: number;
  readonly curve_order_q_bits: number;
  readonly curve_cofactor: string;
  readonly bitstring_vectors: readonly BitStringVector[];
  readonly seed_words_vectors: readonly HistoricalSeedWordsVector[];
  readonly schnorr_vectors: readonly SchnorrVector[];
}

export interface HistoricalVectorCorpus {
  readonly schema_version: number;
  readonly generator_version: string;
  readonly rng_seed_bits: string;
  readonly generated_at_utc: string;
  readonly host: string;
  readonly leto: HistoricalCurveBlock;
  readonly artemis: HistoricalCurveBlock;
  readonly apollo: HistoricalCurveBlock;
}

let cachedCorpus: VectorCorpus | undefined;
let cachedHistoricalCorpus: HistoricalVectorCorpus | undefined;

/**
 * Load the Go-reference Genesis test vector corpus. Cached after first call.
 *
 * Validates schema_version BEFORE caching so a malformed file cannot poison
 * subsequent calls — repeated loads will re-attempt the read and re-throw.
 */
export function loadCorpus(): VectorCorpus {
  if (cachedCorpus === undefined) {
    const raw = readFileSync(corpusPath, 'utf-8');
    const parsed = JSON.parse(raw) as VectorCorpus;
    if (parsed.schema_version !== 1) {
      throw new Error(`Genesis corpus schema mismatch: expected 1, got ${parsed.schema_version}`);
    }
    cachedCorpus = parsed;
  }
  return cachedCorpus;
}

/**
 * Load the Go-reference historical-curves (LETO/ARTEMIS/APOLLO) test vector
 * corpus. Cached after first call.
 *
 * Validates schema_version BEFORE caching so a malformed file cannot poison
 * subsequent calls — repeated loads will re-attempt the read and re-throw.
 */
export function loadHistoricalCorpus(): HistoricalVectorCorpus {
  if (cachedHistoricalCorpus === undefined) {
    const raw = readFileSync(historicalCorpusPath, 'utf-8');
    const parsed = JSON.parse(raw) as HistoricalVectorCorpus;
    if (parsed.schema_version !== 2) {
      throw new Error(
        `Historical corpus schema mismatch: expected 2, got ${parsed.schema_version}`,
      );
    }
    cachedHistoricalCorpus = parsed;
  }
  return cachedHistoricalCorpus;
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

/**
 * Phase 6 (REQ-19): Adversarial cofactor vectors loaded from
 * testvectors/v1_adversarial.json. Each vector is a (signature, message,
 * pubkey) triple with an expected_verify_result. Used by the TS adversarial
 * test suite to assert schnorrVerify behaviour matches the Go reference
 * generator's pre-computed expectations.
 */
export interface AdversarialCofactorVector {
  readonly id: string;
  readonly description: string;
  readonly malformed_signature: string;
  readonly legit_message: string;
  readonly legit_public_key: string;
  readonly expected_verify_result: boolean;
  readonly construction_method: string;
  readonly order_proof: string;
}

export interface AdversarialCorpus {
  readonly adversarial_cofactor_vectors: readonly AdversarialCofactorVector[];
}

let cachedAdversarialCorpus: AdversarialCorpus | undefined;

/**
 * Load the Go-reference adversarial-vector corpus. Cached after first call.
 */
export function loadAdversarialCorpus(): AdversarialCorpus {
  if (cachedAdversarialCorpus === undefined) {
    const raw = readFileSync(adversarialCorpusPath, 'utf-8');
    cachedAdversarialCorpus = JSON.parse(raw) as AdversarialCorpus;
  }
  return cachedAdversarialCorpus;
}

export function adversarialCofactorVectors(): readonly AdversarialCofactorVector[] {
  return loadAdversarialCorpus().adversarial_cofactor_vectors;
}

export function schnorrVectors(): readonly SchnorrVector[] {
  return loadCorpus().schnorr_vectors;
}

export function letoBitstringVectors(): readonly BitStringVector[] {
  return loadHistoricalCorpus().leto.bitstring_vectors;
}

export function letoSeedwordsVectors(): readonly HistoricalSeedWordsVector[] {
  return loadHistoricalCorpus().leto.seed_words_vectors;
}

export function letoSchnorrVectors(): readonly SchnorrVector[] {
  return loadHistoricalCorpus().leto.schnorr_vectors;
}

export function artemisBitstringVectors(): readonly BitStringVector[] {
  return loadHistoricalCorpus().artemis.bitstring_vectors;
}

export function artemisSeedwordsVectors(): readonly HistoricalSeedWordsVector[] {
  return loadHistoricalCorpus().artemis.seed_words_vectors;
}

export function artemisSchnorrVectors(): readonly SchnorrVector[] {
  return loadHistoricalCorpus().artemis.schnorr_vectors;
}

export function apolloBitstringVectors(): readonly BitStringVector[] {
  return loadHistoricalCorpus().apollo.bitstring_vectors;
}

export function apolloSeedwordsVectors(): readonly HistoricalSeedWordsVector[] {
  return loadHistoricalCorpus().apollo.seed_words_vectors;
}

export function apolloSchnorrVectors(): readonly SchnorrVector[] {
  return loadHistoricalCorpus().apollo.schnorr_vectors;
}
