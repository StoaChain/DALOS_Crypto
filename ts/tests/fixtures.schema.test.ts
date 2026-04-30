/**
 * Schema-version assertion tests for both Genesis and Historical corpus loaders.
 *
 * These tests exercise the parse-validate-assign branching logic that protects
 * the suite from a corpus regenerated under a future incompatible schema.
 *
 * The loaders module-cache their result, so each test imports the module fresh
 * via vi.resetModules() to force a re-read of the (mocked) JSON payload.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:fs', () => ({
  readFileSync: vi.fn(),
}));

const { readFileSync } = await import('node:fs');
const mockedReadFileSync = readFileSync as unknown as ReturnType<typeof vi.fn>;

afterEach(() => {
  mockedReadFileSync.mockReset();
  vi.resetModules();
});

describe('loadCorpus — Genesis schema-version assertion', () => {
  it('throws when schema_version is not 1', async () => {
    mockedReadFileSync.mockReturnValue(
      JSON.stringify({
        schema_version: 99,
        generator_version: 'fake',
        curve: 'fake',
        curve_field_p_bits: 0,
        curve_order_q_bits: 0,
        curve_cofactor: '0',
        rng_seed_bits: '',
        rng_seed_bitmaps: '',
        generated_at_utc: '',
        host: '',
        bitstring_vectors: [],
        seed_words_vectors: [],
        bitmap_vectors: [],
        schnorr_vectors: [],
      }),
    );
    const { loadCorpus } = await import('./fixtures.js');
    expect(() => loadCorpus()).toThrow(/Genesis corpus schema mismatch: expected 1, got 99/);
  });

  it('does not cache the parsed corpus on schema mismatch (re-throws on retry)', async () => {
    mockedReadFileSync.mockReturnValue(
      JSON.stringify({ schema_version: 42, bitstring_vectors: [] }),
    );
    const { loadCorpus } = await import('./fixtures.js');
    expect(() => loadCorpus()).toThrow(/expected 1, got 42/);
    expect(() => loadCorpus()).toThrow(/expected 1, got 42/);
    expect(mockedReadFileSync).toHaveBeenCalledTimes(2);
  });

  it('returns the corpus when schema_version is 1', async () => {
    mockedReadFileSync.mockReturnValue(
      JSON.stringify({
        schema_version: 1,
        generator_version: 'test',
        curve: 'TEST',
        curve_field_p_bits: 0,
        curve_order_q_bits: 0,
        curve_cofactor: '0',
        rng_seed_bits: '',
        rng_seed_bitmaps: '',
        generated_at_utc: '',
        host: '',
        bitstring_vectors: [],
        seed_words_vectors: [],
        bitmap_vectors: [],
        schnorr_vectors: [],
      }),
    );
    const { loadCorpus } = await import('./fixtures.js');
    expect(loadCorpus().schema_version).toBe(1);
  });
});

describe('loadHistoricalCorpus — Historical schema-version assertion', () => {
  it('throws when schema_version is not 2', async () => {
    mockedReadFileSync.mockReturnValue(
      JSON.stringify({
        schema_version: 1,
        generator_version: 'fake',
        rng_seed_bits: '',
        generated_at_utc: '',
        host: '',
        leto: {},
        artemis: {},
        apollo: {},
      }),
    );
    const { loadHistoricalCorpus } = await import('./fixtures.js');
    expect(() => loadHistoricalCorpus()).toThrow(
      /Historical corpus schema mismatch: expected 2, got 1/,
    );
  });

  it('does not cache the parsed corpus on schema mismatch (re-throws on retry)', async () => {
    mockedReadFileSync.mockReturnValue(JSON.stringify({ schema_version: 7 }));
    const { loadHistoricalCorpus } = await import('./fixtures.js');
    expect(() => loadHistoricalCorpus()).toThrow(/expected 2, got 7/);
    expect(() => loadHistoricalCorpus()).toThrow(/expected 2, got 7/);
    expect(mockedReadFileSync).toHaveBeenCalledTimes(2);
  });

  it('returns the corpus when schema_version is 2', async () => {
    mockedReadFileSync.mockReturnValue(
      JSON.stringify({
        schema_version: 2,
        generator_version: 'test',
        rng_seed_bits: '',
        generated_at_utc: '',
        host: '',
        leto: {
          curve: 'LETO',
          curve_field_p_bits: 0,
          curve_order_q_bits: 0,
          curve_cofactor: '0',
          bitstring_vectors: [],
          seed_words_vectors: [],
          schnorr_vectors: [],
        },
        artemis: {
          curve: 'ARTEMIS',
          curve_field_p_bits: 0,
          curve_order_q_bits: 0,
          curve_cofactor: '0',
          bitstring_vectors: [],
          seed_words_vectors: [],
          schnorr_vectors: [],
        },
        apollo: {
          curve: 'APOLLO',
          curve_field_p_bits: 0,
          curve_order_q_bits: 0,
          curve_cofactor: '0',
          bitstring_vectors: [],
          seed_words_vectors: [],
          schnorr_vectors: [],
        },
      }),
    );
    const { loadHistoricalCorpus } = await import('./fixtures.js');
    expect(loadHistoricalCorpus().schema_version).toBe(2);
  });
});
