/**
 * Tests for the 40×40 bitmap utilities.
 */

import { describe, expect, it } from 'vitest';
import {
  BITMAP_COLS,
  BITMAP_ROWS,
  BITMAP_TOTAL_BITS,
  type Bitmap,
  bitStringToBitmapReveal,
  bitmapToAscii,
  bitmapToBitString,
  equalBitmap,
  parseAsciiBitmap,
  validateBitmap,
} from '../../src/gen1/bitmap.ts';
import { bitmapVectors } from '../fixtures.ts';

describe('bitmap constants', () => {
  it('dimensions are 40 × 40 = 1600 bits', () => {
    expect(BITMAP_ROWS).toBe(40);
    expect(BITMAP_COLS).toBe(40);
    expect(BITMAP_TOTAL_BITS).toBe(1600);
  });
});

describe('parseAsciiBitmap / bitmapToAscii round-trip', () => {
  it('all 20 committed bitmap fixtures round-trip identity', () => {
    for (const v of bitmapVectors()) {
      const b = parseAsciiBitmap(v.bitmap_ascii);
      const back = bitmapToAscii(b);
      expect(back).toEqual([...v.bitmap_ascii]);
    }
  });

  it('rejects wrong row count', () => {
    expect(() => parseAsciiBitmap(['#'.repeat(40)])).toThrow(); // only 1 row
  });

  it('rejects wrong column count', () => {
    const rows = Array(40).fill('#'.repeat(39)); // 39 cols, not 40
    expect(() => parseAsciiBitmap(rows)).toThrow();
  });

  it('rejects invalid characters', () => {
    const rows = Array(40).fill('#'.repeat(40));
    rows[0] = `${'#'.repeat(39)}X`;
    expect(() => parseAsciiBitmap(rows)).toThrow();
  });
});

describe('bitmapToBitString', () => {
  it('all-black bitmap → 1600 "1"s', () => {
    const b = Array(40)
      .fill(null)
      .map(() => Array(40).fill(true));
    expect(bitmapToBitString(b)).toBe('1'.repeat(1600));
  });

  it('all-white bitmap → 1600 "0"s', () => {
    const b = Array(40)
      .fill(null)
      .map(() => Array(40).fill(false));
    expect(bitmapToBitString(b)).toBe('0'.repeat(1600));
  });

  it('matches derived_bitstring for each committed bitmap vector', () => {
    for (const v of bitmapVectors()) {
      const b = parseAsciiBitmap(v.bitmap_ascii);
      expect(bitmapToBitString(b)).toBe(v.derived_bitstring);
    }
  });
});

describe('bitStringToBitmapReveal', () => {
  it('round-trips bitmap → bitstring → bitmap', () => {
    for (const v of bitmapVectors().slice(0, 5)) {
      const b = parseAsciiBitmap(v.bitmap_ascii);
      const bits = bitmapToBitString(b);
      const b2 = bitStringToBitmapReveal(bits);
      expect(equalBitmap(b, b2)).toBe(true);
    }
  });

  it('rejects wrong length', () => {
    expect(() => bitStringToBitmapReveal('0'.repeat(1599))).toThrow();
  });

  it('rejects invalid characters', () => {
    expect(() => bitStringToBitmapReveal('X'.repeat(1600))).toThrow();
  });
});

describe('validateBitmap', () => {
  it('accepts valid 40×40', () => {
    const b: Bitmap = Array(40)
      .fill(null)
      .map(() => Array(40).fill(false));
    expect(validateBitmap(b)).toEqual({ valid: true });
  });

  it('rejects wrong row count', () => {
    const b: Bitmap = Array(39).fill([]);
    expect(validateBitmap(b).valid).toBe(false);
  });

  it('rejects 41-row input with row-count reason', () => {
    const b = Array(41)
      .fill(null)
      .map(() => Array(40).fill(false)) as Bitmap;
    const result = validateBitmap(b);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expected 40 rows, got 41/);
  });

  it('rejects jagged array with column-count reason', () => {
    const b = Array(40)
      .fill(null)
      .map((_, i) => Array(i < 20 ? 40 : 39).fill(false)) as Bitmap;
    const result = validateBitmap(b);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/row \d+ must have 40 columns, got \d+/);
  });

  it('rejects single 41-column row inside an otherwise 40×40 array', () => {
    const rows: boolean[][] = Array(40)
      .fill(null)
      .map(() => Array(40).fill(false));
    rows[5] = Array(41).fill(false);
    const result = validateBitmap(rows as Bitmap);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/row \d+ must have 40 columns, got 41/);
  });
});
