/**
 * Tests for the 16×16 DALOS Character Matrix.
 *
 * Critical invariants:
 *   1. Exactly 256 positions (flat length == 256 code-units)
 *   2. All 256 characters are unique (no duplicates)
 *   3. Every character is in the Basic Multilingual Plane (BMP) so
 *      JavaScript's UTF-16 indexing returns a single complete char
 *   4. Position [0][10] is 'Ѻ' (U+047A, Cyrillic Round Omega)
 *   5. Position [11][9]  is 'Σ' (U+03A3, Greek Capital Sigma)
 *   6. Matches the Go reference's `CharacterMatrix()` byte-for-byte
 *      at every position (validated implicitly via Phase 3 address
 *      byte-identity tests)
 */

import { describe, expect, it } from 'vitest';
import {
  CHARACTER_MATRIX,
  CHARACTER_MATRIX_FLAT,
  SMART_ACCOUNT_PREFIX,
  STANDARD_ACCOUNT_PREFIX,
} from '../../src/gen1/character-matrix.ts';

describe('CHARACTER_MATRIX_FLAT', () => {
  it('has exactly 256 code units (= 256 BMP characters)', () => {
    expect(CHARACTER_MATRIX_FLAT.length).toBe(256);
  });

  it('all characters are in the Basic Multilingual Plane', () => {
    for (let i = 0; i < CHARACTER_MATRIX_FLAT.length; i++) {
      const cp = CHARACTER_MATRIX_FLAT.codePointAt(i);
      expect(cp).toBeDefined();
      expect(cp).toBeLessThanOrEqual(0xffff);
    }
  });

  it('contains no duplicate characters', () => {
    const set = new Set(CHARACTER_MATRIX_FLAT);
    expect(set.size).toBe(256);
  });

  it('position 10 is Ѻ (Cyrillic Round Omega, U+047A)', () => {
    expect(CHARACTER_MATRIX_FLAT[10]).toBe('Ѻ');
    expect(CHARACTER_MATRIX_FLAT[10]!.codePointAt(0)).toBe(0x047a);
  });

  it('position 185 is Σ (Greek Capital Sigma, U+03A3)', () => {
    // Row 11, col 9 → flat index 11 * 16 + 9 = 185
    expect(CHARACTER_MATRIX_FLAT[185]).toBe('Σ');
    expect(CHARACTER_MATRIX_FLAT[185]!.codePointAt(0)).toBe(0x03a3);
  });

  it('positions 0-9 are digits "0".."9"', () => {
    for (let i = 0; i < 10; i++) {
      expect(CHARACTER_MATRIX_FLAT[i]).toBe(String(i));
    }
  });

  it('positions 20-45 are A..Z', () => {
    for (let i = 0; i < 26; i++) {
      expect(CHARACTER_MATRIX_FLAT[20 + i]).toBe(String.fromCharCode(65 + i));
    }
  });

  it('positions 46-71 are a..z', () => {
    for (let i = 0; i < 26; i++) {
      expect(CHARACTER_MATRIX_FLAT[46 + i]).toBe(String.fromCharCode(97 + i));
    }
  });
});

describe('CHARACTER_MATRIX (2D view)', () => {
  it('has 16 rows', () => {
    expect(CHARACTER_MATRIX).toHaveLength(16);
  });

  it('every row has exactly 16 columns', () => {
    for (const row of CHARACTER_MATRIX) {
      expect(row).toHaveLength(16);
    }
  });

  it('[0][10] === Ѻ', () => {
    expect(CHARACTER_MATRIX[0]?.[10]).toBe('Ѻ');
  });

  it('[11][9] === Σ', () => {
    expect(CHARACTER_MATRIX[11]?.[9]).toBe('Σ');
  });

  it('2D view matches flat string: row*16+col', () => {
    for (let r = 0; r < 16; r++) {
      for (let c = 0; c < 16; c++) {
        expect(CHARACTER_MATRIX[r]?.[c]).toBe(CHARACTER_MATRIX_FLAT[r * 16 + c]);
      }
    }
  });
});

describe('account-prefix constants', () => {
  it('STANDARD_ACCOUNT_PREFIX === Ѻ', () => {
    expect(STANDARD_ACCOUNT_PREFIX).toBe('Ѻ');
  });

  it('SMART_ACCOUNT_PREFIX === Σ', () => {
    expect(SMART_ACCOUNT_PREFIX).toBe('Σ');
  });
});
