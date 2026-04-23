/**
 * 40 × 40 black/white bitmap — the 6th DALOS key-generation input type.
 *
 * Mirrors `Bitmap/Bitmap.go` in the Go reference byte-for-byte:
 *   - 40 × 40 = 1600 pixels = 1600 bits = the DALOS safe-scalar size
 *   - Bit convention: BLACK pixel = true = 1; WHITE pixel = false = 0
 *   - Scan order: row-major, top-to-bottom, left-to-right
 *   - ASCII rendering: '#' = black (1), '.' = white (0)
 *
 * The bitmap is treated as a PRIVATE KEY. Any caller that stores,
 * displays or transmits a bitmap must apply the same operational-
 * security care as a seed phrase.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/** Fixed dimensions of a DALOS bitmap (40 rows × 40 cols = 1600 bits). */
export const BITMAP_ROWS = 40;
export const BITMAP_COLS = 40;
export const BITMAP_TOTAL_BITS = BITMAP_ROWS * BITMAP_COLS;

/**
 * A DALOS bitmap — 40 rows of 40 booleans. `b[row][col] === true`
 * means black (bit 1); `false` means white (bit 0).
 *
 * Row 0 is the top row; column 0 is the leftmost column.
 */
export type Bitmap = readonly (readonly boolean[])[];

/**
 * Convert a Bitmap to its 1600-character bitstring representation
 * using the Genesis scan order (row-major, top-to-bottom, left-to-right).
 *
 * Throws on malformed input (non-40×40 shape).
 */
export function bitmapToBitString(b: Bitmap): string {
  if (b.length !== BITMAP_ROWS) {
    throw new Error(`bitmapToBitString: expected ${BITMAP_ROWS} rows, got ${b.length}`);
  }
  let out = '';
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const row = b[r];
    if (row === undefined || row.length !== BITMAP_COLS) {
      throw new Error(
        `bitmapToBitString: row ${r} must have ${BITMAP_COLS} columns, got ${row?.length ?? 'undefined'}`,
      );
    }
    for (let c = 0; c < BITMAP_COLS; c++) {
      out += row[c] ? '1' : '0';
    }
  }
  return out;
}

/**
 * Reverse of `bitmapToBitString`.
 *
 * WARNING: the resulting Bitmap is equivalent to the private key the
 * bitstring encodes. This function is exported for visualisation and
 * testing. The parameter name `bitsReveal` is intentional: callers
 * must acknowledge the sensitivity.
 */
export function bitStringToBitmapReveal(bitsReveal: string): Bitmap {
  if (bitsReveal.length !== BITMAP_TOTAL_BITS) {
    throw new Error(
      `bitStringToBitmapReveal: expected ${BITMAP_TOTAL_BITS} chars, got ${bitsReveal.length}`,
    );
  }
  const rows: boolean[][] = [];
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < BITMAP_COLS; c++) {
      const ch = bitsReveal[r * BITMAP_COLS + c];
      if (ch === '1') row.push(true);
      else if (ch === '0') row.push(false);
      else
        throw new Error(
          `bitStringToBitmapReveal: invalid char '${ch}' at index ${r * BITMAP_COLS + c}`,
        );
    }
    rows.push(row);
  }
  return rows;
}

/**
 * Structural validity check. Always returns `{ valid: true }` for
 * any `Bitmap` whose 2D array shape is correct; `{ valid: false }`
 * with a reason otherwise.
 */
export function validateBitmap(b: Bitmap): { valid: boolean; reason?: string } {
  if (b.length !== BITMAP_ROWS) {
    return { valid: false, reason: `expected ${BITMAP_ROWS} rows, got ${b.length}` };
  }
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const row = b[r];
    if (row === undefined || row.length !== BITMAP_COLS) {
      return {
        valid: false,
        reason: `row ${r} must have ${BITMAP_COLS} columns, got ${row?.length ?? 'undefined'}`,
      };
    }
  }
  return { valid: true };
}

/**
 * Parse a 40-row ASCII bitmap as produced by `BitmapToAscii` in the
 * Go reference. Each row must be exactly 40 characters of '#' or '.'.
 *
 * - '#' = black = true = bit 1
 * - '.' = white = false = bit 0
 */
export function parseAsciiBitmap(rows: readonly string[]): Bitmap {
  if (rows.length !== BITMAP_ROWS) {
    throw new Error(`parseAsciiBitmap: expected ${BITMAP_ROWS} rows, got ${rows.length}`);
  }
  const out: boolean[][] = [];
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const row = rows[r];
    if (row === undefined || row.length !== BITMAP_COLS) {
      throw new Error(
        `parseAsciiBitmap: row ${r}: expected ${BITMAP_COLS} columns, got ${row?.length ?? 'undefined'}`,
      );
    }
    const cells: boolean[] = [];
    for (let c = 0; c < BITMAP_COLS; c++) {
      const ch = row[c];
      if (ch === '#') cells.push(true);
      else if (ch === '.') cells.push(false);
      else
        throw new Error(
          `parseAsciiBitmap: row ${r} col ${c}: invalid char '${ch}' (expected '#' or '.')`,
        );
    }
    out.push(cells);
  }
  return out;
}

/**
 * Reverse of `parseAsciiBitmap` — convert a Bitmap back into its ASCII
 * representation (40 rows × 40 chars).
 *
 * WARNING: the result is equivalent to the private key the bitmap
 * encodes. Treat with the same OPSEC care as a seed phrase.
 */
export function bitmapToAscii(b: Bitmap): string[] {
  const rows: string[] = [];
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const row = b[r];
    if (row === undefined) continue;
    let s = '';
    for (let c = 0; c < BITMAP_COLS; c++) {
      s += row[c] ? '#' : '.';
    }
    rows.push(s);
  }
  return rows;
}

/**
 * Equality check for two bitmaps. `true` iff every cell matches.
 */
export function equalBitmap(a: Bitmap, b: Bitmap): boolean {
  if (a.length !== BITMAP_ROWS || b.length !== BITMAP_ROWS) return false;
  for (let r = 0; r < BITMAP_ROWS; r++) {
    const ra = a[r];
    const rb = b[r];
    if (!ra || !rb || ra.length !== BITMAP_COLS || rb.length !== BITMAP_COLS) return false;
    for (let c = 0; c < BITMAP_COLS; c++) {
      if (ra[c] !== rb[c]) return false;
    }
  }
  return true;
}
