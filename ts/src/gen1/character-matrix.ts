/**
 * The 16 × 16 DALOS Character Matrix — 256 Unicode runes used to encode
 * `Ѻ.xxx...` / `Σ.xxx...` account addresses.
 *
 * Every byte of the seven-fold Blake3 hash output is mapped through
 * this matrix at position `(byte / 16, byte % 16)` to produce one
 * character of the 160-character address body.
 *
 * The matrix is FROZEN at Genesis — altering any rune would produce
 * different address strings for the same keys and orphan every
 * existing Ouronet account. Mirror of `CharacterMatrix()` in
 * `Elliptic/KeyGeneration.go` byte-for-byte.
 *
 * Layout:
 *   Rows 0–1   : digits + currency signs (Ѻ, ₿, $, ¢, €, £, ¥, ₱, ₳, ∇)
 *   Rows 1–3   : Latin capital + small letters (A–Z, a–z)
 *   Rows 4–7   : Latin extended capital letters (Æ, Œ, Á, Ă, Â, Ä, À, …)
 *   Rows 7–10  : Latin extended small letters (æ, œ, á, ă, â, ä, à, …)
 *   Rows 11    : Sharp-s, Greek capital letters (Γ, Δ, Θ, Λ, Ξ, Π, Σ, Φ, Ψ, Ω)
 *   Rows 11–13 : Greek small letters (α–ω)
 *   Rows 13–14 : Cyrillic capital letters (Б, Д, Ж, З, И, Й, Л, П, У, Ц, Ч, Ш, Щ, Ъ, Ы, Ь, Э, Ю, Я)
 *   Rows 14–15 : Cyrillic small letters (б, в, д, ж, з, и, й, к, л, м, н, п, т, у, ф, ц, ч, ш, щ, ъ, ы, ь, э, ю, я)
 *
 * Notable positions used elsewhere:
 *   [0][10]  = 'Ѻ'    (Cyrillic Round Omega — Ouronet Standard Account prefix)
 *   [11][9]  = 'Σ'    (Greek Capital Sigma — Ouronet Smart Account prefix)
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/**
 * Flattened 256-character string in row-major order. Every character
 * in this string is inside the Basic Multilingual Plane (U+0000–U+FFFF),
 * so UTF-16 indexing `CHARACTER_MATRIX_FLAT[byte]` returns the correct
 * single character for `byte ∈ [0, 255]`.
 */
export const CHARACTER_MATRIX_FLAT =
  // Row 0 — digits (10) + currency start (6)
  '0123456789Ѻ₿$¢€£' +
  // Row 1 — currencies cont'd (4) + A..L (12)
  '¥₱₳∇ABCDEFGHIJKL' +
  // Row 2 — M..Z (14) + a, b
  'MNOPQRSTUVWXYZab' +
  // Row 3 — c..r
  'cdefghijklmnopqr' +
  // Row 4 — s..z (8) + Latin-extended capitals Æ Œ Á Ă Â Ä À Ą (8)
  'stuvwxyzÆŒÁĂÂÄÀĄ' +
  // Row 5 — Å Ã Ć Č Ç Ď Đ É Ě Ê Ë È Ę Ğ Í Î
  'ÅÃĆČÇĎĐÉĚÊËÈĘĞÍÎ' +
  // Row 6 — Ï Ì Ł Ń Ñ Ó Ô Ö Ò Ø Õ Ř Ś Š Ş Ș
  'ÏÌŁŃÑÓÔÖÒØÕŘŚŠŞȘ' +
  // Row 7 — Þ Ť Ț Ú Û Ü Ù Ů Ý Ÿ Ź Ž Ż + æ œ á
  'ÞŤȚÚÛÜÙŮÝŸŹŽŻæœá' +
  // Row 8 — ă â ä à ą å ã ć č ç ď đ é ě ê ë
  'ăâäàąåãćčçďđéěêë' +
  // Row 9 — è ę ğ í î ï ì ł ń ñ ó ô ö ò ø õ
  'èęğíîïìłńñóôöòøõ' +
  // Row 10 — ř ś š ş ș þ ť ț ú û ü ù ů ý ÿ ź
  'řśšşșþťțúûüùůýÿź' +
  // Row 11 — ž ż ß + Greek caps Γ Δ Θ Λ Ξ Π Σ Φ Ψ Ω + Greek small α β γ
  'žżßΓΔΘΛΞΠΣΦΨΩαβγ' +
  // Row 12 — δ ε ζ η θ ι κ λ μ ν ξ π ρ σ ς τ
  'δεζηθικλμνξπρσςτ' +
  // Row 13 — φ χ ψ ω + Cyrillic caps Б Д Ж З И Й Л П У Ц Ч Ш
  'φχψωБДЖЗИЙЛПУЦЧШ' +
  // Row 14 — Щ Ъ Ы Ь Э Ю Я + Cyrillic small б в д ж з и й к л
  'ЩЪЫЬЭЮЯбвджзийкл' +
  // Row 15 — м н п т у ф ц ч ш щ ъ ы ь э ю я
  'мнптуфцчшщъыьэюя';

/**
 * Convenience: 2D view of the character matrix. `CHARACTER_MATRIX[row][col]`
 * returns the single-character string at that position.
 *
 * Built from `CHARACTER_MATRIX_FLAT` at module load; rows are frozen
 * tuples of length 16.
 */
export const CHARACTER_MATRIX: readonly (readonly string[])[] = (() => {
  const rows: string[][] = [];
  for (let r = 0; r < 16; r++) {
    const row: string[] = [];
    for (let c = 0; c < 16; c++) {
      row.push(CHARACTER_MATRIX_FLAT[r * 16 + c] ?? '');
    }
    rows.push(row);
  }
  return rows.map((r) => Object.freeze(r));
})();

/**
 * Ouronet Standard Account prefix character: `Ѻ` (Cyrillic Capital
 * Round Omega, U+047A). Position [0][10] in the matrix.
 */
export const STANDARD_ACCOUNT_PREFIX = CHARACTER_MATRIX[0]?.[10] ?? 'Ѻ';

/**
 * Ouronet Smart Account prefix character: `Σ` (Greek Capital Sigma,
 * U+03A3). Position [11][9] in the matrix.
 */
export const SMART_ACCOUNT_PREFIX = CHARACTER_MATRIX[11]?.[9] ?? 'Σ';
