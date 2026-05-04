package Bitmap

import (
	"strings"
	"testing"
)

// =============================================================================
// F-TEST-002 (audit cycle 2026-05-04, v4.0.1): unit tests for the Bitmap
// package. Pre-v4.0.1 the package had ZERO direct unit tests on the Go side —
// correctness rode on end-to-end byte-identity via the testvector corpus's
// 20 bitmap vectors in v1_genesis.json. That catches macroscopic regressions
// (any change that shifts a bit anywhere in the 40×40 → 1600-bit pipeline)
// but does NOT cover:
//
//   - The strict pixel-character validators in ParseAsciiBitmap
//   - The roundtrip property between BitmapToAscii ↔ ParseAsciiBitmap
//   - The roundtrip property between BitmapToBitString ↔ BitStringToBitmapReveal
//   - EqualBitmap's true-on-same / false-on-different contract
//   - Boundary-error messages (length wrong, char wrong, position-in-error)
//
// These tests pin those properties directly. ParsePngFileToBitmap is NOT
// covered here because it requires committing PNG fixture binaries to the
// repo; deferred to a separate spec.
//
// Scope: DALOS-only (40×40 → 1600 bits) — see the package docstring for
// the cross-curve consumer-side pattern.

// makeTestBitmap returns a deterministic 40×40 pattern: cell (r, c) is true
// iff (r*40 + c) % 7 == 0. Provides a non-trivial pattern with both true
// and false cells distributed across the grid.
func makeTestBitmap() Bitmap {
	var b Bitmap
	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			b[r][c] = ((r*Cols + c) % 7) == 0
		}
	}
	return b
}

// TestBitmapToBitString_LengthIsAlwaysBits pins the most fundamental contract:
// a 40×40 Bitmap converts to a string of EXACTLY 1600 chars. Any other length
// breaks the downstream GenerateScalarFromBitString validator.
func TestBitmapToBitString_LengthIsAlwaysBits(t *testing.T) {
	cases := map[string]Bitmap{
		"all_zero":  Bitmap{},
		"all_one":   makeAllOnes(),
		"alternate": makeTestBitmap(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			got := BitmapToBitString(b)
			if len(got) != Bits {
				t.Errorf("expected %d chars, got %d", Bits, len(got))
			}
			for i, ch := range got {
				if ch != '0' && ch != '1' {
					t.Errorf("char at index %d is %q, expected '0' or '1'", i, ch)
				}
			}
		})
	}
}

// TestBitmapToBitString_RowMajorTopLeftFirst pins the scan order convention.
// A bitmap with a single `true` at position (0, 1) — row 0, column 1 —
// must produce a bitstring whose first two characters are "01" followed by
// 1598 zeros. This catches:
//   - Accidental column-major (would produce "0...010...0" with the 1 at
//     index 40, not index 1)
//   - Row inversion (bottom-to-top would put the 1 near the end)
//   - Column inversion (right-to-left would put the 1 at index 38)
func TestBitmapToBitString_RowMajorTopLeftFirst(t *testing.T) {
	var b Bitmap
	b[0][1] = true

	got := BitmapToBitString(b)

	if got[0] != '0' {
		t.Errorf("char at index 0 should be '0' (cell [0][0] is false), got %q", got[0])
	}
	if got[1] != '1' {
		t.Errorf("char at index 1 should be '1' (cell [0][1] is true); convention is row-major top-to-bottom, left-to-right. got %q", got[1])
	}
	for i := 2; i < Bits; i++ {
		if got[i] != '0' {
			t.Errorf("char at index %d should be '0' (no other cells are true), got %q", i, got[i])
			break
		}
	}
}

// TestBitmapToBitString_AllZeroAllOne pins the boundary cases.
func TestBitmapToBitString_AllZeroAllOne(t *testing.T) {
	allZero := BitmapToBitString(Bitmap{})
	if allZero != strings.Repeat("0", Bits) {
		t.Errorf("all-false bitmap should produce 1600 zeros; first 20 chars: %q", allZero[:20])
	}

	allOne := BitmapToBitString(makeAllOnes())
	if allOne != strings.Repeat("1", Bits) {
		t.Errorf("all-true bitmap should produce 1600 ones; first 20 chars: %q", allOne[:20])
	}
}

// TestBitmapToBitString_BitStringToBitmapReveal_RoundTrip pins the
// inverse-function contract: a Bitmap → bitstring → Bitmap must equal
// the original.
func TestBitmapToBitString_BitStringToBitmapReveal_RoundTrip(t *testing.T) {
	cases := map[string]Bitmap{
		"all_zero":  Bitmap{},
		"all_one":   makeAllOnes(),
		"alternate": makeTestBitmap(),
		"single_pixel_at_corners": func() Bitmap {
			var b Bitmap
			b[0][0] = true
			b[0][Cols-1] = true
			b[Rows-1][0] = true
			b[Rows-1][Cols-1] = true
			return b
		}(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			bits := BitmapToBitString(b)
			recovered, err := BitStringToBitmapReveal(bits)
			if err != nil {
				t.Fatalf("BitStringToBitmapReveal returned error on round-trip: %v", err)
			}
			if !EqualBitmap(b, recovered) {
				t.Errorf("round-trip differs from original")
			}
		})
	}
}

// TestBitStringToBitmapReveal_RejectsWrongLength pins the length-validation
// branch. Inputs that aren't exactly 1600 chars must return an error
// naming the expected and actual lengths.
func TestBitStringToBitmapReveal_RejectsWrongLength(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"one_short", strings.Repeat("0", Bits-1)},
		{"one_over", strings.Repeat("0", Bits+1)},
		{"way_short", "01010101"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := BitStringToBitmapReveal(c.in)
			if err == nil {
				t.Fatalf("expected error for length %d, got nil", len(c.in))
			}
			if !strings.Contains(err.Error(), "must be exactly") {
				t.Errorf("error message should mention 'must be exactly', got: %q", err.Error())
			}
		})
	}
}

// TestBitStringToBitmapReveal_RejectsBadChars pins the character-validation
// branch. A 1600-char input containing anything other than '0' or '1' must
// return an error naming the offending character + position.
func TestBitStringToBitmapReveal_RejectsBadChars(t *testing.T) {
	cases := []struct {
		name string
		bad  byte
		pos  int
	}{
		{"x_at_start", 'x', 0},
		{"space_in_middle", ' ', 800},
		{"two_at_end", '2', Bits - 1},
		{"newline", '\n', 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, Bits)
			for i := range buf {
				buf[i] = '0'
			}
			buf[c.pos] = c.bad
			_, err := BitStringToBitmapReveal(string(buf))
			if err == nil {
				t.Fatalf("expected error for bad char %q at position %d, got nil", c.bad, c.pos)
			}
			if !strings.Contains(err.Error(), "invalid char at position") {
				t.Errorf("error should mention 'invalid char at position', got: %q", err.Error())
			}
		})
	}
}

// TestParseAsciiBitmap_HappyPath pins the canonical accept path.
func TestParseAsciiBitmap_HappyPath(t *testing.T) {
	rows := make([]string, Rows)
	for r := 0; r < Rows; r++ {
		var sb strings.Builder
		for c := 0; c < Cols; c++ {
			if (r+c)%2 == 0 {
				sb.WriteByte('#')
			} else {
				sb.WriteByte('.')
			}
		}
		rows[r] = sb.String()
	}
	b, err := ParseAsciiBitmap(rows)
	if err != nil {
		t.Fatalf("expected nil error on valid input, got: %v", err)
	}
	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			want := (r+c)%2 == 0
			if b[r][c] != want {
				t.Errorf("cell [%d][%d]: got %v, want %v", r, c, b[r][c], want)
				return
			}
		}
	}
}

// TestParseAsciiBitmap_RejectsMalformedInput pins the validation branches.
// Drives row count, column count, and per-character validation paths.
func TestParseAsciiBitmap_RejectsMalformedInput(t *testing.T) {
	validRow := strings.Repeat(".", Cols)

	cases := []struct {
		name        string
		rows        []string
		expectInMsg string
	}{
		{
			name:        "too_few_rows",
			rows:        []string{validRow, validRow, validRow},
			expectInMsg: "expected 40 rows",
		},
		{
			name:        "too_many_rows",
			rows:        append(makeNValidRows(Rows), validRow),
			expectInMsg: "expected 40 rows",
		},
		{
			name:        "row_too_short",
			rows:        replaceRow(makeNValidRows(Rows), 5, strings.Repeat(".", Cols-1)),
			expectInMsg: "row 5",
		},
		{
			name:        "row_too_long",
			rows:        replaceRow(makeNValidRows(Rows), 12, strings.Repeat(".", Cols+1)),
			expectInMsg: "row 12",
		},
		{
			name:        "invalid_char_uppercase",
			rows:        replaceRow(makeNValidRows(Rows), 0, "X"+strings.Repeat(".", Cols-1)),
			expectInMsg: "invalid char",
		},
		{
			name:        "invalid_char_space",
			rows:        replaceRow(makeNValidRows(Rows), 7, strings.Repeat(".", 5)+" "+strings.Repeat(".", Cols-6)),
			expectInMsg: "invalid char",
		},
		{
			name:        "invalid_char_newline",
			rows:        replaceRow(makeNValidRows(Rows), 39, strings.Repeat(".", Cols-1)+"\n"),
			expectInMsg: "invalid char",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseAsciiBitmap(c.rows)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
			if !strings.Contains(err.Error(), c.expectInMsg) {
				t.Errorf("error message should contain %q, got: %q", c.expectInMsg, err.Error())
			}
		})
	}
}

// TestBitmapToAscii_RoundTripWithParse pins the inverse-function contract
// for the ASCII path: ParseAsciiBitmap(BitmapToAscii(b)) == b.
func TestBitmapToAscii_RoundTripWithParse(t *testing.T) {
	cases := map[string]Bitmap{
		"all_zero":  Bitmap{},
		"all_one":   makeAllOnes(),
		"alternate": makeTestBitmap(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			ascii := BitmapToAscii(b)
			if len(ascii) != Rows {
				t.Errorf("BitmapToAscii returned %d rows, expected %d", len(ascii), Rows)
			}
			for r, row := range ascii {
				if len(row) != Cols {
					t.Errorf("row %d has %d chars, expected %d", r, len(row), Cols)
				}
			}
			recovered, err := ParseAsciiBitmap(ascii)
			if err != nil {
				t.Fatalf("ParseAsciiBitmap rejected the output of BitmapToAscii: %v", err)
			}
			if !EqualBitmap(b, recovered) {
				t.Errorf("ASCII round-trip differs from original")
			}
		})
	}
}

// TestEqualBitmap_TrueOnSameFalseOnSinglePixelDiff pins the equality
// semantics. Self-equality + single-pixel-difference rejection are the
// two cases that matter; intermediate cases follow from the cell-by-cell
// implementation.
func TestEqualBitmap_TrueOnSameFalseOnSinglePixelDiff(t *testing.T) {
	a := makeTestBitmap()
	bSame := makeTestBitmap()
	if !EqualBitmap(a, bSame) {
		t.Errorf("EqualBitmap on identical bitmaps returned false")
	}

	bDiff := makeTestBitmap()
	bDiff[15][20] = !bDiff[15][20]
	if EqualBitmap(a, bDiff) {
		t.Errorf("EqualBitmap returned true for bitmaps differing in cell [15][20]")
	}
}

// =============================================================================
// Test-helper utilities (not part of the public surface).
// =============================================================================

func makeAllOnes() Bitmap {
	var b Bitmap
	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			b[r][c] = true
		}
	}
	return b
}

func makeNValidRows(n int) []string {
	row := strings.Repeat(".", Cols)
	out := make([]string, n)
	for i := range out {
		out[i] = row
	}
	return out
}

func replaceRow(rows []string, idx int, replacement string) []string {
	out := make([]string, len(rows))
	copy(out, rows)
	out[idx] = replacement
	return out
}
