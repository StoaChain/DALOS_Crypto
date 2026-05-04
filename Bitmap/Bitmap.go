// Package Bitmap implements the 40x40 black/white bitmap input type
// for DALOS private-key generation.
//
// A Bitmap is exactly 40 x 40 = 1600 pixels, which matches the DALOS
// safe-scalar size of 1600 bits. Each pixel contributes exactly one bit.
//
// SCOPE NOTE (v4.0.1, F-TEST-002): this package is intentionally
// DALOS-Genesis-only. The Bitmap type is hardcoded to 40x40, and
// (*Ellipse).GenerateFromBitmap accepts only this type — calling it on
// APOLLO (1024-bit safe-scalar) or any non-square-scalar curve returns
// a length-validation error.
//
// For other curves with perfect-square safe-scalar sizes (today: APOLLO
// at 32x32 = 1024 bits; future post-quantum primitives may add more),
// the per-curve bitmap-to-bitstring conversion is a CONSUMER-SIDE
// concern: paint the appropriately-sized grid in your UI, convert to a
// flat row-major bitstring of the correct length, and call this
// package's `(*Ellipse).GenerateScalarFromBitString` (or its npm
// equivalent `fromBitString`) directly. The reference consumer-side
// implementation is `OuronetUI/src/lib/dalos/bitmap-local.ts` — it
// exposes `bitmapDimensionsFor(curve)` returning per-curve rows/cols
// and a generic flat-conversion helper. Consumer-side dimensioning
// keeps this package's bitmap helpers tightly tied to the Genesis
// 40x40 contract while giving consumers full per-curve flexibility.
//
// Genesis conventions (locked at v1.2.0, permanent):
//
//   - Bit convention: BLACK pixel = 1, WHITE pixel = 0
//   - Scan order:     row-major, top-to-bottom, left-to-right
//   - Greyscale:      strict — pure black (0,0,0) and pure white (255,255,255)
//                     ONLY; any other pixel value is rejected as an error
//
// The bitmap is treated as a PRIVATE KEY. Any caller that exposes or
// stores a bitmap must treat it with the same operational-security care
// as a seed phrase. Do NOT photograph, print on business cards, transmit
// unencrypted, or display in shared contexts.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
// See ../LICENSE for terms.
package Bitmap

import (
	"fmt"
	"image/png"
	"os"
	"strings"
)

// Dimensions and total bit count.
const (
	Rows = 40
	Cols = 40
	Bits = Rows * Cols // 1600
)

// Bitmap is a 40x40 black/white image.
//
// Convention: b[row][col] = true  means BLACK  (bit value 1)
//             b[row][col] = false means WHITE  (bit value 0)
//
// Row 0 is the top row; column 0 is the leftmost column.
type Bitmap [Rows][Cols]bool

// BitmapToBitString converts a Bitmap to its 1600-character bitstring
// representation using row-major top-to-bottom, left-to-right scan order.
//
// The output is always exactly Bits (1600) characters, each '0' or '1'.
func BitmapToBitString(b Bitmap) string {
	var sb strings.Builder
	sb.Grow(Bits)
	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			if b[r][c] {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}
	return sb.String()
}

// BitStringToBitmapReveal reverses BitmapToBitString.
//
// WARNING: the resulting Bitmap is equivalent to the private key the
// bitstring encodes. This function exists for visualisation and testing
// purposes; any caller must treat the returned bitmap as a secret.
//
// The parameter is deliberately named bitsReveal to force the caller to
// acknowledge the sensitivity.
//
// Returns an error if bitsReveal is not exactly Bits characters long or
// contains any character other than '0' or '1'.
func BitStringToBitmapReveal(bitsReveal string) (Bitmap, error) {
	var b Bitmap
	if len(bitsReveal) != Bits {
		return b, fmt.Errorf("bitstring must be exactly %d chars, got %d", Bits, len(bitsReveal))
	}
	for i := 0; i < Bits; i++ {
		r := i / Cols
		c := i % Cols
		switch bitsReveal[i] {
		case '0':
			b[r][c] = false
		case '1':
			b[r][c] = true
		default:
			return Bitmap{}, fmt.Errorf("invalid char at position %d: %q (expected '0' or '1')", i, bitsReveal[i])
		}
	}
	return b, nil
}

// ValidateBitmap is a NO-OP that always returns nil. It exists as a
// reserved hook for future structural validation but currently performs
// no checks.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-API-006): the pre-v4.0.1
// Godoc summary line read "performs structural validation of a Bitmap"
// — misleading, since the function body is `return nil`. A consumer
// reading the Godoc would believe the bitmap was being inspected and
// might skip their own checks. The summary line is now explicit about
// the no-op nature.
//
// Why no real validation today:
//   - The Go type system already enforces structural validity:
//     `[40][40]bool` cannot hold non-bool values, cannot have wrong
//     dimensions at the type level, and cannot be a nil reference
//     (it's a value type).
//   - A meaningful "is this a valid DALOS bitmap" check would have to
//     be CURVE-SPECIFIC: DALOS Genesis uses 40×40=1600 bits, but
//     APOLLO uses 32×32=1024 bits, LETO uses different again. This
//     function takes a single Bitmap type that's already typed for the
//     Genesis grid; per-curve dimension checks would belong on the
//     receiving Ellipse, not on the Bitmap helper itself.
//   - Entropy / "is this all zeros" checks are arguable — the
//     downstream key-gen pipeline produces a valid scalar from any
//     1600-bit input, including all-zeros (the resulting scalar would
//     be 0 → rejected by F-ERR-007's range check in SchnorrSign at the
//     point of use). Catching it here would be earlier-error but not
//     fundamentally different.
//
// Cross-impl note: TS port's `validateBitmap`
// (`ts/src/gen1/bitmap.ts:91`) returns `{ valid: boolean; reason?: string }`
// and DOES perform structural checks. The Go side intentionally diverges
// here because the Go type system covers the structural cases the TS
// runtime check has to do dynamically.
//
// If you need real bitmap validation, do it explicitly at the call site
// rather than relying on this function to grow checks later.
func ValidateBitmap(_ Bitmap) error {
	return nil
}

// ParseAsciiBitmap parses a 40-row ASCII bitmap.
//
// Each row must be exactly 40 characters of '#' or '.':
//   - '#' = BLACK = bit value 1
//   - '.' = WHITE = bit value 0
//
// Any other character at any position produces an error.
//
// Example input (4x4 subset shown; real input is 40x40):
//
//	"####"
//	"#..#"
//	"#..#"
//	"####"
func ParseAsciiBitmap(rows []string) (Bitmap, error) {
	var b Bitmap
	if len(rows) != Rows {
		return b, fmt.Errorf("expected %d rows, got %d", Rows, len(rows))
	}
	for r, row := range rows {
		if len(row) != Cols {
			return Bitmap{}, fmt.Errorf("row %d: expected %d columns, got %d", r, Cols, len(row))
		}
		for c := 0; c < Cols; c++ {
			switch row[c] {
			case '#':
				b[r][c] = true
			case '.':
				b[r][c] = false
			default:
				return Bitmap{}, fmt.Errorf("row %d col %d: invalid char %q (expected '#' or '.')", r, c, row[c])
			}
		}
	}
	return b, nil
}

// BitmapToAscii returns the ASCII representation of a Bitmap.
//
// 40 rows of 40 characters each, using '#' for black/1 and '.' for white/0.
// Useful for display, logging, and test-vector fixtures.
//
// WARNING: the output is equivalent to the private key the bitmap encodes.
// Treat it as a secret. Do not log in production, transmit unencrypted, etc.
func BitmapToAscii(b Bitmap) []string {
	rows := make([]string, Rows)
	for r := 0; r < Rows; r++ {
		var sb strings.Builder
		sb.Grow(Cols)
		for c := 0; c < Cols; c++ {
			if b[r][c] {
				sb.WriteByte('#')
			} else {
				sb.WriteByte('.')
			}
		}
		rows[r] = sb.String()
	}
	return rows
}

// ParsePngFileToBitmap reads a PNG file at path and converts it to a Bitmap.
//
// The PNG must be exactly 40x40 pixels. Each pixel must be either pure
// black (RGB 0,0,0) or pure white (RGB 255,255,255); any other pixel
// value returns an error citing the position and observed RGB.
//
// The alpha channel is not checked. RGBA inputs are accepted as long as
// the RGB components match the strict black/white requirement.
//
// WARNING: the file on disk encodes a private key. Ensure the file is
// stored with the same operational-security posture as any other key
// material (encrypted at rest, access-controlled, deleted after load).
func ParsePngFileToBitmap(path string) (Bitmap, error) {
	var b Bitmap
	f, err := os.Open(path)
	if err != nil {
		return b, fmt.Errorf("open png %q: %w", path, err)
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		return Bitmap{}, fmt.Errorf("decode png %q: %w", path, err)
	}

	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	if w != Cols || h != Rows {
		return Bitmap{}, fmt.Errorf("png must be exactly %dx%d pixels, got %dx%d", Cols, Rows, w, h)
	}

	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			px := img.At(bounds.Min.X+c, bounds.Min.Y+r)
			// RGBA returns 16-bit per channel scaled to [0, 65535].
			red, green, blue, _ := px.RGBA()
			r8 := red >> 8
			g8 := green >> 8
			b8 := blue >> 8
			switch {
			case r8 == 0 && g8 == 0 && b8 == 0:
				b[r][c] = true // black = 1
			case r8 == 255 && g8 == 255 && b8 == 255:
				b[r][c] = false // white = 0
			default:
				return Bitmap{}, fmt.Errorf(
					"row %d col %d: non-pure pixel (RGB %d,%d,%d); Genesis requires strict pure black/white",
					r, c, r8, g8, b8,
				)
			}
		}
	}

	return b, nil
}

// EqualBitmap reports whether two bitmaps contain identical pixels.
func EqualBitmap(a, b Bitmap) bool {
	for r := 0; r < Rows; r++ {
		for c := 0; c < Cols; c++ {
			if a[r][c] != b[r][c] {
				return false
			}
		}
	}
	return true
}
