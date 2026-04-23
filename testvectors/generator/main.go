// Test vector generator for the DALOS Genesis cryptographic primitive.
//
// Produces a reproducible JSON corpus of input → output pairs covering:
//   - Key generation from fixed-seeded bitstrings
//   - Key generation from seed-word lists (ASCII + Unicode)
//   - Key generation from 40×40 bitmaps (hand-designed + deterministic random)
//   - Schnorr signatures (sign + self-verify; the R-component is random
//     per Go crypto/rand so the signature bytes are NOT deterministic,
//     but the verify-to-true property is)
//
// These vectors are the oracle for the forthcoming TypeScript port:
// bit-for-bit equivalence is the correctness criterion.
//
// Usage:
//     cd DALOS_Crypto
//     go run testvectors/generator/main.go
//
// Writes: testvectors/v1_genesis.json
//
// Determinism: math/rand is seeded with fixed constants below. crypto/rand
// is used by SchnorrSign internally (random nonce), so Schnorr signature
// bytes vary per run but the verify() result is stable true.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
// See ../LICENSE for terms.

package main

import (
	bmp "DALOS_Crypto/Bitmap"
	el "DALOS_Crypto/Elliptic"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"time"
)

// --- Deterministic seeds (fixed forever; changing them invalidates vectors) ---

const (
	RNG_SEED_BITS    int64 = 0xD4105C09702 // "DALOSCRYPTO" in 0x base
	RNG_SEED_BITMAPS int64 = 0xB17A77      // "BITAPP" in 0x base
)

// --- Vector schema -------------------------------------------------------

type BitStringVector struct {
	ID              string `json:"id"`
	Source          string `json:"source"` // "deterministic-rng"
	InputBitString  string `json:"input_bitstring"`
	ScalarInt10     string `json:"scalar_int10"`
	PrivInt10       string `json:"priv_int10"`
	PrivInt49       string `json:"priv_int49"`
	PublicKey       string `json:"public_key"`
	StandardAddress string `json:"standard_address"`
	SmartAddress    string `json:"smart_address"`
}

type SeedWordsVector struct {
	ID               string   `json:"id"`
	InputWords       []string `json:"input_words"`
	DerivedBitstring string   `json:"derived_bitstring"`
	ScalarInt10      string   `json:"scalar_int10"`
	PrivInt49        string   `json:"priv_int49"`
	PublicKey        string   `json:"public_key"`
	StandardAddress  string   `json:"standard_address"`
	SmartAddress     string   `json:"smart_address"`
}

type BitmapVector struct {
	ID               string   `json:"id"`
	Pattern          string   `json:"pattern"`
	BitmapAscii      []string `json:"bitmap_ascii"` // 40 rows of "#/."; treat as secret
	DerivedBitstring string   `json:"derived_bitstring"`
	ScalarInt10      string   `json:"scalar_int10"`
	PrivInt49        string   `json:"priv_int49"`
	PublicKey        string   `json:"public_key"`
	StandardAddress  string   `json:"standard_address"`
	SmartAddress     string   `json:"smart_address"`
}

type SchnorrVector struct {
	ID             string `json:"id"`
	InputBitString string `json:"input_bitstring"`
	PrivInt49      string `json:"priv_int49"`
	PublicKey      string `json:"public_key"`
	Message        string `json:"message"`
	Signature      string `json:"signature"`       // R-point + s, non-deterministic
	VerifyExpected bool   `json:"verify_expected"` // always true for our own signatures
	VerifyActual   bool   `json:"verify_actual"`
}

type VectorCorpus struct {
	SchemaVersion    int    `json:"schema_version"`
	GeneratorVersion string `json:"generator_version"`
	Curve            string `json:"curve"`
	CurveFieldPBits  int    `json:"curve_field_p_bits"`
	CurveOrderQBits  int    `json:"curve_order_q_bits"`
	CurveCofactor    string `json:"curve_cofactor"`
	RngSeedBits      string `json:"rng_seed_bits"`
	RngSeedBitmaps   string `json:"rng_seed_bitmaps"`
	GeneratedAtUTC   string `json:"generated_at_utc"`
	Host             string `json:"host"`

	BitStringVectors []BitStringVector `json:"bitstring_vectors"`
	SeedWordsVectors []SeedWordsVector `json:"seed_words_vectors"`
	BitmapVectors    []BitmapVector    `json:"bitmap_vectors"`
	SchnorrVectors   []SchnorrVector   `json:"schnorr_vectors"`
}

// --- Bitstring generation using math/rand (deterministic) ----------------

func randomBitString(rng *mrand.Rand, length int) string {
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		if rng.Intn(2) == 0 {
			buf[i] = '0'
		} else {
			buf[i] = '1'
		}
	}
	return string(buf)
}

// --- Bitmap fixtures -----------------------------------------------------

type bitmapFixture struct {
	name string
	b    bmp.Bitmap
}

func zeroBitmap() bmp.Bitmap { // all white
	return bmp.Bitmap{}
}

func onesBitmap() bmp.Bitmap { // all black
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = true
		}
	}
	return b
}

func checkerboardBitmap() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = (r+c)%2 == 1
		}
	}
	return b
}

func invertedCheckerboard() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = (r+c)%2 == 0
		}
	}
	return b
}

func horizontalStripes() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		black := r%2 == 0
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = black
		}
	}
	return b
}

func verticalStripes() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = c%2 == 0
		}
	}
	return b
}

func border() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			if r == 0 || r == bmp.Rows-1 || c == 0 || c == bmp.Cols-1 {
				b[r][c] = true
			}
		}
	}
	return b
}

func centerCross() bmp.Bitmap {
	var b bmp.Bitmap
	midR := bmp.Rows / 2
	midC := bmp.Cols / 2
	for r := 0; r < bmp.Rows; r++ {
		b[r][midC] = true
	}
	for c := 0; c < bmp.Cols; c++ {
		b[midR][c] = true
	}
	return b
}

func topHalfBlack() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows/2; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = true
		}
	}
	return b
}

func leftHalfBlack() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols/2; c++ {
			b[r][c] = true
		}
	}
	return b
}

func diagonalTLBR() bmp.Bitmap { // top-left to bottom-right
	var b bmp.Bitmap
	for i := 0; i < bmp.Rows; i++ {
		b[i][i] = true
	}
	return b
}

func diagonalTRBL() bmp.Bitmap { // top-right to bottom-left
	var b bmp.Bitmap
	for i := 0; i < bmp.Rows; i++ {
		b[i][bmp.Cols-1-i] = true
	}
	return b
}

func centerDot() bmp.Bitmap {
	var b bmp.Bitmap
	b[bmp.Rows/2][bmp.Cols/2] = true
	return b
}

func cornersOnly() bmp.Bitmap {
	var b bmp.Bitmap
	b[0][0] = true
	b[0][bmp.Cols-1] = true
	b[bmp.Rows-1][0] = true
	b[bmp.Rows-1][bmp.Cols-1] = true
	return b
}

func quadrantBlack() bmp.Bitmap { // top-left quadrant black, others white
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows/2; r++ {
		for c := 0; c < bmp.Cols/2; c++ {
			b[r][c] = true
		}
	}
	return b
}

func concentricSquares() bmp.Bitmap {
	var b bmp.Bitmap
	// Black on ring 0, 4, 8, 12, 16; white elsewhere.
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			// ring = min distance to the edge
			ring := r
			if bmp.Rows-1-r < ring {
				ring = bmp.Rows - 1 - r
			}
			if c < ring {
				ring = c
			}
			if bmp.Cols-1-c < ring {
				ring = bmp.Cols - 1 - c
			}
			b[r][c] = ring%4 == 0
		}
	}
	return b
}

func randomBitmap(rng *mrand.Rand) bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = rng.Intn(2) == 1
		}
	}
	return b
}

// --- Seed-word fixtures --------------------------------------------------

var seedWordFixtures = [][]string{
	{"hello", "world", "dalos", "genesis"},
	{"Ouro", "Network", "Testnet"},
	{"a", "b", "c", "d", "e", "f", "g", "h"},
	{"single"},
	{"привет", "мир"},                   // Cyrillic
	{"Γειά", "σου", "κόσμε"},            // Greek
	{"café", "naïve", "façade", "über"}, // Accented Latin
	{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
	{"the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"},
	{"StoaChain", "AncientHoldings", "GmbH"},
	{"Ѻ", "Σ", "DALOS"}, // Account prefix characters themselves
	{"correct", "horse", "battery", "staple"},
	{"Mahatma", "Gandhi", "India", "1947"},
	{"Blake3", "Schnorr", "TwistedEdwards"},
	{"a", "very", "long", "seed", "phrase", "with", "many", "words", "to", "exercise", "the", "hashing"},
}

// --- Helpers -------------------------------------------------------------

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: %v\n", context, err)
		os.Exit(1)
	}
}

// --- Main generator ------------------------------------------------------

func main() {
	ellipse := el.DalosEllipse()
	rngBits := mrand.New(mrand.NewSource(RNG_SEED_BITS))
	rngBitmap := mrand.New(mrand.NewSource(RNG_SEED_BITMAPS))

	corpus := VectorCorpus{
		SchemaVersion:    1,
		GeneratorVersion: "1.2.0",
		Curve:            ellipse.Name,
		CurveFieldPBits:  1606,
		CurveOrderQBits:  1604,
		CurveCofactor:    "4",
		RngSeedBits:      fmt.Sprintf("0x%X", RNG_SEED_BITS),
		RngSeedBitmaps:   fmt.Sprintf("0x%X", RNG_SEED_BITMAPS),
		GeneratedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		Host:             "StoaChain/DALOS_Crypto test-vector generator v1.2.0",
	}

	// 1. Bitstring → keys → addresses (50 vectors)
	fmt.Fprintln(os.Stderr, "[1/4] Generating 50 bitstring vectors...")
	for i := 0; i < 50; i++ {
		bits := randomBitString(rngBits, int(ellipse.S))
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("bitstring %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("bitstring %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("bitstring %d: ScalarToKeys", i))

		stdAddr := el.DalosAddressMaker(keyPair.PUBL, false)
		smartAddr := el.DalosAddressMaker(keyPair.PUBL, true)

		corpus.BitStringVectors = append(corpus.BitStringVectors, BitStringVector{
			ID:              fmt.Sprintf("bs-%04d", i+1),
			Source:          "deterministic-rng",
			InputBitString:  bits,
			ScalarInt10:     scalar.Text(10),
			PrivInt10:       priv.Int10,
			PrivInt49:       priv.Int49,
			PublicKey:       keyPair.PUBL,
			StandardAddress: stdAddr,
			SmartAddress:    smartAddr,
		})
		if (i+1)%10 == 0 {
			fmt.Fprintf(os.Stderr, "      %d / 50\n", i+1)
		}
	}

	// 2. Seed words → keys → addresses
	fmt.Fprintln(os.Stderr, "[2/4] Generating seed-word vectors...")
	for i, words := range seedWordFixtures {
		bits := ellipse.SeedWordsToBitString(words)
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("seedwords %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToKeys", i))

		corpus.SeedWordsVectors = append(corpus.SeedWordsVectors, SeedWordsVector{
			ID:               fmt.Sprintf("sw-%04d", i+1),
			InputWords:       words,
			DerivedBitstring: bits,
			ScalarInt10:      scalar.Text(10),
			PrivInt49:        priv.Int49,
			PublicKey:        keyPair.PUBL,
			StandardAddress:  el.DalosAddressMaker(keyPair.PUBL, false),
			SmartAddress:     el.DalosAddressMaker(keyPair.PUBL, true),
		})
	}
	fmt.Fprintf(os.Stderr, "      %d fixtures\n", len(seedWordFixtures))

	// 3. Bitmap fixtures → keys → addresses
	fmt.Fprintln(os.Stderr, "[3/4] Generating bitmap vectors...")
	bitmapFixtures := []bitmapFixture{
		{"all-white (zeros)", zeroBitmap()},
		{"all-black (ones)", onesBitmap()},
		{"checkerboard-even", checkerboardBitmap()},
		{"checkerboard-odd", invertedCheckerboard()},
		{"horizontal-stripes", horizontalStripes()},
		{"vertical-stripes", verticalStripes()},
		{"border-frame", border()},
		{"center-cross", centerCross()},
		{"top-half-black", topHalfBlack()},
		{"left-half-black", leftHalfBlack()},
		{"diagonal-tl-br", diagonalTLBR()},
		{"diagonal-tr-bl", diagonalTRBL()},
		{"center-dot", centerDot()},
		{"four-corners", cornersOnly()},
		{"top-left-quadrant", quadrantBlack()},
		{"concentric-squares", concentricSquares()},
		{"random-seed-1", randomBitmap(rngBitmap)},
		{"random-seed-2", randomBitmap(rngBitmap)},
		{"random-seed-3", randomBitmap(rngBitmap)},
		{"random-seed-4", randomBitmap(rngBitmap)},
	}

	for i, fx := range bitmapFixtures {
		keyPair, err := ellipse.GenerateFromBitmap(fx.b)
		must(err, fmt.Sprintf("bitmap %s: GenerateFromBitmap", fx.name))

		bits := bmp.BitmapToBitString(fx.b)
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("bitmap %s: GenerateScalarFromBitString (cross-check)", fx.name))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("bitmap %s: ScalarToPrivateKey", fx.name))

		// Cross-check: bitmap path must produce identical keys to the bitstring
		// path fed the same bits.
		if crossCheck, err2 := ellipse.ScalarToKeys(scalar); err2 == nil {
			if crossCheck.PRIV != keyPair.PRIV || crossCheck.PUBL != keyPair.PUBL {
				fmt.Fprintf(os.Stderr, "FATAL: bitmap %s diverges from bitstring path!\n", fx.name)
				os.Exit(1)
			}
		}

		corpus.BitmapVectors = append(corpus.BitmapVectors, BitmapVector{
			ID:               fmt.Sprintf("bmp-%04d", i+1),
			Pattern:          fx.name,
			BitmapAscii:      bmp.BitmapToAscii(fx.b),
			DerivedBitstring: bits,
			ScalarInt10:      scalar.Text(10),
			PrivInt49:        priv.Int49,
			PublicKey:        keyPair.PUBL,
			StandardAddress:  el.DalosAddressMaker(keyPair.PUBL, false),
			SmartAddress:     el.DalosAddressMaker(keyPair.PUBL, true),
		})
	}
	fmt.Fprintf(os.Stderr, "      %d fixtures (16 hand-designed + 4 deterministic-random)\n", len(bitmapFixtures))

	// 4. Schnorr sign + self-verify (20 vectors)
	fmt.Fprintln(os.Stderr, "[4/4] Generating Schnorr sign+verify vectors...")
	schnorrMessages := []string{
		"",
		"Hello, Ouronet.",
		"The quick brown fox jumps over the lazy dog.",
		"Multi-line\nmessage\nwith\nnewlines",
		"Unicode: αβγδε ҶҸҽӻ 𝔸𝔹ℂ",
		"A" + string(make([]byte, 1024)), // 1 KB
	}
	for i := 0; i < 20; i++ {
		bits := randomBitString(rngBits, int(ellipse.S))
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("schnorr %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("schnorr %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("schnorr %d: ScalarToKeys", i))

		msg := schnorrMessages[i%len(schnorrMessages)]
		if i >= len(schnorrMessages) {
			msg = fmt.Sprintf("%s (iteration %d)", msg, i)
		}

		sig := ellipse.SchnorrSign(keyPair, msg)
		verifyResult := ellipse.SchnorrVerify(sig, msg, keyPair.PUBL)

		corpus.SchnorrVectors = append(corpus.SchnorrVectors, SchnorrVector{
			ID:             fmt.Sprintf("sch-%04d", i+1),
			InputBitString: bits,
			PrivInt49:      priv.Int49,
			PublicKey:      keyPair.PUBL,
			Message:        msg,
			Signature:      sig,
			VerifyExpected: true,
			VerifyActual:   verifyResult,
		})
	}
	fmt.Fprintf(os.Stderr, "      20 / 20\n")

	// Write corpus
	out, err := os.Create("testvectors/v1_genesis.json")
	must(err, "create output file")
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	err = enc.Encode(corpus)
	must(err, "json encode")

	// Summary
	totalVectors := len(corpus.BitStringVectors) +
		len(corpus.SeedWordsVectors) +
		len(corpus.BitmapVectors) +
		len(corpus.SchnorrVectors)
	schnorrPass := 0
	for _, v := range corpus.SchnorrVectors {
		if v.VerifyActual {
			schnorrPass++
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintf(os.Stderr, "  DONE. %d total vectors written to testvectors/v1_genesis.json\n", totalVectors)
	fmt.Fprintf(os.Stderr, "    %d bitstring vectors\n", len(corpus.BitStringVectors))
	fmt.Fprintf(os.Stderr, "    %d seed-words vectors\n", len(corpus.SeedWordsVectors))
	fmt.Fprintf(os.Stderr, "    %d bitmap vectors\n", len(corpus.BitmapVectors))
	fmt.Fprintf(os.Stderr, "    %d schnorr vectors\n", len(corpus.SchnorrVectors))
	fmt.Fprintf(os.Stderr, "    %d / %d schnorr signatures self-verified\n", schnorrPass, len(corpus.SchnorrVectors))
	fmt.Fprintln(os.Stderr, "=============================================================")
}
