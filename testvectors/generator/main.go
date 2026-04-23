// Test vector generator for the DALOS Genesis cryptographic primitive.
//
// Produces a reproducible JSON corpus of input → output pairs covering:
//   - Key generation from fixed-seeded bitstrings
//   - Key generation from seed-word lists (ASCII + Unicode)
//   - Key generation from integers (base 10 and base 49 representations,
//     which are already covered as by-products of the bitstring path)
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
// Determinism: math/rand is seeded with a fixed constant below. crypto/rand
// is used by SchnorrSign internally (random nonce), so Schnorr signature
// bytes vary per run but the verify() result is stable true.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
// See ../LICENSE for terms.

package main

import (
	el "DALOS_Crypto/Elliptic"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"time"
)

// --- Deterministic seed for reproducible bitstring generation ------------

const RNG_SEED int64 = 0xD4105C09702 // "DALOSCRYPTO" in 0x base

// --- Vector schema -------------------------------------------------------

type BitStringVector struct {
	ID              string `json:"id"`
	Source          string `json:"source"`      // "deterministic-rng"
	InputBitString  string `json:"input_bitstring"`
	ScalarInt10     string `json:"scalar_int10"`
	PrivInt10       string `json:"priv_int10"`
	PrivInt49       string `json:"priv_int49"`
	PublicKey       string `json:"public_key"`
	StandardAddress string `json:"standard_address"`
	SmartAddress    string `json:"smart_address"`
}

type SeedWordsVector struct {
	ID              string   `json:"id"`
	InputWords      []string `json:"input_words"`
	DerivedBitstring string   `json:"derived_bitstring"`
	ScalarInt10     string   `json:"scalar_int10"`
	PrivInt49       string   `json:"priv_int49"`
	PublicKey       string   `json:"public_key"`
	StandardAddress string   `json:"standard_address"`
	SmartAddress    string   `json:"smart_address"`
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
	SchemaVersion     int              `json:"schema_version"`
	GeneratorVersion  string           `json:"generator_version"`
	Curve             string           `json:"curve"`
	CurveFieldP_Bits  int              `json:"curve_field_p_bits"`
	CurveOrderQ_Bits  int              `json:"curve_order_q_bits"`
	CurveCofactor     string           `json:"curve_cofactor"`
	RngSeed           string           `json:"rng_seed"`
	GeneratedAtUTC    string           `json:"generated_at_utc"`
	Host              string           `json:"host"`
	BitStringVectors  []BitStringVector  `json:"bitstring_vectors"`
	SeedWordsVectors  []SeedWordsVector  `json:"seed_words_vectors"`
	SchnorrVectors    []SchnorrVector    `json:"schnorr_vectors"`
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

// --- Seed-word fixtures --------------------------------------------------

// Mix of ASCII, Unicode (Cyrillic, Greek, accented Latin), various lengths.
// These stress-test the UTF-8 + Blake3 pipeline.
var seedWordFixtures = [][]string{
	{"hello", "world", "dalos", "genesis"},
	{"Ouro", "Network", "Testnet"},
	{"a", "b", "c", "d", "e", "f", "g", "h"},
	{"single"},
	{"привет", "мир"},                           // Cyrillic
	{"Γειά", "σου", "κόσμε"},                    // Greek
	{"café", "naïve", "façade", "über"},         // Accented Latin
	{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
	{"the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"},
	{"StoaChain", "AncientHoldings", "GmbH"},
	{"Ѻ", "Σ", "DALOS"},                         // Account prefix characters themselves
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
	rng := mrand.New(mrand.NewSource(RNG_SEED))

	corpus := VectorCorpus{
		SchemaVersion:    1,
		GeneratorVersion: "1.0.0",
		Curve:            ellipse.Name,
		CurveFieldP_Bits: 1606,
		CurveOrderQ_Bits: 1604,
		CurveCofactor:    "4",
		RngSeed:          fmt.Sprintf("0x%X", RNG_SEED),
		GeneratedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		Host:             "StoaChain/DALOS_Crypto test-vector generator v1.0.0",
	}

	// 1. Bitstring → keys → addresses (50 vectors)
	fmt.Fprintln(os.Stderr, "[1/3] Generating 50 bitstring vectors...")
	for i := 0; i < 50; i++ {
		bits := randomBitString(rng, int(ellipse.S))
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

	// 2. Seed words → keys → addresses (one per fixture + a few derived)
	fmt.Fprintln(os.Stderr, "[2/3] Generating seed-word vectors...")
	for i, words := range seedWordFixtures {
		bits := ellipse.SeedWordsToBitString(words)
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("seedwords %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToKeys", i))

		corpus.SeedWordsVectors = append(corpus.SeedWordsVectors, SeedWordsVector{
			ID:              fmt.Sprintf("sw-%04d", i+1),
			InputWords:      words,
			DerivedBitstring: bits,
			ScalarInt10:     scalar.Text(10),
			PrivInt49:       priv.Int49,
			PublicKey:       keyPair.PUBL,
			StandardAddress: el.DalosAddressMaker(keyPair.PUBL, false),
			SmartAddress:    el.DalosAddressMaker(keyPair.PUBL, true),
		})
	}
	fmt.Fprintf(os.Stderr, "      %d fixtures\n", len(seedWordFixtures))

	// 3. Schnorr sign + self-verify (20 vectors)
	fmt.Fprintln(os.Stderr, "[3/3] Generating Schnorr sign+verify vectors...")
	schnorrMessages := []string{
		"",
		"Hello, Ouronet.",
		"The quick brown fox jumps over the lazy dog.",
		"Multi-line\nmessage\nwith\nnewlines",
		"Unicode: αβγδε ҶҸҽӻ 𝔸𝔹ℂ",
		"A" + string(make([]byte, 1024)), // 1 KB
	}
	for i := 0; i < 20; i++ {
		bits := randomBitString(rng, int(ellipse.S))
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
	totalVectors := len(corpus.BitStringVectors) + len(corpus.SeedWordsVectors) + len(corpus.SchnorrVectors)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintf(os.Stderr, "  DONE. %d total vectors written to testvectors/v1_genesis.json\n", totalVectors)
	fmt.Fprintf(os.Stderr, "    %d bitstring vectors\n", len(corpus.BitStringVectors))
	fmt.Fprintf(os.Stderr, "    %d seed-words vectors\n", len(corpus.SeedWordsVectors))
	fmt.Fprintf(os.Stderr, "    %d schnorr vectors\n", len(corpus.SchnorrVectors))
	// Schnorr self-verify sanity check
	schnorrPass := 0
	for _, v := range corpus.SchnorrVectors {
		if v.VerifyActual {
			schnorrPass++
		}
	}
	fmt.Fprintf(os.Stderr, "    %d / %d schnorr signatures self-verified\n", schnorrPass, len(corpus.SchnorrVectors))
	fmt.Fprintln(os.Stderr, "=============================================================")
}
