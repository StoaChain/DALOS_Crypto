package Blake3

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// =============================================================================
// F-MED-012 (audit cycle 2026-05-04, v4.0.2): Blake3 package test suite.
// =============================================================================
//
// Pre-v4.0.2 the Blake3/ package had ZERO direct tests. Correctness was
// gated only by the 105-vector Genesis corpus byte-identity check —
// every Blake3 invocation in the production code path feeds into that
// corpus, so a bit-flip in the round function that happened to perturb
// even one corpus output would be caught. But a subtle round-function
// regression that JUST happens to preserve all 105 corpus outputs (e.g.,
// a swap that cancels out for the specific input set, or a regression
// in a code path the corpus doesn't exercise) would slip through
// undetected.
//
// This file closes that gap by combining two complementary strategies:
//
//   1. KAT (Known-Answer Test) lock for the empty-input hash. The
//      empty-input BLAKE3 256-bit output is universally documented in
//      every BLAKE3 reference (RFC, official test_vectors.json, Wikipedia,
//      every spec document). Any change to the round function or the
//      flag/key/counter-handling for empty input flips this constant —
//      catches the broadest class of round-function regressions.
//
//   2. Internal consistency / cross-path equivalence tests. The package
//      has THREE distinct fast paths inside Sum512:
//        - len <= blockSize (64): direct hashBlock
//        - len <= chunkSize (1024): single compressChunk
//        - len > chunkSize: full Hasher.Write + rootNode pipeline
//      And SEVERAL output paths: Sum256, Sum512, Sum1024, SumCustom,
//      and the streaming Hasher.Write / Hasher.Sum / Hasher.XOF surface.
//      Each of these MUST agree with the others on overlapping inputs.
//      Catches regressions where one path drifts from another even if
//      the Genesis corpus happens to use only one of them.
//
// Anti-circular note: these tests intentionally do NOT depend on the
// Genesis corpus or any other Blake3 invocation in the codebase — they
// hash known-shape inputs and assert against either hardcoded constants
// or other paths in this same package. If the round function regresses,
// the cross-path tests will diverge regardless of whether the corpus
// inputs happen to perturb it.
//
// Adding new KAT vectors: pull from
// https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
// — the input format is `bytes[i] = i % 251` for the given length, and
// the truncated 32-byte hash is the first 64 hex characters of the
// "hash" field. Extending the KATs to cover more input lengths is a
// safe additive change.

// kat0Empty is the universally-documented BLAKE3-256 hash of the empty
// input. Hardcoded from BLAKE3-team/BLAKE3 test_vectors.json (input_len=0,
// first 64 hex chars of the "hash" field). Any change to the unkeyed
// flag, IV, or root-finalization logic perturbs this constant.
const kat0Empty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"

// patternInput returns the BLAKE3 KAT-style input pattern: bytes[i] = i % 251.
// Used by the cross-path consistency tests so they exercise the same input
// shape that the official KAT generator uses.
func patternInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// TestSum256_KATEmpty locks the canonical empty-input KAT. Catches the
// broadest class of round-function / IV / flag-handling regressions.
func TestSum256_KATEmpty(t *testing.T) {
	got := Sum256(nil)
	want, err := hex.DecodeString(kat0Empty)
	if err != nil {
		t.Fatalf("test setup: bad KAT hex: %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("Sum256(nil) drift:\n  got:  %x\n  want: %x\n  This indicates a regression in the unkeyed empty-input path. Verify the round function, IV, and root-finalization flag handling.", got, want)
	}

	// Also exercise the empty-input path through the streaming surface
	// to catch divergence between the fast path and the Hasher path.
	h := New(32, nil)
	out := h.Sum(nil)
	if !bytes.Equal(out, want) {
		t.Fatalf("Hasher.Sum(empty) diverges from Sum256(nil):\n  Hasher: %x\n  Sum256: %x", out, want)
	}
}

// TestSum256_TruncatesSum512 locks the documented invariant in Sum256's
// implementation: Sum256(b) is byte-for-byte the first 32 bytes of
// Sum512(b). Trivial today (Sum256 calls Sum512 + copy), but the test
// guards against any future "optimization" that computes Sum256
// independently and accidentally diverges. Run across all three internal
// size paths.
func TestSum256_TruncatesSum512(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"single-block-mid", 32},                 // < blockSize
		{"single-block-boundary", blockSize},     // == blockSize
		{"single-block-plus-one", blockSize + 1}, // > blockSize, < chunkSize
		{"single-chunk-mid", 512},                // mid-chunk
		{"single-chunk-boundary", chunkSize},     // == chunkSize boundary
		{"multi-chunk-plus-one", chunkSize + 1},  // > chunkSize, exercises Hasher path
		{"multi-chunk-large", 5000},              // multi-chunk
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := patternInput(tc.n)
			s256 := Sum256(b)
			s512 := Sum512(b)
			if !bytes.Equal(s256[:], s512[:32]) {
				t.Fatalf("Sum256 != Sum512[:32] for len=%d:\n  Sum256:     %x\n  Sum512[:32]: %x", tc.n, s256, s512[:32])
			}
		})
	}
}

// TestSumCustom_AgreesWithFixedSizes locks SumCustom against the fixed-
// size convenience wrappers. SumCustom(b, 32) must equal Sum256(b);
// SumCustom(b, 64) must equal Sum512(b); SumCustom(b, 128) must equal
// Sum1024(b). All three exercise the same New(size).Write.Sum pipeline
// internally, but the wrappers have their own fast paths — divergence
// here would indicate a bug in either the wrappers or the variable-
// output path.
func TestSumCustom_AgreesWithFixedSizes(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"sub-block", 32},
		{"chunk-boundary", chunkSize},
		{"multi-chunk", 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := patternInput(tc.n)

			s256 := Sum256(b)
			c32 := SumCustom(b, 32)
			if !bytes.Equal(s256[:], c32) {
				t.Fatalf("SumCustom(b, 32) != Sum256(b) for len=%d:\n  custom: %x\n  Sum256: %x", tc.n, c32, s256)
			}

			s512 := Sum512(b)
			c64 := SumCustom(b, 64)
			if !bytes.Equal(s512[:], c64) {
				t.Fatalf("SumCustom(b, 64) != Sum512(b) for len=%d:\n  custom: %x\n  Sum512: %x", tc.n, c64, s512)
			}

			s1024 := Sum1024(b)
			c128 := SumCustom(b, 128)
			if !bytes.Equal(s1024[:], c128) {
				t.Fatalf("SumCustom(b, 128) != Sum1024(b) for len=%d:\n  custom: %x\n  Sum1024: %x", tc.n, c128, s1024)
			}
		})
	}
}

// TestXOF_FirstBytesAgreeWithSum512 locks the contract that the XOF
// output starting at counter=0 is byte-identical to Sum512 for the first
// 64 bytes (and to Sum256 for the first 32). This is fundamental to
// BLAKE3 — Sum256/Sum512 are defined as truncations of the XOF — so any
// drift indicates a bug in either the hashing finalization or the XOF
// reader's counter init.
func TestXOF_FirstBytesAgreeWithSum512(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"sub-block", 16},
		{"chunk-boundary", chunkSize},
		{"multi-chunk", 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := patternInput(tc.n)
			s512 := Sum512(b)

			h := New(64, nil)
			h.Write(b)
			xof := h.XOF()
			buf := make([]byte, 64)
			n, err := xof.Read(buf)
			if err != nil || n != 64 {
				t.Fatalf("XOF.Read(64): got n=%d err=%v", n, err)
			}
			if !bytes.Equal(buf, s512[:]) {
				t.Fatalf("XOF first 64 bytes != Sum512 for len=%d:\n  XOF:    %x\n  Sum512: %x", tc.n, buf, s512)
			}
		})
	}
}

// TestHasher_IncrementalEqualsSingleWrite locks the io.Writer contract:
// streaming the input via multiple Write calls must produce the same
// digest as a single Write of the concatenation. Bug class caught:
// internal buffer/state corruption between Write calls (e.g., chunk
// boundary off-by-one, residual bytes mishandled).
func TestHasher_IncrementalEqualsSingleWrite(t *testing.T) {
	// Pick an input that straddles 2+ chunk boundaries and an awkward
	// split-point that doesn't align with blockSize or chunkSize.
	b := patternInput(3000) // >= 2 chunks (each 1024 bytes)
	splits := []int{1, 7, 63, 64, 65, 1023, 1024, 1025, 1500} // various boundaries

	// Single-write reference.
	hRef := New(32, nil)
	hRef.Write(b)
	ref := hRef.Sum(nil)

	for _, split := range splits {
		t.Run("split-at-"+itoa(split), func(t *testing.T) {
			h := New(32, nil)
			h.Write(b[:split])
			h.Write(b[split:])
			got := h.Sum(nil)
			if !bytes.Equal(got, ref) {
				t.Fatalf("incremental write at split=%d diverges from single write:\n  got: %x\n  ref: %x", split, got, ref)
			}
		})
	}
}

// TestHasher_SumIsIdempotent locks the contract that calling Sum twice
// on the same Hasher returns the same value. Sum should not mutate the
// internal state. Bug class caught: rootNode() accidentally consuming
// the buffer or advancing internal counters on each call.
func TestHasher_SumIsIdempotent(t *testing.T) {
	h := New(32, nil)
	h.Write(patternInput(500))
	first := h.Sum(nil)
	second := h.Sum(nil)
	if !bytes.Equal(first, second) {
		t.Fatalf("Hasher.Sum is not idempotent:\n  first:  %x\n  second: %x", first, second)
	}
}

// TestKeyedHash_DiffersFromUnkeyed locks that supplying a 32-byte key
// changes the output. Bug class caught: the key being silently ignored,
// or the keyed-hash flag not being set. Without this, an attacker
// substituting a keyed-hash KDF for an unkeyed one could collide.
func TestKeyedHash_DiffersFromUnkeyed(t *testing.T) {
	b := patternInput(100)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x55) // arbitrary non-zero key
	}

	unkeyed := New(32, nil)
	unkeyed.Write(b)
	uk := unkeyed.Sum(nil)

	keyed := New(32, key)
	keyed.Write(b)
	kd := keyed.Sum(nil)

	if bytes.Equal(uk, kd) {
		t.Fatalf("keyed hash output equals unkeyed hash — key is being ignored!\n  output: %x", uk)
	}

	// Also lock that two DIFFERENT keys produce different outputs (would
	// catch a key being silently zeroed).
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(0xAA)
	}
	keyed2 := New(32, key2)
	keyed2.Write(b)
	kd2 := keyed2.Sum(nil)

	if bytes.Equal(kd, kd2) {
		t.Fatalf("keyed hashes with DIFFERENT keys produced same output:\n  key1 out: %x\n  key2 out: %x", kd, kd2)
	}
}

// TestSizeBoundaries_DistinctOutputs locks that inputs at adjacent size
// boundaries produce DIFFERENT outputs. Specifically: empty vs len=1,
// blockSize vs blockSize+1, chunkSize vs chunkSize+1. Bug class caught:
// the size-path dispatch silently sending same-shape inputs through the
// same code path with the same output (would be catastrophic for any
// hash function).
func TestSizeBoundaries_DistinctOutputs(t *testing.T) {
	pairs := []struct {
		name string
		n1   int
		n2   int
	}{
		{"empty-vs-1byte", 0, 1},
		{"block-boundary", blockSize, blockSize + 1},
		{"chunk-boundary", chunkSize, chunkSize + 1},
		{"sub-block-vs-chunk", 32, chunkSize},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			h1 := Sum256(patternInput(p.n1))
			h2 := Sum256(patternInput(p.n2))
			if bytes.Equal(h1[:], h2[:]) {
				t.Fatalf("Sum256(len=%d) == Sum256(len=%d) — size-path collision!\n  h1: %x\n  h2: %x", p.n1, p.n2, h1, h2)
			}
		})
	}
}

// itoa is a small int-to-string helper used in subtest names. Avoids
// pulling strconv just for test naming.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
