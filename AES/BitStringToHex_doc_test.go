package AES

import (
	"testing"
)

// TestBitStringToHex_DocumentedOddNibbleTruncation asserts the behavior
// documented in BitStringToHex's doc-comment (AES-4 / F-ERR-004 note):
// when the bigint(base 2) -> Text(16) conversion produces a hex string
// of odd length, hex.DecodeString returns the partial decode + ErrLength,
// the function silently discards the error, and returns the partial bytes
// (LSB half-nibble dropped).
//
// This test exists to lock the documented Genesis-format limitation: if
// any future refactor changes this behavior, this test fails — flagging
// the docstring as out-of-date and the change as a Genesis-contract break.
func TestBitStringToHex_DocumentedOddNibbleTruncation(t *testing.T) {
	// "1" -> bigint 1 -> Text(16) "1" (odd length: 1 char) -> []byte{} (empty,
	// the lone nibble is the LSB and is dropped). This is the canonical
	// odd-nibble case.
	got := BitStringToHex("1")
	if len(got) != 0 {
		t.Fatalf("BitStringToHex(\"1\"): expected empty (LSB nibble dropped per docstring), got % x", got)
	}

	// "100" -> bigint 4 -> Text(16) "4" (odd, 1 char) -> []byte{} (empty).
	got = BitStringToHex("100")
	if len(got) != 0 {
		t.Fatalf("BitStringToHex(\"100\"): expected empty (LSB nibble dropped per docstring), got % x", got)
	}

	// "100000000" -> bigint 256 -> Text(16) "100" (odd, 3 chars) ->
	// []byte{0x10} (partial decode: even prefix "10" decodes; trailing "0"
	// nibble dropped). This is the multi-byte odd-nibble confirmation that
	// matches the docstring's example.
	got = BitStringToHex("100000000")
	if len(got) != 1 || got[0] != 0x10 {
		t.Fatalf("BitStringToHex(\"100000000\"): expected [0x10] (LSB nibble dropped per docstring), got % x", got)
	}

	// "100000" -> bigint 32 -> Text(16) "20" (even length: 2 chars) -> [0x20].
	// Sanity: even-length hex path returns bytes as expected (not affected
	// by the documented edge case).
	got = BitStringToHex("100000")
	if len(got) != 1 || got[0] != 0x20 {
		t.Fatalf("BitStringToHex(\"100000\"): expected [0x20], got % x", got)
	}

	// "10000" -> bigint 16 -> Text(16) "10" (even, 2 chars) -> [0x10].
	got = BitStringToHex("10000")
	if len(got) != 1 || got[0] != 0x10 {
		t.Fatalf("BitStringToHex(\"10000\"): expected [0x10], got % x", got)
	}

	// "11111" -> bigint 31 -> Text(16) "1f" (even, 2 chars) -> [0x1f].
	// Confirms the truncation only triggers on ODD hex length.
	got = BitStringToHex("11111")
	if len(got) != 1 || got[0] != 0x1f {
		t.Fatalf("BitStringToHex(\"11111\"): expected [0x1f], got % x", got)
	}
}
