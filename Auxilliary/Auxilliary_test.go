package Auxilliary

import "testing"

// TestCeilDiv8 is the canonical table-driven test for the bit-to-byte
// ceiling helper. It pins the contract that downstream packages depend on:
// bitmap serialization, key-derivation byte sizing, and the Schnorr
// nonce-expansion path which consumes CeilDiv8(2*S) for byte-aligned curves.
//
// The table covers four classes of input:
//   - Byte-aligned curve scalar widths (DALOS S=1600, APOLLO S=1024)
//     and their doubled forms used by the Schnorr expansion path.
//   - Non-byte-aligned curve scalar widths (LETO S=545, ARTEMIS S=1023)
//     and their doubled forms.
//   - Byte-boundary tightness (one short of and one past a byte boundary).
//   - Edges (zero bits, one bit).
//
// On mismatch we use t.Errorf so every failing case is reported in one run,
// rather than aborting at the first failure.
func TestCeilDiv8(t *testing.T) {
    cases := []struct {
        name string
        in   int
        want int
    }{
        {"DALOS_S=1600", 1600, 200},
        {"APOLLO_S=1024", 1024, 128},
        {"DALOS_doubled_S=3200", 3200, 400},
        {"APOLLO_doubled_S=2048", 2048, 256},
        {"LETO_S=545_non_aligned", 545, 69},
        {"ARTEMIS_S=1023_non_aligned", 1023, 128},
        {"LETO_doubled", 1090, 137},
        {"ARTEMIS_doubled", 2046, 256},
        {"trivial_8", 8, 1},
        {"seven_one_short_of_byte", 7, 1},
        {"nine_one_past_byte", 9, 2},
        {"edge_zero", 0, 0},
        {"edge_one", 1, 1},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if got := CeilDiv8(tc.in); got != tc.want {
                t.Errorf("CeilDiv8(%d) = %d, want %d", tc.in, got, tc.want)
            }
        })
    }
}
