package Elliptic

import (
    aux "DALOS_Crypto/Auxilliary"
    "testing"
)

// TestXCurveCeilDivByteSizing pins the post-edit invariant for the three
// XCURVE-{1,2,3} call sites:
//
//   Schnorr.go        SchnorrHash         outputSize    = aux.CeilDiv8(int(e.S))
//   Schnorr.go        deterministicNonce  expansionSize = aux.CeilDiv8(2 * int(e.S))
//   KeyGeneration.go  SeedWordsToBitString OutputSize   = aux.CeilDiv8(int(e.S))
//
// For byte-aligned curves (DALOS S=1600, APOLLO S=1024) the ceil and floor
// idioms agree. For non-byte-aligned curves (LETO S=545, ARTEMIS S=1023)
// the floor idiom truncates, returning a byte-count one short of what is
// actually needed to hold every bit of the safe-scalar — the exact bug
// XCURVE-1/2/3 closes.
func TestXCurveCeilDivByteSizing(t *testing.T) {
    cases := []struct {
        name              string
        sBits             uint32
        wantSingle        int
        wantDoubled       int
        floorAgreesSingle bool
        floorAgreesDouble bool
    }{
        {"DALOS_byte_aligned", 1600, 200, 400, true, true},
        {"APOLLO_byte_aligned", 1024, 128, 256, true, true},
        {"LETO_non_aligned", 545, 69, 137, false, false},
        {"ARTEMIS_non_aligned", 1023, 128, 256, false, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            singleCeil := aux.CeilDiv8(int(tc.sBits))
            doubleCeil := aux.CeilDiv8(2 * int(tc.sBits))
            singleFloor := int(tc.sBits) / 8
            doubleFloor := 2 * int(tc.sBits) / 8

            if singleCeil != tc.wantSingle {
                t.Errorf("aux.CeilDiv8(int(S=%d)) = %d, want %d", tc.sBits, singleCeil, tc.wantSingle)
            }
            if doubleCeil != tc.wantDoubled {
                t.Errorf("aux.CeilDiv8(2*int(S=%d)) = %d, want %d", tc.sBits, doubleCeil, tc.wantDoubled)
            }

            if (singleCeil == singleFloor) != tc.floorAgreesSingle {
                t.Errorf("S=%d: floor==ceil expected %v, got ceil=%d floor=%d",
                    tc.sBits, tc.floorAgreesSingle, singleCeil, singleFloor)
            }
            if (doubleCeil == doubleFloor) != tc.floorAgreesDouble {
                t.Errorf("2*S=%d: floor==ceil expected %v, got ceil=%d floor=%d",
                    2*tc.sBits, tc.floorAgreesDouble, doubleCeil, doubleFloor)
            }

            if !tc.floorAgreesSingle && singleCeil <= singleFloor {
                t.Errorf("S=%d non-aligned: ceil(%d) must exceed floor(%d) — XCURVE-{1,3} regression",
                    tc.sBits, singleCeil, singleFloor)
            }
            if !tc.floorAgreesDouble && doubleCeil <= doubleFloor {
                t.Errorf("2*S=%d non-aligned: ceil(%d) must exceed floor(%d) — XCURVE-2 regression",
                    2*tc.sBits, doubleCeil, doubleFloor)
            }
        })
    }
}
