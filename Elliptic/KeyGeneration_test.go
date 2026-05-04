package Elliptic

import (
    "math/big"
    "strings"
    "testing"
)

func TestConvertHashToBitString(t *testing.T) {
    cases := []struct {
        name      string
        hash      []byte
        bitLength uint32
        want      string
    }{
        {"leading_zero_byte_aligned_16", []byte{0x00, 0xFF}, 16, "0000000011111111"},
        {"leading_zeros_byte_aligned_24", []byte{0x00, 0x00, 0x01}, 24, "000000000000000000000001"},
        {"truncate_branch", []byte{0xFF, 0xFF, 0xFF, 0xFF}, 24, "111111111111111111111111"},
        {"left_pad_branch", []byte{0xAB}, 12, "000010101011"},
        {"dalos_happy_path_1600", make200ByteAllFF(), 1600, strings1600AllOnes()},
        {"leading_zero_non_byte_aligned_15", []byte{0x00, 0xAB}, 15, "000000001010101"},
        {"empty_hash_all_pad_16", []byte{}, 16, "0000000000000000"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            e := &Ellipse{S: tc.bitLength}
            got := e.ConvertHashToBitString(tc.hash)
            if got != tc.want {
                t.Errorf("ConvertHashToBitString = %q, want %q", got, tc.want)
            }
        })
    }
}

func make200ByteAllFF() []byte {
    out := make([]byte, 200)
    for i := range out {
        out[i] = 0xFF
    }
    return out
}

func strings1600AllOnes() string {
    out := make([]byte, 1600)
    for i := range out {
        out[i] = '1'
    }
    return string(out)
}

// =============================================================================
// F-ERR-003 (audit cycle 2026-05-04, v4.0.1):
// PublicKeyToAddress + AffineToPublicKey panic-on-malformed contract
// =============================================================================
//
// Pre-v4.0.1 these helpers had two latent crash/silent-corruption vectors:
//   - PublicKeyToAddress: SplitString[1] without length check → obscure
//     index-out-of-range panic; SetString(_, 49) discarded ok return →
//     malformed input silently produced a "valid-looking" wrong address.
//   - AffineToPublicKey: nil AX/AY → obscure nil-pointer-deref panic on
//     the first .String() call.
// Post-v4.0.1: explicit panic at function entry naming the offending
// field/condition. Mirrors the TS port's throws.

// TestPublicKeyToAddress_PanicsOnMissingDot pins the explicit panic for
// the no-separator case. Pre-v4.0.1 this was an obscure index-out-of-range.
func TestPublicKeyToAddress_PanicsOnMissingDot(t *testing.T) {
    defer func() {
        r := recover()
        if r == nil {
            t.Fatalf("expected panic for input with no '.' separator, got none")
        }
        msg, ok := r.(string)
        if !ok {
            t.Fatalf("expected string panic value, got %T: %v", r, r)
        }
        if !strings.Contains(msg, "PublicKeyToAddress") {
            t.Errorf("panic message should name function; got: %s", msg)
        }
        if !strings.Contains(msg, "expected exactly 1") {
            t.Errorf("panic message should describe expected separator count; got: %s", msg)
        }
    }()
    PublicKeyToAddress("no-dot-separator-anywhere")
}

// TestPublicKeyToAddress_PanicsOnMultipleDots pins symmetric rejection
// of inputs with 2+ dots (matches TS port's parts.length !== 2 throw).
func TestPublicKeyToAddress_PanicsOnMultipleDots(t *testing.T) {
    defer func() {
        if recover() == nil {
            t.Fatalf("expected panic for input with multiple '.' separators, got none")
        }
    }()
    PublicKeyToAddress("a.b.c")
}

// TestPublicKeyToAddress_PanicsOnInvalidBase49 pins the explicit panic
// when the body contains chars outside the base-49 alphabet.
func TestPublicKeyToAddress_PanicsOnInvalidBase49(t *testing.T) {
    defer func() {
        r := recover()
        if r == nil {
            t.Fatalf("expected panic for input with invalid base-49 body, got none")
        }
        msg, ok := r.(string)
        if !ok {
            t.Fatalf("expected string panic value, got %T: %v", r, r)
        }
        if !strings.Contains(msg, "malformed base-49") {
            t.Errorf("panic message should mention malformed base-49; got: %s", msg)
        }
    }()
    PublicKeyToAddress("3.abcZZZ") // 'Z' is above 'M' in the base-49 alphabet
}

// TestAffineToPublicKey_PanicsOnNilCoords pins the explicit panic for
// uninitialised CoordAffine. Pre-v4.0.1 this was an obscure nil-pointer
// dereference inside (*big.Int).String().
func TestAffineToPublicKey_PanicsOnNilCoords(t *testing.T) {
    cases := []struct {
        name string
        in   CoordAffine
    }{
        {"both_nil", CoordAffine{}},
        {"ax_nil", CoordAffine{AY: big.NewInt(1)}},
        {"ay_nil", CoordAffine{AX: big.NewInt(1)}},
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            defer func() {
                r := recover()
                if r == nil {
                    t.Fatalf("expected panic for %s, got none", c.name)
                }
                msg, ok := r.(string)
                if !ok {
                    t.Fatalf("expected string panic value, got %T: %v", r, r)
                }
                if !strings.Contains(msg, "AffineToPublicKey") {
                    t.Errorf("panic message should name function; got: %s", msg)
                }
            }()
            AffineToPublicKey(c.in)
        })
    }
}

// bs0001InputBitstring is the 1600-bit deterministic-RNG fixture from the
// frozen Genesis corpus (testvectors/v1_genesis.json, record bs-0001's
// "input_bitstring" field). Used by Schnorr_adversarial_test.go in this
// same package; the previous consumer (TestExportPrivateKey_FileCreateFailure_*)
// moved with ExportPrivateKey to ../keystore/export_test.go in Phase 10
// (REQ-31, v4.0.0) and duplicates this const there.
const bs0001InputBitstring = "0010010111000100101111000100101100000000101001110010101110010101010100010011000010000001001001111011011011000100010010001100000110001100001100101011000100000010110000111010011011110010101000010100101011111110110111101111101101101111101011110000110111000110101111000000110110100101100101011001100010010101101110011100001101100011001110110010101000111000000101111011011100100110101101001110110101010001100100100100000111011101011011010101101111110001011011111111111011010000110000111011010001111101100101101111000001010111101110111010101101001101000010001111010010100111000111101001001111111010010101111100100010110001111101111100100100001011100110101011111011101100110111100100110011100010110101011001110000011011110011100000000011111100110101101101010011110011001111001101110011001111011001111111100100011010010000001011000010001010010011010100000011111111000111111100100011001111000101101101110110100111111010010000011101101110001101110101110111101111001110101111110010011000110010101010110010001110011010010111000101100100001011100010101010111011101001111110011100000001101111111110001000001010100000010001000001010111011010001010000011011010100100110111111111111100110110110001011010001001010011001001100001001111101000111000010101000110001100011011111011100001000000111010011010100100101010100101100100111111100100100100101111101000000111111100000000100101100010011101101011011011100011011011011010010000110011001101001100110001000011101000101101011100010100111011100100110000000101101101110101111100101101011011100001000101101101000101111100000000010100010111010101011010110101000111011110001111"
