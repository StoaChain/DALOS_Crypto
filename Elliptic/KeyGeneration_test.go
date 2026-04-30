package Elliptic

import "testing"

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
