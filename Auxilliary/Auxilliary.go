package Auxilliary

import "unicode/utf8"

func TrimFirstRune(s string) string {
    _, i := utf8.DecodeRuneInString(s)
    return s[i:]
}

// CeilDiv8 returns the smallest whole number of bytes that can hold x bits.
// It implements the bit-to-byte ceiling rule: for any non-negative bit count x,
// the result is ceil(x / 8), computed branchlessly as (x + 7) / 8.
//
// WARNING to future maintainers: do NOT re-inline the floor expression x / 8
// at any callsite. The floor idiom silently truncates partial bytes (e.g. a
// 9-bit value would be reported as fitting in 1 byte), which has historically
// caused off-by-one corruption in serialization and key-derivation paths.
// Always route bit-to-byte conversions through CeilDiv8.
func CeilDiv8(x int) int {
    return (x + 7) / 8
}
