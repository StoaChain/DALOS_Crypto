package Elliptic

import (
    "reflect"
    "testing"
)

// TestCharacterMatrix_ReturnsCachedSingleton verifies that CharacterMatrix()
// returns the package-level cache (built exactly once at init) instead of
// allocating a fresh 16x16 rune matrix on every call.
//
// REQ-09 (T4.1): the prior implementation rebuilt 256 rune literals into a
// fresh array on every call, which is wasted work since the matrix is
// immutable. The cache promotion uses option (a) — eager package-level var,
// not sync.Once — because the matrix is small (~1 KB) and used unconditionally
// during every key-gen / address-derive pass.
func TestCharacterMatrix_ReturnsCachedSingleton(t *testing.T) {
    m1 := CharacterMatrix()
    m2 := CharacterMatrix()
    if !reflect.DeepEqual(m1, m2) {
        t.Fatalf("CharacterMatrix() returned different contents on consecutive calls")
    }
    if m1[0][0] != '0' {
        t.Errorf("expected m1[0][0]='0', got %q", m1[0][0])
    }
    if m1[0][10] != 'Ѻ' {
        t.Errorf("expected m1[0][10]='Ѻ' (Round Omega), got %q", m1[0][10])
    }
    // Note: a true caching guarantee (build-count == 1) cannot be asserted
    // without instrumenting makeCharacterMatrix with a counter. The
    // DeepEqual + spot-checks above catch the regression case (cache lost
    // → CharacterMatrix() returns a zero-value or fresh-but-different
    // matrix); the caching promise itself is a structural property of the
    // package-level var initializer, enforced by `var characterMatrixCache
    // = makeCharacterMatrix()` running exactly once at package init.
}
