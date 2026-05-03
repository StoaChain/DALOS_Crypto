package Elliptic

import (
	"math/big"
	"regexp"
	"testing"
)

// TestQuoModulus_* are the regression guard for the F-ERR-005 / REQ-05
// adoption of the PO-3 noErr-helper panic pattern in QuoModulus.
//
// Pre-fix: QuoModulus called (*big.Int).ModInverse(b, prime) and ignored
// its nil return. When b was non-invertible mod prime (e.g. b == 0, or
// gcd(b, prime) != 1), mmi was left as the zero big.Int and silently
// fed to MulModulus, producing a meaningless 0 result that masked the
// real defect at the call site. Worse, future refactors that reuse
// QuoModulus on attacker-influenced operands would inherit the silent
// failure mode.
//
// Post-fix: the nil return from ModInverse triggers an explicit panic
// with a diagnostic message, mirroring the PO-3 noErrAddition /
// noErrDoubling helpers at PointOperations.go:389-405. Internal
// programming errors fail fast with full operand context instead of
// silently corrupting downstream arithmetic.
//
// Genesis byte-identity is preserved: the 105-vector corpus generator
// never feeds a non-invertible operand to QuoModulus (the curve prime
// is, well, prime, and the generator never divides by zero). The panic
// path is therefore unreachable from the corpus — and the happy path
// is asserted byte-identical by Test 3 below.
func TestQuoModulus_NonInvertibleInput_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on QuoModulus(prime, a, 0), got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic value to be a string, got %T: %v", r, r)
		}
		if !regexp.MustCompile(`QuoModulus.*not invertible`).MatchString(msg) {
			t.Errorf("panic message %q does not match expected pattern `QuoModulus.*not invertible`", msg)
		}
	}()
	prime := big.NewInt(7)
	a := big.NewInt(3)
	// b == 0 is the canonical non-invertible case: gcd(0, prime) == prime != 1
	// for any prime > 1, so (*big.Int).ModInverse(0, prime) returns nil.
	QuoModulus(prime, a, big.NewInt(0))
	t.Fatalf("unreachable — QuoModulus must have panicked on non-invertible b")
}

// TestQuoModulus_NilB_Panics pins the panic shape for b == nil.
//
// Per the math/big contract, (*big.Int).ModInverse(nil, prime) panics
// with a runtime nil-pointer-dereference BEFORE the QuoModulus guard
// gets a chance to fire. The QuoModulus-level guard cannot catch this
// case because it cannot distinguish between "ModInverse returned nil"
// and "ModInverse never returned because the receiver dereferenced a
// nil argument". So this test asserts only that *some* panic occurs;
// the specific runtime message is observed empirically and pinned in
// the regex below to catch any future change in math/big behaviour.
func TestQuoModulus_NilB_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on QuoModulus(prime, a, nil), got none")
		}
		// The runtime delivers a *runtime.Error (specifically a
		// runtime.Error implementing error) for nil-pointer derefs.
		// We accept either a string panic value (if math/big ever
		// switches to fmt.Sprintf-style panics) or a runtime error
		// whose String contains "nil pointer".
		var msg string
		switch v := r.(type) {
		case string:
			msg = v
		case error:
			msg = v.Error()
		default:
			t.Fatalf("expected panic value to be string or error, got %T: %v", r, r)
		}
		if !regexp.MustCompile(`(?i)nil pointer|invalid memory|QuoModulus.*not invertible`).MatchString(msg) {
			t.Errorf("panic message %q does not match expected pattern (nil-pointer-deref or QuoModulus guard)", msg)
		}
	}()
	prime := big.NewInt(7)
	a := big.NewInt(3)
	QuoModulus(prime, a, nil)
	t.Fatalf("unreachable — QuoModulus must have panicked on nil b")
}

// TestQuoModulus_BEqualsModulus_Panics extends the non-invertible
// coverage from b==0 to b==prime. gcd(prime, prime) == prime != 1, so
// (*big.Int).ModInverse(prime, prime) returns nil and the new guard
// fires. Without this case, a future refactor that special-cased the
// b==0 path (e.g., `if b.Sign() == 0 { panic }` instead of relying on
// ModInverse's nil sentinel) would silently drop coverage of the
// broader "non-invertible" contract while still passing Test 1.
// Same defensive intent as TestQuoModulus_NonInvertibleInput_Panics
// but exercises a different representative member of the class.
func TestQuoModulus_BEqualsModulus_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on QuoModulus(prime, a, prime), got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic value to be a string, got %T: %v", r, r)
		}
		if !regexp.MustCompile(`QuoModulus.*not invertible`).MatchString(msg) {
			t.Errorf("panic message %q does not match expected pattern `QuoModulus.*not invertible`", msg)
		}
	}()
	prime := big.NewInt(7)
	a := big.NewInt(3)
	// b == prime: gcd(prime, prime) == prime != 1, non-invertible.
	QuoModulus(prime, a, big.NewInt(7))
	t.Fatalf("unreachable — QuoModulus must have panicked on b == prime")
}

// TestQuoModulus_HappyPath_PreservedBehavior pins the happy-path
// output to its pre-edit value, ensuring the new nil-guard does not
// perturb the byte-identical Genesis-corpus arithmetic.
//
// 2^-1 mod 7 == 4  (since 2*4 == 8 == 1 mod 7)
// QuoModulus(7, 3, 2) == (3 * 4) mod 7 == 12 mod 7 == 5
func TestQuoModulus_HappyPath_PreservedBehavior(t *testing.T) {
	prime := big.NewInt(7)
	a := big.NewInt(3)
	b := big.NewInt(2)
	got := QuoModulus(prime, a, b)
	want := big.NewInt(5)
	if got.Cmp(want) != 0 {
		t.Errorf("QuoModulus(7, 3, 2) = %v, want %v (Genesis byte-identity violated)", got, want)
	}
}
