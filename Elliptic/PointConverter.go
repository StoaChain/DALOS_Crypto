package Elliptic

import (
    "fmt"
    "math/big"
)

/*
CoordAffine
Affine Coordinates are the standard(normal) X, Y Coordinates of a point on the Ellipse
*/
type CoordAffine struct {
    AX *big.Int
    AY *big.Int
}

/*
CoordExtended
Extended coordinates represent x y as X Y Z T satisfying the following equations:

  x=X/Z
  y=Y/Z
  x*y=T/Z
There are two variants of formulas,
Variant 1: Assumes Parameter A of the curve is -1,
Variant 2: Makes no Assumption
*/
type CoordExtended struct {
    EX *big.Int
    EY *big.Int
    EZ *big.Int
    ET *big.Int
}

/*
CoordInverted
Inverted coordinates represent x y as X Y Z satisfying the following equations:

  x=Z/X
  y=Z/Y
*/
type CoordInverted struct {
    IX *big.Int
    IY *big.Int
    IZ *big.Int
}

/*
CoordProjective
Projective coordinates [more information] represent x y as X Y Z satisfying the following equations:

  x=X/Z
  y=Y/Z
*/
type CoordProjective struct {
    PX *big.Int
    PY *big.Int
    PZ *big.Int
}

//Basic Modulus Operations

// AddModulus
// Addition Modulo prime
func AddModulus(prime, a, b *big.Int) *big.Int {
    var result = new(big.Int)
    return result.Add(a, b).Mod(result, prime)
}

// SubModulus
// Subtraction Modulo prime
func SubModulus(prime, a, b *big.Int) *big.Int {
    var result = new(big.Int)
    return result.Sub(a, b).Mod(result, prime)
}

// MulModulus
// Multiplication Modulo prime
func MulModulus(prime, a, b *big.Int) *big.Int {
    var result = new(big.Int)
    return result.Mul(a, b).Mod(result, prime)
}

// QuoModulus
// Division Modulo prime.
//
// PO-3 hardening (F-ERR-005 / REQ-05): when b is non-invertible mod
// prime (gcd(b, prime) != 1, e.g. b == 0), (*big.Int).ModInverse
// returns nil. Pre-fix the nil was silently fed to MulModulus,
// producing a meaningless 0 result that masked the real defect at
// the call site. Post-fix the nil triggers an explicit panic with
// operand context, mirroring the noErrAddition / noErrDoubling
// helpers at PointOperations.go:389-405. Internal programming
// errors fail fast instead of silently corrupting downstream
// arithmetic.
//
// Genesis byte-identity preserved: the 105-vector corpus generator
// never feeds a non-invertible operand here (curve prime is prime;
// generator never divides by zero), so the panic path is unreachable
// from the corpus and the happy-path return is byte-identical.
func QuoModulus(prime, a, b *big.Int) *big.Int {
    var mmi = new(big.Int)
    if mmi.ModInverse(b, prime) == nil {
        panic(fmt.Sprintf("QuoModulus: b=%v not invertible mod prime=%v", b, prime))
    }
    return MulModulus(prime, a, mmi)
}

//Coordinate Conversion Methods

func (e *Ellipse) Affine2Extended(InputP CoordAffine) (OutputP CoordExtended) {
    OutputP.EX = InputP.AX
    OutputP.EY = InputP.AY
    OutputP.EZ = One
    OutputP.ET = e.MulModP(InputP.AX, InputP.AY)
    return OutputP
}

func (e *Ellipse) Extended2Affine(InputP CoordExtended) (OutputP CoordAffine) {
    OutputP.AX = e.QuoModP(InputP.EX, InputP.EZ)
    OutputP.AY = e.QuoModP(InputP.EY, InputP.EZ)
    return OutputP
}
