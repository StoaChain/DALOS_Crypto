package Elliptic

import (
    "errors"
    "fmt"
    "math/big"
)

type EllipseMethods interface {
    // I - Mod P Methods
    AddModP(a, b *big.Int) *big.Int // Ia.1
    SubModP(a, b *big.Int) *big.Int // Ia.2
    MulModP(a, b *big.Int) *big.Int // Ia.3
    QuoModP(a, b *big.Int) *big.Int // Ia.4
    
    // II - Coordinate Conversion
    Affine2Extended(InputP CoordAffine) (OutputP CoordExtended)
    Extended2Affine(InputP CoordExtended) (OutputP CoordAffine)
    
    // III Boolean Methods
    IsInfinityPoint(InputP CoordExtended) bool
    IsOnCurve(InputP CoordExtended) (OnCurve bool, Infinity bool)
    IsInverseOnCurve(P1, P2 CoordExtended) bool
    ArePointsEqual(P1, P2 CoordExtended) bool
    
    // IV Basic Operations
    Addition(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV1(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV2(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV3(P1, P2 CoordExtended) (CoordExtended, error)
    Doubling(P CoordExtended) (CoordExtended, error)
    DoublingV1(P CoordExtended) (CoordExtended, error)
    DoublingV2(P CoordExtended) (CoordExtended, error)
    Tripling(P CoordExtended) CoordExtended
    
    // V Complex Operations
    FortyNiner(P CoordExtended) CoordExtended
    PrecomputeMatrixWithGenerator() [7][7]CoordExtended
    PrecomputeMatrix(P CoordExtended) [7][7]CoordExtended
    ScalarMultiplierWithGenerator(Scalar *big.Int) CoordExtended
    ScalarMultiplier(Scalar *big.Int, P CoordExtended) CoordExtended
    
    // VI Key Generation
    GenerateRandomBitsOnCurve() string
    SeedWordsToBitString(SeedWords []string) string
    ConvertHashToBitString(Hash []byte) string
    ValidateBitString(BitString string) (bool, bool, bool)
    ValidatePrivateKey(privateKey string, isBase10 bool) (bool, string)
    GenerateScalarFromBitString(BitString string) (*big.Int, error)
    ScalarToKeys(Scalar *big.Int) (DalosKeyPair, error)
    ScalarToPrivateKey(Scalar *big.Int) (DalosPrivateKey, error)
    ScalarToPublicKey(Scalar *big.Int) string
    
    // VII Key Processing
    ProcessIntegerFlag(flagValue string, isBase10 bool)
    ProcessPrivateKeyConversion(BitString string)
    ProcessKeyGeneration(BitString string, smartFlag *bool, password string)
    SaveBitString(BitString string, Password string)
    ExportPrivateKey(BitString, Password string)
    
    // VIII Schnorr Signature
    SchnorrHash(R *big.Int, PublicKey string, Message string) *big.Int
    SchnorrSign(KeyPair DalosKeyPair, Message string) string
    SchnorrVerify(Signature, PublicKey, Message string) bool
}

func (e *Ellipse) AddModP(a, b *big.Int) *big.Int {
    return AddModulus(&e.P, a, b)
}
func (e *Ellipse) SubModP(a, b *big.Int) *big.Int {
    return SubModulus(&e.P, a, b)
}
func (e *Ellipse) MulModP(a, b *big.Int) *big.Int {
    return MulModulus(&e.P, a, b)
}
func (e *Ellipse) QuoModP(a, b *big.Int) *big.Int {
    return QuoModulus(&e.P, a, b)
}

// III Boolean Methods
func (e *Ellipse) IsInfinityPoint(InputP CoordExtended) bool {
    Cmp1 := InputP.EX.Cmp(Zero)
    Cmp2 := InputP.ET.Cmp(Zero)
    Cmp3 := InputP.EY.Cmp(InputP.EZ)
    return Cmp1 == 0 && Cmp2 == 0 && Cmp3 == 0
}

func (e *Ellipse) IsOnCurve(InputP CoordExtended) (OnCurve bool, Infinity bool) {
    var (
        PointAffine = e.Extended2Affine(InputP)
        A           = new(big.Int)
        B           = new(big.Int)
    )
    
    if e.IsInfinityPoint(InputP) == true {
        Infinity = true
    } else {
        Infinity = false
    }
    
    //Left Member Construction
    //x^2
    A.Exp(PointAffine.AX, Two, &e.P)
    //y^2
    B.Exp(PointAffine.AY, Two, &e.P)
    //Left member (x^2 + y^2)
    Left := e.AddModP(A, B)
    
    //Right Member Construction
    //C is x^2 * y^2
    C := e.MulModP(A, B)
    //D is C multiplied by the D Coefficient of the Ellipse
    D := e.MulModP(C, &e.D)
    //Right member is D + 1
    Right := e.AddModP(One, D)
    
    //Now we compare Left and Right
    CompareResult := Left.Cmp(Right)
    if CompareResult == 0 {
        OnCurve = true
    } else {
        OnCurve = false
    }
    return OnCurve, Infinity
}

func (e *Ellipse) IsInverseOnCurve(P1, P2 CoordExtended) bool {
    //The inverse of a point
    //(x1, y1) on E is (−x1, y1).
    P1Affine := e.Extended2Affine(P1)
    P2Affine := e.Extended2Affine(P2)
    
    var SummedX = new(big.Int)
    SummedX.Add(P1Affine.AX, P2Affine.AX)
    Cmp1 := SummedX.Cmp(Zero)
    Cmp2 := P1Affine.AY.Cmp(P2Affine.AY)
    
    return Cmp1 == 0 && Cmp2 == 0
}

func (e *Ellipse) ArePointsEqual(P1, P2 CoordExtended) bool {
    P1Affine := e.Extended2Affine(P1)
    P2Affine := e.Extended2Affine(P2)
    return P1Affine.AX.Cmp(P2Affine.AX) == 0 && P1Affine.AY.Cmp(P2Affine.AY) == 0
}

//Basic Point Operations

//Addition on Extended Coordinates of TEC, with no assumption that a=-1(which it isn't)
func (e *Ellipse) Addition(P1, P2 CoordExtended) (CoordExtended, error) {
    // Check if both Z1 and Z2 are 1
    var (
        Output CoordExtended
        err    error
    )
    if P1.EZ.Cmp(One) == 0 && P2.EZ.Cmp(One) == 0 {
        // Variant 1: If both Z1 and Z2 are 1
        Output, err = e.AdditionV1(P1, P2) // Uses "mmadd-2008-hwcd-2" addition formulas
        return Output, err
    } else if P2.EZ.Cmp(One) == 0 {
        // Variant 2: If Z2 is 1, but Z1 is not
        Output, err = e.AdditionV2(P1, P2) // Uses "madd-2008-hwcd-2" addition formulas
        return Output, err
    } else {
        // Variant 3: If both Z1 and Z2 are different from 1
        Output, err = e.AdditionV3(P1, P2) // Uses "add-2008-hwcd-2" addition formulas
        return Output, err
    }
}
func (e *Ellipse) AdditionV1(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/mmadd-2008-hwcd
    
    // Declare result point
    var Output CoordExtended
    // Verify that both Z1 and Z2 are 1
    if P1.EZ.Cmp(One) != 0 || P2.EZ.Cmp(One) != 0 {
        return Output, fmt.Errorf("AdditionV1 requires both Z1 and Z2 to be 1")
    }
    // Addition logic for the case when Z1 = 1 and Z2 = 1 (mmadd-2008-hwcd)
    A := e.MulModP(P1.EX, P2.EX)                  // A = X1 * X2
    B := e.MulModP(P1.EY, P2.EY)                  // B = Y1 * Y2
    C := e.MulModP(P1.ET, e.MulModP(&e.D, P2.ET)) // C = T1 * d * T2
    v1 := e.AddModP(P1.EX, P1.EY)
    v2 := e.AddModP(P2.EX, P2.EY)
    v3 := e.MulModP(v1, v2)
    v4 := e.SubModP(v3, A)
    E := e.SubModP(v4, B)  // E = (X1 + Y1)(X2 + Y2) - A - B
    F := e.SubModP(One, C) // F = 1 - C
    G := e.AddModP(One, C)
    H := e.SubModP(B, e.MulModP(&e.A, A))       // H = B - a * A
    Output.EX = e.MulModP(E, F)                 // X3 = E * F
    Output.EY = e.MulModP(G, H)                 // Y3 = G * H
    Output.ET = e.MulModP(E, H)                 // T3 = E * H
    Output.EZ = e.SubModP(One, e.MulModP(C, C)) // Z3 = 1 - C^2
    /*
       fmt.Println("A iz", A)
       fmt.Println("B iz", B)
       fmt.Println("C iz", C)
       fmt.Println("E iz", E)
       fmt.Println("F iz", F)
       fmt.Println("G iz", G)
       fmt.Println("H iz", H)
    */
    return Output, nil
}

func (e *Ellipse) AdditionV2(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/madd-2008-hwcd-2
    // Declare result point
    var Output CoordExtended
    
    // Verify that Z2 is 1
    if P2.EZ.Cmp(One) != 0 {
        return CoordExtended{}, errors.New("Z2 must be 1 for AdditionV2")
    }
    
    // Addition logic for the case when Z2 = 1 (madd-2008-hwcd-2)
    A := e.MulModP(P1.EX, P2.EX)
    B := e.MulModP(P1.EY, P2.EY)
    C := e.MulModP(P1.EZ, P2.ET)
    D := P1.ET
    E := e.AddModP(C, D)
    v1 := e.SubModP(P1.EX, P1.EY)
    v2 := e.AddModP(P2.EX, P2.EY)
    v3 := e.MulModP(v1, v2)
    v4 := e.AddModP(v3, B)
    F := e.SubModP(v4, A)
    v5 := e.MulModP(A, &e.A)
    G := e.AddModP(B, v5)
    H := e.SubModP(D, C)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) AdditionV3(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/add-2008-hwcd
    // Verify that Z1 and Z2 are different from 1
    if P2.EZ.Cmp(One) == 0 {
        return CoordExtended{}, errors.New("Both Z1 and Z2 must be different from 1 for AdditionV3")
    }
    
    // Initialize result point
    var Output CoordExtended
    
    // Addition logic for the case when Z2 = 1 (add-2008-hwcd)
    A := e.MulModP(P1.EX, P2.EX)
    B := e.MulModP(P1.EY, P2.EY)
    v1 := e.MulModP(&e.D, P2.ET)
    C := e.MulModP(P1.ET, v1)
    D := e.MulModP(P1.EZ, P2.EZ)
    v2 := e.AddModP(P1.EX, P1.EY)
    v3 := e.AddModP(P2.EX, P2.EY)
    v4 := e.MulModP(v2, v3)
    v5 := e.SubModP(v4, A)
    E := e.SubModP(v5, B)
    F := e.SubModP(D, C)
    G := e.AddModP(D, C)
    v6 := e.MulModP(&e.A, A)
    H := e.SubModP(B, v6)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) Doubling(P CoordExtended) (CoordExtended, error) {
    // Check if Z1 is 1
    var (
        Output CoordExtended
        err    error
    )
    if P.EZ.Cmp(One) == 0 {
        // Variant 1: If Z1 is 1
        Output, err = e.DoublingV1(P) // Uses the "mdbl-2008-hwcd" doubling formulas
        return Output, err
    } else {
        // Variant 2: If Z1 is not 1
        Output, err = e.DoublingV2(P) // Uses the "dbl-2008-hwcd" doubling formulas
        return Output, err
    }
}

// Doubling Variant 1: Z1 is 1
func (e *Ellipse) DoublingV1(P CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/mdbl-2008-hwcd
    // Verify that Z is 1
    if P.EZ.Cmp(One) != 0 {
        return CoordExtended{}, errors.New("Z must be 1 for Doubling Variant1")
    }
    
    // Initialize result point
    var Output CoordExtended
    
    // Addition logic for the case when Z2 = 1 (mdbl-2008-hwcd)
    A := e.MulModP(P.EX, P.EX)
    B := e.MulModP(P.EY, P.EY)
    D := e.MulModP(A, &e.A)
    v1 := e.AddModP(P.EX, P.EY)
    v2 := e.MulModP(v1, v1)
    v3 := e.SubModP(v2, A)
    E := e.SubModP(v3, B)
    G := e.AddModP(D, B)
    H := e.SubModP(D, B)
    v4 := e.SubModP(G, Two)
    Output.EX = e.MulModP(E, v4)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    v5 := e.MulModP(Two, G)
    v6 := e.MulModP(G, G)
    Output.EZ = e.SubModP(v6, v5)
    
    return Output, nil
}

// DoublingV2 Doubling Variant 2: Z1 is not 1
func (e *Ellipse) DoublingV2(P CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/dbl-2008-hwcd
    // Initialize result point
    var Output CoordExtended
    
    // Logic for DoublingV2 ("dbl-2008-hwcd")
    A := e.MulModP(P.EX, P.EX)
    B := e.MulModP(P.EY, P.EY)
    v1 := e.MulModP(P.EZ, P.EZ)
    C := e.MulModP(Two, v1)
    D := e.MulModP(A, &e.A)
    v2 := e.AddModP(P.EX, P.EY)
    v3 := e.MulModP(v2, v2)
    v4 := e.SubModP(v3, A)
    E := e.SubModP(v4, B)
    G := e.AddModP(D, B)
    F := e.SubModP(G, C)
    H := e.SubModP(D, B)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) Tripling(P CoordExtended) CoordExtended {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/tripling/tpl-2015-c
    // Initialize result point
    var Output CoordExtended
    
    //Checking
    //fmt.Printf("P before tripling: EX = %v, EY = %v\n", P.EX, P.EY)
    
    // Logic for Tripling (tpl-2015-c)
    YY := e.MulModP(P.EY, P.EY)
    XX := e.MulModP(P.EX, P.EX)
    aXX := e.MulModP(&e.A, XX)
    Ap := e.AddModP(YY, aXX)
    ZZ := e.MulModP(P.EZ, P.EZ)
    v1 := e.MulModP(Two, ZZ)
    v2 := e.SubModP(v1, Ap)
    B := e.MulModP(Two, v2)
    xB := e.MulModP(aXX, B)
    yB := e.MulModP(YY, B)
    v3 := e.SubModP(YY, aXX)
    AA := e.MulModP(Ap, v3)
    F := e.SubModP(AA, yB)
    G := e.AddModP(AA, xB)
    v4 := e.AddModP(yB, AA)
    xE := e.MulModP(P.EX, v4)
    v5 := e.SubModP(xB, AA)
    yH := e.MulModP(P.EY, v5)
    zF := e.MulModP(P.EZ, F)
    zG := e.MulModP(P.EZ, G)
    Output.EX = e.MulModP(xE, zF)
    Output.EY = e.MulModP(yH, zG)
    Output.EZ = e.MulModP(zF, zG)
    Output.ET = e.MulModP(xE, yH)
    return Output
}

// V Complex Operations

//FortyNiner Adds a Point to Itself 49 Times
func (e *Ellipse) FortyNiner(P CoordExtended) CoordExtended {
    Point03 := e.Tripling(P)
    Point06, _ := e.Doubling(Point03)
    Point12, _ := e.Doubling(Point06)
    Point24, _ := e.Doubling(Point12)
    Point48, _ := e.Doubling(Point24)
    Point49, _ := e.Addition(Point48, P)
    return Point49
}

func (e *Ellipse) PrecomputeMatrixWithGenerator() [7][7]CoordExtended {
    //Creates Precomputed Matrix using the Ellipse Generator Point
    return e.PrecomputeMatrix(e.Affine2Extended(e.G))
}

func (e *Ellipse) PrecomputeMatrix(P CoordExtended) [7][7]CoordExtended {
    //Creates a Precompute-Matrix using the Curves Generator Point
    
    P02, _ := e.Doubling(P)
    P03, _ := e.Addition(P02, P)
    P04, _ := e.Doubling(P02)
    P05, _ := e.Addition(P04, P)
    P06, _ := e.Doubling(P03)
    P07, _ := e.Addition(P06, P)
    P08, _ := e.Doubling(P04)
    P09, _ := e.Addition(P08, P)
    P10, _ := e.Doubling(P05)
    P11, _ := e.Addition(P10, P)
    P12, _ := e.Doubling(P06)
    P13, _ := e.Addition(P12, P)
    P14, _ := e.Doubling(P07)
    P15, _ := e.Addition(P14, P)
    P16, _ := e.Doubling(P08)
    P17, _ := e.Addition(P16, P)
    P18, _ := e.Doubling(P09)
    P19, _ := e.Addition(P18, P)
    P20, _ := e.Doubling(P10)
    P21, _ := e.Addition(P20, P)
    P22, _ := e.Doubling(P11)
    P23, _ := e.Addition(P22, P)
    P24, _ := e.Doubling(P12)
    P25, _ := e.Addition(P24, P)
    P26, _ := e.Doubling(P13)
    P27, _ := e.Addition(P26, P)
    P28, _ := e.Doubling(P14)
    P29, _ := e.Addition(P28, P)
    P30, _ := e.Doubling(P15)
    P31, _ := e.Addition(P30, P)
    P32, _ := e.Doubling(P16)
    P33, _ := e.Addition(P32, P)
    P34, _ := e.Doubling(P17)
    P35, _ := e.Addition(P34, P)
    P36, _ := e.Doubling(P18)
    P37, _ := e.Addition(P36, P)
    P38, _ := e.Doubling(P19)
    P39, _ := e.Addition(P38, P)
    P40, _ := e.Doubling(P20)
    P41, _ := e.Addition(P40, P)
    P42, _ := e.Doubling(P21)
    P43, _ := e.Addition(P42, P)
    P44, _ := e.Doubling(P22)
    P45, _ := e.Addition(P44, P)
    P46, _ := e.Doubling(P23)
    P47, _ := e.Addition(P46, P)
    P48, _ := e.Doubling(P24)
    P49, _ := e.Addition(P48, P)
    
    MR1 := [...]CoordExtended{P, P02, P03, P04, P05, P06, P07}
    MR2 := [...]CoordExtended{P08, P09, P10, P11, P12, P13, P14}
    MR3 := [...]CoordExtended{P15, P16, P17, P18, P19, P20, P21}
    MR4 := [...]CoordExtended{P22, P23, P24, P25, P26, P27, P28}
    MR5 := [...]CoordExtended{P29, P30, P31, P32, P33, P34, P35}
    MR6 := [...]CoordExtended{P36, P37, P38, P39, P40, P41, P42}
    MR7 := [...]CoordExtended{P43, P44, P45, P46, P47, P48, P49}
    
    return [7][7]CoordExtended{MR1, MR2, MR3, MR4, MR5, MR6, MR7}
}

func (e *Ellipse) ScalarMultiplierWithGenerator(Scalar *big.Int) CoordExtended {
    return e.ScalarMultiplier(Scalar, e.Affine2Extended(e.G))
}


// digitValueBase49 returns the numeric value (0..48) of a single base-49
// digit character as produced by (*big.Int).Text(49).
//
// Mapping:  '0'..'9'  -> 0..9
//           'a'..'z'  -> 10..35
//           'A'..'M'  -> 36..48
//
// Valid base-49 digits produce values in [0, 48]. Any invalid character
// produces 0, which is the same no-op branch the legacy switch statement
// used for a '0' digit (addition with the infinity point).
func digitValueBase49(c byte) int {
    switch {
    case c >= '0' && c <= '9':
        return int(c - '0')
    case c >= 'a' && c <= 'z':
        return int(c-'a') + 10
    case c >= 'A' && c <= 'M':
        return int(c-'A') + 36
    }
    return 0
}

// ScalarMultiplier computes Scalar * P using the 48-element precompute
// matrix and base-49 Horner evaluation.
//
// HARDENING (v1.3.0, finding PO-1):
//
// Algorithmic constant-time point selection. Every iteration performs
// exactly one Addition and (on all but the last digit) one FortyNiner,
// regardless of the scalar digit's value. Point selection is a linear
// scan over all 48 precompute entries that always completes with no
// early exit - the sequence of Go-level operations is identical for
// every scalar of the same base-49 length.
//
// This removes the MACRO-level timing channel that the pre-v1.3.0
// implementation (a switch statement over base-49 digit characters)
// exposed. The micro-level timing of big.Int arithmetic itself is not
// constant-time (math/big is not designed for this); removing it would
// require a custom limb-oriented implementation, which is out of scope
// for the Genesis Go reference.
//
// BYTE-FOR-BYTE COMPATIBILITY: identical output to the pre-v1.3.0
// implementation for all inputs. Verified against the committed
// testvectors/v1_genesis.json corpus (85 deterministic records).
func (e *Ellipse) ScalarMultiplier(Scalar *big.Int, P CoordExtended) CoordExtended {
    var (
        PrivKey49 = Scalar.Text(49)
        PM        = e.PrecomputeMatrix(P)
        Result    = InfinityPoint
    )

    for i := 0; i < len(PrivKey49); i++ {
        value := digitValueBase49(PrivKey49[i])

        // Branch-free point selection across the 48 precompute entries.
        // Start with InfinityPoint (the no-op for Addition) and
        // conditionally replace with PM[row][col] when value matches
        // idx. Always scans all 48 indices; no early exit.
        toAdd := InfinityPoint
        for idx := 1; idx <= 48; idx++ {
            row := (idx - 1) / 7
            col := (idx - 1) % 7
            if value == idx {
                toAdd = PM[row][col]
            }
        }
        Result, _ = e.Addition(Result, toAdd)

        if i != len(PrivKey49)-1 {
            Result = e.FortyNiner(Result)
        }
    }
    return Result
}
