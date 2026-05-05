package Elliptic

import (
    aux "DALOS_Crypto/Auxilliary"
    "math/big"
    "strconv"
    "sync"
)

var (
    Zero = big.NewInt(0)
    One  = big.NewInt(1)
    Two  = big.NewInt(2)
    
    InfinityPoint = CoordExtended{Zero, One, One, Zero}
)

type Ellipse struct {
    Name string //Name
    //Prime Numbers
    P big.Int //Prime Number defining the Prime Field
    Q big.Int //Prime Number defining the Generator (Base-Point) Order
    T big.Int //Trace of the Curve
    R big.Int //Elliptic Curve Cofactor: R*Q = P + 1 - T

    //Coefficients (Equation Parameters)
    A big.Int // x^2 Coefficient (Twisted Edwards Curve)
    D big.Int // x^2 * y^2 Coefficient (Twisted Edwards Curve)

    //Curve safe scalar size in bits
    S uint32

    //Point Coordinates
    G CoordAffine

    // Generator-precompute cache. Single *generatorPMCache pointer so
    // the underlying memory (sync.Once + cached matrix slot) is shared
    // across all value-copies of an Ellipse — the curve factories return
    // Ellipse by value and downstream callers may further copy the
    // struct, but the *generatorPMCache is aliased on every copy. The
    // populator runs at most once per holder; subsequent reads on any
    // value-copy hit the same cached matrix. Populated lazily on first
    // call to PrecomputeMatrixWithGenerator under the once guard. The
    // matrix is identical to e.PrecomputeMatrix(e.Affine2Extended(e.G))
    // — only the COMPUTATION PATH changes (cache-lookup vs rebuild),
    // never the COMPUTED VALUE. Genesis byte-identity is preserved.
    generatorCache *generatorPMCache
}

// generatorPMCache is the heap-resident holder for the per-curve
// generator-precompute matrix. Lives on the heap so that value-copies
// of Ellipse all reference the SAME cache slot — eliminates the latent
// value-copy NPE where one copy populates and a second pre-populated
// copy reads its own (still-nil) generatorPM. Sealed inside the package
// because consumers should never construct one directly; the curve
// factories own initialisation.
type generatorPMCache struct {
    once sync.Once
    pm   *[7][7]CoordExtended
}

type PrimePowerTwo struct {
    Power      int
    RestString string
    Sign       bool
}

func MakePrime(PrimeNumber PrimePowerTwo) big.Int {
    var (
        Prime = new(big.Int)
        Rest  = new(big.Int)
    )
    
    Rest.SetString(PrimeNumber.RestString, 10)
    if PrimeNumber.Sign == true {
        Prime.SetBit(Zero, PrimeNumber.Power, 1).Add(Prime, Rest)
    } else {
        Prime.SetBit(Zero, PrimeNumber.Power, 1).Sub(Prime, Rest)
    }
    
    return *Prime
}

func ComputeCofactor(P, Q, T big.Int) big.Int {
    var h = new(big.Int)
    h.Add(&P, One).Sub(h, &T).Quo(h, &Q)
    return *h
}

func ComputeSafeScalar(Prime, Trace, Cofactor *big.Int) (uint64, string) {
    //@doc "Computes the Safe Scalar, given Prime Number, Trace and Cofactor of an Elliptic Curve
    //The Safe scalar, is the power of 2, in this case 2^1600 means this many private keys possible
    //Computing the Safe Scalar assumes, the Prime is a prime Number, the Cofactor is correct for the Elliptic Curve
    //and the Trace is also Correct. Computing the Safe Scalar also yields the Generator of the elliptic curve."
    var (
        Q         = new(big.Int)
        Remainder = new(big.Int)
        Qs        string
        Ss        string
        X         uint64
    )
    
    CofactorBase2 := Cofactor.Text(2)
    CofactorBase2Trimmed := aux.TrimFirstRune(CofactorBase2)
    CofactorBitSize := uint64(len(CofactorBase2Trimmed))
    v1 := InferiorTrace(Prime, Trace)
    Q.QuoRem(v1, Cofactor, Remainder)
    Power, Sign, Rest := Power2DistanceChecker(Q)
    
    if Sign == false {
        X = Power - (2 + CofactorBitSize)
        Ss = "-"
    } else if Sign == true {
        X = Power - (1 + CofactorBitSize)
        Ss = "+"
    }
    PowerString := strconv.FormatInt(int64(Power), 10)
    RestS := Rest.Text(10)
    Qs = "2^" + PowerString + Ss + RestS
    return X, Qs
}

func Power2DistanceChecker(Number *big.Int) (uint64, bool, *big.Int) {
    //@doc "Transforms a big.Int in 2^x +/- y representation,
    //Returning the Power(uint), Sign(bool), and the remainder, y(*big.Int)"
    var (
        BetweenInt  = new(big.Int)
        HalfBetween = new(big.Int)
        LowerPower  = new(big.Int)
        HigherPower = new(big.Int)
        
        Rest  = new(big.Int)
        Sign  bool
        Power uint64
    )
    NumberBase2 := Number.Text(2)
    Between := aux.TrimFirstRune(NumberBase2)
    BetweenInt.SetString(Between, 2)   //22
    LowerPower.Sub(Number, BetweenInt) //32
    HigherPower.Mul(LowerPower, Two)   //64
    HalfBetween.Quo(LowerPower, Two)   //16
    HigherPowerBin := HigherPower.Text(2)
    Cmp := BetweenInt.Cmp(HalfBetween)
    if Cmp == 1 {
        Rest.Sub(LowerPower, BetweenInt)
        Sign = false
        Power = uint64(len(HigherPowerBin)) - 1
    } else if Cmp == -1 {
        Rest = BetweenInt
        Sign = true
        Power = uint64(len(HigherPowerBin)) - 2
    } else {
        Rest = BetweenInt
        Sign = true
        Power = uint64(len(HigherPowerBin)) - 2
    }
    return Power, Sign, Rest
}

func InferiorTrace(Prime, Trace *big.Int) *big.Int {
    var output = new(big.Int)
    return output.Add(Prime, One).Sub(output, Trace)
}

func SuperiorTrace(Prime, Trace *big.Int) *big.Int {
    var output = new(big.Int)
    return output.Add(Prime, One).Add(output, Trace)
}

// E521Ellipse returns parameters for the published E-521 reference
// curve. NOT a production primitive — see SCOPE NOTE below.
//
// SCOPE NOTE (F-LOW-011, audit cycle 2026-05-04, v4.0.3): E521 is
// intentionally kept in this package as a CROSS-CURVE TEST FIXTURE
// and as a worked example of how to define new curve parameters
// against the `Ellipse` struct. It has zero production callers
// (verified 2026-05-05 via `grep -rn "E521Ellipse"` on workspace
// `Z:\` outside this repo) and is NOT registered against the
// `ts/src/registry/` primitive-registry surface. Calls to
// `E521Ellipse()` work correctly post-F-MED-014 (the latent
// `e.G.AX = new(big.Int)` allocation bug surfaced by Cluster C's
// cross-curve test sweep was fixed inline at lines 207-208 below
// this declaration).
//
// Why kept rather than deleted:
//   1. The Cluster C cross-curve test sweep (PointOperations_test.go
//      runs 11 tests across 5 curves) uses E521 as a non-DALOS
//      reference data point — its different prime field shape
//      provides genuine cross-coverage that LETO/ARTEMIS/APOLLO
//      (all DALOS-family TEC variants) don't.
//   2. The factory itself documents the canonical E-521 parameters,
//      which are useful as a reference for anyone adding a new
//      published curve to this codebase later.
//   3. Adding E521 to the primitive-registry surface is YAGNI today
//      — Ouronet does not mint E521 addresses and has no plans to;
//      promoting it to a registry-backed primitive would require
//      defining E521-specific address prefixes, Schnorr v2 spec
//      conformance, and a TS-port mirror, all without a real
//      consumer.
//
// If a future cycle does need E521 as a production primitive (e.g.,
// a separate StoaChain product wants to use it), the path is the
// same as the historical curves got in v1.2.0: add a TS-side
// counterpart in `ts/src/historical/`, add a `CryptographicPrimitive`
// adapter in `ts/src/registry/`, register against the default
// registry, and add E521-specific test vectors to a NEW corpus file
// (NOT v1_genesis.json — that's frozen). Until then, this factory
// is documentation + test fixture only.
//
// Documented as DOCUMENTED-NOT-FIXED-BY-DESIGN in the v4.0.3 audit
// close-out — mirrors F-MED-018 / F-MED-007 architectural-boundary
// precedent.
func E521Ellipse() Ellipse {
    var (
        e Ellipse
        P PrimePowerTwo
        Q PrimePowerTwo
    )
    //Name
    e.Name = "E521"
    
    //Prime Numbers
    //P=2^521 - 1
    P.Power = 521
    P.RestString = "1"
    P.Sign = false
    e.P = MakePrime(P)
    
    //Q=2^519 - 337554763258501705789107630418782636071904961214051226618635150085779108655765
    Q.Power = 519
    Q.RestString = "337554763258501705789107630418782636071904961214051226618635150085779108655765"
    Q.Sign = false
    e.Q = MakePrime(Q)
    
    //Trace and Cofactor
    e.T.SetString("1350219053034006823156430521675130544287619844856204906474540600343116434623060", 10)
    e.R = ComputeCofactor(e.P, e.Q, e.T)
    
    //Safe Scalar Size in bits = 1600
    e.S = 515
    
    //A and D Coefficients
    e.A.SetInt64(1)
    e.D.SetInt64(-376014)
    
    //Generator Coordinates
    // F-MED-014 (v4.0.2): the AX/AY *big.Int pointers are nil after the
    // zero-value Ellipse declaration; calling SetString on a nil
    // *big.Int panics. The other four curve factories (Dalos, Leto,
    // Artemis, Apollo) all allocate them explicitly before assigning.
    // E521Ellipse was missing these two allocations since v1.0.0 and
    // panicked the moment a caller invoked it — but no production or
    // test code did, so the latent bug went undetected for the entire
    // codebase lifetime. Surfaced when F-MED-014's cross-curve test
    // sweep added the first real caller.
    e.G.AX = new(big.Int)
    e.G.AY = new(big.Int)
    e.G.AX.SetString("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324", 10)
    e.G.AY.SetInt64(12)

    e.generatorCache = &generatorPMCache{}

    return e
}

func DalosEllipse() Ellipse {
    var (
        e Ellipse
        P PrimePowerTwo
        Q PrimePowerTwo
    )
    //Name
    e.Name = "TEC_S1600_Pr1605p2315_m26"
    
    //Prime Numbers
    //P=2^1605 + 2315
    P.Power = 1605
    P.RestString = "2315"
    P.Sign = true
    e.P = MakePrime(P)
    
    //2^1603+1258387060301909514024042379046449850251725029634697115619073843890705481440046740552204199635883885272944914904655483501916023678206167596650367826811846862157534952990004386839463386963494516862067933899764941962204635259228497801901380413
    Q.Power = 1603
    Q.RestString = "1258387060301909514024042379046449850251725029634697115619073843890705481440046740552204199635883885272944914904655483501916023678206167596650367826811846862157534952990004386839463386963494516862067933899764941962204635259228497801901380413"
    Q.Sign = true
    e.Q = MakePrime(Q)
    
    //Trace and Cofactor
    e.T.SetString("-5033548241207638056096169516185799401006900118538788462476295375562821925760186962208816798543535541091779659618621934007664094712824670386601471307247387448630139811960017547357853547853978067448271735599059767848818541036913991207605519336", 10)
    e.R = ComputeCofactor(e.P, e.Q, e.T)
    
    //Safe Scalar Size in bits = 1600
    e.S = 1600
    
    //A and D Coefficients
    e.A.SetInt64(1)
    e.D.SetInt64(-26)
    
    //Generator Coordinates
    e.G.AX = new(big.Int) // Allocate memory for AX
    e.G.AY = new(big.Int) // Allocate memory for AY
    e.G.AX.SetInt64(2)
    e.G.AY.SetString("479577721234741891316129314062096440203224800598561362604776518993348406897758651324205216647014453759416735508511915279509434960064559686580741767201752370055871770203009254182472722342456597752506165983884867351649283353392919401537107130232654743719219329990067668637876645065665284755295099198801899803461121192253205447281506198423683290960014859350933836516450524873032454015597501532988405894858561193893921904896724509904622632232182531698393484411082218273681226753590907472", 10)

    e.generatorCache = &generatorPMCache{}

    return e
}

// dalosEllipseSingletonState is the package-level once-guarded slot
// for the DALOS Genesis Ellipse. F-LOW-007 (audit cycle 2026-05-04,
// v4.0.3): see DalosEllipseSingleton's docstring for rationale.
var (
    dalosEllipseOnce     sync.Once
    dalosEllipseInstance Ellipse
)

// DalosEllipseSingleton returns a process-wide singleton DALOS Genesis
// Ellipse. First call builds the Ellipse via DalosEllipse() under a
// sync.Once guard; subsequent calls return a copy of the cached value.
// Because Ellipse's generatorCache field is a *generatorPMCache pointer,
// every value-copy returned by this function aliases the SAME underlying
// cache slot — so the per-curve generator PrecomputeMatrix is built
// AT MOST ONCE across the entire process, regardless of how many
// callers invoke DalosEllipseSingleton().
//
// HARDENING (v4.0.3, audit cycle 2026-05-04, F-LOW-007): the existing
// DalosEllipse() factory allocates a fresh Ellipse + fresh
// generatorPMCache slot on every call. Production CLI (Dalos.go) calls
// it once at main() startup, so the perf cost is paid once per
// invocation — fine. But test code calls it many times (see
// PointOperations_test.go's cross-curve sweep, KeyGeneration_test.go's
// per-test fixtures, etc.); each test gets a fresh Ellipse with a
// fresh empty cache, so the PrecomputeMatrix is rebuilt on first
// scalar-mult per test. With the test suite's ~30+ DalosEllipse()
// calls, that's 30+ redundant PM builds (~50ms each) → ~1.5s of pure
// test-runtime overhead.
//
// Tests that don't need a fresh isolated curve (the common case)
// should switch to DalosEllipseSingleton() for the runtime saving.
// Tests that DO need isolation (e.g., probing the cache-population
// behavior itself, or testing an Ellipse-modifying operation) should
// continue using DalosEllipse() to get a fresh instance per test.
//
// API surface: returns Ellipse (by value) to match DalosEllipse()'s
// signature exactly — drop-in interchangeable. The struct copy on each
// call is tiny relative to a single PM build it avoids.
//
// Goroutine safety: sync.Once.Do guarantees exactly-one execution and
// proper happens-before ordering for readers; the cached Ellipse is
// safe to read from any goroutine after the first call returns.
//
// Genesis byte-identity: the singleton's underlying Ellipse is built
// by DalosEllipse() unmodified — same params, same generator, same
// cofactor. Identical to anything DalosEllipse() returns on the same
// machine. No effect on the 105-vector corpus or any address-derivation
// path.
//
// Other curves (E521, LETO, ARTEMIS, APOLLO) do NOT have singletons
// added in this commit because (a) their factories are rarely called
// in production, (b) the cross-curve test sweep added in F-MED-014
// only calls each one once per test, and (c) adding 4 more singletons
// is YAGNI. Future commits may extend the pattern if test runtime
// becomes a concern.
func DalosEllipseSingleton() Ellipse {
    dalosEllipseOnce.Do(func() {
        dalosEllipseInstance = DalosEllipse()
    })
    return dalosEllipseInstance
}

//=============================================================================
// HISTORICAL CURVES
//
// Three novel Twisted-Edwards curves from the author's original
// Cryptoplasm research phase, named after the Delian family — LETO (the
// mother), ARTEMIS, and APOLLO (the twin children) — matching the
// aesthetic of DALOS itself (the sacred island).
//
// Same structural family as DALOS_ELLIPSE (Twisted Edwards, cofactor 4,
// negative D). Preserved here for historical purposes and
// cross-reference from the TypeScript port's /historical subpath.
//
// NOT used to mint Ouronet addresses — every production Ouronet account
// is derived exclusively from DalosEllipse.
//
// See docs/HISTORICAL_CURVES.md for provenance and
// verification/VERIFICATION_LOG.md for the full 7-test audit per curve.
//=============================================================================

// LetoEllipse — smallest of the historical curves.
//   P = 2^551 + 335  (552-bit prime)
//   Q = 2^549 − rest (549-bit prime subgroup order)
//   R = 4, a = 1, d = −1874
//   S = 545 bits → 2^545 ≈ 1.15 × 10^164 keys
// Formerly TEC_S545_Pr551p335_m1874 in the Cryptoplasm roster.
func LetoEllipse() Ellipse {
    var (
        e Ellipse
        P PrimePowerTwo
        Q PrimePowerTwo
    )
    e.Name = "LETO"

    P.Power = 551
    P.RestString = "335"
    P.Sign = true
    e.P = MakePrime(P)

    Q.Power = 549
    Q.RestString = "32999719876419924862440765771944715506860861139489669592317112655962959048275399831"
    Q.Sign = false
    e.Q = MakePrime(Q)

    e.T.SetString("131998879505679699449763063087778862027443444557958678369268450623851836193101599660", 10)
    e.R = ComputeCofactor(e.P, e.Q, e.T)

    e.S = 545

    e.A.SetInt64(1)
    e.D.SetInt64(-1874)

    e.G.AX = new(big.Int)
    e.G.AY = new(big.Int)
    e.G.AX.SetInt64(5)
    e.G.AY.SetString("4518488039903337342061416616304793185577751419009710712882273229786958102867981468569632796010757506367702155510163192445896310025029799220155797291359909742186717128", 10)

    e.generatorCache = &generatorPMCache{}

    return e
}

// ArtemisEllipse — smaller twin of APOLLO.
//   P = 2^1029 + 639  (1030-bit prime; shared with APOLLO)
//   Q = 2^1027 − rest (1027-bit prime subgroup order)
//   R = 4, a = 1, d = −200
//   S = 1023 bits → 2^1023 ≈ 9.0 × 10^307 keys
// Formerly TEC_S1023_Pr1029p639_m200 in the Cryptoplasm roster.
func ArtemisEllipse() Ellipse {
    var (
        e Ellipse
        P PrimePowerTwo
        Q PrimePowerTwo
    )
    e.Name = "ARTEMIS"

    P.Power = 1029
    P.RestString = "639"
    P.Sign = true
    e.P = MakePrime(P)

    Q.Power = 1027
    Q.RestString = "13048810356164098687722578038659254541745638134607534327178785488911851451225729494174990871326244818073066727207431577242595505052831067258628249533735995"
    Q.Sign = false
    e.Q = MakePrime(Q)

    e.T.SetString("52195241424656394750890312154637018166982552538430137308715141955647405804902917976699963485304979272292266908829726308970382020211324269034512998134944620", 10)
    e.R = ComputeCofactor(e.P, e.Q, e.T)

    e.S = 1023

    e.A.SetInt64(1)
    e.D.SetInt64(-200)

    e.G.AX = new(big.Int)
    e.G.AY = new(big.Int)
    e.G.AX.SetInt64(18)
    e.G.AY.SetString("5006392512810367543241026017186205828475671321699765938632799901604288413670061260105487647663536568022230479638139010351335665470173712718298837530633945899923869302110921390691280063917337749102198086546109683731403172016859789550276802795383170944526602213977392860793115308281053135496569817870067300616902", 10)

    e.generatorCache = &generatorPMCache{}

    return e
}

// ApolloEllipse — larger twin of ARTEMIS.
//   P = 2^1029 + 639  (1030-bit prime; shared with ARTEMIS)
//   Q = 2^1027 + rest (1028-bit prime subgroup order)
//   R = 4, a = 1, d = −729
//   S = 1024 bits → 2^1024 ≈ 1.8 × 10^308 keys (double ARTEMIS's)
// Formerly TEC_S1024_Pr1029p639_m729 in the Cryptoplasm roster.
func ApolloEllipse() Ellipse {
    var (
        e Ellipse
        P PrimePowerTwo
        Q PrimePowerTwo
    )
    e.Name = "APOLLO"

    P.Power = 1029
    P.RestString = "639"
    P.Sign = true
    e.P = MakePrime(P)

    Q.Power = 1027
    Q.RestString = "9418258840691661048958693280848051387209299408194089012775090979625514940291099061879232380228215863338991692577868713164205283324554730781862605682126581"
    Q.Sign = true
    e.Q = MakePrime(Q)

    e.T.SetString("-37673035362766644195834773123392205548837197632776356051100363918502059761164396247516929520912863453355966770311474852656821133298218923127450422728505684", 10)
    e.R = ComputeCofactor(e.P, e.Q, e.T)

    e.S = 1024

    e.A.SetInt64(1)
    e.D.SetInt64(-729)

    e.G.AX = new(big.Int)
    e.G.AY = new(big.Int)
    e.G.AX.SetInt64(18)
    e.G.AY.SetString("215278369951571488896917596155404324026002302190181825431681175816997859909367143653000579666656344456792257669605762582468610930751115704301503268336066379058325768607564533090162357247378501333085803173440477981455490888754538866823680129180124913908161391361773138634347515375569488540295649449731695734303", 10)

    e.generatorCache = &generatorPMCache{}

    return e
}
