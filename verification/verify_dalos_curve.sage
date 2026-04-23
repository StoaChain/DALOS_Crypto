#!/usr/bin/env sage
# -*- coding: utf-8 -*-
#
# DALOS Curve Parameter Verification  (Sage version)
#
# Run locally:
#     sage verify_dalos_curve.sage
#
# Or paste the whole thing into https://sagecell.sagemath.org/ and click "Evaluate".
#
# Sage ships Pari/GP under the hood, so is_prime() here is deterministic
# (uses BPSW + APR-CL), and EllipticCurve objects can operate natively on
# twisted Edwards as a birational transform of an equivalent Montgomery form.
# For clarity, we do the arithmetic explicitly rather than via EllipticCurve().

# --- DALOS parameters (verbatim from Parameters.go) ---

P_POWER = 1605
P_REST  = 2315
P = 2^P_POWER + P_REST

Q_POWER = 1603
Q_REST  = 1258387060301909514024042379046449850251725029634697115619073843890705481440046740552204199635883885272944914904655483501916023678206167596650367826811846862157534952990004386839463386963494516862067933899764941962204635259228497801901380413
Q = 2^Q_POWER + Q_REST

T = -5033548241207638056096169516185799401006900118538788462476295375562821925760186962208816798543535541091779659618621934007664094712824670386601471307247387448630139811960017547357853547853978067448271735599059767848818541036913991207605519336

a = 1
d = -26

G_X = 2
G_Y = 479577721234741891316129314062096440203224800598561362604776518993348406897758651324205216647014453759416735508511915279509434960064559686580741767201752370055871770203009254182472722342456597752506165983884867351649283353392919401537107130232654743719219329990067668637876645065665284755295099198801899803461121192253205447281506198423683290960014859350933836516450524873032454015597501532988405894858561193893921904896724509904622632232182531698393484411082218273681226753590907472

# --- Test 1 : P is prime ---
print("Test 1: P prime")
print("  P.bit_length() =", P.nbits())
assert is_prime(P), "P is NOT prime!"
print("  [PASS]")

# --- Test 2 : Q is prime ---
print("Test 2: Q prime")
print("  Q.bit_length() =", Q.nbits())
assert is_prime(Q), "Q is NOT prime!"
print("  [PASS]")

# --- Test 3 : cofactor is integer ---
print("Test 3: Cofactor")
R = (P + 1 - T) / Q
assert R in ZZ, "cofactor is not integer -- order of curve not divisible by Q!"
print("  R =", R)
print("  [PASS]")

# --- Test 4 : -26 is non-square mod P ---
print("Test 4: d = -26 non-square mod P")
Fp = GF(P)
assert not Fp(d).is_square(), "d is a square! Addition law has exceptional points."
print("  [PASS]")

# --- Test 5 : G on curve ---
print("Test 5: G on curve")
# Twisted Edwards: a*x^2 + y^2 = 1 + d*x^2*y^2
x = Fp(G_X)
y = Fp(G_Y)
lhs = a*x^2 + y^2
rhs = 1 + d*x^2*y^2
assert lhs == rhs, "G is NOT on curve!  lhs = %s, rhs = %s" % (lhs, rhs)
print("  [PASS]")

# --- Test 6 : [Q]*G = O ---
# Projective twisted Edwards addition, a = 1.
# Identity: (0 : 1 : 1).
print("Test 6: [Q]*G = O   (this performs full scalar multiplication)")

def te_add(P1, P2):
    (X1, Y1, Z1) = P1
    (X2, Y2, Z2) = P2
    Ap = Z1 * Z2
    Bp = Ap^2
    Cp = X1 * X2
    Dp = Y1 * Y2
    Ep = d * Cp * Dp
    Fp_ = Bp - Ep
    Gp = Bp + Ep
    X3 = Ap * Fp_ * ((X1 + Y1) * (X2 + Y2) - Cp - Dp)
    Y3 = Ap * Gp * (Dp - a * Cp)
    Z3 = Fp_ * Gp
    return (X3, Y3, Z3)

def te_scalar_mul(k, P1):
    R = (Fp(0), Fp(1), Fp(1))  # identity
    A_ = P1
    while k > 0:
        if k & 1:
            R = te_add(R, A_)
        A_ = te_add(A_, A_)
        k >>= 1
    return R

G = (Fp(G_X), Fp(G_Y), Fp(1))
QG = te_scalar_mul(Q, G)
(X3, Y3, Z3) = QG

# Identity check: X3 == 0 and Y3 == Z3
assert X3 == 0 and Y3 == Z3, "[Q]*G != O !!  got X=%s  Y/Z=%s" % (X3, Y3/Z3)
print("  [PASS]")

# --- Test 7 : Safe scalar bits ---
print("Test 7: Safe-scalar size fits in log2(Q)")
assert 1600 <= Q.nbits(), "S=1600 > log2(Q) = %d" % Q.nbits()
print("  [PASS]")

print()
print("All 7 checks PASSED.  DALOS curve parameters are mathematically sound.")
