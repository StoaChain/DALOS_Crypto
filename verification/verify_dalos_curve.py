#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DALOS Curve Parameter Verification (Genesis / Gen 1)

Verifies mathematically that the DALOS Twisted Edwards curve parameters
embedded in StoaChain/DALOS_Crypto/Elliptic/Parameters.go are sound.

Curve equation (twisted Edwards):
    y^2 + a*x^2  =  1 + d*x^2*y^2    (mod P)

with:
    a = 1
    d = -26
    P = 2^1605 + 2315
    Q = 2^1603 + K                  (where K is the giant constant below)
    G = (2, Y_G)                    (Y_G is the giant constant below)

The tests performed here (in order):

    1. P is prime
    2. Q is prime
    3. Cofactor R = (P + 1 - T) / Q is an integer  (curve order divides)
    4. d = -26 is a quadratic non-residue mod P   (addition-law completeness)
    5. G = (2, Y_G) lies on the curve
    6. [Q] * G = O                                 (G has order Q)
    7. The safe-scalar size 1600 <= bit length of Q

Usage:
    python verify_dalos_curve.py

Optional (much faster primality): install gmpy2
    pip install gmpy2

Dependencies:
    sympy  (required fallback for primality if gmpy2 is absent)

Runtime:
    ~10-30 seconds with gmpy2.
    ~3-10 minutes without gmpy2 (sympy's BPSW is reliable but slower).

Author: verification harness for Phase 0 of the DALOS Crypto TypeScript port.
"""

from __future__ import annotations
import sys
import time

# --- Primality backend selection -------------------------------------------

try:
    import gmpy2  # type: ignore
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

try:
    from sympy import isprime as _sympy_isprime  # type: ignore
    _HAS_SYMPY = True
except ImportError:
    _HAS_SYMPY = False


def is_prime(n: int, rounds: int = 50) -> bool:
    """Strong probabilistic primality test.

    With gmpy2:  Miller-Rabin with `rounds` random bases.
                 False-positive probability <= 4^-rounds (= 2^-100 for 50).
    With sympy:  BPSW (no known counter-examples, effectively deterministic).
    """
    if _HAS_GMPY2:
        return bool(gmpy2.is_prime(gmpy2.mpz(n), rounds))
    if _HAS_SYMPY:
        return _sympy_isprime(n)
    raise RuntimeError("Install gmpy2 or sympy:  pip install gmpy2  (or)  pip install sympy")


# --- DALOS curve parameters (copied verbatim from Parameters.go) -----------

P_POWER = 1605
P_REST  = 2315
P = (1 << P_POWER) + P_REST

Q_POWER = 1603
Q_REST = int(
    "1258387060301909514024042379046449850251725029634697115619073843890"
    "705481440046740552204199635883885272944914904655483501916023678206"
    "167596650367826811846862157534952990004386839463386963494516862067"
    "933899764941962204635259228497801901380413"
)
Q = (1 << Q_POWER) + Q_REST

T = int(
    "-5033548241207638056096169516185799401006900118538788462476295375562"
    "821925760186962208816798543535541091779659618621934007664094712824"
    "670386601471307247387448630139811960017547357853547853978067448271"
    "735599059767848818541036913991207605519336"
)

A = 1
D = -26

G_X = 2
G_Y = int(
    "479577721234741891316129314062096440203224800598561362604776518993"
    "348406897758651324205216647014453759416735508511915279509434960064"
    "559686580741767201752370055871770203009254182472722342456597752506"
    "165983884867351649283353392919401537107130232654743719219329990067"
    "668637876645065665284755295099198801899803461121192253205447281506"
    "198423683290960014859350933836516450524873032454015597501532988405"
    "894858561193893921904896724509904622632232182531698393484411082218"
    "273681226753590907472"
)

EXPECTED_SAFE_SCALAR_BITS = 1600


# --- Modular helpers --------------------------------------------------------

def modinv(a: int, p: int) -> int:
    """Modular inverse via Python 3.8+ extended pow."""
    return pow(a, -1, p)


def is_quadratic_residue(a: int, p: int) -> bool:
    """Euler's criterion.  a^((p-1)/2) mod p  == 1 iff a is a QR."""
    a = a % p
    if a == 0:
        return True
    return pow(a, (p - 1) // 2, p) == 1


# --- Twisted Edwards point arithmetic in PROJECTIVE coords -----------------
# Faster than affine (no modular inverse per op).
# Identity: (0 : 1 : 1).  Affine: x = X/Z, y = Y/Z.
# Addition formula (twisted Edwards projective, a=1):
#   A = Z1*Z2
#   B = A^2
#   C = X1*X2
#   D = Y1*Y2
#   E = d*C*D
#   F = B - E
#   G = B + E
#   X3 = A*F*((X1+Y1)*(X2+Y2) - C - D)
#   Y3 = A*G*(D - a*C)
#   Z3 = F*G

class Point:
    __slots__ = ("X", "Y", "Z")

    def __init__(self, X: int, Y: int, Z: int = 1):
        self.X = X % P
        self.Y = Y % P
        self.Z = Z % P

    @staticmethod
    def identity() -> "Point":
        return Point(0, 1, 1)

    def is_identity(self) -> bool:
        # identity: X = 0  AND  Y/Z = 1  i.e.  X == 0 AND Y == Z
        return self.X % P == 0 and (self.Y - self.Z) % P == 0

    def to_affine(self) -> tuple[int, int]:
        inv_z = modinv(self.Z, P)
        return (self.X * inv_z) % P, (self.Y * inv_z) % P

    def is_on_curve(self) -> bool:
        x, y = self.to_affine()
        lhs = (A * x * x + y * y) % P
        rhs = (1 + D * x * x * y * y) % P
        return lhs == rhs

    def __add__(self, other: "Point") -> "Point":
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = other.X, other.Y, other.Z
        a_coef = A
        d_coef = D % P

        Ap = (Z1 * Z2) % P
        Bp = (Ap * Ap) % P
        Cp = (X1 * X2) % P
        Dp = (Y1 * Y2) % P
        Ep = (d_coef * Cp * Dp) % P
        Fp = (Bp - Ep) % P
        Gp = (Bp + Ep) % P
        X3 = (Ap * Fp * (((X1 + Y1) * (X2 + Y2) - Cp - Dp) % P)) % P
        Y3 = (Ap * Gp * ((Dp - a_coef * Cp) % P)) % P
        Z3 = (Fp * Gp) % P
        return Point(X3, Y3, Z3)

    def double(self) -> "Point":
        return self + self

    def scalar_mul(self, k: int, progress: bool = False) -> "Point":
        """Double-and-add.  Non-constant time — fine for one-off verification."""
        if k == 0:
            return Point.identity()
        if k < 0:
            raise ValueError("negative scalar not implemented")

        result = Point.identity()
        addend = self
        total_bits = k.bit_length()
        bits_done = 0
        last_report = time.time()

        while k > 0:
            if k & 1:
                result = result + addend
            addend = addend.double()
            k >>= 1
            bits_done += 1
            if progress and (time.time() - last_report) > 2.0:
                pct = 100.0 * bits_done / total_bits
                sys.stderr.write(f"    [scalar_mul] {bits_done}/{total_bits} bits ({pct:.1f}%)\r")
                sys.stderr.flush()
                last_report = time.time()

        if progress:
            sys.stderr.write(" " * 60 + "\r")
            sys.stderr.flush()
        return result


# --- Reporting --------------------------------------------------------------

_FAILURES = 0


def _check(label: str, passed: bool, detail: str = "") -> None:
    global _FAILURES
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"  {mark}  {label}")
    if detail:
        print(f"         {detail}")
    if not passed:
        _FAILURES += 1


def banner(msg: str) -> None:
    print()
    print("=" * 72)
    print(f"  {msg}")
    print("=" * 72)


# --- Test battery -----------------------------------------------------------

def main() -> int:
    global _FAILURES
    banner("DALOS Curve (Genesis)  -  Mathematical Verification")

    print()
    print(f"  Primality backend : {'gmpy2' if _HAS_GMPY2 else 'sympy' if _HAS_SYMPY else 'NONE (install one!)'}")
    print(f"  P bit length      : {P.bit_length()}")
    print(f"  Q bit length      : {Q.bit_length()}")
    print(f"  G.X bit length    : {G_X.bit_length()}")
    print(f"  G.Y bit length    : {G_Y.bit_length()}")
    print(f"  a, d              : {A}, {D}")

    # --- Test 1 : P prime ---
    banner("Test 1 :  P = 2^1605 + 2315  is prime")
    t0 = time.time()
    passed = is_prime(P)
    print(f"    runtime: {time.time() - t0:.2f}s")
    _check("P is prime", passed)

    # --- Test 2 : Q prime ---
    banner("Test 2 :  Q = 2^1603 + K  is prime")
    t0 = time.time()
    passed = is_prime(Q)
    print(f"    runtime: {time.time() - t0:.2f}s")
    _check("Q is prime", passed)

    # --- Test 3 : cofactor is integer ---
    banner("Test 3 :  Cofactor R = (P + 1 - T) / Q  is an integer")
    order = P + 1 - T
    R, remainder = divmod(order, Q)
    passed = (remainder == 0)
    _check(
        "order of E divides cleanly into Q * R",
        passed,
        f"R (cofactor) = {R}" if passed else f"remainder = {remainder}",
    )

    # --- Test 4 : d is non-square ---
    banner("Test 4 :  d = -26  is a quadratic NON-residue mod P")
    print("           (required for Bernstein-Lange addition-law completeness)")
    d_mod = D % P
    is_qr = is_quadratic_residue(d_mod, P)
    passed = not is_qr
    _check(
        "-26 is NOT a quadratic residue mod P",
        passed,
        "Addition law is complete on E(F_P)" if passed else
        "WARNING: d is a QR -- exceptional points exist in the addition law",
    )

    # --- Test 5 : G on curve ---
    banner("Test 5 :  G = (2, Y_G) satisfies curve equation")
    G = Point(G_X, G_Y, 1)
    passed = G.is_on_curve()
    _check("G is on E", passed)
    if not passed:
        x, y = G.to_affine()
        lhs = (A * x * x + y * y) % P
        rhs = (1 + D * x * x * y * y) % P
        print(f"           lhs = {lhs}")
        print(f"           rhs = {rhs}")

    # --- Test 6 : G has order Q ---
    banner("Test 6 :  [Q] * G = O   (G has order Q)")
    print("           This performs a full scalar multiplication -- ~20-60s expected.")
    t0 = time.time()
    QG = G.scalar_mul(Q, progress=True)
    dt = time.time() - t0
    passed = QG.is_identity()
    _check(f"[Q] * G = O   (runtime: {dt:.1f}s)", passed)
    if not passed:
        x, y = QG.to_affine()
        print(f"           instead got: ({x}, {y})")

    # --- Test 7 : safe scalar size is sound ---
    banner("Test 7 :  Safe scalar size 1600  <=  floor(log2(Q))")
    passed = EXPECTED_SAFE_SCALAR_BITS <= Q.bit_length()
    _check(
        f"S = {EXPECTED_SAFE_SCALAR_BITS}  <=  log2(Q) = {Q.bit_length()}",
        passed,
    )

    # --- Summary ---
    banner("Summary")
    if _FAILURES == 0:
        print("  [PASS]  All 7 checks passed.  DALOS curve parameters are sound.")
        print()
        print("  Safe to proceed with the TypeScript port (Phase 1 of DALOS_CRYPTO_PLAN.md).")
        return 0
    else:
        print(f"  [FAIL]  {_FAILURES} check(s) failed.  Halt the port and investigate.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
