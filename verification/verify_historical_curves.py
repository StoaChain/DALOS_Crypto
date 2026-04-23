#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Historical Curves Parameter Verification

Runs the same 7-test mathematical audit that `verify_dalos_curve.py`
runs on DALOS Genesis, but applied to the three historical curves
shipped in `@stoachain/dalos-crypto@1.1.0` under the `./historical`
subpath:

    LETO    (S = 545 bits, P = 2^551 + 335,   d = -1874)
    ARTEMIS (S = 1023 bits, P = 2^1029 + 639, d = -200)
    APOLLO  (S = 1024 bits, P = 2^1029 + 639, d = -729)

The 7 tests, per curve:

    1. P is prime
    2. Q is prime
    3. Cofactor R = (P + 1 - T) / Q is an integer  (curve order divides)
    4. d is a quadratic non-residue mod P           (addition-law completeness)
    5. G = (G_X, G_Y) lies on the curve
    6. [Q] * G = O                                  (G has order Q)
    7. Safe-scalar size <= bit length of Q

Usage:
    python verify_historical_curves.py

Optional (much faster primality): install gmpy2
    pip install gmpy2

Dependencies:
    sympy  (fallback for primality if gmpy2 is absent)

Author: verification harness for @stoachain/dalos-crypto@1.1.0
        historical-curves sidecar.
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


# --- Modular helpers --------------------------------------------------------

def modinv(a: int, p: int) -> int:
    return pow(a, -1, p)


def is_quadratic_residue(a: int, p: int) -> bool:
    """Euler's criterion. a^((p-1)/2) mod p == 1 iff a is a QR."""
    a = a % p
    if a == 0:
        return True
    return pow(a, (p - 1) // 2, p) == 1


# --- Twisted Edwards point arithmetic (curve-parameterised) ----------------
# Projective coordinates. Identity: (0 : 1 : 1).  Affine: x = X/Z, y = Y/Z.

class Point:
    __slots__ = ("X", "Y", "Z", "_curve")

    def __init__(self, X: int, Y: int, Z: int, curve: "Curve"):
        P = curve.P
        self.X = X % P
        self.Y = Y % P
        self.Z = Z % P
        self._curve = curve

    @staticmethod
    def identity(curve: "Curve") -> "Point":
        return Point(0, 1, 1, curve)

    def is_identity(self) -> bool:
        P = self._curve.P
        return self.X % P == 0 and (self.Y - self.Z) % P == 0

    def to_affine(self) -> tuple[int, int]:
        P = self._curve.P
        inv_z = modinv(self.Z, P)
        return (self.X * inv_z) % P, (self.Y * inv_z) % P

    def is_on_curve(self) -> bool:
        c = self._curve
        x, y = self.to_affine()
        lhs = (c.A * x * x + y * y) % c.P
        rhs = (1 + c.D * x * x * y * y) % c.P
        return lhs == rhs

    def __add__(self, other: "Point") -> "Point":
        c = self._curve
        P, A, D = c.P, c.A, c.D % c.P
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = other.X, other.Y, other.Z

        Ap = (Z1 * Z2) % P
        Bp = (Ap * Ap) % P
        Cp = (X1 * X2) % P
        Dp = (Y1 * Y2) % P
        Ep = (D * Cp * Dp) % P
        Fp = (Bp - Ep) % P
        Gp = (Bp + Ep) % P
        X3 = (Ap * Fp * (((X1 + Y1) * (X2 + Y2) - Cp - Dp) % P)) % P
        Y3 = (Ap * Gp * ((Dp - A * Cp) % P)) % P
        Z3 = (Fp * Gp) % P
        return Point(X3, Y3, Z3, c)

    def double(self) -> "Point":
        return self + self

    def scalar_mul(self, k: int, progress: bool = False) -> "Point":
        """Double-and-add. Non-constant time — fine for one-off verification."""
        if k == 0:
            return Point.identity(self._curve)
        if k < 0:
            raise ValueError("negative scalar not implemented")

        result = Point.identity(self._curve)
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


# --- Curve parameter container ---------------------------------------------

class Curve:
    def __init__(self, *, name: str, P: int, Q: int, T: int,
                 A: int, D: int, G_X: int, G_Y: int, S: int):
        self.name = name
        self.P = P
        self.Q = Q
        self.T = T
        self.A = A
        self.D = D
        self.G_X = G_X
        self.G_Y = G_Y
        self.S = S


# --- The three historical curves -------------------------------------------
# Constants mirror Elliptic/Parameters.go (LetoEllipse / ArtemisEllipse /
# ApolloEllipse) byte-for-byte.

LETO = Curve(
    name="LETO",
    P=(1 << 551) + 335,
    Q=(1 << 549) - int(
        "32999719876419924862440765771944715506860861139489669592317112655962"
        "959048275399831"
    ),
    T=int(
        "131998879505679699449763063087778862027443444557958678369268450623851"
        "836193101599660"
    ),
    A=1,
    D=-1874,
    G_X=5,
    G_Y=int(
        "4518488039903337342061416616304793185577751419009710712882273229786958"
        "1028679814685696327960107575063677021555101631924458963100250297992201"
        "55797291359909742186717128"
    ),
    S=545,
)

ARTEMIS = Curve(
    name="ARTEMIS",
    P=(1 << 1029) + 639,
    Q=(1 << 1027) - int(
        "13048810356164098687722578038659254541745638134607534327178785488911"
        "85145122572949417499087132624481807306672720743157724259550505283106"
        "7258628249533735995"
    ),
    T=int(
        "52195241424656394750890312154637018166982552538430137308715141955647"
        "40580490291797669996348530497927229226690882972630897038202021132426"
        "9034512998134944620"
    ),
    A=1,
    D=-200,
    G_X=18,
    G_Y=int(
        "5006392512810367543241026017186205828475671321699765938632799901604288"
        "4136700612601054876476635365680222304796381390103513356654701737127182"
        "9883753063394589992386930211092139069128006391733774910219808654610968"
        "3731403172016859789550276802795383170944526602213977392860793115308281"
        "053135496569817870067300616902"
    ),
    S=1023,
)

APOLLO = Curve(
    name="APOLLO",
    P=(1 << 1029) + 639,  # shared with ARTEMIS (twin)
    Q=(1 << 1027) + int(
        "94182588406916610489586932808480513872092994081940890127750909796255"
        "14940291099061879232380228215863338991692577868713164205283324554730"
        "781862605682126581"
    ),
    T=int(
        "-37673035362766644195834773123392205548837197632776356051100363918502"
        "05976116439624751692952091286345335596677031147485265682113329821892"
        "3127450422728505684"
    ),
    A=1,
    D=-729,
    G_X=18,  # shared with ARTEMIS (twin)
    G_Y=int(
        "2152783699515714888969175961554043240260023021901818254316811758169978"
        "5990936714365300057966665634445679225766960576258246861093075111570430"
        "1503268336066379058325768607564533090162357247378501333085803173440477"
        "9814554908887545388668236801291801249139081613913617731386343475153755"
        "69488540295649449731695734303"
    ),
    S=1024,
)


# --- Reporting --------------------------------------------------------------

def _check(failures: list[tuple[str, str]], label: str, curve: str,
           passed: bool, detail: str = "") -> None:
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"  {mark}  {label}")
    if detail:
        print(f"         {detail}")
    if not passed:
        failures.append((curve, label))


def banner(msg: str) -> None:
    print()
    print("=" * 72)
    print(f"  {msg}")
    print("=" * 72)


# --- Test battery (per curve) ----------------------------------------------

def verify_curve(curve: Curve, failures: list[tuple[str, str]]) -> None:
    banner(f"Curve: {curve.name}  (S = {curve.S} bits, d = {curve.D})")

    print()
    print(f"  P bit length : {curve.P.bit_length()}")
    print(f"  Q bit length : {curve.Q.bit_length()}")
    print(f"  G.X          : {curve.G_X}")
    print(f"  G.Y bitlen   : {curve.G_Y.bit_length()}")
    print(f"  a, d         : {curve.A}, {curve.D}")

    # Test 1: P prime
    banner(f"[{curve.name}] Test 1: P is prime")
    t0 = time.time()
    passed = is_prime(curve.P)
    print(f"    runtime: {time.time() - t0:.2f}s")
    _check(failures, "P is prime", curve.name, passed)

    # Test 2: Q prime
    banner(f"[{curve.name}] Test 2: Q is prime")
    t0 = time.time()
    passed = is_prime(curve.Q)
    print(f"    runtime: {time.time() - t0:.2f}s")
    _check(failures, "Q is prime", curve.name, passed)

    # Test 3: cofactor is integer
    banner(f"[{curve.name}] Test 3: Cofactor R = (P + 1 - T) / Q is an integer")
    order = curve.P + 1 - curve.T
    R, remainder = divmod(order, curve.Q)
    passed = (remainder == 0)
    _check(
        failures,
        "order of E divides cleanly into Q * R",
        curve.name,
        passed,
        f"R (cofactor) = {R}" if passed else f"remainder = {remainder}",
    )

    # Test 4: d is non-square
    banner(f"[{curve.name}] Test 4: d is a quadratic NON-residue mod P")
    print("           (required for Bernstein-Lange addition-law completeness)")
    d_mod = curve.D % curve.P
    is_qr = is_quadratic_residue(d_mod, curve.P)
    passed = not is_qr
    _check(
        failures,
        f"d = {curve.D} is NOT a quadratic residue mod P",
        curve.name,
        passed,
        "Addition law is complete on E(F_P)" if passed else
        "WARNING: d is a QR -- exceptional points exist in the addition law",
    )

    # Test 5: G on curve
    banner(f"[{curve.name}] Test 5: G satisfies curve equation")
    G = Point(curve.G_X, curve.G_Y, 1, curve)
    passed = G.is_on_curve()
    _check(failures, "G is on E", curve.name, passed)
    if not passed:
        x, y = G.to_affine()
        lhs = (curve.A * x * x + y * y) % curve.P
        rhs = (1 + curve.D * x * x * y * y) % curve.P
        print(f"           lhs = {lhs}")
        print(f"           rhs = {rhs}")

    # Test 6: [Q] * G = O
    banner(f"[{curve.name}] Test 6: [Q] * G = O (G has order Q)")
    print("           Full scalar multiplication -- a few seconds expected.")
    t0 = time.time()
    QG = G.scalar_mul(curve.Q, progress=True)
    dt = time.time() - t0
    passed = QG.is_identity()
    _check(failures, f"[Q] * G = O (runtime: {dt:.1f}s)", curve.name, passed)
    if not passed:
        x, y = QG.to_affine()
        print(f"           instead got: ({x}, {y})")

    # Test 7: safe scalar size sound
    banner(f"[{curve.name}] Test 7: S = {curve.S} <= log2(Q) = {curve.Q.bit_length()}")
    passed = curve.S <= curve.Q.bit_length()
    _check(
        failures,
        f"S = {curve.S} <= log2(Q) = {curve.Q.bit_length()}",
        curve.name,
        passed,
    )


# --- Main -------------------------------------------------------------------

def main() -> int:
    banner("Historical Curves (LETO / ARTEMIS / APOLLO) — Mathematical Verification")

    print()
    print(f"  Primality backend : "
          f"{'gmpy2' if _HAS_GMPY2 else 'sympy' if _HAS_SYMPY else 'NONE'}")

    failures: list[tuple[str, str]] = []

    for curve in (LETO, ARTEMIS, APOLLO):
        verify_curve(curve, failures)

    # Summary
    banner("Summary")
    total_tests = 7 * 3  # 7 checks × 3 curves
    pass_count = total_tests - len(failures)

    if not failures:
        print(f"  [PASS]  All {total_tests} checks passed across 3 historical curves.")
        print("          LETO, ARTEMIS, APOLLO parameters are sound.")
        return 0
    print(f"  [FAIL]  {len(failures)}/{total_tests} checks failed:")
    for curve_name, label in failures:
        print(f"          - {curve_name}: {label}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
