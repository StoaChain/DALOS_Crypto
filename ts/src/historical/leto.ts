/**
 * LETO — one of Kjrekntolopon's original novel twisted-Edwards curves,
 * discovered during the Cryptoplasm research phase (the very first
 * iteration of the DALOS work).
 *
 * Named after the Titaness who arrived on Delos to give birth to the
 * twin gods — she predates Apollo and Artemis on the sacred island,
 * just as this smaller curve predates its larger twin siblings in the
 * DALOS family tree.
 *
 * Go-reference identifier: `TEC_S545_Pr551p335_m1874`.
 *
 * Same structural family as DALOS_ELLIPSE (Twisted Edwards, cofactor 4,
 * `y² + x² = 1 + d·x²·y²` over GF(P), with `d` negative) but with a
 * smaller prime. **Production-ready as of v3.0.0+** — wrapped by
 * `Leto` at `ts/src/registry/leto.ts` with byte-identity against the Go
 * reference (XCURVE-1..4 fixes; requires Go reference v3.0.0+). Address
 * prefixes: standard `Ł.`, smart `Λ.` (distinct from DALOS Genesis).
 * Ouronet's first-class Genesis primitive remains DALOS_ELLIPSE; LETO
 * is registered opt-in via `registry.register(Leto)`.
 *
 * Parameters:
 *
 *   P   = 2^551 + 335                (552-bit prime)
 *   Q   = 2^549 - 32999…831          (549-bit prime subgroup order)
 *   T   = 1319988…193101599660       (trace of Frobenius)
 *   R   = 4                          (cofactor)
 *   a   = 1,   d = -1874             (complete addition law)
 *   G   = (5, 45184880…91359909742186717128)
 *   S   = 545                        (safe-scalar bits → 2^545 ≈ 1.2×10¹⁶⁴ keys)
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Ellipse } from '../gen1/curve.js';

/**
 * LETO curve parameters. Permanently frozen.
 *
 * Key-space: 2^545 ≈ 1.15 × 10¹⁶⁴ unique scalars.
 */
export const LETO: Ellipse = (() => {
  const P = (1n << 551n) + 335n;
  const Q =
    (1n << 549n) -
    BigInt(
      '32999719876419924862440765771944715506860861139489669592317112655962' + '959048275399831',
    );
  const T = BigInt(
    '131998879505679699449763063087778862027443444557958678369268450623851' + '836193101599660',
  );
  // R = (P + 1 - T) / Q; must divide cleanly to 4. Verified at load time by the test suite.
  const R = (P + 1n - T) / Q;
  const gx = 5n;
  const gy = BigInt(
    '4518488039903337342061416616304793185577751419009710712882273229786958' +
      '1028679814685696327960107575063677021555101631924458963100250297992201' +
      '55797291359909742186717128',
  );
  return {
    name: 'LETO',
    p: P,
    q: Q,
    t: T,
    r: R,
    s: 545,
    a: 1n,
    d: -1874n,
    g: { ax: gx, ay: gy },
  };
})();
