/**
 * ARTEMIS — mid-scale Kjrekntolopon novel twisted-Edwards curve from the
 * Cryptoplasm research phase. Twin sister of APOLLO: they share the
 * same underlying prime P, differ only in `d` and consequently in Q.
 *
 * Named after the goddess of the hunt, twin of Apollo, born on Delos
 * — a direct nod to the shared-prime / divergent-D "twin" relationship
 * between this curve and APOLLO.
 *
 * ARTEMIS is the slightly-smaller twin (1023-bit safe scalar vs APOLLO's
 * 1024-bit) — fitting the myth where Artemis was traditionally born
 * moments before her brother, then helped Leto deliver him.
 *
 * Go-reference identifier: `TEC_S1023_Pr1029p639_m200`.
 *
 * Same structural family as DALOS_ELLIPSE (Twisted Edwards, cofactor 4,
 * `y² + x² = 1 + d·x²·y²` over GF(P), with `d` negative). Ported here
 * for historical purposes — **not** intended for production use and
 * **not** registered as a DALOS primitive.
 *
 * Parameters:
 *
 *   P   = 2^1029 + 639               (1030-bit prime; shared with APOLLO)
 *   Q   = 2^1027 - 13048…995         (1027-bit prime subgroup order)
 *   T   = 52195241…998134944620      (trace of Frobenius)
 *   R   = 4                          (cofactor)
 *   a   = 1,   d = -200              (complete addition law)
 *   G   = (18, 50063925…07870067300616902)
 *   S   = 1023                       (safe-scalar bits → 2^1023 ≈ 9.0×10³⁰⁷ keys)
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Ellipse } from '../gen1/curve.js';

/**
 * ARTEMIS curve parameters. Permanently frozen.
 *
 * Key-space: 2^1023 ≈ 9.0 × 10³⁰⁷ unique scalars.
 */
export const ARTEMIS: Ellipse = (() => {
  const P = (1n << 1029n) + 639n;
  const Q =
    (1n << 1027n) -
    BigInt(
      '13048810356164098687722578038659254541745638134607534327178785488911' +
        '85145122572949417499087132624481807306672720743157724259550505283106' +
        '7258628249533735995',
    );
  const T = BigInt(
    '52195241424656394750890312154637018166982552538430137308715141955647' +
      '40580490291797669996348530497927229226690882972630897038202021132426' +
      '9034512998134944620',
  );
  // R = (P + 1 - T) / Q; must divide cleanly to 4. Verified at load time by the test suite.
  const R = (P + 1n - T) / Q;
  const gx = 18n;
  const gy = BigInt(
    '5006392512810367543241026017186205828475671321699765938632799901604288' +
      '4136700612601054876476635365680222304796381390103513356654701737127182' +
      '9883753063394589992386930211092139069128006391733774910219808654610968' +
      '3731403172016859789550276802795383170944526602213977392860793115308281' +
      '053135496569817870067300616902',
  );
  return {
    name: 'ARTEMIS',
    p: P,
    q: Q,
    t: T,
    r: R,
    s: 1023,
    a: 1n,
    d: -200n,
    g: { ax: gx, ay: gy },
  };
})();
