/**
 * APOLLO — twin of ARTEMIS. Shares its prime P with ARTEMIS but uses
 * `d = -729` and a different (positive-sign) trace-residual, landing
 * at a full 1024-bit safe-scalar — one bit larger than ARTEMIS.
 *
 * Named after the god of sun, music, and prophecy — twin of Artemis,
 * born on Delos. The shared prime P with ARTEMIS is the mathematical
 * expression of their shared birthplace; the different D is what makes
 * them distinct curves.
 *
 * Go-reference identifier: `TEC_S1024_Pr1029p639_m729`.
 *
 * Same structural family as DALOS_ELLIPSE (Twisted Edwards, cofactor 4,
 * `y² + x² = 1 + d·x²·y²` over GF(P), with `d` negative). Ported here
 * for historical purposes — **not** intended for production use and
 * **not** registered as a DALOS primitive.
 *
 * Note: the original Go source contains a copy-paste bug (line 907)
 * setting `p.Name = "TEC_S1023_Pr1029p639_m200"` on this factory. The
 * TypeScript port preserves the **correct** identity under the name
 * `APOLLO`.
 *
 * Parameters:
 *
 *   P   = 2^1029 + 639               (1030-bit prime; shared with ARTEMIS)
 *   Q   = 2^1027 + 94182…581         (1028-bit prime subgroup order)
 *   T   = -37673…505684              (negative trace — accepted form)
 *   R   = 4                          (cofactor)
 *   a   = 1,   d = -729              (complete addition law)
 *   G   = (18, 21527836…31695734303)
 *   S   = 1024                       (safe-scalar bits → 2^1024 ≈ 1.8×10³⁰⁸ keys)
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Ellipse } from '../gen1/curve.js';

/**
 * APOLLO curve parameters. Permanently frozen.
 *
 * Key-space: 2^1024 ≈ 1.8 × 10³⁰⁸ unique scalars — double ARTEMIS's.
 */
export const APOLLO: Ellipse = (() => {
  const P = (1n << 1029n) + 639n;
  const Q =
    (1n << 1027n) +
    BigInt(
      '94182588406916610489586932808480513872092994081940890127750909796255' +
        '14940291099061879232380228215863338991692577868713164205283324554730' +
        '781862605682126581',
    );
  const T = BigInt(
    '-37673035362766644195834773123392205548837197632776356051100363918502' +
      '05976116439624751692952091286345335596677031147485265682113329821892' +
      '3127450422728505684',
  );
  // R = (P + 1 - T) / Q; must divide cleanly to 4. Verified at load time by the test suite.
  const R = (P + 1n - T) / Q;
  const gx = 18n;
  const gy = BigInt(
    '2152783699515714888969175961554043240260023021901818254316811758169978' +
      '5990936714365300057966665634445679225766960576258246861093075111570430' +
      '1503268336066379058325768607564533090162357247378501333085803173440477' +
      '9814554908887545388668236801291801249139081613913617731386343475153755' +
      '69488540295649449731695734303',
  );
  return {
    name: 'APOLLO',
    p: P,
    q: Q,
    t: T,
    r: R,
    s: 1024,
    a: 1n,
    d: -729n,
    g: { ax: gx, ay: gy },
  };
})();
