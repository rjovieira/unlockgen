/**
 * The test vectors from `unlockgen.py`, in the same order.
 *
 * They are a module of their own because both the in-page self test and the
 * Node runner (`tests/parity.mjs`) consume them.
 */

import { Version, internals } from "./unlockgen.js";

const { ALGORITHMS_V2, ALGORITHMS_V3, selectV2, selectV3 } = internals;

/** [label, algorithm, IMEI, expected code] — every slot, including the awkward branches. */
export const SLOT_VECTORS = [
  ["V3 slot 0", ALGORITHMS_V3[0], "166794546749343", "31572464"],

  ["V2 slot 1", ALGORITHMS_V2[1], "867010022091625", "89740701"],
  ["V2 slot 1", ALGORITHMS_V2[1], "867010022093346", "90496577"],
  ["V3 slot 1", ALGORITHMS_V3[1], "867010022091336", "43479313"],
  ["V3 slot 1", ALGORITHMS_V3[1], "486043736169958", "20766653"],
  ["V3 slot 1", ALGORITHMS_V3[1], "152782107774300", "99353390"],

  ["V2 slot 2", ALGORITHMS_V2[2], "867010022091626", "55760904"],
  ["V2 slot 2", ALGORITHMS_V2[2], "867010022091545", "77395563"],
  ["V3 slot 2", ALGORITHMS_V3[2], "867010022091566", "98820346"],
  ["V3 slot 2", ALGORITHMS_V3[2], "133887909865624", "13553393"],

  ["V2 slot 3", ALGORITHMS_V2[3], "867010022091677", "50284150"],
  ["V3 slot 3", ALGORITHMS_V3[3], "867010022091677", "48425064"],

  ["V2 slot 4", ALGORITHMS_V2[4], "867010022091661", "16672676"],
  ["V2 slot 4", ALGORITHMS_V2[4], "867010022091698", "16672086"],

  ["V2 slot 5", ALGORITHMS_V2[5], "867010022091692", "16678430"],
  ["V3 slot 4", ALGORITHMS_V3[4], "867010022091696", "26958384"],
  ["V3 slot 5", ALGORITHMS_V3[5], "867010022091697", "11406485"],

  ["V2 slot 6", ALGORITHMS_V2[6], "867010022093344", "41232318"],
  ["V2 slot 6", ALGORITHMS_V2[6], "234242342432305", "68014899"],
  ["V2 slot 6", ALGORITHMS_V2[6], "221724677371250", "92023179"],
  ["V3 slot 6", ALGORITHMS_V3[6], "867010022093350", "13122759"],
];

/** [label, selector, IMEI, expected slot] */
export const SELECTOR_VECTORS = [
  ["selectV3", selectV3, "667010022091624", 2],
  ["selectV3", selectV3, "867010022091624", 3],
  ["selectV2", selectV2, "867010022091624", 0],
];

/**
 * End to end regression vectors. The IMEI here is the public documentation
 * example, not a real device: an unlock code plus a known model narrows the
 * IMEI down to a brute-forceable range, so real IMEIs do not belong in source.
 */
export const END_TO_END_VECTORS = [
  ["490154203237518", {
    [Version.V1]: "49212137",
    [Version.V2]: "29965404",
    [Version.V3]: "18625085",
    [Version.FLASH]: "50799099",
  }],
];
