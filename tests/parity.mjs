#!/usr/bin/env node
/**
 * Check that the browser port agrees with `unlockgen.py`.
 *
 * Two passes:
 *
 *   1. The vectors that ship in both implementations, run against the JS.
 *   2. A batch of pseudo-random IMEIs generated here, run through *both* the
 *      JS module and the Python script, comparing all four codes each time.
 *
 * The second pass is the one that matters: the four codes fan out across
 * fourteen slots, so a few thousand IMEIs exercise every branch many times.
 *
 *     node tests/parity.mjs [count]
 */

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { generateAll, hasValidLuhn, unlock, Version } from "../docs/unlockgen.js";
import { END_TO_END_VECTORS, SELECTOR_VECTORS, SLOT_VECTORS } from "../docs/vectors.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PYTHON = process.env.PYTHON ?? "python3";
const COUNT = Number(process.argv[2] ?? 2000);

let checks = 0;
let failures = 0;

function check(label, actual, expected) {
  checks += 1;
  if (actual !== expected) {
    failures += 1;
    console.error(`FAIL ${label}: got ${actual}, expected ${expected}`);
  }
}

// --- Pass 1: the shared vectors -------------------------------------------

const encode = (imei) => Uint8Array.from(imei, (character) => character.charCodeAt(0));

for (const [label, algorithm, imei, expected] of SLOT_VECTORS) {
  check(`${label} ${imei}`, algorithm(encode(imei)), expected);
}
for (const [label, selector, imei, expected] of SELECTOR_VECTORS) {
  check(`${label} ${imei}`, selector(encode(imei)), expected);
}
for (const [imei, codes] of END_TO_END_VECTORS) {
  for (const [version, expected] of Object.entries(codes)) {
    check(`${version} ${imei}`, unlock(imei, version), expected);
  }
}

// Luhn, on the documentation IMEI and on a deliberate typo of it.
check("luhn valid", hasValidLuhn("490154203237518"), true);
check("luhn invalid", hasValidLuhn("490154203237519"), false);

// --- Pass 2: differential test against the Python implementation -----------

/** Deterministic 32 bit PRNG, so a failure is always reproducible. */
function* randomIMEIs(count, seed = 0x5eed1234) {
  let state = seed >>> 0;
  const next = () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return state;
  };
  for (let i = 0; i < count; i += 1) {
    let imei = "";
    while (imei.length < 15) imei += String(next() % 10);
    yield imei;
  }
}

const imeis = [...randomIMEIs(COUNT)];

// One Python process for the whole batch: it reads IMEIs on stdin and prints
// "imei v1 v2 v3 flash" per line.
const script = `
import sys
sys.path.insert(0, ${JSON.stringify(ROOT)})
from unlockgen import Version, generate_all
for line in sys.stdin:
    imei = line.strip()
    if not imei:
        continue
    codes = generate_all(imei)
    print(imei, *(codes[v] for v in Version))
`;

let reference;
try {
  const stdout = execFileSync(PYTHON, ["-c", script], {
    input: imeis.join("\n"),
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  reference = stdout.trim().split("\n");
} catch (error) {
  console.error(`Could not run the Python reference with '${PYTHON}': ${error.message}`);
  console.error("Set PYTHON=/path/to/python3 to point at a different interpreter.");
  process.exit(2);
}

const ORDER = [Version.V1, Version.V2, Version.V3, Version.FLASH];

for (const line of reference) {
  const [imei, ...expected] = line.split(" ");
  const codes = generateAll(imei);
  ORDER.forEach((version, index) => {
    check(`${version} ${imei}`, codes[version], expected[index]);
    if (!/^[1-9][0-9]{7}$/.test(codes[version])) {
      failures += 1;
      console.error(`FAIL ${version} ${imei}: ${codes[version]} is not 8 digits without a leading zero`);
    }
  });
}

if (reference.length !== imeis.length) {
  failures += 1;
  console.error(`FAIL: Python returned ${reference.length} lines for ${imeis.length} IMEIs`);
}

if (failures) {
  console.error(`${failures} of ${checks} checks failed.`);
  process.exit(1);
}
console.log(`All ${checks} checks passed (${imeis.length} IMEIs cross-checked against unlockgen.py).`);
