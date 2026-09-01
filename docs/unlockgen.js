/**
 * Generate unlock and flash codes for Huawei modems, dongles and routers.
 *
 * A direct port of `unlockgen.py`, kept deliberately close to it: same slot
 * decomposition, same names, same fixups. If the two ever disagree the Python
 * file is the reference — `tests/parity.mjs` checks that they do not.
 *
 *     V1       the oldest scheme: MD5 over the IMEI plus a hard coded salt.
 *     V2       a family of seven algorithms; the IMEI itself selects which one.
 *     V3/201   the same seven slots, but with different constants and variants.
 *     Flash    identical to V1, with the firmware-flashing salt instead.
 *
 * Runs anywhere with ES modules and no dependencies, browser or Node.
 */

import { ascii, concat, crc32, md5, sha1, toHex } from "./digest.js";

export const VERSION = "2.0.0";

export const IMEI_LENGTH = 15;
const CODE_LENGTH = 8;

const IMEI_RE = /^[0-9]{15}$/;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Salts baked into the V1 code generator, one per purpose.
const SALT_UNLOCK = ascii("hwe620datacard");
const SALT_FLASH = ascii("e630upgrade");

// Salts used by the "salted MD5" slot of the V2 / V3 families.
const SALT_V2 = ascii("hwideadatacard");
const SALT_V201 = ascii("dfkdkfllekkodk");

// Per-digit multipliers for the "weighted sum" slot.
const WEIGHTS_V2 = [
  0x01966a9, 0x021058f, 0x02aeda9, 0x037ce91, 0x0488c9f, 0x05e507d,
  0x07a9be5, 0x09f644b, 0x0cf35a1, 0x10d5f55, 0x15e2f25, 0x1c73d6b,
  0x24fcfdd, 0x3015b47, 0x3e829e9, 0x5143685,
];
const WEIGHTS_V201 = [
  0x06e9c2a, 0x3ca2b3c, 0x01080dc, 0x30855ee, 0x3d3283a, 0x2f4f85a,
  0x1f8808e, 0x3147d10, 0x34bbbb5, 0x29eeadd, 0x2318616, 0x50f3adc,
  0x0d11f38, 0x2123bd2, 0x4276c86, 0x355caad,
];

// AND-masks applied while scrambling the buffer in the "scrambled MD5" slot.
const SCRAMBLE_MASKS_V2 = [
  0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90,
];
const SCRAMBLE_MASKS_V201 = [
  0x0b, 0x0d, 0x11, 0x13, 0x17, 0x1d, 0x1f, 0x25, 0x29, 0x2b, 0x3b, 0x61,
];

// Digit substitution table for the "substitution cipher" slot. Indices run from
// 0 to 30, the widest value `(byte >> 4) + (byte & 0x0F)` can produce.
const SUBSTITUTION = "5739146280098765432112345678905";

// Huawei's own CRC-32 table. It reuses the values of the standard CRC-32 table
// but in a different, deliberately scrambled order, so it cannot be generated
// from the usual 0xEDB88320 polynomial and has to be embedded verbatim.
const CRC_TABLE_HUAWEI = Uint32Array.from([
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x196c3671,
  0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0xfbd44c65, 0x4db26158,
  0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d,
  0xd3d6f4fb, 0x4369e96a, 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
  0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb,
  0xf4d4b551, 0x83d385c7, 0x136c9856, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8,
  0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd,
  0xa50ab56b, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a, 0xc8d75180,
  0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0x706af48f, 0xe963a535,
  0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b,
  0x7eb17cbd, 0xe7b82d07, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x4969474d,
  0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53,
  0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330,
  0x24b4a3a6, 0xbad03605, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af,
  0x04db2615, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b,
  0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27,
  0x7d079eb1, 0xf00f9344, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0,
  0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226,
  0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f,
  0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010, 0x01db7106, 0x98d220bc,
  0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2,
  0x0f00f934, 0x9609a88e, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409,
  0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
  0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02,
  0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2eb40d81, 0xb7bd5c3b,
  0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43,
  0x60b08ed5, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d,
  0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 0xd70dd2ee, 0x4e048354,
  0x3903b3c2, 0xa7672661, 0xd06016f7, 0x2d02ef8d,
]);

// ---------------------------------------------------------------------------
// Small numeric helpers
// ---------------------------------------------------------------------------

/** Read a little endian 32 bit integer out of `data` at `offset`. */
function leUint32(data, offset) {
  return (
    (data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 24)) >>> 0
  );
}

/** Read a big endian 32 bit integer out of `data` at `offset`. */
function beUint32(data, offset) {
  return (
    ((data[offset] << 24) |
      (data[offset + 1] << 16) |
      (data[offset + 2] << 8) |
      data[offset + 3]) >>> 0
  );
}

/**
 * Fold a 16 byte digest into the 8 digit code used by V1, Flash and slot 3.
 *
 * The digest is treated as a 4x4 matrix; each column is XOR-folded into one
 * byte, the four bytes form a 32 bit number, and the top bits are forced so
 * that the result always lands in 0x2000000..0x3FFFFFF, i.e. exactly eight
 * decimal digits with no leading zero.
 */
function foldDigest(digest) {
  let code = 0;
  for (let i = 0; i < 4; i += 1) {
    code = ((code << 8) | (digest[i] ^ digest[i + 4] ^ digest[i + 8] ^ digest[i + 12])) >>> 0;
  }
  return String(((code & 0x01ffffff) | 0x02000000) >>> 0);
}

// ---------------------------------------------------------------------------
// V1 / Flash
// ---------------------------------------------------------------------------

/**
 * V1 code generator: MD5 of the IMEI plus a salt derived from `saltKey`.
 *
 * The salt is the middle 16 hex characters of `md5(saltKey)`.
 */
function saltedHexMd5(imei, saltKey) {
  const salt = ascii(toHex(md5(saltKey)).slice(8, 24));
  return foldDigest(md5(concat(imei, salt)));
}

// ---------------------------------------------------------------------------
// The seven V2 / V3 algorithm slots
// ---------------------------------------------------------------------------

/**
 * Slot 0: multiply every IMEI digit by a magic weight and read the nibbles.
 *
 * The 32 bit accumulator is sliced into eight nibbles (least significant
 * first) and each nibble is reduced modulo 10 to yield a decimal digit.
 */
function slotWeightedSum(imei, weights) {
  // The running sum stays well inside Number's exact integer range, so it can
  // be reduced modulo 2**32 once at the end rather than on every term.
  let sum = 0;
  for (let i = 0; i < weights.length && i < imei.length; i += 1) sum += imei[i] * weights[i];
  const total = sum % 0x100000000;

  const digits = [];
  for (let i = 0; i < CODE_LENGTH; i += 1) digits.push(((total >>> (4 * i)) & 0xf) % 10);
  if (digits[0] === 0) digits[0] = 1; // Codes must not start with a zero.
  return digits.join("");
}

/**
 * Slot 1: take a CRC-32 of the IMEI and use its last eight decimal digits.
 *
 * V2 uses the standard CRC-32; V3 uses Huawei's table. Short values are left
 * padded with nines rather than zeros, and a leading zero is rewritten to a
 * nine, so the code is always eight digits.
 */
function slotCrc32(imei, huaweiTable) {
  const crc = huaweiTable ? crc32(imei, CRC_TABLE_HUAWEI) : crc32(imei);

  // Huawei reads the checksum as a signed integer and takes its magnitude.
  const value = Math.abs(crc | 0);
  if (value === 0) return "9".repeat(CODE_LENGTH);

  let code = String(value).slice(-CODE_LENGTH);
  if (code[0] === "0") code = `9${code.slice(1)}`;
  return code.padStart(CODE_LENGTH, "9");
}

/**
 * Slot 2: read eight bytes out of `md5(imei)` and coerce them to digits.
 *
 * A byte that already happens to be the ASCII code of a digit is used as that
 * character; anything else is reduced modulo 10.
 */
function slotMd5Digits(imei, offset) {
  const window = md5(imei).subarray(offset, offset + CODE_LENGTH);

  const first = window[0] % 10;
  const code = [first ? String(first) : "5"];
  for (let i = 1; i < window.length; i += 1) {
    const byte = window[i];
    code.push(byte >= 0x30 && byte <= 0x39 ? String.fromCharCode(byte) : String(byte % 10));
  }
  return code.join("");
}

/** Slot 3: like V1, but the salt is the raw `md5(saltKey)` digest. */
function slotSaltedMd5(imei, saltKey) {
  return foldDigest(md5(concat(imei, md5(saltKey))));
}

/**
 * Slot 4: XOR the two halves of the IMEI and map the result through a table.
 *
 * The IMEI is 15 digits, so a filler character is appended to give the second
 * half its eighth byte.
 */
function slotSubstitution(imei) {
  const padded = concat(imei, ascii("Z"));
  const code = [];
  for (let i = 0; i < CODE_LENGTH; i += 1) {
    const mixed = padded[i] ^ padded[i + 8];
    code.push(Number(SUBSTITUTION[(mixed >> 4) + (mixed & 0x0f)]));
  }

  if (code[0] === 0) {
    // Replace a leading zero with the position of the first non-zero digit,
    // falling back to 7 when every digit is zero.
    const firstNonZero = code.findIndex((digit) => digit !== 0);
    code[0] = firstNonZero === -1 ? 7 : firstNonZero;
  }
  return code.join("");
}

/**
 * Slot 5: concatenate two of the five 32 bit words of `sha1(imei)`.
 *
 * Which two words are used is what distinguishes the three variants of this
 * slot; the decimal concatenation is then truncated or zero padded to eight
 * digits.
 */
function slotSha1(imei, [firstWord, secondWord]) {
  const digest = sha1(imei);
  const joined = `${beUint32(digest, firstWord * 4)}${beUint32(digest, secondWord * 4)}`;
  return joined.slice(0, CODE_LENGTH).padEnd(CODE_LENGTH, "0");
}

/**
 * Slot 6: scramble the IMEI into a 128 byte buffer, then hash it.
 *
 * Three stages:
 *
 * 1. Each IMEI byte is bit-rotated by an amount that cycles with its position.
 * 2. The 15 byte result is grown to 128 bytes; every new byte mixes three
 *    earlier bytes, two of them chosen by a checksum of the rotated IMEI.
 * 3. The buffer is MD5'd and eight decimal digits are harvested from the
 *    digest, topped up from a 32 bit slice of the digest when the digest does
 *    not contain eight ASCII digits of its own.
 *
 * Stage 2 is a direct transcription of compiled ARM code; the original used
 * magic-number division, which is spelled out here as ordinary arithmetic.
 */
function slotScrambledMd5(imei, masks) {
  const buffer = new Uint8Array(128);
  for (let i = 0; i < imei.length; i += 1) {
    const byte = imei[i];
    const rotation = i % 3;
    if (rotation === 0) buffer[i] = ((byte << 6) | (byte >> 2)) & 0xff;
    else if (rotation === 1) buffer[i] = ((byte << 5) | (byte >> 3)) & 0xff;
    else buffer[i] = ((byte >> 4) | (byte << 4)) & 0xff;
  }

  // Big endian checksum over the rotated bytes; it steers the mixing below.
  let mixer = buffer[8];
  for (let i = 0; i < 7; i += 1) mixer += buffer[14 - i] + (buffer[i] << 8);

  for (let pos = IMEI_LENGTH; pos < 128; pos += 1) {
    const age = pos - IMEI_LENGTH;
    const quotient = Math.floor(pos / 12);
    const remainder = pos % 12;

    let maskIndex = quotient + remainder;
    if (maskIndex > 11) maskIndex -= 12;

    let source = quotient + (age % 12);
    if (quotient > 1) source += 12 * quotient - 24;

    const near = mixer % pos;
    const far = age === 0 ? near + 1 : mixer % age;
    const merged = (buffer[source] & masks[maskIndex]) | buffer[near];
    buffer[pos] = (~buffer[far] | merged) & 0xff;
  }

  const digest = md5(buffer);

  // A second, independent checksum, this time over the raw IMEI.
  let checksum = imei[14];
  for (let i = 0; i < 7; i += 1) checksum += (imei[i] << 8) | imei[i + 1];

  const code = [];
  for (const byte of digest) {
    if (code.length === CODE_LENGTH) break;
    if (byte >= 0x30 && byte <= 0x39) code.push(String.fromCharCode(byte));
  }

  // Top the code up with digits taken from the back of a 32 bit slice of the
  // digest, switching to the mirrored slice if the first one runs out.
  let spare = String(leUint32(digest, (checksum & 3) << 2));
  while (code.length < CODE_LENGTH) {
    code.push(spare[spare.length - 1]);
    spare = spare.slice(0, -1);
    if (!spare) spare = String(leUint32(digest, (3 - (checksum & 3)) << 2));
  }

  if (code[0] === "0") code[0] = String((digest[checksum ? 1 : 0] & 7) + 1);
  return code.join("");
}

// ---------------------------------------------------------------------------
// Algorithm selection
// ---------------------------------------------------------------------------

// Slot 5 exists in three flavours that differ only in which SHA-1 words they
// concatenate: V2 uses the first two, V3 uses two other pairs.
const SHA1_WORDS_A = [0, 1];
const SHA1_WORDS_B = [1, 4];
const SHA1_WORDS_C = [2, 3];

const ALGORITHMS_V2 = [
  (imei) => slotWeightedSum(imei, WEIGHTS_V2),
  (imei) => slotCrc32(imei, false),
  (imei) => slotMd5Digits(imei, 0),
  (imei) => slotSaltedMd5(imei, SALT_V2),
  slotSubstitution,
  (imei) => slotSha1(imei, SHA1_WORDS_A),
  (imei) => slotScrambledMd5(imei, SCRAMBLE_MASKS_V2),
];

const ALGORITHMS_V3 = [
  (imei) => slotWeightedSum(imei, WEIGHTS_V201),
  (imei) => slotCrc32(imei, true),
  (imei) => slotMd5Digits(imei, 5),
  (imei) => slotSaltedMd5(imei, SALT_V201),
  (imei) => slotSha1(imei, SHA1_WORDS_B),
  (imei) => slotSha1(imei, SHA1_WORDS_C),
  (imei) => slotScrambledMd5(imei, SCRAMBLE_MASKS_V201),
];

/** Pick which of the seven V2 slots this IMEI uses. */
function selectV2(imei) {
  let total = 0;
  for (let i = 1; i <= imei.length; i += 1) total += (imei[i - 1] + i) * i;
  return total % 7;
}

/** Pick which of the seven V3 slots this IMEI uses. */
function selectV3(imei) {
  let total = 0;
  for (let i = 1; i <= imei.length; i += 1) {
    const byte = imei[i - 1];
    total += (byte + i) * byte * (byte + 313);
  }
  return total % 7;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Thrown when the supplied IMEI is not exactly 15 decimal digits. */
export class InvalidIMEIError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidIMEIError";
  }
}

/**
 * The code generations this tool knows how to produce. Each value is the label
 * used in the interface and as the key returned by `generateAll`, matching the
 * Python `--json` output exactly.
 */
export const Version = Object.freeze({
  V1: "V1",
  V2: "V2",
  V3: "V3/201",
  FLASH: "Flash",
});

const GENERATORS = new Map([
  [Version.V1, (imei) => saltedHexMd5(imei, SALT_UNLOCK)],
  [Version.V2, (imei) => ALGORITHMS_V2[selectV2(imei)](imei)],
  [Version.V3, (imei) => ALGORITHMS_V3[selectV3(imei)](imei)],
  [Version.FLASH, (imei) => saltedHexMd5(imei, SALT_FLASH)],
]);

// Everything callers have historically passed as a "version", mapped onto the
// labels: the CLI names, the legacy integers and the "201" alias for V3.
const VERSION_ALIASES = new Map([
  [1, Version.V1], ["1", Version.V1], ["v1", Version.V1],
  [2, Version.V2], ["2", Version.V2], ["v2", Version.V2],
  [3, Version.V3], ["3", Version.V3], ["v3", Version.V3],
  [201, Version.V3], ["201", Version.V3], ["v201", Version.V3],
  ["flash", Version.FLASH],
]);

function coerceVersion(version) {
  if (GENERATORS.has(version)) return version;
  const key = typeof version === "string" ? version.toLowerCase() : version;
  const resolved = VERSION_ALIASES.get(key);
  if (resolved === undefined) throw new Error(`unknown unlock code version: ${version}`);
  return resolved;
}

/** True if `imei` is exactly 15 ASCII decimal digits. */
export function isValidIMEI(imei) {
  return typeof imei === "string" && IMEI_RE.test(imei);
}

/**
 * True if the IMEI's trailing Luhn check digit is consistent.
 *
 * Codes are derived from the digits alone, so a bad check digit does not stop
 * generation; it is a useful hint that the IMEI was mistyped.
 */
export function hasValidLuhn(imei) {
  let total = 0;
  for (let position = 0; position < imei.length; position += 1) {
    let digit = imei.charCodeAt(imei.length - 1 - position) - 48;
    if (position % 2) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    total += digit;
  }
  return total % 10 === 0;
}

function encode(imei) {
  if (!isValidIMEI(imei)) {
    throw new InvalidIMEIError(`expected ${IMEI_LENGTH} decimal digits, got ${JSON.stringify(imei)}`);
  }
  return ascii(imei);
}

/**
 * Return the eight digit code of one `version` for `imei`.
 *
 *     unlock("490154203237518", Version.V2)  // "29965404"
 *     unlock("490154203237518", 1)           // "49212137"
 */
export function unlock(imei, version = Version.V2) {
  return GENERATORS.get(coerceVersion(version))(encode(imei));
}

/**
 * Return every code for `imei`, keyed by version label.
 *
 * Computing all four costs barely more than computing one, and which version a
 * device accepts is not knowable from the IMEI alone.
 *
 *     generateAll("490154203237518")["V3/201"]  // "18625085"
 */
export function generateAll(imei) {
  const encoded = encode(imei);
  const codes = {};
  for (const [version, generate] of GENERATORS) codes[version] = generate(encoded);
  return codes;
}

/**
 * Implementation details, exported only so the test vectors can address
 * individual slots and selectors the way the Python self-test does.
 */
export const internals = Object.freeze({
  ALGORITHMS_V2,
  ALGORITHMS_V3,
  selectV2,
  selectV3,
});
