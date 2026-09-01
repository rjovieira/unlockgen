/**
 * The hash and checksum primitives the Huawei code generators are built on.
 *
 * Everything here operates on `Uint8Array` and returns `Uint8Array`, so the
 * generators can hash raw scrambled buffers, not just text. MD5 is implemented
 * by hand because `crypto.subtle` does not offer it, and SHA-1 follows so the
 * whole library stays synchronous and usable outside a secure context.
 *
 * These are compatibility primitives, reimplemented because the device firmware
 * uses them. Neither is fit for new security work.
 */

// ---------------------------------------------------------------------------
// MD5
// ---------------------------------------------------------------------------

// Per-round left-rotation amounts.
const MD5_SHIFTS = Int32Array.from([
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);

// floor(abs(sin(i + 1)) * 2**32), spelled out rather than recomputed so the
// table cannot drift with the platform's sine implementation.
const MD5_SINE = Uint32Array.from([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

const rotl32 = (value, bits) => (value << bits) | (value >>> (32 - bits));

/**
 * Pad a message the way both MD5 and SHA-1 do: a 0x80 byte, zeroes, then the
 * bit length. MD5 writes that length little endian, SHA-1 big endian.
 */
function padMessage(message, littleEndian) {
  const blockCount = Math.floor(message.length / 64) + (message.length % 64 < 56 ? 1 : 2);
  const padded = new Uint8Array(blockCount * 64);
  padded.set(message);
  padded[message.length] = 0x80;

  // Messages here are short enough that the high half of the 64 bit length is
  // always zero, but write both halves anyway.
  const bitLength = message.length * 8;
  const view = new DataView(padded.buffer);
  const tail = padded.length - 8;
  if (littleEndian) {
    view.setUint32(tail, bitLength >>> 0, true);
    view.setUint32(tail + 4, Math.floor(bitLength / 0x100000000), true);
  } else {
    view.setUint32(tail, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(tail + 4, bitLength >>> 0, false);
  }
  return padded;
}

/** MD5 digest of `message`, as 16 bytes. */
export function md5(message) {
  const padded = padMessage(message, true);
  const view = new DataView(padded.buffer);
  const block = new Int32Array(16);

  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) block[i] = view.getUint32(offset + i * 4, true);

    let [a, b, c, d] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i += 1) {
      let mixed;
      let index;
      if (i < 16) {
        mixed = (b & c) | (~b & d);
        index = i;
      } else if (i < 32) {
        mixed = (d & b) | (~d & c);
        index = (5 * i + 1) % 16;
      } else if (i < 48) {
        mixed = b ^ c ^ d;
        index = (3 * i + 5) % 16;
      } else {
        mixed = c ^ (b | ~d);
        index = (7 * i) % 16;
      }

      const rotated = rotl32((a + mixed + MD5_SINE[i] + block[index]) | 0, MD5_SHIFTS[i]);
      [a, d, c, b] = [d, c, b, (b + rotated) | 0];
    }

    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  const digest = new Uint8Array(16);
  const out = new DataView(digest.buffer);
  out.setUint32(0, a0 >>> 0, true);
  out.setUint32(4, b0 >>> 0, true);
  out.setUint32(8, c0 >>> 0, true);
  out.setUint32(12, d0 >>> 0, true);
  return digest;
}

// ---------------------------------------------------------------------------
// SHA-1
// ---------------------------------------------------------------------------

/** SHA-1 digest of `message`, as 20 bytes. */
export function sha1(message) {
  const padded = padMessage(message, false);
  const view = new DataView(padded.buffer);
  const schedule = new Int32Array(80);

  const state = Int32Array.from([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) schedule[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 80; i += 1) {
      schedule[i] = rotl32(
        schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1,
      );
    }

    let [a, b, c, d, e] = state;
    for (let i = 0; i < 80; i += 1) {
      let mixed;
      let constant;
      if (i < 20) {
        mixed = (b & c) | (~b & d);
        constant = 0x5a827999;
      } else if (i < 40) {
        mixed = b ^ c ^ d;
        constant = 0x6ed9eba1;
      } else if (i < 60) {
        mixed = (b & c) | (b & d) | (c & d);
        constant = 0x8f1bbcdc;
      } else {
        mixed = b ^ c ^ d;
        constant = 0xca62c1d6;
      }

      const next = (rotl32(a, 5) + mixed + e + constant + schedule[i]) | 0;
      [e, d, c, b, a] = [d, c, rotl32(b, 30), a, next];
    }

    state[0] = (state[0] + a) | 0;
    state[1] = (state[1] + b) | 0;
    state[2] = (state[2] + c) | 0;
    state[3] = (state[3] + d) | 0;
    state[4] = (state[4] + e) | 0;
  }

  const digest = new Uint8Array(20);
  const out = new DataView(digest.buffer);
  for (let i = 0; i < 5; i += 1) out.setUint32(i * 4, state[i] >>> 0, false);
  return digest;
}

// ---------------------------------------------------------------------------
// CRC-32
// ---------------------------------------------------------------------------

// The textbook table, generated once from the 0xEDB88320 polynomial. Huawei's
// deliberately scrambled table lives in unlockgen.js, next to the slot that
// needs it.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[i] = value >>> 0;
  }
  return table;
})();

/**
 * CRC-32 of `message`, as an unsigned 32 bit number.
 *
 * The table is a parameter because the V3 generator feeds in Huawei's own,
 * differently ordered table; everything else about the computation is the same.
 */
export function crc32(message, table = CRC_TABLE) {
  let crc = 0xffffffff;
  for (const byte of message) crc = table[(crc & 0xff) ^ byte] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const HEX = "0123456789abcdef";

/** Lowercase hexadecimal rendering of a byte string. */
export function toHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += HEX[byte >> 4] + HEX[byte & 0x0f];
  return hex;
}

/** ASCII bytes of `text`. Only ever called with ASCII literals. */
export function ascii(text) {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i) & 0x7f;
  return bytes;
}

/** Concatenate byte strings. */
export function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}
