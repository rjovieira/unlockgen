#!/usr/bin/env python3
"""Generate unlock and flash codes for Huawei modems, dongles and routers.

Huawei ships several generations of code-generation algorithms. Each one turns
the device IMEI into an eight digit code; which generation a given device
accepts depends on its firmware, so this tool prints every candidate and lets
the operator try them.

    V1       the oldest scheme: MD5 over the IMEI plus a hard coded salt.
    V2       a family of seven algorithms; the IMEI itself selects which one.
    V3/201   the same seven slots, but with different constants and variants.
    Flash    identical to V1, with the firmware-flashing salt instead.

Usage:
    python unlockgen.py 490154203237518
    python unlockgen.py 490154203237518 --json
    python unlockgen.py --test

Original algorithm research by the Huawei modem unlocking community; this file
is a modernised, Python 3 rewrite of the widely circulated ``unlockgen.py``
script.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import re
import sys
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Callable, Iterable, Sequence

__version__ = "2.0.0"
__all__ = ["Version", "InvalidIMEIError", "unlock", "generate_all", "is_valid_imei"]

IMEI_LENGTH = 15
CODE_LENGTH = 8

_IMEI_RE = re.compile(r"\A[0-9]{15}\Z")

# An algorithm implementation takes the IMEI as ASCII bytes and returns the
# eight digit code as a string.
Algorithm = Callable[[bytes], str]


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Salts baked into the V1 code generator, one per purpose.
_SALT_UNLOCK = b"hwe620datacard"
_SALT_FLASH = b"e630upgrade"

# Salts used by the "salted MD5" slot of the V2 / V3 families.
_SALT_V2 = b"hwideadatacard"
_SALT_V201 = b"dfkdkfllekkodk"

# Per-digit multipliers for the "weighted sum" slot.
_WEIGHTS_V2 = (
    0x01966A9, 0x021058F, 0x02AEDA9, 0x037CE91, 0x0488C9F, 0x05E507D,
    0x07A9BE5, 0x09F644B, 0x0CF35A1, 0x10D5F55, 0x15E2F25, 0x1C73D6B,
    0x24FCFDD, 0x3015B47, 0x3E829E9, 0x5143685,
)
_WEIGHTS_V201 = (
    0x06E9C2A, 0x3CA2B3C, 0x01080DC, 0x30855EE, 0x3D3283A, 0x2F4F85A,
    0x1F8808E, 0x3147D10, 0x34BBBB5, 0x29EEADD, 0x2318616, 0x50F3ADC,
    0x0D11F38, 0x2123BD2, 0x4276C86, 0x355CAAD,
)

# AND-masks applied while scrambling the buffer in the "scrambled MD5" slot.
_SCRAMBLE_MASKS_V2 = (
    0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0D, 0x15, 0x22, 0x37, 0x59, 0x90,
)
_SCRAMBLE_MASKS_V201 = (
    0x0B, 0x0D, 0x11, 0x13, 0x17, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x3B, 0x61,
)

# Digit substitution table for the "substitution cipher" slot. Indices run from
# 0 to 30, the widest value ``(byte >> 4) + (byte & 0x0F)`` can produce.
_SUBSTITUTION = "5739146280098765432112345678905"

# Huawei's own CRC-32 table. It reuses the values of the standard CRC-32 table
# but in a different, deliberately scrambled order, so it cannot be generated
# from the usual 0xEDB88320 polynomial and has to be embedded verbatim.
_CRC_TABLE = (
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x196C3671,
    0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0xFBD44C65, 0x4DB26158,
    0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D,
    0xD3D6F4FB, 0x4369E96A, 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C,
    0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB,
    0xF4D4B551, 0x83D385C7, 0x136C9856, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8,
    0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD,
    0xA50AB56B, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A, 0xC8D75180,
    0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0x706AF48F, 0xE963A535,
    0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B,
    0x7EB17CBD, 0xE7B82D07, 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x4969474D,
    0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53,
    0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330,
    0x24B4A3A6, 0xBAD03605, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF,
    0x04DB2615, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B,
    0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27,
    0x7D079EB1, 0xF00F9344, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0,
    0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226,
    0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F,
    0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010, 0x01DB7106, 0x98D220BC,
    0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2,
    0x0F00F934, 0x9609A88E, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
    0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17,
    0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02,
    0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2EB40D81, 0xB7BD5C3B,
    0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43,
    0x60B08ED5, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D,
    0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242, 0xD70DD2EE, 0x4E048354,
    0x3903B3C2, 0xA7672661, 0xD06016F7, 0x2D02EF8D,
)


# --------------------------------------------------------------------------- #
# Small numeric helpers
# --------------------------------------------------------------------------- #

def _as_signed32(value: int) -> int:
    """Reinterpret a 32 bit unsigned integer as a two's complement signed one."""
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def _le_uint32(data: bytes, offset: int) -> int:
    """Read a little endian 32 bit integer out of ``data`` at ``offset``."""
    return int.from_bytes(data[offset:offset + 4], "little")


def _fold_digest(digest: bytes) -> str:
    """Fold a 16 byte digest into the 8 digit code used by V1, Flash and slot 4.

    The digest is treated as a 4x4 matrix; each column is XOR-folded into one
    byte, the four bytes form a 32 bit number, and the top bits are forced so
    that the result always lands in 0x2000000..0x3FFFFFF, i.e. exactly eight
    decimal digits with no leading zero.
    """
    code = 0
    for i in range(4):
        code = (code << 8) | (digest[i] ^ digest[i + 4] ^ digest[i + 8] ^ digest[i + 12])
    return str((code & 0x01FF_FFFF) | 0x0200_0000)


# --------------------------------------------------------------------------- #
# V1 / Flash
# --------------------------------------------------------------------------- #

def _salted_hex_md5(imei: bytes, salt_key: bytes) -> str:
    """V1 code generator: MD5 of the IMEI plus a salt derived from ``salt_key``.

    The salt is the middle 16 hex characters of ``md5(salt_key)``.
    """
    salt = hashlib.md5(salt_key).hexdigest()[8:24].encode("ascii")
    return _fold_digest(hashlib.md5(imei + salt).digest())


# --------------------------------------------------------------------------- #
# The seven V2 / V3 algorithm slots
# --------------------------------------------------------------------------- #

def _slot_weighted_sum(imei: bytes, weights: Sequence[int]) -> str:
    """Slot 0: multiply every IMEI digit by a magic weight and read the nibbles.

    The 32 bit accumulator is sliced into eight nibbles (least significant
    first) and each nibble is reduced modulo 10 to yield a decimal digit.
    """
    total = sum(digit * weight for digit, weight in zip(imei, weights)) & 0xFFFF_FFFF
    digits = [((total >> (4 * i)) & 0xF) % 10 for i in range(CODE_LENGTH)]
    if digits[0] == 0:
        digits[0] = 1  # Codes must not start with a zero.
    return "".join(map(str, digits))


def _huawei_crc32(imei: bytes) -> int:
    """CRC-32 over the IMEI using Huawei's scrambled table (V3 only)."""
    crc = 0xFFFF_FFFF
    table = _CRC_TABLE
    for byte in imei:
        crc = table[(crc & 0xFF) ^ byte] ^ (crc >> 8)
    return crc


def _slot_crc32(imei: bytes, huawei_table: bool) -> str:
    """Slot 1: take a CRC-32 of the IMEI and use its last eight decimal digits.

    V2 uses the standard CRC-32; V3 uses Huawei's table and inverts the result.
    Short values are left padded with nines rather than zeros, and a leading
    zero is rewritten to a nine, so the code is always eight digits.
    """
    if huawei_table:
        crc = _huawei_crc32(imei) ^ 0xFFFF_FFFF
    else:
        crc = binascii.crc32(imei) & 0xFFFF_FFFF

    value = abs(_as_signed32(crc))
    if value == 0:
        return "9" * CODE_LENGTH

    code = str(value)[-CODE_LENGTH:]
    if code[0] == "0":
        code = "9" + code[1:]
    return code.rjust(CODE_LENGTH, "9")


def _slot_md5_digits(imei: bytes, offset: int) -> str:
    """Slot 2: read eight bytes out of ``md5(imei)`` and coerce them to digits.

    A byte that already happens to be the ASCII code of a digit is used as that
    character; anything else is reduced modulo 10.
    """
    window = hashlib.md5(imei).digest()[offset:offset + CODE_LENGTH]

    first = window[0] % 10
    code = [str(first) if first else "5"]
    for byte in window[1:]:
        code.append(chr(byte) if 0x30 <= byte <= 0x39 else str(byte % 10))
    return "".join(code)


def _slot_salted_md5(imei: bytes, salt_key: bytes) -> str:
    """Slot 3: like V1, but the salt is the raw ``md5(salt_key)`` digest."""
    salt = hashlib.md5(salt_key).digest()
    return _fold_digest(hashlib.md5(imei + salt).digest())


def _slot_substitution(imei: bytes) -> str:
    """Slot 4: XOR the two halves of the IMEI and map the result through a table.

    The IMEI is 15 digits, so a filler character is appended to give the second
    half its eighth byte.
    """
    padded = imei + b"Z"
    code = [
        int(_SUBSTITUTION[(mixed >> 4) + (mixed & 0x0F)])
        for mixed in (padded[i] ^ padded[i + 8] for i in range(CODE_LENGTH))
    ]

    if code[0] == 0:
        # Replace a leading zero with the position of the first non-zero digit,
        # falling back to 7 when every digit is zero.
        code[0] = next((i for i, digit in enumerate(code) if digit), 7)
    return "".join(map(str, code))


def _slot_sha1(imei: bytes, words: tuple[int, int]) -> str:
    """Slot 5: concatenate two of the five 32 bit words of ``sha1(imei)``.

    Which two words are used is what distinguishes the three variants of this
    slot; the decimal concatenation is then truncated or zero padded to eight
    digits.
    """
    digest = hashlib.sha1(imei).digest()
    first, second = (
        int.from_bytes(digest[index * 4:index * 4 + 4], "big") for index in words
    )
    return f"{first}{second}"[:CODE_LENGTH].ljust(CODE_LENGTH, "0")


def _slot_scrambled_md5(imei: bytes, masks: Sequence[int]) -> str:
    """Slot 6: scramble the IMEI into a 128 byte buffer, then hash it.

    Three stages:

    1. Each IMEI byte is bit-rotated by an amount that cycles with its position.
    2. The 15 byte result is grown to 128 bytes; every new byte mixes three
       earlier bytes, two of them chosen by a checksum of the rotated IMEI.
    3. The buffer is MD5'd and eight decimal digits are harvested from the
       digest, topped up from a 32 bit slice of the digest when the digest does
       not contain eight ASCII digits of its own.

    Stage 2 is a direct transcription of compiled ARM code; the original used
    magic-number division, which is spelled out here as ``divmod`` instead.
    """
    buffer = bytearray(128)
    for i, byte in enumerate(imei):
        rotation = i % 3
        if rotation == 0:
            buffer[i] = ((byte << 6) | (byte >> 2)) & 0xFF
        elif rotation == 1:
            buffer[i] = ((byte << 5) | (byte >> 3)) & 0xFF
        else:
            buffer[i] = ((byte >> 4) | (byte << 4)) & 0xFF

    # Big endian checksum over the rotated bytes; it steers the mixing below.
    mixer = sum(buffer[14 - i] + (buffer[i] << 8) for i in range(7)) + buffer[8]

    for pos in range(IMEI_LENGTH, 128):
        age = pos - IMEI_LENGTH
        quotient, remainder = divmod(pos, 12)

        mask_index = quotient + remainder
        if mask_index > 11:
            mask_index -= 12

        source = quotient + age % 12
        if quotient > 1:
            source += 12 * quotient - 24

        near = mixer % pos
        far = near + 1 if age == 0 else mixer % age
        merged = (buffer[source] & masks[mask_index]) | buffer[near]
        buffer[pos] = (~buffer[far] | merged) & 0xFF

    digest = hashlib.md5(bytes(buffer)).digest()

    # A second, independent checksum, this time over the raw IMEI.
    checksum = sum((imei[i] << 8) | imei[i + 1] for i in range(7)) + imei[14]

    code = [chr(byte) for byte in digest if 0x30 <= byte <= 0x39][:CODE_LENGTH]

    # Top the code up with digits taken from the back of a 32 bit slice of the
    # digest, switching to the mirrored slice if the first one runs out.
    spare = str(_le_uint32(digest, (checksum & 3) << 2))
    while len(code) < CODE_LENGTH:
        spare, last = spare[:-1], spare[-1]
        code.append(last)
        if not spare:
            spare = str(_le_uint32(digest, (3 - (checksum & 3)) << 2))

    if code[0] == "0":
        code[0] = str((digest[1 if checksum else 0] & 7) + 1)
    return "".join(code)


# --------------------------------------------------------------------------- #
# Algorithm selection
# --------------------------------------------------------------------------- #

# Slot 5 exists in three flavours that differ only in which SHA-1 words they
# concatenate: V2 uses the first two, V3 uses two other pairs.
_SHA1_WORDS_A = (0, 1)
_SHA1_WORDS_B = (1, 4)
_SHA1_WORDS_C = (2, 3)

_ALGORITHMS_V2: tuple[Algorithm, ...] = (
    partial(_slot_weighted_sum, weights=_WEIGHTS_V2),
    partial(_slot_crc32, huawei_table=False),
    partial(_slot_md5_digits, offset=0),
    partial(_slot_salted_md5, salt_key=_SALT_V2),
    _slot_substitution,
    partial(_slot_sha1, words=_SHA1_WORDS_A),
    partial(_slot_scrambled_md5, masks=_SCRAMBLE_MASKS_V2),
)

_ALGORITHMS_V3: tuple[Algorithm, ...] = (
    partial(_slot_weighted_sum, weights=_WEIGHTS_V201),
    partial(_slot_crc32, huawei_table=True),
    partial(_slot_md5_digits, offset=5),
    partial(_slot_salted_md5, salt_key=_SALT_V201),
    partial(_slot_sha1, words=_SHA1_WORDS_B),
    partial(_slot_sha1, words=_SHA1_WORDS_C),
    partial(_slot_scrambled_md5, masks=_SCRAMBLE_MASKS_V201),
)


def _select_v2(imei: bytes) -> int:
    """Pick which of the seven V2 slots this IMEI uses."""
    return sum((byte + i) * i for i, byte in enumerate(imei, 1)) % 7


def _select_v3(imei: bytes) -> int:
    """Pick which of the seven V3 slots this IMEI uses."""
    return sum((byte + i) * byte * (byte + 313) for i, byte in enumerate(imei, 1)) % 7


def _generate_v2(imei: bytes) -> str:
    return _ALGORITHMS_V2[_select_v2(imei)](imei)


def _generate_v3(imei: bytes) -> str:
    return _ALGORITHMS_V3[_select_v3(imei)](imei)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

class InvalidIMEIError(ValueError):
    """Raised when the supplied IMEI is not exactly 15 decimal digits."""


class Version(Enum):
    """The code generations this tool knows how to produce.

    The value of each member is the label used in the human readable output and
    as the key in ``--json`` output.
    """

    V1 = "V1"
    V2 = "V2"
    V3 = "V3/201"
    FLASH = "Flash"

    @property
    def generator(self) -> Algorithm:
        return _GENERATORS[self]


_GENERATORS: dict[Version, Algorithm] = {
    Version.V1: partial(_salted_hex_md5, salt_key=_SALT_UNLOCK),
    Version.V2: _generate_v2,
    Version.V3: _generate_v3,
    Version.FLASH: partial(_salted_hex_md5, salt_key=_SALT_FLASH),
}

# Everything callers have historically passed as a "version", mapped onto the
# enum: the CLI names, the legacy integers and the "201" alias for V3.
_VERSION_ALIASES: dict[object, Version] = {
    1: Version.V1, "1": Version.V1, "v1": Version.V1,
    2: Version.V2, "2": Version.V2, "v2": Version.V2,
    3: Version.V3, "3": Version.V3, "v3": Version.V3,
    201: Version.V3, "201": Version.V3, "v201": Version.V3,
    "flash": Version.FLASH,
}


def _coerce_version(version: Version | int | str) -> Version:
    if isinstance(version, Version):
        return version
    key = version.lower() if isinstance(version, str) else version
    try:
        return _VERSION_ALIASES[key]
    except (KeyError, TypeError):
        raise ValueError(f"unknown unlock code version: {version!r}") from None


def is_valid_imei(imei: str) -> bool:
    """Return ``True`` if ``imei`` is exactly 15 ASCII decimal digits."""
    return bool(_IMEI_RE.match(imei))


def has_valid_luhn(imei: str) -> bool:
    """Return ``True`` if the IMEI's trailing Luhn check digit is consistent.

    Codes are derived from the digits alone, so a bad check digit does not stop
    generation; it is a useful hint that the IMEI was mistyped.
    """
    total = 0
    for position, char in enumerate(reversed(imei)):
        digit = ord(char) - 48
        if position % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _encode(imei: str) -> bytes:
    if not is_valid_imei(imei):
        raise InvalidIMEIError(
            f"expected {IMEI_LENGTH} decimal digits, got {imei!r}"
        )
    return imei.encode("ascii")


def unlock(imei: str, version: Version | int | str = Version.V2) -> str:
    """Return the eight digit code of one ``version`` for ``imei``.

    >>> unlock("490154203237518", Version.V2)
    '29965404'
    >>> unlock("490154203237518", 1)
    '49212137'
    """
    return _coerce_version(version).generator(_encode(imei))


def generate_all(imei: str) -> dict[Version, str]:
    """Return every code for ``imei``, keyed by :class:`Version`.

    Computing all four costs barely more than computing one, and which version a
    device accepts is not knowable from the IMEI alone.

    >>> generate_all("490154203237518")[Version.V3]
    '18625085'
    """
    encoded = _encode(imei)
    return {version: generate(encoded) for version, generate in _GENERATORS.items()}


# --------------------------------------------------------------------------- #
# Self test
# --------------------------------------------------------------------------- #

# (algorithm, IMEI, expected code) triples covering every slot, including the
# awkward branches: leading zeros, nine padding and short digests.
_SLOT_VECTORS: tuple[tuple[Algorithm, str, str], ...] = (
    (_ALGORITHMS_V3[0], "166794546749343", "31572464"),

    (_ALGORITHMS_V2[1], "867010022091625", "89740701"),
    (_ALGORITHMS_V2[1], "867010022093346", "90496577"),
    (_ALGORITHMS_V3[1], "867010022091336", "43479313"),
    (_ALGORITHMS_V3[1], "486043736169958", "20766653"),
    (_ALGORITHMS_V3[1], "152782107774300", "99353390"),

    (_ALGORITHMS_V2[2], "867010022091626", "55760904"),
    (_ALGORITHMS_V2[2], "867010022091545", "77395563"),
    (_ALGORITHMS_V3[2], "867010022091566", "98820346"),
    (_ALGORITHMS_V3[2], "133887909865624", "13553393"),

    (_ALGORITHMS_V2[3], "867010022091677", "50284150"),
    (_ALGORITHMS_V3[3], "867010022091677", "48425064"),

    (_ALGORITHMS_V2[4], "867010022091661", "16672676"),
    (_ALGORITHMS_V2[4], "867010022091698", "16672086"),

    (_ALGORITHMS_V2[5], "867010022091692", "16678430"),
    (_ALGORITHMS_V3[4], "867010022091696", "26958384"),
    (_ALGORITHMS_V3[5], "867010022091697", "11406485"),

    (_ALGORITHMS_V2[6], "867010022093344", "41232318"),
    (_ALGORITHMS_V2[6], "234242342432305", "68014899"),
    (_ALGORITHMS_V2[6], "221724677371250", "92023179"),
    (_ALGORITHMS_V3[6], "867010022093350", "13122759"),
)

# (selector, IMEI, expected slot) triples.
_SELECTOR_VECTORS: tuple[tuple[Callable[[bytes], int], str, int], ...] = (
    (_select_v3, "667010022091624", 2),
    (_select_v3, "867010022091624", 3),
    (_select_v2, "867010022091624", 0),
)

# End to end regression vectors. The IMEI here is the public documentation
# example, not a real device: an unlock code plus a known model narrows the IMEI
# down to a brute-forceable range, so real IMEIs do not belong in source.
_END_TO_END_VECTORS: tuple[tuple[str, dict[Version, str]], ...] = (
    (
        "490154203237518",
        {
            Version.V1: "49212137",
            Version.V2: "29965404",
            Version.V3: "18625085",
            Version.FLASH: "50799099",
        },
    ),
)

# Optional bulk vectors: "<imei> <expected code>" per line.
_VECTOR_FILES: dict[Version, str] = {
    Version.V1: "tests/test-1.txt",
    Version.V2: "tests/test-2.txt",
    Version.V3: "tests/test-3.txt",
}


def _iter_file_vectors(root: Path) -> Iterable[tuple[Version, str, str]]:
    for version, relative in _VECTOR_FILES.items():
        path = root / relative
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                imei, expected = line.split()
            except ValueError:
                raise ValueError(f"{path}:{line_number}: expected 'IMEI CODE'") from None
            yield version, imei, expected


def run_self_test(root: Path | None = None) -> int:
    """Run every known test vector. Returns the number of failures."""
    root = root or Path(__file__).resolve().parent
    failures = 0

    def check(label: str, actual: str, expected: str) -> None:
        nonlocal failures
        if actual != expected:
            failures += 1
            print(f"FAIL {label}: got {actual}, expected {expected}", file=sys.stderr)

    checks = 0
    for algorithm, imei, expected in _SLOT_VECTORS:
        check(f"{algorithm!r} {imei}", algorithm(imei.encode()), expected)
        checks += 1

    for selector, imei, expected_slot in _SELECTOR_VECTORS:
        check(f"{selector.__name__} {imei}", str(selector(imei.encode())), str(expected_slot))
        checks += 1

    for imei, expected_codes in _END_TO_END_VECTORS:
        for version, expected in expected_codes.items():
            check(f"{version.value} {imei}", unlock(imei, version), expected)
            checks += 1

    for version, imei, expected in _iter_file_vectors(root):
        check(f"{version.value} {imei}", unlock(imei, version), expected)
        checks += 1

    if failures:
        print(f"{failures} of {checks} checks failed.", file=sys.stderr)
    else:
        print(f"All {checks} checks passed.")
    return failures


# --------------------------------------------------------------------------- #
# Command line interface
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unlockgen",
        description="Generate Huawei device unlock and flash codes from an IMEI.",
        epilog=(
            "Devices accept only one of these code generations, and which one is "
            "not derivable from the IMEI. Try them in the order printed."
        ),
    )
    parser.add_argument("imei", nargs="?", help=f"the device IMEI ({IMEI_LENGTH} digits)")
    parser.add_argument(
        "-o", "--only", dest="versions", action="append", metavar="VERSION",
        choices=[member.name.lower() for member in Version],
        help="print only this generation (v1, v2, v3, flash); repeatable",
    )
    parser.add_argument("--json", action="store_true", help="print the codes as JSON")
    parser.add_argument("--test", action="store_true", help="run the built-in test vectors")
    parser.add_argument("--version", action="version", version=f"unlockgen {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.test:
        return 1 if run_self_test() else 0

    if not args.imei:
        parser.error("an IMEI is required (or use --test)")

    try:
        codes = generate_all(args.imei)
    except InvalidIMEIError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if not has_valid_luhn(args.imei):
        print(
            "warning: IMEI check digit is invalid, it may be mistyped",
            file=sys.stderr,
        )

    if args.versions:
        wanted = {Version[name.upper()] for name in args.versions}
        codes = {version: code for version, code in codes.items() if version in wanted}

    if args.json:
        print(json.dumps({version.value: code for version, code in codes.items()}, indent=2))
        return 0

    print(f"IMEI: {args.imei}")
    for version, code in codes.items():
        label = "Flash:" if version is Version.FLASH else f"Unlock ({version.value}):"
        print(f"{label:<16} {code}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
