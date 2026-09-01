# unlockgen

Generate SIM-unlock and firmware-flash codes for Huawei modems, dongles and
routers from their IMEI.

A single, dependency-free Python file. Give it an IMEI, it prints the four
candidate codes; type them into your device's unlock prompt.

```console
$ python unlockgen.py 490154203237518
IMEI: 490154203237518
Unlock (V1):     49212137
Unlock (V2):     29965404
Unlock (V3/201): 18625085
Flash:           50799099
```

**Nothing to install: [use it in your browser][web].** The same four algorithms,
ported to JavaScript and running entirely on your own machine — no server, no
upload, no analytics. See [Run it in your browser](#run-it-in-your-browser).

[web]: https://rjovieira.github.io/unlockgen/

---

## Table of contents

- [What this does](#what-this-does)
- [Run it in your browser](#run-it-in-your-browser)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Using it as a library](#using-it-as-a-library)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Limitations and caveats](#limitations-and-caveats)
- [Legal](#legal)
- [Credits](#credits)

---

## What this does

Huawei network hardware ships locked to a carrier. Unlocking is done by typing
an eight-digit code into the device's web UI or AT-command interface. That code
is not stored on the device — it is *derived* from the device's IMEI by a keyed
algorithm, and the same algorithm runs in the firmware to check what you type.

Huawei shipped **four such algorithms** over the years, and nothing in the IMEI
tells you which one a given device uses. So this tool computes all four:

| Code | Purpose | Notes |
| --- | --- | --- |
| **V1** | SIM unlock | The oldest scheme. Early E-series dongles. |
| **V2** | SIM unlock | The most common. Widely used across dongles and routers. |
| **V3/201** | SIM unlock | Newer firmware. Also called "v201" in older tooling. |
| **Flash** | Firmware flashing | Not an unlock code — it authorises firmware writes. |

**Try them in the order printed.** One of them will be accepted; the rest will
be rejected. Devices typically allow a limited number of attempts before
permanently locking the unlock function, so read
[Limitations and caveats](#limitations-and-caveats) before you start guessing.

> Confirmed working in practice on a **Huawei B593s-22**, which accepted the
> **V2** code.
>
> The IMEI used throughout this README (`490154203237518`) is the public
> documentation example, not a real device. Treat your own IMEI and the codes
> derived from it as private: given a known device model, the codes narrow the
> IMEI down to a range small enough to brute-force, so publishing either one
> effectively publishes both.

## Run it in your browser

**<https://rjovieira.github.io/unlockgen/>**

Type the IMEI, get the four codes. It is the same algorithm set as
`unlockgen.py`, ported to JavaScript and served as a static page from GitHub
Pages.

- **Nothing is uploaded.** The codes are computed by JavaScript in your own
  browser. There is no server, no analytics, and no network request at all after
  the page has loaded. The IMEI is never put in the URL, in browser history or
  in storage — with a known device model a code narrows the IMEI down to a
  brute-forceable range, so a URL containing either is a URL containing both.
- **It works offline.** A service worker caches the page on first visit, which
  matters when the device you are unlocking is the one your internet comes
  through. It is network-first, so an update still lands as soon as you are
  online again.
- **No dependencies and no build step.** Seven static files, plain ES modules.
  MD5, SHA-1 and CRC-32 are implemented in the page rather than pulled from a
  library, because `crypto.subtle` offers no MD5 and the generators need to hash
  raw scrambled buffers, not just text.

### The files

| File | Contents |
| --- | --- |
| `docs/index.html` | The page. |
| `docs/styles.css` | Styling; light and dark follow the system setting. |
| `docs/app.js` | Wiring only — input handling, rendering, clipboard. |
| `docs/unlockgen.js` | The port itself — same slots, same names as `unlockgen.py`. |
| `docs/digest.js` | MD5, SHA-1 and CRC-32. |
| `docs/vectors.js` | The test vectors, shared by the in-page self test and CI. |
| `docs/sw.js` | The offline cache. |

### Using the JavaScript module

`docs/unlockgen.js` is an ES module with no DOM dependencies, so it runs in a
browser, in Node and in a bundler unchanged. The API mirrors the Python one:

```js
import { generateAll, unlock, Version } from "./docs/unlockgen.js";

unlock("490154203237518", Version.V2);     // "29965404"
unlock("490154203237518", 1);              // "49212137"  (legacy integer forms work)
unlock("490154203237518", 201);            // "18625085"  (alias for V3)

generateAll("490154203237518");
// { "V1": "49212137", "V2": "29965404", "V3/201": "18625085", "Flash": "50799099" }
```

| Name | Description |
| --- | --- |
| `Version` | Frozen object: `V1`, `V2`, `V3`, `FLASH`. Each value is the display label. |
| `unlock(imei, version = Version.V2)` | One eight-digit code. |
| `generateAll(imei)` | Every code, keyed by label — the same shape as `--json`. |
| `isValidIMEI(imei)` | Exactly 15 ASCII decimal digits. |
| `hasValidLuhn(imei)` | Trailing check digit is consistent. |
| `InvalidIMEIError` | Thrown on malformed IMEIs. |

Keys and error messages match the Python side deliberately, so output from
either implementation is interchangeable.

### Running the page locally

ES modules are not loadable over `file://`, so serve the directory rather than
opening the HTML file:

```console
$ python -m http.server -d docs 8000
$ open http://localhost:8000
```

### Publishing your own copy

Fork the repository, then **Settings → Pages → Build and deployment**, source
**Deploy from a branch**, branch **`main`**, folder **`/docs`**. There is no
build step; the folder is served as-is. Your copy appears at
`https://<user>.github.io/unlockgen/`.

## Requirements

- **Command line:** Python **3.9 or newer** (tested on 3.9.6 and 3.14.6). No
  third-party packages; standard library only.
- **Browser:** anything with ES module support — Chrome, Edge, Firefox and
  Safari from 2018 onwards. No dependencies, no build step, no polyfills.
- **Only to run the cross-implementation test:** Node **18 or newer**.

## Installation

There is nothing to install. Download the single file and run it:

```console
$ curl -O https://raw.githubusercontent.com/rjovieira/unlockgen/refs/heads/main/unlockgen.py
$ python unlockgen.py 490154203237518
```

Optionally make it directly executable:

```console
$ chmod +x unlockgen.py
$ ./unlockgen.py 490154203237518
```

## Usage

```
usage: unlockgen [-h] [-o VERSION] [--json] [--test] [--version] [imei]

Generate Huawei device unlock and flash codes from an IMEI.

positional arguments:
  imei                the device IMEI (15 digits)

options:
  -h, --help          show this help message and exit
  -o, --only VERSION  print only this generation (v1, v2, v3, flash);
                      repeatable
  --json              print the codes as JSON
  --test              run the built-in test vectors
  --version           show program's version number and exit

Devices accept only one of these code generations, and which one is not
derivable from the IMEI. Try them in the order printed.
```

### Finding your IMEI

It is the 15-digit number printed on the label under the battery or on the
underside of the router, on the box, and usually shown in the device's web UI
under *Device Information*. Over an AT-command serial interface, `AT+CGSN`
returns it.

### Examples

Print every code:

```console
$ python unlockgen.py 490154203237518
IMEI: 490154203237518
Unlock (V1):     49212137
Unlock (V2):     29965404
Unlock (V3/201): 18625085
Flash:           50799099
```

Print just the one you need:

```console
$ python unlockgen.py 490154203237518 --only v2
IMEI: 490154203237518
Unlock (V2):     29965404
```

Machine-readable output, for scripting:

```console
$ python unlockgen.py 490154203237518 --json
{
  "V1": "49212137",
  "V2": "29965404",
  "V3/201": "18625085",
  "Flash": "50799099"
}

$ python unlockgen.py 490154203237518 --json | jq -r '."V2"'
29965404
```

Batch-process a file of IMEIs:

```console
$ while read imei; do
    echo "$imei $(python unlockgen.py "$imei" --only v2 --json | jq -r '."V2"')"
  done < imeis.txt
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Codes generated, or all self-tests passed |
| `1` | `--test` was given and at least one test vector failed |
| `2` | Bad input: malformed IMEI, or no IMEI and no `--test` |

Malformed input goes to **stderr**, codes go to **stdout**, so piping is safe:

```console
$ python unlockgen.py 12345
error: expected 15 decimal digits, got '12345'
$ echo $?
2
```

If the IMEI's Luhn check digit does not match, a warning is printed to stderr
but the codes are still produced — the algorithms only use the digits, so a
technically-invalid IMEI still generates a code. The warning is there to catch
typos:

```console
$ python unlockgen.py 490154203237519
warning: IMEI check digit is invalid, it may be mistyped
IMEI: 490154203237519
...
```

## Using it as a library

`unlockgen.py` is importable and has no side effects at import time.

```python
from unlockgen import Version, generate_all, unlock, InvalidIMEIError

unlock("490154203237518", Version.V2)     # '29965404'
unlock("490154203237518", Version.FLASH)  # '50799099'

# Legacy integer forms from the original script still work:
unlock("490154203237518", 1)      # '49212137'
unlock("490154203237518", 201)    # '18625085'  (alias for V3)

# All four at once — barely more expensive than computing one.
generate_all("490154203237518")
# {<Version.V1: 'V1'>: '49212137', <Version.V2: 'V2'>: '29965404',
#  <Version.V3: 'V3/201'>: '18625085', <Version.FLASH: 'Flash'>: '50799099'}

unlock("nope", Version.V2)
# InvalidIMEIError: expected 15 decimal digits, got 'nope'
```

### Public API

| Name | Description |
| --- | --- |
| `Version` | Enum: `V1`, `V2`, `V3`, `FLASH`. `.value` is the display label. |
| `unlock(imei, version=Version.V2) -> str` | One eight-digit code. Accepts a `Version`, or the legacy `1`/`2`/`3`/`201`/`"flash"`. |
| `generate_all(imei) -> dict[Version, str]` | Every code, keyed by `Version`. |
| `is_valid_imei(imei) -> bool` | Exactly 15 ASCII decimal digits. |
| `has_valid_luhn(imei) -> bool` | Trailing check digit is consistent. |
| `InvalidIMEIError` | Subclass of `ValueError`, raised on malformed IMEIs. |
| `main(argv=None) -> int` | The CLI entry point; returns the exit code. |
| `run_self_test(root=None) -> int` | Runs the vectors; returns the failure count. |

Everything else is prefixed with `_` and is an implementation detail of the
algorithms — treat it as private.

## How it works

### V1 and Flash

The simplest scheme. A hardcoded key is hashed, a slice of that hash becomes the
salt, and the IMEI is hashed with it:

```
salt = hex(md5(key))[8:24]
code = fold(md5(imei + salt))
```

`fold` treats the 16-byte digest as a 4×4 matrix, XORs each column down to a
single byte, and forces the top bits of the resulting 32-bit number into the
range `0x2000000..0x3FFFFFF` — which is exactly the eight-decimal-digit range
with no leading zero.

V1 and Flash are the same function with different keys: `hwe620datacard` for
unlocking, `e630upgrade` for flashing.

### V2 and V3/201

These are not single algorithms but **families of seven**. A checksum of the
IMEI picks which one to use:

```
slot = checksum(imei) % 7
code = algorithms[slot](imei)
```

The checksum differs between V2 and V3, so the same IMEI generally lands in a
different slot in each family. The seven slots:

| Slot | Technique | V2 | V3/201 |
| --- | --- | --- | --- |
| 0 | Weighted digit sum, read out as nibbles | 16 magic weights | different weights |
| 1 | CRC-32, last eight decimal digits | standard CRC-32 | Huawei's scrambled table, inverted |
| 2 | Bytes of `md5(imei)` coerced to digits | offset 0 | offset 5 |
| 3 | `md5(imei + md5(key))`, folded | key `hwideadatacard` | key `dfkdkfllekkodk` |
| 4 | XOR the IMEI halves through a substitution table | ✔ | — |
| 5 | Two 32-bit words of `sha1(imei)`, concatenated | words 0+1 | words 1+4 |
| 6 | Scramble into a 128-byte buffer, then MD5 | mask set A | mask set B |

V3 has no substitution slot; it uses a second and third SHA-1 variant instead
(words 1+4 and 2+3), which is why slots 4 and 5 do not line up between the two
columns.

Two details worth knowing, because they look like bugs and are not:

- **The CRC table is deliberately non-standard.** Huawei's table contains the
  same 256 values as the textbook CRC-32 table, but in a scrambled order, so it
  cannot be generated from the `0xEDB88320` polynomial. It is embedded verbatim.
- **Codes never start with zero.** Every slot has its own fixup for that — the
  weighted sum forces a `1`, the CRC pads with `9`s, the substitution cipher
  substitutes the index of the first non-zero digit, and so on. These fixups are
  where most of the awkwardness in the code lives.

Slot 6 is the elaborate one: each IMEI byte is bit-rotated by an amount that
cycles with its position, then that 15-byte block is grown to 128 bytes where
every new byte mixes three earlier ones — two of them chosen by a checksum of
the block. The buffer is MD5'd, and eight decimal digits are harvested from the
digest, topped up from a 32-bit slice of it when the digest does not happen to
contain eight ASCII digits.

## Testing

The test vectors ship inside the script:

```console
$ python unlockgen.py --test
All 28 checks passed.
```

They cover every one of the fourteen slots (seven each for V2 and V3), the slot
selectors for both families, the awkward leading-zero and padding branches, and
one end-to-end IMEI with all four codes.

### The browser port

The same 28 vectors run in the page: open it and expand *Verify it yourself →
Run the self test*.

That only proves the port passes the vectors, though, not that it agrees with
the Python everywhere. `tests/parity.mjs` is the check that matters — it
generates IMEIs from a seeded PRNG, runs each one through both implementations,
and compares all four codes:

```console
$ node tests/parity.mjs 50000
All 200030 checks passed (50000 IMEIs cross-checked against unlockgen.py).
```

Because the four codes fan out across all fourteen slots, a batch that size
exercises each of them several thousand times. It also asserts the invariant
every slot has its own fixup for: eight digits, never a leading zero. Pass a
count to change the batch size, and `PYTHON=/path/to/python3` to pick the
interpreter. CI runs it, plus the vectors and doctests on Python 3.14,
on every push.

### Adding bulk vectors

If you have a corpus of known-good IMEI/code pairs, drop them next to the script
as `tests/test-1.txt`, `tests/test-2.txt` and `tests/test-3.txt` (for V1, V2 and
V3), one `IMEI CODE` pair per line. Blank lines and `#` comments are ignored.
`--test` picks them up automatically and stays quiet if the files are absent.

```
# tests/test-2.txt
490154203237518 29965404
```

### Doctests

The public functions carry runnable examples:

```console
$ python -m doctest unlockgen.py -v | tail -1
Test passed.
```

## Limitations and caveats

- **Attempt counters are real.** Most Huawei devices allow around ten wrong
  unlock attempts before disabling the unlock function permanently. Four codes
  is well within that budget, but do not brute-force beyond them.
- **Newer firmware is out of scope.** Huawei moved to server-side, per-device
  unlock codes on later hardware (roughly post-2015). If none of the four codes
  work, your device almost certainly uses that scheme and no offline generator
  can help.
- **The Flash code is not an unlock code.** It authorises firmware writes. A bad
  flash bricks the device. Do not use it unless you know why you need it.
- **The IMEI must be exactly 15 ASCII digits.** Non-ASCII digit characters
  (Arabic-Indic numerals, for instance) are rejected rather than silently
  producing a wrong code.
- **MD5 and SHA-1 appear here because the firmware uses them**, not because they
  are appropriate choices. This is a compatibility reimplementation, not a
  design.

## Legal

Unlocking a device you own is legal in many jurisdictions, and in several it is
an explicit statutory right — but not everywhere, and carrier contracts may say
otherwise regardless. **Use this only on hardware you own or are authorised to
modify**, and check your local rules first. This tool is provided for
interoperability and repair; the authors take no responsibility for how you use
it or for damage to your device.

## Credits

The algorithms were reverse-engineered from Huawei firmware by the modem
unlocking community over many years; slot 6 in particular is a transcription of
compiled ARM code. This file descends from the widely circulated `unlockgen.py`,
[most recently via this gist][gist].

The JavaScript in `docs/` is a port of the Python file in this repository, not
of the original script, and is held to the same output byte-for-byte by
`tests/parity.mjs`. Where the two ever disagree, the Python is the reference.

This version is a Python 3 rewrite: the Python 2 compatibility shims are gone,
the lookup tables are module-level constants rather than being rebuilt on every
call, the register-level ARM transcription in slot 6 is expressed as ordinary
arithmetic, and the whole thing was validated **bit-for-bit against the original
implementation across more than a million generated codes** covering all fourteen
slots. It runs about **1.8× faster** as a result.

[gist]: https://gist.github.com/matthieutirelli-pro/c5f173c8941f6ea7b082fb1984592129
