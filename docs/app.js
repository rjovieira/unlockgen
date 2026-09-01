/**
 * Page behaviour for unlockgen.
 *
 * All the interesting work lives in unlockgen.js; this file only moves strings
 * between the input, the DOM and the clipboard. Nothing here talks to the
 * network, and the IMEI is deliberately never written to the URL, to history or
 * to storage — see the privacy note on the page.
 */

import { generateAll, hasValidLuhn, InvalidIMEIError, isValidIMEI, Version } from "./unlockgen.js";
import { END_TO_END_VECTORS, SELECTOR_VECTORS, SLOT_VECTORS } from "./vectors.js";

const EXAMPLE_IMEI = "490154203237518";
const IMEI_LENGTH = 15;

// Order and presentation of the four codes. `kind` drives the styling: the
// flash code gets the warning treatment because it is not an unlock code.
const CARDS = [
  { version: Version.V1, label: "Unlock · V1", kind: "unlock" },
  { version: Version.V2, label: "Unlock · V2", kind: "unlock" },
  { version: Version.V3, label: "Unlock · V3/201", kind: "unlock" },
  { version: Version.FLASH, label: "Flash", kind: "flash" },
];

const form = document.getElementById("form");
const input = document.getElementById("imei");
const status = document.getElementById("status");
const results = document.getElementById("results");

/** Write a message into a status line, tinting it by tone. */
function setStatus(element, message, tone = "info") {
  element.textContent = message;
  element.dataset.tone = tone;
}

function clearResults() {
  results.replaceChildren();
}

/**
 * Copy `text`, preferring the async clipboard API and falling back to a
 * throwaway textarea for browsers that withhold it outside a secure context.
 */
async function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.setAttribute("readonly", "");
  scratch.style.position = "fixed";
  scratch.style.opacity = "0";
  document.body.append(scratch);
  scratch.select();
  try {
    if (!document.execCommand("copy")) throw new Error("copy was refused");
  } finally {
    scratch.remove();
  }
}

/** Build one result card. */
function renderCard({ version, label, kind }, code) {
  const card = document.createElement("div");
  card.className = "code";
  card.dataset.kind = kind;

  const meta = document.createElement("div");
  meta.className = "meta";

  const name = document.createElement("span");
  name.className = "name";
  name.textContent = label;

  const value = document.createElement("span");
  value.className = "value";
  value.textContent = code;

  meta.append(name, value);

  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "copy";
  copy.textContent = "Copy";
  copy.setAttribute("aria-label", `Copy the ${version} code, ${code.split("").join(" ")}`);

  copy.addEventListener("click", async () => {
    try {
      await copyToClipboard(code);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Press ⌘/Ctrl+C";
    }
    setTimeout(() => { copy.textContent = "Copy"; }, 1800);
  });

  card.append(meta, copy);
  return card;
}

/**
 * Generate and display the codes for whatever is currently in the input.
 *
 * `explain` is false while the user is still typing, so a half-entered IMEI
 * does not shout "invalid" at them; the submit button passes true.
 */
function update(explain = false) {
  const imei = input.value;

  if (!isValidIMEI(imei)) {
    clearResults();
    const missing = IMEI_LENGTH - imei.length;
    if (!imei && !explain) setStatus(status, "");
    else if (!imei) setStatus(status, `Enter the ${IMEI_LENGTH}-digit IMEI first.`, "error");
    else if (explain) setStatus(status, `An IMEI is ${IMEI_LENGTH} digits; this one has ${imei.length}.`, "error");
    else setStatus(status, `${missing} more ${missing === 1 ? "digit" : "digits"} to go.`);
    return;
  }

  let codes;
  try {
    codes = generateAll(imei);
  } catch (error) {
    clearResults();
    setStatus(status, error instanceof InvalidIMEIError ? error.message : String(error), "error");
    return;
  }

  results.replaceChildren(...CARDS.map((card) => renderCard(card, codes[card.version])));

  if (hasValidLuhn(imei)) {
    setStatus(status, "Try the codes in the order shown.");
  } else {
    // The algorithms only use the digits, so a bad check digit still produces
    // codes; the warning is there to catch typos.
    setStatus(status, "Warning: the IMEI check digit does not match — it may be mistyped. Codes are shown anyway.", "warning");
  }
}

// --- Wiring ----------------------------------------------------------------

input.addEventListener("input", () => {
  // Keep the field to digits, preserving the caret when nothing was stripped.
  const digits = input.value.replace(/\D/g, "").slice(0, IMEI_LENGTH);
  if (digits !== input.value) {
    const caret = input.selectionStart - (input.value.length - digits.length);
    input.value = digits;
    input.setSelectionRange(caret, caret);
  }
  update();
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  update(true);
});

document.getElementById("example").addEventListener("click", () => {
  input.value = EXAMPLE_IMEI;
  update(true);
  input.focus();
});

document.getElementById("clear").addEventListener("click", () => {
  input.value = "";
  clearResults();
  setStatus(status, "");
  input.focus();
});

// --- Self test -------------------------------------------------------------

const selfTestStatus = document.getElementById("self-test-status");

document.getElementById("self-test").addEventListener("click", () => {
  const encode = (imei) => Uint8Array.from(imei, (character) => character.charCodeAt(0));
  const failures = [];
  let checks = 0;

  const check = (label, actual, expected) => {
    checks += 1;
    if (actual !== expected) failures.push(`${label}: got ${actual}, expected ${expected}`);
  };

  for (const [label, algorithm, imei, expected] of SLOT_VECTORS) {
    check(`${label} ${imei}`, algorithm(encode(imei)), expected);
  }
  for (const [label, selector, imei, expected] of SELECTOR_VECTORS) {
    check(`${label} ${imei}`, selector(encode(imei)), expected);
  }
  for (const [imei, expectedCodes] of END_TO_END_VECTORS) {
    const codes = generateAll(imei);
    for (const [version, expected] of Object.entries(expectedCodes)) {
      check(`${version} ${imei}`, codes[version], expected);
    }
  }

  if (failures.length) {
    setStatus(selfTestStatus, `${failures.length} of ${checks} checks failed: ${failures[0]}`, "error");
    console.error(failures.join("\n"));
  } else {
    setStatus(selfTestStatus, `All ${checks} checks passed.`);
  }
});

// --- Offline support -------------------------------------------------------

// A router that needs unlocking is often the router you would be downloading
// this page through, so cache it. The worker is network-first, so an update
// still lands as soon as there is a connection.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {
      // Offline support is a bonus; the page is fully functional without it.
    });
  });
}

input.focus();
