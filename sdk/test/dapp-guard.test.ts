/**
 * dApp quote-guard gate — proves that NO security-critical value can come from a relay.
 *
 * `assertQuoteSafe` is extracted VERBATIM from distribution/index.html (between its BEGIN/END
 * markers) and executed here, so the function under test is the exact code the dApp ships —
 * not a copy that could drift. Red paths per attack: a relay-supplied `to`, a relay-supplied
 * `allowanceTarget` (the two together are a taker-funds drain chain), and flat quote fields
 * that are not the inversion of the signed order (display integrity).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const HTML = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", "..", "distribution", "index.html"),
  "utf8",
);

const BEGIN = "// ── BEGIN assertQuoteSafe";
const END = "// ── END assertQuoteSafe";
const start = HTML.indexOf(BEGIN);
const end = HTML.indexOf(END);
assert.ok(start !== -1 && end !== -1 && end > start, "assertQuoteSafe markers missing in index.html");
const source = HTML.slice(HTML.indexOf("\n", start) + 1, end);

// Materialize the exact shipped function.
const assertQuoteSafe = new Function(`${source}; return assertQuoteSafe;`)() as (
  q: Record<string, unknown>, configuredSpender: string,
) => boolean;

const SPARTAN1 = "0x000000000000000000000000000000000000dEaD";
const EVIL = "0x00000000000000000000000000000000000BadBad".slice(0, 42);

function goodQuote(): Record<string, unknown> {
  // Flat fields are the exact inversion of the maker-centric order (taker view).
  return {
    sellToken: "0x3333333333333333333333333333333333333333",   // taker pays  = order.buyToken
    buyToken: "0x2222222222222222222222222222222222222222",    // taker gets  = order.sellToken
    sellAmount: "3000000000",                                   // = order.buyAmount
    buyAmount: "1000000000000000000",                           // = order.sellAmount
    order: {
      maker: "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7",
      taker: "0x0000000000000000000000000000000000000000",
      sellToken: "0x2222222222222222222222222222222222222222",
      buyToken: "0x3333333333333333333333333333333333333333",
      sellAmount: "1000000000000000000",
      buyAmount: "3000000000",
      recipient: "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7",
      maxTip: "0",
      fillWindow: 1900000000,
      deadline: 1900000045,
    },
    nonce: "777",
    signature: "0x" + "ab".repeat(65),
    allowanceTarget: SPARTAN1,
    to: SPARTAN1,
  };
}

test("green: a consistent quote with matching to/allowanceTarget passes", () => {
  assert.equal(assertQuoteSafe(goodQuote(), SPARTAN1), true);
});

test("green: to/allowanceTarget absent is fine (they are locally known anyway)", () => {
  const q = goodQuote();
  delete q.to;
  delete q.allowanceTarget;
  assert.equal(assertQuoteSafe(q, SPARTAN1), true);
});

test("green: case-insensitive address comparison (checksummed vs lowercase)", () => {
  const q = goodQuote();
  q.to = SPARTAN1.toLowerCase();
  q.allowanceTarget = SPARTAN1.toUpperCase().replace("0X", "0x");
  assert.equal(assertQuoteSafe(q, SPARTAN1), true);
});

test("RED: relay-supplied `to` different from the configured Spartan1 is refused", () => {
  const q = goodQuote();
  q.to = EVIL;
  assert.throws(() => assertQuoteSafe(q, SPARTAN1), /'to'.*refused/);
});

test("RED: relay-supplied allowanceTarget different from the configured Spartan1 is refused", () => {
  const q = goodQuote();
  q.allowanceTarget = EVIL;
  assert.throws(() => assertQuoteSafe(q, SPARTAN1), /allowanceTarget.*refused/);
});

test("RED: the full drain chain (evil allowanceTarget + evil to) is refused", () => {
  const q = goodQuote();
  q.to = EVIL;
  q.allowanceTarget = EVIL;
  assert.throws(() => assertQuoteSafe(q, SPARTAN1));
});

test("RED: flat fields that are not the inversion of the signed order are refused", () => {
  // A relay showing a cheap price while the signed order charges more: display says the taker
  // pays 1, the order's buyAmount (what the taker actually pays in settle()) says 3000e6.
  const q = goodQuote();
  q.sellAmount = "1";
  assert.throws(() => assertQuoteSafe(q, SPARTAN1), /inversion.*refused/);

  const q2 = goodQuote();
  (q2.order as Record<string, unknown>).buyAmount = "999999999999";
  assert.throws(() => assertQuoteSafe(q2, SPARTAN1), /inversion.*refused/);

  const q3 = goodQuote();
  q3.sellToken = q3.buyToken; // token swap confusion
  assert.throws(() => assertQuoteSafe(q3, SPARTAN1), /inversion.*refused/);
});

test("RED: a quote without the settleable payload is refused", () => {
  const q = goodQuote();
  delete q.signature;
  assert.throws(() => assertQuoteSafe(q, SPARTAN1), /missing settleable payload/);
});

test("call sites: the dApp never uses a relay-supplied destination and always runs the guard", () => {
  // The function tests above cannot catch a regression at the CALL SITE (e.g. reverting to
  // `to: q.to ?? spender()` or dropping the guard call). Static assertions on the shipped file:
  assert.ok(!HTML.includes("q.to ??"), "relay-supplied `to` fallback reintroduced in index.html");
  assert.match(HTML, /to:\s*spender\(\)/, "sendTransaction must target the configured Spartan1");
  assert.match(HTML, /assertQuoteSafe\(candidate,\s*spender\(\)\)/, "guard missing at quote intake");
  assert.match(HTML, /assertQuoteSafe\(q,\s*spender\(\)\)/, "guard missing before settle");
  assert.match(HTML, /getChainId\(\)/, "wallet chainId guard missing");
});
