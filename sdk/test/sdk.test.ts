/**
 * Spartan1 SDK conformance gate.
 *
 * Two load-bearing gates, same discipline as the Python/Foundry suites:
 *
 *  1. DRIFT GATE — regenerates the constants into a temp dir via scripts/gen_constants.py and
 *     asserts BYTE EQUALITY with the committed files. Any drift between client/order.py and
 *     sdk/src/generated/* (or any hand edit of the generated files) goes red here.
 *
 *  2. CROSS-LANGUAGE DIGEST GATE — reproduces the frozen canonical vector byte-for-byte. This is
 *     the FOURTH independent leg (Python client == eth-account oracle == forge == TS). The digest
 *     is computed TWO ways in TS: manually from the generated constants, and independently via
 *     viem's hashTypedData. If either disagrees, the SDK is wrong — the frozen values are never
 *     adjusted.
 *
 * Run:  node --experimental-strip-types --test test/*.test.ts   (from sdk/)
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { hashTypedData, keccak256, recoverAddress, stringToHex, type Address, type Hex } from "viem";

import {
  ORDER_TYPE,
  ORDER_TYPEHASH,
  PERMIT2,
  QUOTE_TTL,
  HOT_WINDOW,
  ZERO_ADDRESS,
  buildOrder,
  makerViewRequest,
  orderFromWire,
  orderHash,
  orderToWire,
  randomNonce,
  signOrder,
  signingDigest,
  takerView,
  type Order,
} from "../src/index.ts";

const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = join(SDK_DIR, "..");

// ── frozen canonical vector (never adjust these — they arbitrate the SDK) ──
const CHAIN_ID = 8453;
const SPENDER = "0x1111111111111111111111111111111111111111" as Address;
const MAKER_PK = ("0x" + BigInt(0xa11ce).toString(16).padStart(64, "0")) as Hex;
const MAKER = "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7" as Address;
const NONCE = 777n;
const EXPECT_WITNESS = "0xcd06eda903e77bb9f5b8b5fd77566d10bfd03e0a68d483411f90b7f6b0465c58";
const EXPECT_DIGEST = "0xbbb89e334fb04f3e32eecb7e77b2a812437ad7dcdaa0101fa3334f1d91daa63b";

const CANONICAL: Order = {
  maker: MAKER,
  taker: ZERO_ADDRESS as Address,
  sellToken: "0x2222222222222222222222222222222222222222" as Address,
  buyToken: "0x3333333333333333333333333333333333333333" as Address,
  sellAmount: 10n ** 18n,
  buyAmount: 3000n * 10n ** 6n,
  recipient: "0x4444444444444444444444444444444444444444" as Address,
  maxTip: 10n ** 16n,
  fillWindow: 1900000000,
  deadline: 1900000045,
};

// ═══════════════════ 1. drift gate — generate, never retype ═══════════════════

test("drift gate: committed constants are byte-identical to a fresh regeneration", () => {
  const tmp = mkdtempSync(join(tmpdir(), "spartan1-gen-"));
  execFileSync("python3", [join(REPO_ROOT, "scripts", "gen_constants.py"), tmp]);
  for (const ext of ["ts", "js"] as const) {
    const committed = readFileSync(join(SDK_DIR, "src", "generated", `constants.${ext}`));
    const fresh = readFileSync(join(tmp, `constants.${ext}`));
    assert.ok(
      committed.equals(fresh),
      `constants.${ext} drifted from client/order.py — regenerate with scripts/gen_constants.py, ` +
      `never hand-edit`,
    );
  }
});

test("generator self-consistency: ORDER_TYPEHASH == keccak256(ORDER_TYPE)", () => {
  assert.equal(keccak256(stringToHex(ORDER_TYPE)), ORDER_TYPEHASH);
});

// ═══════════════ 2. cross-language digest gate — the 4th independent leg ═══════════════

test("frozen vector: witness matches Python/forge byte-for-byte", () => {
  assert.equal(orderHash(CANONICAL), EXPECT_WITNESS);
});

test("frozen vector: signing digest matches (manual construction from generated constants)", () => {
  assert.equal(signingDigest(CANONICAL, NONCE, SPENDER, CHAIN_ID), EXPECT_DIGEST);
});

test("frozen vector: signing digest matches (independent viem hashTypedData leg)", () => {
  // Independent oracle: viem derives the encodeType itself from this shape (referenced types
  // sorted alphabetically), so agreement here is a genuine second derivation, like eth-account
  // is for the Python client.
  const digest = hashTypedData({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: PERMIT2 as Address },
    types: {
      TokenPermissions: [
        { name: "token", type: "address" },
        { name: "amount", type: "uint256" },
      ],
      Order: [
        { name: "maker", type: "address" },
        { name: "taker", type: "address" },
        { name: "sellToken", type: "address" },
        { name: "buyToken", type: "address" },
        { name: "sellAmount", type: "uint256" },
        { name: "buyAmount", type: "uint256" },
        { name: "recipient", type: "address" },
        { name: "maxTip", type: "uint256" },
        { name: "fillWindow", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
      PermitWitnessTransferFrom: [
        { name: "permitted", type: "TokenPermissions" },
        { name: "spender", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "witness", type: "Order" },
      ],
    },
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: CANONICAL.sellToken, amount: CANONICAL.sellAmount + CANONICAL.maxTip },
      spender: SPENDER,
      nonce: NONCE,
      deadline: BigInt(CANONICAL.deadline),
      witness: {
        maker: CANONICAL.maker, taker: CANONICAL.taker, sellToken: CANONICAL.sellToken,
        buyToken: CANONICAL.buyToken, sellAmount: CANONICAL.sellAmount,
        buyAmount: CANONICAL.buyAmount, recipient: CANONICAL.recipient,
        maxTip: CANONICAL.maxTip, fillWindow: BigInt(CANONICAL.fillWindow),
        deadline: BigInt(CANONICAL.deadline),
      },
    },
  });
  assert.equal(digest, EXPECT_DIGEST);
});

test("signOrder produces a 65-byte signature that recovers to the maker", async () => {
  const sig = await signOrder(CANONICAL, NONCE, SPENDER, CHAIN_ID, MAKER_PK);
  assert.equal(sig.length, 2 + 65 * 2);
  const recovered = await recoverAddress({ hash: EXPECT_DIGEST as Hex, signature: sig });
  assert.equal(recovered.toLowerCase(), MAKER.toLowerCase());
});

// ── tamper negatives: any single-input mutation must move the digest ──

test("tamper: mutating any single Order field changes the digest", () => {
  const base = signingDigest(CANONICAL, NONCE, SPENDER, CHAIN_ID);
  const mutations: Array<[string, Order]> = [
    ["maker", { ...CANONICAL, maker: "0x00000000000000000000000000000000000000a1" as Address }],
    ["taker", { ...CANONICAL, taker: "0x00000000000000000000000000000000000000a2" as Address }],
    ["sellToken", { ...CANONICAL, sellToken: "0x00000000000000000000000000000000000000a3" as Address }],
    ["buyToken", { ...CANONICAL, buyToken: "0x00000000000000000000000000000000000000a4" as Address }],
    ["sellAmount", { ...CANONICAL, sellAmount: CANONICAL.sellAmount + 1n }],
    ["buyAmount", { ...CANONICAL, buyAmount: CANONICAL.buyAmount + 1n }],
    ["recipient", { ...CANONICAL, recipient: "0x00000000000000000000000000000000000000a5" as Address }],
    ["maxTip", { ...CANONICAL, maxTip: CANONICAL.maxTip + 1n }],
    ["fillWindow", { ...CANONICAL, fillWindow: CANONICAL.fillWindow + 1 }],
    ["deadline", { ...CANONICAL, deadline: CANONICAL.deadline + 1 }],
  ];
  for (const [field, mutated] of mutations) {
    assert.notEqual(signingDigest(mutated, NONCE, SPENDER, CHAIN_ID), base,
      `mutating ${field} must change the digest`);
    assert.notEqual(orderHash(mutated), EXPECT_WITNESS, `mutating ${field} must change the witness`);
  }
});

test("tamper: nonce, spender, and chainId are all inside the digest", () => {
  const base = signingDigest(CANONICAL, NONCE, SPENDER, CHAIN_ID);
  assert.notEqual(signingDigest(CANONICAL, NONCE + 1n, SPENDER, CHAIN_ID), base, "nonce");
  assert.notEqual(
    signingDigest(CANONICAL, NONCE, "0x9999999999999999999999999999999999999999" as Address, CHAIN_ID),
    base, "spender (anti-#250 binding)");
  assert.notEqual(signingDigest(CANONICAL, NONCE, SPENDER, 1), base, "chainId (cross-chain replay)");
});

// ═══════════════════ perspective inversion — must NOT be the identity ═══════════════════

test("takerView is the mirror of the maker-centric Order (and not the identity)", () => {
  const tv = takerView(CANONICAL);
  assert.equal(tv.sellToken, CANONICAL.buyToken, "taker pays order.buyToken");
  assert.equal(tv.buyToken, CANONICAL.sellToken, "taker receives order.sellToken");
  assert.equal(tv.sellAmount, CANONICAL.buyAmount.toString(), "taker pays order.buyAmount");
  assert.equal(tv.buyAmount, CANONICAL.sellAmount.toString(), "taker receives order.sellAmount");
  // The assertion that makes the inversion bug visible:
  assert.notEqual(tv.sellToken, CANONICAL.sellToken, "the mapping must NOT be the identity");
});

test("makerViewRequest inverts a taker-centric /quote query (round trip restores it)", () => {
  const A = "0xAA00000000000000000000000000000000000000" as Address;
  const B = "0xBB00000000000000000000000000000000000000" as Address;
  const req = makerViewRequest({ sellToken: A, buyToken: B, sellAmount: 500n });
  assert.equal(req.buyToken, A, "taker sellToken becomes maker buyToken");
  assert.equal(req.sellToken, B, "taker buyToken becomes maker sellToken");
  assert.equal(req.buyAmount, "500", "taker sellAmount becomes maker buyAmount");
  assert.equal(req.sellAmount, undefined, "maker sellAmount left open");

  // Round trip: a maker order satisfying the request maps back to the taker's own view.
  const back = takerView({ ...CANONICAL, sellToken: B, buyToken: A, sellAmount: 1n, buyAmount: 500n });
  assert.equal(back.sellToken, A);
  assert.equal(back.sellAmount, "500");
});

// ═══════════════════ construction & wire discipline ═══════════════════

test("buildOrder applies the frozen expiry defaults and fillWindow <= deadline", () => {
  const o = buildOrder({
    maker: MAKER, sellToken: CANONICAL.sellToken, buyToken: CANONICAL.buyToken,
    sellAmount: 1n, buyAmount: 1n, now: 1_900_000_000,
  });
  assert.equal(o.deadline - 1_900_000_000, QUOTE_TTL);
  assert.equal(o.fillWindow - 1_900_000_000, HOT_WINDOW);
  assert.ok(o.fillWindow <= o.deadline);
  assert.equal(o.taker, ZERO_ADDRESS, "default is an open order");
  assert.equal(o.recipient, MAKER, "recipient defaults to maker");
  assert.throws(() => buildOrder({
    maker: MAKER, sellToken: CANONICAL.sellToken, buyToken: CANONICAL.buyToken,
    sellAmount: 1n, buyAmount: 1n, quoteTtl: 10, hotWindow: 20,
  }), /fillWindow past the deadline/);
});

test("wire round trip: uint256 as decimal strings, exact above 2^53", () => {
  const big = 2n ** 200n + 12345n;
  const o = { ...CANONICAL, sellAmount: big };
  const wire = orderToWire(o);
  assert.equal(wire.sellAmount, big.toString(), "amounts travel as decimal strings");
  assert.equal(typeof wire.sellAmount, "string");
  const back = orderFromWire(wire);
  assert.equal(back.sellAmount, big, "round trip is lossless");
  assert.equal(orderHash(back), orderHash(o));
});

test("randomNonce spans 256 bits and never repeats trivially", () => {
  const a = randomNonce();
  const b = randomNonce();
  assert.notEqual(a, b);
  assert.ok(a > 2n ** 64n && b > 2n ** 64n, "draws live in the high 256-bit space");
});
