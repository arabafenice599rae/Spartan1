/**
 * Spartan1 SDK — Order building, Permit2 witness signing, relay client.
 *
 * SINGLE SOURCE OF TRUTH: every typehash, type string, and the Order field order come from
 * `./generated/constants` (emitted by scripts/gen_constants.py from client/order.py). Nothing
 * hash-bearing is retyped here — that is the whole defense against the Across M-06 class.
 *
 * Wire discipline (openapi.yaml is the interface source):
 *   - uint256 travels as a DECIMAL STRING, never a JSON number (doubles round above 2^53);
 *   - `Order` is MAKER-centric; `GET /quote` is TAKER-centric — use takerView/makerViewRequest,
 *     the mapping is NOT the identity;
 *   - an order is valid AT the deadline second (`now <= deadline`, matching Permit2's strict `>`).
 *
 * Runtime dependency: viem only (peer). Never hand-roll keccak or secp256k1.
 */

import {
  concatHex,
  encodeAbiParameters,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  EIP712_DOMAIN_TYPEHASH,
  ORDER_TYPEHASH,
  PERMIT2,
  PERMIT2_HASHED_NAME,
  PERMIT_WITNESS_TYPEHASH,
  PLACEHOLDER_SPENDER,
  TOKEN_PERMISSIONS_TYPEHASH,
  ZERO_ADDRESS,
  QUOTE_TTL,
  HOT_WINDOW,
} from "./generated/constants.js";

export * from "./generated/constants.js";

// ─────────────────────────────── types (mirror openapi.yaml) ───────────────────────────────

/** The 10 signed fields, MAKER-centric, in the frozen struct order. Amounts are atomic bigints
 *  in memory and decimal strings on the wire. */
export interface Order {
  maker: Address;
  taker: Address;        // ZERO_ADDRESS = open order
  sellToken: Address;    // what the MAKER gives (== Permit2 permitted.token)
  buyToken: Address;     // what the MAKER receives
  sellAmount: bigint;
  buyAmount: bigint;
  recipient: Address;
  maxTip: bigint;
  fillWindow: number;    // unix seconds
  deadline: number;      // unix seconds; MUST equal the permit deadline
}

/** Wire form of Order — uint256 amounts as decimal strings (schema `Uint256`). */
export interface OrderWire {
  maker: Address;
  taker: Address;
  sellToken: Address;
  buyToken: Address;
  sellAmount: string;
  buyAmount: string;
  recipient: Address;
  maxTip: string;
  fillWindow: number;
  deadline: number;
}

/** schema `SignedOrder` (+ the optional honesty fields). */
export interface SignedOrder {
  order: OrderWire;
  nonce: string;
  signature: Hex;
  chainId?: number;
  spartan1?: Address;
  /** false = signed against a placeholder/DRY_RUN spender — can NEVER settle. */
  settleable?: boolean;
  dryRun?: boolean;
  warning?: string;
}

/** schema `PooledOrder` — relay claims; recompute/verify everything locally before use. */
export interface PooledOrder extends SignedOrder {
  orderHash: Hex;
  receivedAt: number;
  sigCheck: "ecdsa" | "erc1271" | "deferred";
}

/** schema `RfqRequest` — MAKER-centric; exactly one of sellAmount/buyAmount. */
export interface RfqRequest {
  sellToken: Address;
  buyToken: Address;
  sellAmount?: string;
  buyAmount?: string;
  taker?: Address;
}

/** schema `AggregatorQuote` — TAKER-centric flat fields + the settleable payload. */
export interface AggregatorQuote {
  sellToken: Address;    // taker pays this  (= order.buyToken)
  buyToken: Address;     // taker gets this  (= order.sellToken)
  sellAmount: string;    // taker pays       (= order.buyAmount)
  buyAmount: string;     // taker receives   (= order.sellAmount)
  price?: string;
  allowanceTarget?: Address;
  to?: Address;
  order: OrderWire;
  nonce: string;
  signature: Hex;
}

// ─────────────────────────────── order building & hashing ───────────────────────────────

export interface BuildOrderParams {
  maker: Address;
  sellToken: Address;
  buyToken: Address;
  sellAmount: bigint;
  buyAmount: bigint;
  taker?: Address;
  recipient?: Address;   // defaults to maker
  maxTip?: bigint;
  /** unix seconds "now"; defaults to Date.now()/1000 */
  now?: number;
  quoteTtl?: number;     // default QUOTE_TTL (45s)
  hotWindow?: number;    // default HOT_WINDOW (30s)
}

/** Build an Order with the frozen expiry defaults (fillWindow <= deadline by construction). */
export function buildOrder(p: BuildOrderParams): Order {
  const now = p.now ?? Math.floor(Date.now() / 1000);
  const ttl = p.quoteTtl ?? QUOTE_TTL;
  const hot = p.hotWindow ?? HOT_WINDOW;
  if (hot > ttl) throw new Error("hotWindow > quoteTtl would put fillWindow past the deadline");
  if (p.sellAmount <= 0n) throw new Error("sellAmount must be > 0");
  return {
    maker: p.maker,
    taker: p.taker ?? (ZERO_ADDRESS as Address),
    sellToken: p.sellToken,
    buyToken: p.buyToken,
    sellAmount: p.sellAmount,
    buyAmount: p.buyAmount,
    recipient: p.recipient ?? p.maker,
    maxTip: p.maxTip ?? 0n,
    fillWindow: now + hot,
    deadline: now + ttl,
  };
}

const ORDER_ABI = [
  { type: "bytes32" }, { type: "address" }, { type: "address" }, { type: "address" },
  { type: "address" }, { type: "uint256" }, { type: "uint256" }, { type: "address" },
  { type: "uint256" }, { type: "uint256" }, { type: "uint256" },
] as const;

/** The witness: keccak256(abi.encode(ORDER_TYPEHASH, order)) — the full Order bound. */
export function orderHash(o: Order): Hex {
  return keccak256(encodeAbiParameters(ORDER_ABI, [
    ORDER_TYPEHASH as Hex, o.maker, o.taker, o.sellToken, o.buyToken,
    o.sellAmount, o.buyAmount, o.recipient, o.maxTip,
    BigInt(o.fillWindow), BigInt(o.deadline),
  ]));
}

/** Permit2 EIP-712 domain separator for a chain. */
export function permit2DomainSeparator(chainId: number): Hex {
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
    [EIP712_DOMAIN_TYPEHASH as Hex, PERMIT2_HASHED_NAME as Hex, BigInt(chainId), PERMIT2 as Address],
  ));
}

/**
 * The EIP-712 digest the maker signs: keccak256(0x1901 || domainSeparator || structHash).
 * `spender` MUST be the deployed Spartan1 address — the signature binds to it and nowhere else.
 * permitted = sellAmount + maxTip (single computation, mirrored on-chain).
 */
export function signingDigest(o: Order, nonce: bigint, spender: Address, chainId: number): Hex {
  const tokenPermissionsHash = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
    [TOKEN_PERMISSIONS_TYPEHASH as Hex, o.sellToken, o.sellAmount + o.maxTip],
  ));
  const structHash = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "address" },
     { type: "uint256" }, { type: "uint256" }, { type: "bytes32" }],
    [PERMIT_WITNESS_TYPEHASH as Hex, tokenPermissionsHash, spender,
     nonce, BigInt(o.deadline), orderHash(o)],
  ));
  return keccak256(concatHex(["0x1901", permit2DomainSeparator(chainId), structHash]));
}

/** Random 256-bit unordered nonce — never sequential (OZ Across lesson). */
export function randomNonce(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return BigInt("0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""));
}

/** Case-insensitive address equality (EIP-55 checksums vs lowercase). The SDK has no other
 *  address helper; this mirrors the dApp's `same()` in distribution/index.html. */
export function sameAddress(a: string | null | undefined, b: string | null | undefined): boolean {
  return typeof a === "string" && typeof b === "string" &&
    a.toLowerCase() === b.toLowerCase();
}

/**
 * Sign the Permit2 witness digest with an EOA key. Returns the 65-byte r‖s‖v signature.
 *
 * Unlike `signingDigest` (which stays pure — hashing the placeholder is exactly how the frozen
 * vector is verified), the SIGNING path refuses a spender that can never settle: an unset/empty/
 * zero address, or the anti-placebo `PLACEHOLDER_SPENDER` sentinel. A signature bound to the
 * placeholder is dead on-chain, and the SDK is the only component that used to accept it silently.
 * The `allowPlaceholder` opt-out exists ONLY for the frozen-vector test (whose canonical spender is
 * the placeholder today); it is named so no integrator enables it by accident.
 */
export async function signOrder(
  o: Order, nonce: bigint, spender: Address, chainId: number, privateKey: Hex,
  opts: { allowPlaceholder?: boolean } = {},
): Promise<Hex> {
  if (!spender || !/^0x[0-9a-fA-F]{40}$/.test(spender) || sameAddress(spender, ZERO_ADDRESS)) {
    throw new Error(
      "signOrder: no configured Spartan1 address (spender is empty/zero) — a signature would be " +
      "unsettleable; supply the deployed Spartan1 address (see distribution/deployments.json).",
    );
  }
  if (sameAddress(spender, PLACEHOLDER_SPENDER) && !opts.allowPlaceholder) {
    throw new Error(
      "signOrder: refusing the placeholder spender " + PLACEHOLDER_SPENDER + " — a signature bound " +
      "to it can NEVER settle. Use the deployed Spartan1 address; pass { allowPlaceholder: true } " +
      "only in tests that assert against the frozen vector.",
    );
  }
  const account = privateKeyToAccount(privateKey);
  return account.sign({ hash: signingDigest(o, nonce, spender, chainId) });
}

// ─────────────────────────────── wire (de)serialisation ───────────────────────────────

export function orderToWire(o: Order): OrderWire {
  return {
    maker: o.maker, taker: o.taker, sellToken: o.sellToken, buyToken: o.buyToken,
    sellAmount: o.sellAmount.toString(), buyAmount: o.buyAmount.toString(),
    recipient: o.recipient, maxTip: o.maxTip.toString(),
    fillWindow: o.fillWindow, deadline: o.deadline,
  };
}

export function orderFromWire(w: OrderWire): Order {
  return {
    maker: w.maker, taker: w.taker, sellToken: w.sellToken, buyToken: w.buyToken,
    sellAmount: BigInt(w.sellAmount), buyAmount: BigInt(w.buyAmount),
    recipient: w.recipient, maxTip: BigInt(w.maxTip),
    fillWindow: w.fillWindow, deadline: w.deadline,
  };
}

// ─────────────────────────────── perspective inversion ───────────────────────────────
// Order is MAKER-centric; /quote is TAKER-centric. Mirror images — conflating them silently
// inverts a swap. The mapping lives here in one named place and is covered by a test that
// asserts it is NOT the identity.

export function takerView(o: Order): {
  sellToken: Address; buyToken: Address; sellAmount: string; buyAmount: string;
} {
  return {
    sellToken: o.buyToken,               // taker pays this
    buyToken: o.sellToken,               // taker receives this
    sellAmount: o.buyAmount.toString(),
    buyAmount: o.sellAmount.toString(),
  };
}

export function makerViewRequest(p: {
  sellToken: Address; buyToken: Address; sellAmount?: bigint; buyAmount?: bigint;
}): RfqRequest {
  const req: RfqRequest = {
    sellToken: p.buyToken,               // maker gives what the taker receives
    buyToken: p.sellToken,               // maker receives what the taker pays
  };
  if (p.buyAmount !== undefined) req.sellAmount = p.buyAmount.toString();
  if (p.sellAmount !== undefined) req.buyAmount = p.sellAmount.toString();
  return req;
}

// ─────────────────────────────── relay HTTP client ───────────────────────────────

async function http(method: "GET" | "POST", url: string, body?: unknown): Promise<{
  status: number; json: unknown;
}> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const resp = await fetch(url, init);
  let json: unknown = {};
  try { json = await resp.json(); } catch { /* non-JSON body */ }
  return { status: resp.status, json };
}

/** POST /order — submit a signed Order to one relay. Idempotent by orderHash (P5). */
export async function postOrder(relayUrl: string, signed: SignedOrder): Promise<{
  status: number; body: { orderHash?: Hex; valid?: boolean; duplicate?: boolean;
    failed?: string[]; detail?: Record<string, string> };
}> {
  const { status, json } = await http("POST", `${relayUrl}/order`, signed);
  return { status, body: json as never };
}

/** GET /orders — list live orders. EVERY field is a relay claim: re-verify before use. */
export async function getOrders(relayUrl: string, params?: {
  sellToken?: Address; buyToken?: Address; taker?: Address; limit?: number;
}): Promise<{ orders: PooledOrder[]; count: number }> {
  const q = new URLSearchParams();
  if (params?.sellToken) q.set("sellToken", params.sellToken);
  if (params?.buyToken) q.set("buyToken", params.buyToken);
  if (params?.taker) q.set("taker", params.taker);
  if (params?.limit) q.set("limit", String(params.limit));
  const qs = q.toString();
  const { json } = await http("GET", `${relayUrl}/orders${qs ? "?" + qs : ""}`);
  return json as never;
}

/** GET /quote — TAKER-centric aggregator adapter. Exactly one of sellAmount/buyAmount. */
export async function getQuote(relayUrl: string, params: {
  sellToken: Address; buyToken: Address; sellAmount?: bigint; buyAmount?: bigint; taker?: Address;
}): Promise<AggregatorQuote | null> {
  if ((params.sellAmount === undefined) === (params.buyAmount === undefined)) {
    throw new Error("supply exactly one of sellAmount / buyAmount");
  }
  const q = new URLSearchParams({ sellToken: params.sellToken, buyToken: params.buyToken });
  if (params.sellAmount !== undefined) q.set("sellAmount", params.sellAmount.toString());
  if (params.buyAmount !== undefined) q.set("buyAmount", params.buyAmount.toString());
  if (params.taker) q.set("taker", params.taker);
  const { status, json } = await http("GET", `${relayUrl}/quote?${q.toString()}`);
  return status === 200 ? (json as AggregatorQuote) : null;   // 404 = not quoting, not an error
}

/** POST /rfq/quote — MAKER-centric RFQ. 404 = no maker quoting (normal, no penalty). */
export async function requestQuote(relayUrl: string, req: RfqRequest): Promise<SignedOrder | null> {
  const { status, json } = await http("POST", `${relayUrl}/rfq/quote`, req);
  return status === 200 ? (json as SignedOrder) : null;
}
