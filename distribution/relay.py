#!/usr/bin/env python3
"""Spartan1 reference relay — untrusted by construction.

Conforms to distribution/openapi.yaml. Where code and schema disagree, the schema
is right and this file is wrong.

MOTHER PRINCIPLE — the whole security argument for this file:
    A relay, malicious or compromised, can only OMIT, DELAY, or SHOW DATA THE
    RECEIVER RE-VERIFIES. It can never alter an amount, move funds, forge a
    signature, or force unsigned execution. It holds no keys and no funds.
Therefore: this file is a cache with a filter. Nothing here is trusted, and an
executor that skips re-verification has misimplemented the protocol.

WHY STDLIB ONLY (beyond the signing stack already required by client/order.py):
    Anyone should be able to fork this and run it — laptop, VPS, phone. No web
    framework, no database, no RPC library. `http.server` + `urllib` + `json`.
    Fewer moving parts is the same argument that keeps the contract at one file.

RUN:
    SPARTAN1_ADDRESS=0x... CHAIN_ID=8453 RPC_URL=https://... python3 relay.py
    # RPC_URL optional: without it P6/P7 cannot be evaluated and /health says so.
"""

from __future__ import annotations

import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_account import Account  # noqa: E402  (signing stack, same as order.py)

from order import (  # noqa: E402  — SINGLE SOURCE: never re-declare these here
    Order,
    PERMIT2,
    order_hash,
    signing_digest,
)

# ─────────────────────────── frozen constants ────────────────────────────
# Expiry defaults, calibrated on Jupiter's ~55 s flow. Loosening them is an
# explicit act: a longer TTL is strictly more adverse selection for the maker.
QUOTE_TTL = 45            # seconds; deadline - now at issuance
HOT_WINDOW = 30           # seconds; fillWindow - now (maker-only before it)
REQUOTE_INTERVAL = 5      # seconds; maker refresh cadence
MAKER_SIGN_BUDGET = 2.0   # seconds; per-webhook timeout in /rfq/quote
L1_TTL_MULTIPLIER = 2     # L1 doubles QUOTE_TTL

# Anti-Sybil rule 2 — random redundancy. Client-side fan-out targets.
FANOUT_TARGET = 8
FANOUT_MIN = 3

ZERO_ADDRESS = "0x" + "00" * 20
ERC1271_MAGIC = "1626ba7e"

# eth_call selectors
SEL_BALANCE_OF = "70a08231"   # balanceOf(address)
SEL_ALLOWANCE = "dd62ed3e"    # allowance(address,address)
SEL_IS_VALID_SIG = "1626ba7e" # isValidSignature(bytes32,bytes)

ALL_PREDICATES = ("P1", "P2", "P3", "P4", "P5", "P6", "P7")

VERSION = "1"


# ────────────────────────────── configuration ─────────────────────────────
@dataclass(frozen=True)
class Config:
    spartan1: str            # the Permit2 `spender`; every signature is bound to it
    chain_id: int
    rpc_url: str | None = None
    maker_webhooks: tuple[str, ...] = ()
    host: str = "127.0.0.1"
    port: int = 8545

    @classmethod
    def from_env(cls) -> "Config":
        addr = os.environ.get("SPARTAN1_ADDRESS")
        if not addr:
            raise SystemExit(
                "SPARTAN1_ADDRESS is required: it is the Permit2 spender, and a signature "
                "is valid for exactly one deployed Spartan1 address. Guessing it would make "
                "every P1 check meaningless."
            )
        hooks = os.environ.get("MAKER_WEBHOOKS", "")
        return cls(
            spartan1=addr,
            chain_id=int(os.environ.get("CHAIN_ID", "8453")),
            rpc_url=os.environ.get("RPC_URL") or None,
            maker_webhooks=tuple(h.strip() for h in hooks.split(",") if h.strip()),
            host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8545")),
        )

    def enforced_predicates(self) -> tuple[str, ...]:
        """P6/P7 need RPC reads. Without RPC they are NOT evaluated, and /health
        must say so rather than imply a check that never ran."""
        if self.rpc_url:
            return ALL_PREDICATES
        return ("P1", "P2", "P3", "P4", "P5")


# ─────────────────────────────── JSON-RPC ─────────────────────────────────
class Rpc:
    """Minimal JSON-RPC over urllib. ~2 reads per order (P6, P7); no simulation."""

    def __init__(self, url: str | None, timeout: float = 4.0):
        self.url = url
        self.timeout = timeout
        self._id = 0
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self.url is not None

    def call(self, method: str, params: list[Any]) -> Any:
        if not self.url:
            raise RuntimeError("no RPC configured")
        with self._lock:
            self._id += 1
            rid = self._id
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        req = urllib.request.Request(
            self.url, data=body.encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read())
        if "error" in payload:
            raise RuntimeError(f"rpc error: {payload['error']}")
        return payload["result"]

    def eth_call(self, to: str, data: str) -> str:
        return self.call("eth_call", [{"to": to, "data": data}, "latest"])

    def code_at(self, address: str) -> str:
        return self.call("eth_getCode", [address, "latest"])

    def latest_block(self) -> tuple[int, str]:
        blk = self.call("eth_getBlockByNumber", ["latest", False])
        return int(blk["number"], 16), blk["hash"]


def _pad_address(addr: str) -> str:
    return addr.lower().replace("0x", "").rjust(64, "0")


def erc20_balance_of(rpc: Rpc, token: str, owner: str) -> int:
    return int(rpc.eth_call(token, "0x" + SEL_BALANCE_OF + _pad_address(owner)) or "0x0", 16)


def erc20_allowance(rpc: Rpc, token: str, owner: str, spender: str) -> int:
    data = "0x" + SEL_ALLOWANCE + _pad_address(owner) + _pad_address(spender)
    return int(rpc.eth_call(token, data) or "0x0", 16)


def erc1271_valid(rpc: Rpc, signer: str, digest: bytes, signature: bytes) -> bool:
    """isValidSignature(bytes32,bytes) -> bytes4; magic 0x1626ba7e means valid."""
    offset = (32 + 32).to_bytes(32, "big")           # head: bytes32 + offset word
    length = len(signature).to_bytes(32, "big")
    padded = signature + b"\x00" * ((32 - len(signature) % 32) % 32)
    data = "0x" + SEL_IS_VALID_SIG + (digest + offset + length + padded).hex()
    try:
        ret = rpc.eth_call(signer, data)
    except Exception:
        return False
    return bool(ret) and ret[2:10].lower() == ERC1271_MAGIC


# ───────────────────────── parsing / serialisation ────────────────────────
# uint256 travels as a decimal STRING: a JSON number would silently round above
# 2**53. This is the same human-vs-atomic discipline the client enforces.
_ORDER_FIELDS = (
    "maker", "taker", "sellToken", "buyToken", "sellAmount", "buyAmount",
    "recipient", "maxTip", "fillWindow", "deadline",
)
_ADDRESS_FIELDS = ("maker", "taker", "sellToken", "buyToken", "recipient")
_UINT_FIELDS = ("sellAmount", "buyAmount", "maxTip", "fillWindow", "deadline")


class Malformed(ValueError):
    """P4 violation: the payload is not a well-formed SignedOrder."""


def _is_address(v: Any) -> bool:
    return (
        isinstance(v, str)
        and len(v) == 42
        and v.startswith("0x")
        and all(c in "0123456789abcdefABCDEF" for c in v[2:])
    )


def _to_uint(v: Any, name: str) -> int:
    if isinstance(v, bool):
        raise Malformed(f"{name}: bool is not a uint256")
    if isinstance(v, int):
        n = v
    elif isinstance(v, str) and v.isdigit():
        n = int(v)
    else:
        raise Malformed(f"{name}: expected decimal string, got {v!r}")
    if not 0 <= n < 2**256:
        raise Malformed(f"{name}: out of uint256 range")
    return n


def parse_signed_order(body: Any) -> tuple[Order, int, bytes]:
    """Strict parse. Anything unexpected raises Malformed (→ P4)."""
    if not isinstance(body, dict):
        raise Malformed("body must be an object")
    for key in ("order", "nonce", "signature"):
        if key not in body:
            raise Malformed(f"missing {key}")
    raw = body["order"]
    if not isinstance(raw, dict):
        raise Malformed("order must be an object")
    unknown = set(raw) - set(_ORDER_FIELDS)
    if unknown:
        raise Malformed(f"unknown order fields: {sorted(unknown)}")
    missing = set(_ORDER_FIELDS) - set(raw)
    if missing:
        raise Malformed(f"missing order fields: {sorted(missing)}")

    fields: dict[str, Any] = {}
    for f in _ADDRESS_FIELDS:
        if not _is_address(raw[f]):
            raise Malformed(f"{f}: not an address")
        fields[f] = raw[f]
    for f in _UINT_FIELDS:
        fields[f] = _to_uint(raw[f], f)

    order = Order(**fields)

    nonce = _to_uint(body["nonce"], "nonce")
    sig = body["signature"]
    if not isinstance(sig, str) or not sig.startswith("0x"):
        raise Malformed("signature: expected 0x-prefixed hex")
    try:
        sig_bytes = bytes.fromhex(sig[2:])
    except ValueError as exc:
        raise Malformed("signature: not hex") from exc
    if not sig_bytes:
        raise Malformed("signature: empty")
    return order, nonce, sig_bytes


def order_to_json(order: Order) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in _ORDER_FIELDS:
        v = getattr(order, f)
        if f in ("fillWindow", "deadline"):
            out[f] = int(v)          # timestamps fit a JSON number safely
        elif f in _UINT_FIELDS:
            out[f] = str(v)          # amounts stay decimal strings
        else:
            out[f] = v
    return out


# ──────────────────────── validity predicate P1–P7 ────────────────────────
# CLOSED LIST. Adding a rule here without changing openapi.yaml and the tests is
# a specification change smuggled in as an implementation detail.
#
#   P1  signature valid (ecrecover, or ERC-1271 via eth_call, or DEFERRED+declared)
#   P2  not expired — `now <= deadline`, matching Permit2's strict `>`
#   P3  fillWindow <= deadline
#   P4  well-formed (enforced by parse_signed_order)
#   P5  local orderHash dedup — idempotent, never an error
#   P6  maker balance >= permitted            ← ANTI-SPAM ONLY (TOCTOU)
#   P7  Permit2 allowance present             ← ANTI-SPAM ONLY (TOCTOU)
#
# P6/P7 are filters, never guarantees: the maker can drain or revoke one block
# later. The ONLY fund guarantee is on-chain, at settlement, via I6.
@dataclass
class Verdict:
    failed: list[str]
    skipped: list[str]
    sig_check: str | None
    detail: dict[str, str]

    @property
    def valid(self) -> bool:
        return not self.failed


def check_signature(
    order: Order, nonce: int, sig: bytes, cfg: Config, rpc: Rpc
) -> tuple[bool, str, str]:
    """P1. Returns (ok, sig_check, detail).

    Order of attempts mirrors Permit2's own SignatureVerification: EOA recover
    first, contract branch second. `deferred` is returned only when the relay
    genuinely cannot check (contract maker, no RPC) — it never masks a failure.
    """
    digest = signing_digest(order, nonce, cfg.spartan1, cfg.chain_id)

    if len(sig) == 65:
        try:
            recovered = Account._recover_hash(digest, signature=sig)
            if recovered.lower() == order.maker.lower():
                return True, "ecdsa", ""
        except Exception:
            pass

    if rpc.available:
        try:
            has_code = len(rpc.code_at(order.maker)) > 2
        except Exception as exc:
            return True, "deferred", f"rpc unavailable for 1271 check: {exc}"
        if has_code:
            if erc1271_valid(rpc, order.maker, digest, sig):
                return True, "erc1271", ""
            return False, "erc1271", "isValidSignature did not return the magic value"
        return False, "ecdsa", "recovered signer != maker"

    # No RPC: cannot distinguish "contract maker with a valid 1271 signature" from
    # "bad signature". Rejecting would censor every smart-account maker, so accept
    # and DECLARE it. Accepting costs the executor one cheap local re-verification;
    # rejecting would break a legitimate class of makers.
    return True, "deferred", "no RPC: contract-maker signatures cannot be verified here"


def evaluate(
    order: Order, nonce: int, sig: bytes, cfg: Config, rpc: Rpc,
    *, known_hash: bool, now: int | None = None,
) -> Verdict:
    now = int(time.time()) if now is None else now
    failed: list[str] = []
    skipped: list[str] = []
    detail: dict[str, str] = {}

    # P1
    ok, sig_check, why = check_signature(order, nonce, sig, cfg, rpc)
    if not ok:
        failed.append("P1")
        detail["P1"] = why
    elif why:
        detail["P1"] = why

    # P2 — `<=`, NOT `<`. Permit2 compares with strict `>`, so an order is valid
    # AT the deadline second. A relay using `<` would discard orders the chain
    # would still settle.
    if now > order.deadline:
        failed.append("P2")
        detail["P2"] = f"expired: now={now} > deadline={order.deadline}"

    # P3
    if order.fillWindow > order.deadline:
        failed.append("P3")
        detail["P3"] = "fillWindow > deadline (fallback would never open)"

    # P4 is enforced at parse time; reaching here means it held.

    # P5 — dedup is IDEMPOTENT, not a rejection. Handled by the caller, which
    # returns the original verdict for a known hash.
    if known_hash:
        detail["P5"] = "already pooled (idempotent no-op)"

    # P6 / P7 — anti-spam only. Skipped and DECLARED when there is no RPC.
    permitted = order.permitted()
    if not rpc.available:
        skipped.extend(("P6", "P7"))
        detail["P6"] = detail["P7"] = "not evaluated: no RPC configured"
    else:
        try:
            bal = erc20_balance_of(rpc, order.sellToken, order.maker)
            if bal < permitted:
                failed.append("P6")
                detail["P6"] = f"maker balance {bal} < permitted {permitted}"
        except Exception as exc:
            skipped.append("P6")
            detail["P6"] = f"not evaluated: {exc}"
        try:
            allw = erc20_allowance(rpc, order.sellToken, order.maker, PERMIT2)
            if allw < permitted:
                failed.append("P7")
                detail["P7"] = f"Permit2 allowance {allw} < permitted {permitted}"
        except Exception as exc:
            skipped.append("P7")
            detail["P7"] = f"not evaluated: {exc}"

    return Verdict(failed=failed, skipped=skipped, sig_check=sig_check, detail=detail)


# ──────────────────────────────── order pool ──────────────────────────────
@dataclass
class Entry:
    order: Order
    nonce: int
    signature: bytes
    order_hash: str
    received_at: int
    sig_check: str

    def to_json(self) -> dict[str, Any]:
        return {
            "order": order_to_json(self.order),
            "nonce": str(self.nonce),
            "signature": "0x" + self.signature.hex(),
            "orderHash": self.order_hash,
            "receivedAt": self.received_at,
            "sigCheck": self.sig_check,
        }


class Pool:
    """In-memory, insertion-ordered, deduplicated by orderHash.

    Stateless beyond this pool: losing it loses nothing that matters, because a
    signed Order is self-contained and whoever holds one can call settle()
    directly. That is exactly why a relay is an accelerator and not a gatekeeper.
    """

    def __init__(self) -> None:
        self._by_hash: dict[str, Entry] = {}
        self._lock = threading.Lock()

    def add(self, entry: Entry) -> bool:
        """Returns True if newly added, False if already present (P5)."""
        with self._lock:
            if entry.order_hash in self._by_hash:
                return False
            self._by_hash[entry.order_hash] = entry
            return True

    def get(self, order_hash: str) -> Entry | None:
        with self._lock:
            return self._by_hash.get(order_hash)

    def prune(self, now: int) -> int:
        """Expired orders are never served. Lazy, so cost is bounded by traffic."""
        with self._lock:
            dead = [h for h, e in self._by_hash.items() if now > e.order.deadline]
            for h in dead:
                del self._by_hash[h]
            return len(dead)

    def live(self, now: int) -> list[Entry]:
        with self._lock:
            return [e for e in self._by_hash.values() if now <= e.order.deadline]

    def query(
        self, now: int, *, sell_token: str | None = None, buy_token: str | None = None,
        taker: str | None = None, limit: int = 200,
    ) -> list[Entry]:
        out = []
        for e in self.live(now):
            if sell_token and e.order.sellToken.lower() != sell_token.lower():
                continue
            if buy_token and e.order.buyToken.lower() != buy_token.lower():
                continue
            # Open orders are for everyone; addressed orders only for their taker.
            if e.order.taker.lower() != ZERO_ADDRESS:
                if not taker or e.order.taker.lower() != taker.lower():
                    continue
            out.append(e)
            if len(out) >= limit:
                break
        return out


# ────────────────────────── perspective inversion ─────────────────────────
# The Order is MAKER-centric; /quote is TAKER-centric (0x / Uniswap convention).
# They are mirror images. Conflating them silently inverts a swap, so the mapping
# lives in one named place and is covered by a test.
#
#   taker sells  (0x sellToken/sellAmount)  ==  order.buyToken  / order.buyAmount
#   taker buys   (0x buyToken /buyAmount )  ==  order.sellToken / order.sellAmount
def taker_view(order: Order) -> dict[str, str]:
    return {
        "sellToken": order.buyToken,     # taker pays this
        "buyToken": order.sellToken,     # taker receives this
        "sellAmount": str(order.buyAmount),
        "buyAmount": str(order.sellAmount),
    }


def maker_view_request(
    *, sell_token: str, buy_token: str,
    sell_amount: int | None, buy_amount: int | None,
) -> dict[str, Any]:
    """Translate a taker-centric /quote query into a maker-centric RFQ request."""
    return {
        "sellToken": buy_token,          # maker gives what the taker receives
        "buyToken": sell_token,          # maker receives what the taker pays
        "sellAmount": str(buy_amount) if buy_amount is not None else None,
        "buyAmount": str(sell_amount) if sell_amount is not None else None,
    }


# ─────────────────────────────── RFQ fan-out ──────────────────────────────
def best_quote(candidates: list[tuple[Order, int, bytes]], *, exact_out: bool):
    """Mechanical selection — no discretion, no maker reputation, no last look.

    exact_out (caller fixed sellAmount, what they receive) → lowest buyAmount wins.
    exact_in  (caller fixed buyAmount, what they pay)      → highest sellAmount wins.
    Ties break by arrival order, which is the list order.
    """
    if not candidates:
        return None
    if exact_out:
        return min(candidates, key=lambda c: c[0].buyAmount)
    return max(candidates, key=lambda c: c[0].sellAmount)


def fan_out_to_makers(
    cfg: Config, rpc: Rpc, request: dict[str, Any], *, exact_out: bool,
) -> tuple[Order, int, bytes] | None:
    """Ask every registered maker webhook in parallel; wait at most MAKER_SIGN_BUDGET.

    A maker that declines or times out is NOT penalised: relays keep no reputation,
    and "not quoting" is a first-class answer. That is what keeps relay
    participation democratic and makes Sybil pointless.
    """
    if not cfg.maker_webhooks:
        return None
    payload = json.dumps({k: v for k, v in request.items() if v is not None}).encode()
    candidates: list[tuple[Order, int, bytes]] = []

    def ask(url: str):
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=MAKER_SIGN_BUDGET) as resp:
            return json.loads(resp.read())

    with ThreadPoolExecutor(max_workers=max(1, len(cfg.maker_webhooks))) as pool:
        futures = {pool.submit(ask, u): u for u in cfg.maker_webhooks}
        for fut in as_completed(futures, timeout=MAKER_SIGN_BUDGET + 0.5):
            try:
                body = fut.result()
                order, nonce, sig = parse_signed_order(body)
            except Exception:
                continue  # decline / timeout / malformed → silently ignored, no penalty
            verdict = evaluate(order, nonce, sig, cfg, rpc, known_hash=False)
            if verdict.valid:
                candidates.append((order, nonce, sig))

    return best_quote(candidates, exact_out=exact_out)


# ───────────────── client-side fan-out (anti-Sybil rule 2) ────────────────
def select_relays(relays: Iterable[str], *, target: int = FANOUT_TARGET,
                  rng: random.Random | None = None) -> list[str]:
    """Uniform-random selection of `target` relays (all of them if fewer exist).

    CLIENT-side helper, not a server route — included because every maker needs it
    and a wrong implementation quietly breaks the security argument.

    Uniform means uniform: equal probability per relay regardless of age, size, or
    uptime. That is what makes participation structurally democratic, and it is
    what makes censorship cost f**target — an attacker needs f ≈ 0.92 (12× all
    honest relays combined) to censor half the flow, for zero revenue, while the
    order remains settleable directly on-chain anyway.

    Weighting by reputation or stake would reintroduce the centralisation this
    design removes. Do not "improve" it.
    """
    pool = list(dict.fromkeys(relays))  # de-dup, preserve order
    r = rng or random.SystemRandom()
    if len(pool) <= target:
        return pool
    return r.sample(pool, target)


# ───────────────────────────── HTTP handler ───────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"spartan1-relay/{VERSION}"

    cfg: Config
    rpc: Rpc
    pool: Pool
    started_at: int
    pairs: list[dict[str, str]]

    # ---------- plumbing ----------
    def _send(self, code: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        if os.environ.get("RELAY_VERBOSE"):
            super().log_message(fmt, *args)

    def _query(self) -> dict[str, list[str]]:
        return parse_qs(urlparse(self.path).query)

    @staticmethod
    def _one(q: dict[str, list[str]], key: str) -> str | None:
        v = q.get(key)
        return v[0] if v else None

    # ---------- routes ----------
    def do_GET(self) -> None:
        route = urlparse(self.path).path.rstrip("/") or "/"
        if route == "/orders":
            return self._get_orders()
        if route == "/rfq/tokens":
            return self._send(200, {"pairs": self.pairs})
        if route == "/quote":
            return self._get_quote()
        if route == "/health":
            return self._get_health()
        self._send(404, {"error": "no such route"})

    def do_POST(self) -> None:
        route = urlparse(self.path).path.rstrip("/") or "/"
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            return self._send(422, {"valid": False, "failed": ["P4"],
                                    "detail": {"P4": "body is not valid JSON"}})
        if route == "/order":
            return self._post_order(body)
        if route == "/rfq/quote":
            return self._post_rfq_quote(body)
        self._send(404, {"error": "no such route"})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ---------- POST /order ----------
    def _post_order(self, body: Any) -> None:
        now = int(time.time())
        self.pool.prune(now)
        try:
            order, nonce, sig = parse_signed_order(body)
        except Malformed as exc:
            return self._send(422, {"valid": False, "failed": ["P4"],
                                    "detail": {"P4": str(exc)}})

        h = "0x" + order_hash(order).hex()
        existing = self.pool.get(h)
        if existing is not None:
            # P5: idempotent. Same body as the first accept, never an error.
            return self._send(200, {"orderHash": h, "valid": True,
                                    "sigCheck": existing.sig_check, "duplicate": True,
                                    "skipped": list(self.cfg.enforced_predicates()
                                                    and set(ALL_PREDICATES)
                                                    - set(self.cfg.enforced_predicates()))})

        verdict = evaluate(order, nonce, sig, self.cfg, self.rpc, known_hash=False, now=now)
        if not verdict.valid:
            return self._send(422, {"valid": False, "failed": verdict.failed,
                                    "detail": verdict.detail})

        added = self.pool.add(Entry(order, nonce, sig, h, now, verdict.sig_check or "deferred"))
        return self._send(200, {"orderHash": h, "valid": True,
                                "sigCheck": verdict.sig_check, "duplicate": not added,
                                "skipped": verdict.skipped})

    # ---------- GET /orders ----------
    def _get_orders(self) -> None:
        q = self._query()
        now = int(time.time())
        self.pool.prune(now)
        try:
            limit = min(1000, max(1, int(self._one(q, "limit") or 200)))
        except ValueError:
            limit = 200
        entries = self.pool.query(
            now,
            sell_token=self._one(q, "sellToken"),
            buy_token=self._one(q, "buyToken"),
            taker=self._one(q, "taker"),
            limit=limit,
        )
        self._send(200, {"orders": [e.to_json() for e in entries], "count": len(entries)})

    # ---------- POST /rfq/quote ----------
    def _post_rfq_quote(self, body: Any) -> None:
        if not isinstance(body, dict):
            return self._send(422, {"error": "body must be an object"})
        sell_token, buy_token = body.get("sellToken"), body.get("buyToken")
        if not (_is_address(sell_token or "") and _is_address(buy_token or "")):
            return self._send(422, {"error": "sellToken and buyToken must be addresses"})
        has_sell, has_buy = body.get("sellAmount") is not None, body.get("buyAmount") is not None
        if has_sell == has_buy:
            return self._send(422, {"error": "supply exactly one of sellAmount / buyAmount"})

        result = fan_out_to_makers(self.cfg, self.rpc, body, exact_out=has_sell)
        if result is None:
            # 404 = not quoting. Normal, no penalty, no maker reputation recorded.
            return self._send(404, {"error": "not quoting"})
        order, nonce, sig = result
        self._send(200, {"order": order_to_json(order), "nonce": str(nonce),
                         "signature": "0x" + sig.hex(),
                         "chainId": self.cfg.chain_id, "spartan1": self.cfg.spartan1})

    # ---------- GET /quote (taker-centric adapter) ----------
    def _get_quote(self) -> None:
        q = self._query()
        sell_token, buy_token = self._one(q, "sellToken"), self._one(q, "buyToken")
        if not (_is_address(sell_token or "") and _is_address(buy_token or "")):
            return self._send(422, {"error": "sellToken and buyToken are required addresses"})
        raw_sell, raw_buy = self._one(q, "sellAmount"), self._one(q, "buyAmount")
        if (raw_sell is None) == (raw_buy is None):
            return self._send(422, {"error": "supply exactly one of sellAmount / buyAmount"})
        try:
            sell_amount = int(raw_sell) if raw_sell is not None else None
            buy_amount = int(raw_buy) if raw_buy is not None else None
        except ValueError:
            return self._send(422, {"error": "amounts must be decimal strings"})

        # Taker-centric query → maker-centric request. EXACT_OUTPUT for the taker
        # (they fixed what they receive) fixes order.sellAmount → exact_out=True.
        request = maker_view_request(
            sell_token=sell_token, buy_token=buy_token,
            sell_amount=sell_amount, buy_amount=buy_amount,
        )
        result = fan_out_to_makers(self.cfg, self.rpc, request, exact_out=buy_amount is not None)
        if result is None:
            # Fall back to the pool: a resting order may already satisfy the query.
            now = int(time.time())
            for e in self.pool.query(now, sell_token=buy_token, buy_token=sell_token):
                if buy_amount is not None and e.order.sellAmount != buy_amount:
                    continue
                if sell_amount is not None and e.order.buyAmount != sell_amount:
                    continue
                result = (e.order, e.nonce, e.signature)
                break
        if result is None:
            return self._send(404, {"error": "no quote available"})

        order, nonce, sig = result
        tv = taker_view(order)
        price = (
            str(int(tv["buyAmount"]) / int(tv["sellAmount"]))
            if int(tv["sellAmount"]) else "0"
        )
        self._send(200, {
            **tv,
            "price": price,
            "allowanceTarget": self.cfg.spartan1,
            "to": self.cfg.spartan1,
            "order": order_to_json(order),
            "nonce": str(nonce),
            "signature": "0x" + sig.hex(),
        })

    # ---------- GET /health ----------
    def _get_health(self) -> None:
        now = int(time.time())
        self.pool.prune(now)
        out: dict[str, Any] = {
            "chainId": self.cfg.chain_id,
            "permit2": PERMIT2,
            "spartan1": self.cfg.spartan1,
            "ordersOpen": len(self.pool.live(now)),
            "uptime": now - self.started_at,
            "predicates": list(self.cfg.enforced_predicates()),
            "version": VERSION,
        }
        nonce = self._one(self._query(), "nonce")
        if nonce is not None:
            # Freshness challenge (anti-Sybil rule 3): echoing a client nonce with a
            # CURRENT blockhash is something a phantom relay serving stale or
            # fabricated listings cannot fake.
            try:
                number, block_hash = self.rpc.latest_block()
                out["challenge"] = {"nonce": nonce, "blockNumber": number,
                                    "blockHash": block_hash}
            except Exception as exc:
                out["challenge"] = None
                out["challengeError"] = str(exc)
        self._send(200, out)


# ─────────────────────────────── entrypoint ───────────────────────────────
def build_server(cfg: Config, rpc: Rpc | None = None,
                 pairs: list[dict[str, str]] | None = None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {
        "cfg": cfg,
        "rpc": rpc or Rpc(cfg.rpc_url),
        "pool": Pool(),
        "started_at": int(time.time()),
        "pairs": pairs or [],
    })
    return ThreadingHTTPServer((cfg.host, cfg.port), handler)


def main() -> None:
    cfg = Config.from_env()
    server = build_server(cfg)
    enforced = ",".join(cfg.enforced_predicates())
    print(f"spartan1-relay/{VERSION} on http://{cfg.host}:{cfg.port}")
    print(f"  chainId={cfg.chain_id} spartan1={cfg.spartan1}")
    print(f"  predicates enforced: {enforced}")
    if not cfg.rpc_url:
        print("  WARNING: no RPC_URL — P6/P7 not evaluated, /health declares this.")
    if not cfg.maker_webhooks:
        print("  note: no MAKER_WEBHOOKS — /rfq/quote and /quote fan-out return 404.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
