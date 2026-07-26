#!/usr/bin/env python3
"""Spartan1 reference executor — polls relays, re-verifies everything, simulates, settles.

Conforms to distribution/openapi.yaml (consumes `GET /orders` and `GET /health`). The executor
is the one actor that spends its OWN capital, so its guardrails are about not losing it.

HARD INVARIANT #1 — THE TAKER GUARD (loses real money if missed):
    `buyAmount` always comes from `msg.sender` (Spartan1.sol step 5–6). Therefore the executor
    settles ONLY when `order.taker == 0x0` (open) OR `order.taker == self`. For an order addressed
    to someone else, the executor would pay `buyAmount`, the named taker would receive `sellAmount`
    for free, and the executor would get back only `tip` → net −buyAmount + tip. This is NOT
    configurable and NOT overridable by env. A naive "tip > gas ⇒ profitable" loop donates buyAmount
    to a stranger.

MOTHER PRINCIPLE: nothing a relay serves is trusted. Every field is re-derived or re-verified
locally — `orderHash` is recomputed, the signature is recovered against `signing_digest`, and the
call is simulated with `eth_call` before any send. A relay can only omit or delay.

Guardrails, ON by default (same convention as maker.py):
  * dry-run by default; real submission needs an explicit flag
  * `eth_call` simulation before every send — NOT disableable
  * full local re-verification (recompute hash, recover signature, `now <= deadline`, fillWindow)
  * poll ALL relays (anti-Sybil rule 3), dedup by recomputed orderHash, no relay ranking
  * optional `/health?nonce=` freshness challenge; a relay that can't answer is skipped
  * skip the hot window (maker-only) without spending an RPC
  * deadline margin, min-profit floor (bps), max notional per settle
  * NO pricing engine — an injected `price_fn`, exactly like maker's `quote_fn`

stdlib + the signing stack already in client/order.py (eth_account, eth_abi, eth_hash). No web3.py.

RUN:
    SPARTAN1_ADDRESS=0x... EXECUTOR_PRIVATE_KEY=0x... RELAYS=https://r1,https://r2 \
    CHAIN_ID=8453 RPC_URL=https://... python3 executor.py        # dry-run
    # add SUBMIT=1 to actually broadcast settle() txs (each still simulated first).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from fractions import Fraction
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_abi import encode as abi_encode  # noqa: E402
from eth_account import Account  # noqa: E402

from order import Order, order_hash  # noqa: E402  — single source: typehash / witness / encoding
import relay as R  # noqa: E402  — reuse parse_signed_order, Rpc, check_signature, taker_view

# settle((Order),uint256 requestedAmount,uint256 nonce,bytes makerSig) — selector asserted in tests.
ORDER_TUPLE = "(address,address,address,address,uint256,uint256,address,uint256,uint256,uint256)"
SETTLE_SIGNATURE = f"settle({ORDER_TUPLE},uint256,uint256,bytes)"
from eth_hash.auto import keccak  # noqa: E402
SETTLE_SELECTOR = keccak(SETTLE_SIGNATURE.encode())[:4]  # == 0x0560694d

PriceFn = Callable[[str, str], Optional[Fraction]]  # (sellToken, buyToken) -> buy-atomic per sell-atomic

VERSION = "1"


# ────────────────────────────── configuration ─────────────────────────────
@dataclass(frozen=True)
class Config:
    spartan1: str
    chain_id: int
    executor: str
    private_key: str
    relays: tuple[str, ...]
    dry_run: bool = True
    min_profit_bps: int = 0
    max_notional: int = 2**255
    deadline_margin_s: int = 8
    freshness_challenge: bool = False
    poll_timeout: float = 4.0

    @classmethod
    def build(cls, *, spartan1: str | None, private_key: str, relays, chain_id: int = 8453,
              submit: bool = False, **kw) -> "Config":
        if not spartan1:
            raise SystemExit("SPARTAN1_ADDRESS is required: the executor simulates and settles against "
                             "it. Without the deployed address every simulation reverts.")
        executor = Account.from_key(private_key).address
        return cls(spartan1=spartan1, chain_id=chain_id, executor=executor, private_key=private_key,
                   relays=tuple(relays), dry_run=not submit, **kw)

    @classmethod
    def from_env(cls) -> "Config":
        pk = os.environ.get("EXECUTOR_PRIVATE_KEY")
        if not pk:
            raise SystemExit("EXECUTOR_PRIVATE_KEY is required.")
        relays = [r.strip() for r in os.environ.get("RELAYS", "").split(",") if r.strip()]
        return cls.build(
            spartan1=os.environ.get("SPARTAN1_ADDRESS"), private_key=pk, relays=relays,
            chain_id=int(os.environ.get("CHAIN_ID", "8453")),
            submit=os.environ.get("SUBMIT") == "1",
            min_profit_bps=int(os.environ.get("MIN_PROFIT_BPS", "0")),
            max_notional=int(os.environ.get("MAX_NOTIONAL", str(2**255))),
            deadline_margin_s=int(os.environ.get("DEADLINE_MARGIN_S", "8")),
            freshness_challenge=os.environ.get("FRESHNESS_CHALLENGE") == "1",
        )

    def _relay_cfg(self) -> "R.Config":
        # For reusing relay.check_signature (needs .spartan1 and .chain_id only).
        return R.Config(spartan1=self.spartan1, chain_id=self.chain_id, rpc_url="executor://")


# ─────────────────────────────── calldata / sim ───────────────────────────
def build_settle_calldata(order: Order, requested: int, nonce: int, sig: bytes) -> bytes:
    tup = (order.maker, order.taker, order.sellToken, order.buyToken, order.sellAmount,
           order.buyAmount, order.recipient, order.maxTip, order.fillWindow, order.deadline)
    return SETTLE_SELECTOR + abi_encode([ORDER_TUPLE, "uint256", "uint256", "bytes"],
                                        [tup, requested, nonce, sig])


def simulate(rpc: "R.Rpc", cfg: Config, order: Order, requested: int, nonce: int, sig: bytes) -> bool:
    """eth_call with `from = self`. NOT disableable. Revert (any exception) → not settleable."""
    data = "0x" + build_settle_calldata(order, requested, nonce, sig).hex()
    try:
        rpc.call("eth_call", [{"from": cfg.executor, "to": cfg.spartan1, "data": data}, "latest"])
        return True
    except Exception:
        return False


def _send(rpc: "R.Rpc", cfg: Config, calldata: bytes) -> str:
    data = "0x" + calldata.hex()
    tx = {
        "chainId": cfg.chain_id, "to": cfg.spartan1, "data": data, "value": 0,
        "nonce": int(rpc.call("eth_getTransactionCount", [cfg.executor, "pending"]), 16),
        "gas": int(rpc.call("eth_estimateGas",
                            [{"from": cfg.executor, "to": cfg.spartan1, "data": data}]), 16),
        "maxFeePerGas": int(rpc.call("eth_gasPrice", []), 16),
        "maxPriorityFeePerGas": 1_000_000_000,
    }
    signed = Account.sign_transaction(tx, cfg.private_key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return rpc.call("eth_sendRawTransaction", ["0x" + raw.hex()])


# ─────────────────────────────── decisions ────────────────────────────────
@dataclass
class Decision:
    order_hash: str
    action: str            # "settle" | "refuse" | "skip"
    reason: str
    sent: bool = False
    tx: Optional[str] = None


def evaluate(cfg: Config, price_fn: PriceFn, rpc: "R.Rpc",
             order: Order, nonce: int, sig: bytes, now: int) -> Decision:
    h = "0x" + order_hash(order).hex()   # recomputed locally; the relay's claim is ignored

    # 1. TAKER GUARD — the money guard. Never configurable.
    if not (order.taker == R.ZERO_ADDRESS or order.taker.lower() == cfg.executor.lower()):
        return Decision(h, "refuse",
                        "taker guard: order addressed to a third party — settling would pay buyAmount "
                        "and receive only the tip")

    # 2. Full local re-verification (zero trust in relay-supplied sigCheck/orderHash).
    ok, how, why = R.check_signature(order, nonce, sig, cfg._relay_cfg(), rpc)
    if not ok or how == "deferred":
        return Decision(h, "refuse", f"signature not verified locally ({how}: {why})")

    # 3. Deadline (<= matches Permit2's strict >) + a safety margin.
    if now > order.deadline:
        return Decision(h, "refuse", "expired (now > deadline)")
    if order.deadline - now < cfg.deadline_margin_s:
        return Decision(h, "refuse", f"within deadline margin ({cfg.deadline_margin_s}s)")

    # 4. Hot window is maker-only — skip without spending an RPC.
    if now < order.fillWindow:
        return Decision(h, "skip", "hot window (maker-only)")

    # 5. Economics. Fallback → requested = sellAmount + maxTip; executor is the taker (guard above),
    #    so it receives sellAmount + tip of sellToken and pays buyAmount of buyToken.
    requested = order.sellAmount + order.maxTip
    mid = price_fn(order.sellToken, order.buyToken)
    if mid is None:
        return Decision(h, "skip", "no price for this pair")
    if order.buyAmount <= 0:
        return Decision(h, "refuse", "degenerate buyAmount")
    received_in_buy = Fraction(order.sellAmount + order.maxTip) * mid
    profit_bps = (received_in_buy - order.buyAmount) * 10000 / order.buyAmount
    if profit_bps < cfg.min_profit_bps:
        return Decision(h, "refuse",
                        f"below min-profit floor ({float(profit_bps):.2f} < {cfg.min_profit_bps} bps)")
    if order.buyAmount > cfg.max_notional:
        return Decision(h, "refuse", "over max notional per settle")

    # 6. Simulation — the last gate before spending gas. NOT disableable.
    if not simulate(rpc, cfg, order, requested, nonce, sig):
        return Decision(h, "refuse", "eth_call simulation reverted")

    return Decision(h, "settle", "would settle (dry-run)" if cfg.dry_run else "settling")


# ─────────────────────────────── relay polling ────────────────────────────
def _http_get_json(url: str, timeout: float):
    with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def _relay_is_fresh(url: str, cfg: Config) -> bool:
    """anti-Sybil rule 3: a relay that cannot echo a current blockhash for our nonce is skipped."""
    n = "%016x" % secrets.randbits(64)
    try:
        h = _http_get_json(f"{url}/health?nonce={n}", cfg.poll_timeout)
    except Exception:
        return False
    ch = h.get("challenge")
    return bool(ch) and ch.get("nonce") == n and isinstance(ch.get("blockHash"), str)


def poll_relays(cfg: Config) -> list[tuple[Order, int, bytes]]:
    """Poll ALL relays, parse every order, dedup by the RECOMPUTED hash. No ranking, no weighting."""
    seen: dict[str, tuple[Order, int, bytes]] = {}
    for url in cfg.relays:
        if cfg.freshness_challenge and not _relay_is_fresh(url, cfg):
            continue
        try:
            body = _http_get_json(f"{url}/orders", cfg.poll_timeout)
        except Exception:
            continue  # a down/omitting relay can only cost liveness, never safety
        for entry in body.get("orders", []):
            try:
                order, nonce, sig = R.parse_signed_order(entry)  # tolerates unknown top-level fields
            except Exception:
                continue
            h = "0x" + order_hash(order).hex()   # never trust entry["orderHash"]
            seen.setdefault(h, (order, nonce, sig))
    return list(seen.values())


def run_once(cfg: Config, price_fn: PriceFn, rpc: "R.Rpc", now: Optional[int] = None) -> list[Decision]:
    now = int(time.time()) if now is None else now
    decisions: list[Decision] = []
    for order, nonce, sig in poll_relays(cfg):
        d = evaluate(cfg, price_fn, rpc, order, nonce, sig, now)
        if d.action == "settle" and not cfg.dry_run:
            requested = order.sellAmount + order.maxTip
            try:
                d.tx = _send(rpc, cfg, build_settle_calldata(order, requested, nonce, sig))
                d.sent = True
            except Exception as exc:
                d.action, d.reason = "refuse", f"send failed after green simulation: {exc}"
        decisions.append(d)
    return decisions


# ─────────────────────────────── reference price ──────────────────────────
def reference_price_fn(table: dict[tuple[str, str], Fraction]) -> PriceFn:
    """DELIBERATELY INADEQUATE static price source (no live feed). Inject your real pricing."""
    t = {(s.lower(), b.lower()): m for (s, b), m in table.items()}

    def fn(sell_token: str, buy_token: str) -> Optional[Fraction]:
        return t.get((sell_token.lower(), buy_token.lower()))
    return fn


def main() -> None:
    cfg = Config.from_env()
    rpc = R.Rpc(os.environ.get("RPC_URL"))
    if not rpc.available:
        raise SystemExit("RPC_URL is required: the executor MUST simulate every settle before sending.")
    print(f"spartan1-executor/{VERSION}  executor={cfg.executor} spartan1={cfg.spartan1}")
    print(f"  relays={list(cfg.relays)} dryRun={cfg.dry_run} minProfitBps={cfg.min_profit_bps}")
    print("  NOTE: no price_fn injected on the CLI — settlement economics are inert until you wire one.")
    # The CLI intentionally ships no prices (pricing is not this file's job). Operators import
    # run_once() with their own price_fn. Here we only demonstrate polling + re-verification.
    decisions = run_once(cfg, reference_price_fn({}), rpc)
    for d in decisions:
        print(f"  {d.action.upper():7} {d.order_hash[:12]}…  {d.reason}")


if __name__ == "__main__":
    main()
