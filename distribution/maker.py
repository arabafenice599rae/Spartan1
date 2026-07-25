#!/usr/bin/env python3
"""Spartan1 reference maker webhook — signs firm quotes. Guardrails ON by default.

Conforms to distribution/openapi.yaml (it is the relay's maker-side counterpart: the
relay POSTs a MAKER-CENTRIC RfqRequest and expects a SignedOrder back, or a 404).

THREE HARD REQUIREMENTS — not suggestions, one is a real-money risk:

  1. NOT A PRICING ENGINE.
     Price enters through an injected `quote_fn`. This file never computes fair value,
     spread from dispersion, inventory skew, exec-gap clamps, or hysteresis — putting
     that here would create a SECOND source of truth on prices (the same failure class
     the witness type string avoids by living in one place). The reference `quote_fn`
     below is trivial and DELIBERATELY UNFIT for production; your bot supplies the real
     one.

  2. NO PLACEBO SIGNING.
     This file SIGNS. With a placeholder `spender` the relay would accept (P1 passes)
     and executors would try, but `settle()` does not exist at that address — the loop
     LOOKS alive and never settles. So the maker REFUSES TO START without a deployed
     Spartan1 address, unless `DRY_RUN=1` is set explicitly, which marks every quote
     `settleable: false`. No silent default, ever.

  3. INVENTORY RESERVATION ON OUTSTANDING QUOTES  (not in the original spec).
     Sign 5 quotes of 1e18 against 2e18 of inventory and all 5 are cryptographically
     valid — distinct nonces, no on-chain conflict — but three can never settle, and
     the maker does not know which while its pricing already assumed inventory it does
     not have. The contract cannot protect you (by design: it knows neither prices nor
     inventory); the relay's P6 checks each order in isolation. So the reservation lives
     HERE: `sellAmount + maxTip` of the given token is committed until `deadline`,
     released at expiry, and subtracted from free inventory before quoting again.

NO LAST-LOOK. Once signed, a quote is firm. The only defenses are a short TTL and the
right to decline (`404`, zero penalty). There is deliberately NO cancel/revoke route:
adding one would reintroduce the maker trust this whole design removes.

stdlib only + the signing stack already in client/order.py. No web framework, no DB.

RUN:
    SPARTAN1_ADDRESS=0x... MAKER_PRIVATE_KEY=0x... CHAIN_ID=8453 \
    MAKER_INVENTORY='{"0x22..":"1000000000000000000000"}' python3 maker.py
    # DRY_RUN=1 to start without a deployed address (every quote marked non-settleable).
"""

from __future__ import annotations

import json
import math
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from fractions import Fraction
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_account import Account  # noqa: E402

from order import Order, sign_order  # noqa: E402  — SINGLE SOURCE for the Order + signing
# Reuse the wire helpers/constants from the relay so serialisation stays single-sourced.
from relay import (  # noqa: E402
    HOT_WINDOW as DEFAULT_HOT_WINDOW,
    QUOTE_TTL as DEFAULT_QUOTE_TTL,
    ZERO_ADDRESS,
    _is_address,
    order_to_json,
)

# The placeholder spender. Signing against it is USELESS on-chain; only DRY_RUN may use it.
PLACEHOLDER_SPENDER = "0x1111111111111111111111111111111111111111"

VERSION = "1"


# ────────────────────────── injectable pricing ────────────────────────────
# The ONLY price interface. `quote_fn(sell_token, buy_token, side, amount) -> Quote|None`.
# `None` = decline (not quoting / out of range / stale). `mid` is a FRACTION of buyToken
# atomic units per 1 sellToken atomic unit (decimals baked in), so all downstream math is
# exact integer arithmetic — never a float on money.
@dataclass(frozen=True)
class Quote:
    mid: Fraction        # buyToken-atomic per sellToken-atomic (fair)
    spread_bps: int      # maker's edge; the maker never quotes tighter than the floor
    as_of: Optional[int] = None  # feed timestamp; None → treated as fresh (staleness guard idle)


QuoteFn = Callable[[str, str, str, int], Optional[Quote]]


def reference_quote_fn(pairs: dict[tuple[str, str], Quote]) -> QuoteFn:
    """A DELIBERATELY INADEQUATE reference price source: a static table, no live feed, no
    dispersion, no skew, no staleness of its own. Present only so the webhook runs end to
    end in tests and demos. DO NOT ship it — inject your real pricing instead."""
    table = {(s.lower(), b.lower()): q for (s, b), q in pairs.items()}

    def fn(sell_token: str, buy_token: str, side: str, amount: int) -> Optional[Quote]:
        return table.get((sell_token.lower(), buy_token.lower()))

    fn.pairs = [{"sellToken": s, "buyToken": b} for (s, b) in pairs]  # type: ignore[attr-defined]
    return fn


# ─────────────────────── inventory reservation ledger ─────────────────────
# The real-money guard. Reservations are keyed by the token the maker GIVES (sellToken),
# so bilateral quoting (giving A on one pair, B on another) reserves each side separately.
class InventoryLedger:
    def __init__(
        self,
        inventory: dict[str, int],
        *,
        max_quote: dict[str, int] | None = None,
        max_window: dict[str, int] | None = None,
    ) -> None:
        self.inventory = {k.lower(): int(v) for k, v in inventory.items()}
        # Guardrails ON by default: absent caps default to the token's own inventory.
        self.max_quote = {**{t: v for t, v in self.inventory.items()},
                          **{k.lower(): int(v) for k, v in (max_quote or {}).items()}}
        self.max_window = {**{t: v for t, v in self.inventory.items()},
                           **{k.lower(): int(v) for k, v in (max_window or {}).items()}}
        self._reservations: list[tuple[str, int, int]] = []   # (token, permitted, deadline)
        self._window: list[tuple[str, int, int]] = []         # (token, permitted, signed_at)
        self._lock = threading.Lock()

    def _committed(self, token: str, now: int) -> int:
        self._reservations = [r for r in self._reservations if r[2] >= now]
        return sum(p for (t, p, _d) in self._reservations if t == token)

    def _window_sum(self, token: str, now: int, ttl: int) -> int:
        self._window = [w for w in self._window if now - w[2] <= ttl]
        return sum(p for (t, p, _s) in self._window if t == token)

    def free(self, token: str, now: int) -> int:
        with self._lock:
            return self.inventory.get(token.lower(), 0) - self._committed(token.lower(), now)

    def try_reserve(
        self, token: str, permitted: int, deadline: int, now: int, ttl: int
    ) -> Optional[str]:
        """Atomic check-and-commit. Returns None on success, or a decline reason string.
        The lock makes the free-inventory check-and-reserve indivisible, so concurrent
        webhook calls cannot double-commit the same inventory."""
        t = token.lower()
        with self._lock:
            if t not in self.inventory:
                return "no inventory configured for sellToken"
            if permitted > self.max_quote.get(t, 0):
                return "exceeds per-quote notional cap"
            if self._window_sum(t, now, ttl) + permitted > self.max_window.get(t, 0):
                return "exceeds per-window notional cap"
            free = self.inventory[t] - self._committed(t, now)
            if permitted > free:
                return "insufficient free inventory (outstanding signed quotes reserve it)"
            self._reservations.append((t, permitted, deadline))
            self._window.append((t, permitted, now))
            return None


# ────────────────────────────── configuration ─────────────────────────────
@dataclass(frozen=True)
class Config:
    spartan1: str                 # the Permit2 spender bound into every signature
    chain_id: int
    private_key: str
    maker: str
    recipient: str
    settleable: bool              # False under DRY_RUN or a placeholder spender
    dry_run: bool
    quote_ttl: int = DEFAULT_QUOTE_TTL
    hot_window: int = DEFAULT_HOT_WINDOW
    spread_floor_bps: int = 10
    max_tip_bps: int = 0          # tip cap as bps of sellAmount (in sellToken)
    feed_staleness_max: int = 5   # seconds; older feed → decline
    host: str = "127.0.0.1"
    port: int = 8546

    @classmethod
    def build(
        cls, *, spartan1: str | None, private_key: str, chain_id: int = 8453,
        dry_run: bool = False, recipient: str | None = None, **kw: Any,
    ) -> "Config":
        # REQUIREMENT 2: refuse to start without a deployed spender, unless DRY_RUN.
        if not spartan1:
            if not dry_run:
                raise SystemExit(
                    "SPARTAN1_ADDRESS is required: this maker SIGNS, and a signature bound to a "
                    "placeholder spender is accepted by relays yet can NEVER settle (settle() does "
                    "not exist there) — the loop would look alive and never regola. Set the deployed "
                    "Spartan1 address, or set DRY_RUN=1 to mark every quote non-settleable."
                )
            spartan1 = PLACEHOLDER_SPENDER
        maker = Account.from_key(private_key).address
        return cls(
            spartan1=spartan1, chain_id=chain_id, private_key=private_key, maker=maker,
            recipient=recipient or maker,
            settleable=(spartan1.lower() != PLACEHOLDER_SPENDER.lower()) and not dry_run,
            dry_run=dry_run, **kw,
        )

    @classmethod
    def from_env(cls) -> "Config":
        pk = os.environ.get("MAKER_PRIVATE_KEY")
        if not pk:
            raise SystemExit("MAKER_PRIVATE_KEY is required.")
        return cls.build(
            spartan1=os.environ.get("SPARTAN1_ADDRESS"),
            private_key=pk,
            chain_id=int(os.environ.get("CHAIN_ID", "8453")),
            dry_run=os.environ.get("DRY_RUN") == "1",
            recipient=os.environ.get("MAKER_RECIPIENT"),
            spread_floor_bps=int(os.environ.get("SPREAD_FLOOR_BPS", "10")),
            max_tip_bps=int(os.environ.get("MAX_TIP_BPS", "0")),
            feed_staleness_max=int(os.environ.get("FEED_STALENESS_MAX", "5")),
            host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8546")),
        )


# ───────────────────────────── quote construction ─────────────────────────
class Decline(Exception):
    """The maker chooses not to quote. Surfaces as 404 — a first-class, penalty-free answer."""


def _parse_request(body: Any) -> tuple[str, str, Optional[int], Optional[int], str]:
    if not isinstance(body, dict):
        raise Decline("body must be an object")
    sell_token, buy_token = body.get("sellToken"), body.get("buyToken")
    if not (_is_address(sell_token or "") and _is_address(buy_token or "")):
        raise Decline("sellToken and buyToken must be addresses")
    has_sell = body.get("sellAmount") is not None
    has_buy = body.get("buyAmount") is not None
    if has_sell == has_buy:
        raise Decline("supply exactly one of sellAmount / buyAmount")

    def _amt(v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, (int, str)):
            raise Decline("amount must be a decimal string")
        n = int(v) if isinstance(v, int) else (int(v) if v.isdigit() else -1)
        if n <= 0:
            raise Decline("amount must be a positive integer")
        return n

    sell_amount = _amt(body["sellAmount"]) if has_sell else None
    buy_amount = _amt(body["buyAmount"]) if has_buy else None
    taker = body.get("taker") or ZERO_ADDRESS
    if not _is_address(taker):
        raise Decline("taker must be an address")
    return sell_token, buy_token, sell_amount, buy_amount, taker


def _price(cfg: Config, feed: QuoteFn, sell_token: str, buy_token: str,
           sell_amount: Optional[int], buy_amount: Optional[int], now: int
           ) -> tuple[int, int, int, int]:
    """Returns (sellAmount, buyAmount, maxTip, permitted). Money-favourable integer rounding.
    Pricing is the feed's job; here we only apply the spread floor and the staleness guard."""
    exact_out = sell_amount is not None
    side = "exactOut" if exact_out else "exactIn"
    amount = sell_amount if exact_out else buy_amount
    q = feed(sell_token, buy_token, side, amount)  # type: ignore[arg-type]
    if q is None:
        raise Decline("not quoting this pair")
    if not isinstance(q, Quote):  # tolerate a bare (mid, spread_bps) from a minimal feed
        mid, spread = q  # type: ignore[misc]
        q = Quote(mid=Fraction(mid), spread_bps=int(spread))
    # REQUIREMENT: staleness guard (ON by default).
    if q.as_of is not None and now - q.as_of > cfg.feed_staleness_max:
        raise Decline("feed stale")
    spread = max(int(q.spread_bps), cfg.spread_floor_bps)   # never tighter than the floor
    factor = Fraction(10000 + spread, 10000)
    if exact_out:
        sell = int(sell_amount)                              # taker receives exactly this
        buy = math.ceil(Fraction(sell) * q.mid * factor)     # maker receives at least fair+edge
    else:
        buy = int(buy_amount)                                # taker pays exactly this
        sell = math.floor(Fraction(buy) / (q.mid * factor))  # maker gives at most
    if sell <= 0 or buy <= 0:
        raise Decline("degenerate amounts")
    max_tip = sell * cfg.max_tip_bps // 10000
    return sell, buy, max_tip, sell + max_tip


def make_signed_quote(cfg: Config, feed: QuoteFn, ledger: InventoryLedger,
                      body: Any, now: int) -> dict[str, Any]:
    sell_token, buy_token, sell_amount, buy_amount, taker = _parse_request(body)
    sell, buy, max_tip, permitted = _price(
        cfg, feed, sell_token, buy_token, sell_amount, buy_amount, now)

    deadline = now + cfg.quote_ttl
    fill_window = now + cfg.hot_window   # fillWindow <= deadline by construction

    # REQUIREMENT 3: reserve inventory (atomic) BEFORE signing. If it cannot be reserved,
    # decline — do NOT sign a quote the inventory cannot back.
    reason = ledger.try_reserve(sell_token, permitted, deadline, now, cfg.quote_ttl)
    if reason is not None:
        raise Decline(reason)

    order = Order(
        maker=cfg.maker, taker=taker, sellToken=sell_token, buyToken=buy_token,
        sellAmount=sell, buyAmount=buy, recipient=cfg.recipient, maxTip=max_tip,
        fillWindow=fill_window, deadline=deadline,
    )
    nonce = secrets.randbits(256)  # unordered 256-bit random — never sequential (OZ Across)
    sig = sign_order(order, nonce, cfg.spartan1, cfg.chain_id, cfg.private_key)

    resp: dict[str, Any] = {
        "order": order_to_json(order), "nonce": str(nonce), "signature": "0x" + sig.hex(),
        "chainId": cfg.chain_id, "spartan1": cfg.spartan1, "settleable": cfg.settleable,
    }
    if not cfg.settleable:
        resp["dryRun"] = True
        resp["warning"] = ("non-settleable: signed against a placeholder/DRY_RUN spender; "
                           "settle() does not exist there. For testing only.")
    return resp


# ───────────────────────────── HTTP handler ───────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"spartan1-maker/{VERSION}"

    cfg: Config
    feed: QuoteFn
    ledger: InventoryLedger
    started_at: int

    def _send(self, code: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("MAKER_VERBOSE"):
            super().log_message(fmt, *args)

    def do_POST(self) -> None:
        route = urlparse(self.path).path.rstrip("/") or "/"
        # The relay POSTs the RfqRequest to the maker webhook. No other POST route exists —
        # in particular there is NO cancel/revoke (no last-look).
        if route not in ("/", "/quote"):
            return self._send(404, {"error": "no such route"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            return self._send(404, {"error": "not quoting", "reason": "invalid JSON"})
        try:
            resp = make_signed_quote(self.cfg, self.feed, self.ledger, body, int(time.time()))
        except Decline as exc:
            # 404 = not quoting. Normal, penalty-free.
            return self._send(404, {"error": "not quoting", "reason": str(exc)})
        self._send(200, resp)

    def do_GET(self) -> None:
        route = urlparse(self.path).path.rstrip("/") or "/"
        if route == "/tokens":
            return self._send(200, {"pairs": getattr(self.feed, "pairs", [])})
        if route == "/health":
            now = int(time.time())
            inv = self.ledger.inventory
            return self._send(200, {
                "maker": self.cfg.maker,
                "spartan1": self.cfg.spartan1,
                "chainId": self.cfg.chain_id,
                "settleable": self.cfg.settleable,
                "dryRun": self.cfg.dry_run,
                "guardrails": {
                    "quoteTtl": self.cfg.quote_ttl, "hotWindow": self.cfg.hot_window,
                    "spreadFloorBps": self.cfg.spread_floor_bps,
                    "maxTipBps": self.cfg.max_tip_bps,
                    "feedStalenessMax": self.cfg.feed_staleness_max,
                    "lastLook": False,
                },
                "inventory": {t: {"total": str(v), "free": str(self.ledger.free(t, now))}
                              for t, v in inv.items()},
                "uptime": now - self.started_at,
                "version": VERSION,
            })
        return self._send(404, {"error": "no such route"})


# ─────────────────────────────── entrypoint ───────────────────────────────
def build_server(cfg: Config, feed: QuoteFn, ledger: InventoryLedger) -> ThreadingHTTPServer:
    handler = type("BoundMakerHandler", (Handler,), {
        # staticmethod: a bare function as a class attr would bind `self` as its first arg.
        "cfg": cfg, "feed": staticmethod(feed), "ledger": ledger, "started_at": int(time.time()),
    })
    return ThreadingHTTPServer((cfg.host, cfg.port), handler)


def _inventory_from_env() -> dict[str, int]:
    raw = os.environ.get("MAKER_INVENTORY", "{}")
    try:
        return {k: int(v) for k, v in json.loads(raw).items()}
    except (ValueError, AttributeError) as exc:
        raise SystemExit(f"MAKER_INVENTORY must be JSON {{token: decimal-string}}: {exc}")


def main() -> None:
    cfg = Config.from_env()
    inventory = _inventory_from_env()
    # No feed can be injected from the env (pricing is not this file's job): the CLI runs the
    # deliberately-inadequate reference feed over whatever pairs the inventory declares, so the
    # process is runnable but obviously unfit for production until you wire in a real quote_fn.
    pairs = {(t, t): Quote(mid=Fraction(1, 1), spread_bps=cfg.spread_floor_bps) for t in inventory}
    ledger = InventoryLedger(inventory)
    server = build_server(cfg, reference_quote_fn(pairs), ledger)
    print(f"spartan1-maker/{VERSION} on http://{cfg.host}:{cfg.port}")
    print(f"  maker={cfg.maker} spartan1={cfg.spartan1} chainId={cfg.chain_id}")
    print(f"  settleable={cfg.settleable} dryRun={cfg.dry_run}  (last-look: OFF, by design)")
    if not cfg.settleable:
        print("  WARNING: quotes are NON-SETTLEABLE (placeholder/DRY_RUN spender).")
    print("  NOTE: running the reference quote_fn — DELIBERATELY unfit for production. "
          "Inject your real pricing.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
