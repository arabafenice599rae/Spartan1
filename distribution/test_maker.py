#!/usr/bin/env python3
"""Conformance gate for the Spartan1 reference maker webhook.

Same method as test_relay.py: for every guardrail, a test that VIOLATES it and asserts the
maker refuses — the money-critical one being inventory double-commit (N valid signatures
against inventory that backs fewer). Runs against a real HTTP server on a real socket.

    python3 test_maker.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from fractions import Fraction
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_account import Account  # noqa: E402

import relay as R  # noqa: E402  — reuse P1 check for the maker↔relay integration test
from order import Order, signing_digest  # noqa: E402
from maker import (  # noqa: E402
    PLACEHOLDER_SPENDER,
    Config,
    InventoryLedger,
    Quote,
    build_server,
    reference_quote_fn,
)

# ───────────────────────────── fixtures ──────────────────────────────────
DEPLOYED = "0x000000000000000000000000000000000000dEaD"   # a non-placeholder "deployed" spender
CHAIN_ID = 8453
MAKER_PK = "0x" + hex(0xA11CE)[2:].rjust(64, "0")
MAKER = Account.from_key(MAKER_PK).address
SELL = "0x2222222222222222222222222222222222222222"       # 18 decimals
BUY = "0x3333333333333333333333333333333333333333"        # 6 decimals (USDC-like)
MID = Fraction(3000 * 10**6, 10**18)                       # 3000 BUY-atomic per 1 SELL-atomic
ONE = 10**18

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {extra}" if extra and not cond else ""))


def feed(spread_bps: int = 20, as_of=None, pair=(SELL, BUY)):
    return reference_quote_fn({pair: Quote(mid=MID, spread_bps=spread_bps, as_of=as_of)})


def cfg(*, spartan1=DEPLOYED, dry_run=False, **kw):
    kw.setdefault("port", 0)  # ephemeral port; many servers run in one process
    return Config.build(spartan1=spartan1, private_key=MAKER_PK, chain_id=CHAIN_ID,
                        dry_run=dry_run, **kw)


class Live:
    def __init__(self, config, quote_fn, ledger):
        self.server = build_server(config, quote_fn, ledger)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def request(self, method, path, body=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        def _body(raw):
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return {}  # e.g. a 501 with an HTML body from BaseHTTPRequestHandler
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, _body(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _body(exc.read())

    def post(self, path, body):
        return self.request("POST", path, body)

    def get(self, path):
        return self.request("GET", path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _order_from_json(d) -> Order:
    return Order(
        maker=d["maker"], taker=d["taker"], sellToken=d["sellToken"], buyToken=d["buyToken"],
        sellAmount=int(d["sellAmount"]), buyAmount=int(d["buyAmount"]),
        recipient=d["recipient"], maxTip=int(d["maxTip"]),
        fillWindow=d["fillWindow"], deadline=d["deadline"],
    )


def _recovers(resp, spender) -> str:
    order = _order_from_json(resp["order"])
    digest = signing_digest(order, int(resp["nonce"]), spender, CHAIN_ID)
    return Account._recover_hash(digest, signature=bytes.fromhex(resp["signature"][2:]))


def req(sell_amount=None, buy_amount=None, taker=None):
    body = {"sellToken": SELL, "buyToken": BUY}
    if sell_amount is not None:
        body["sellAmount"] = str(sell_amount)
    if buy_amount is not None:
        body["buyAmount"] = str(buy_amount)
    if taker is not None:
        body["taker"] = taker
    return body


# ══════════════════════════════ tests ════════════════════════════════════
def test_happy_maker_centric_and_signature():
    print("\nhappy path — maker-centric, exact pricing, settleable, signature binds to maker")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", req(sell_amount=ONE))
        check("quote accepted 200", code == 200, f"{code} {r}")
        o = r.get("order", {})
        check("maker gives sellToken (no perspective inversion)", o.get("sellToken") == SELL)
        check("maker receives buyToken", o.get("buyToken") == BUY)
        check("order.maker is the maker", o.get("maker") == MAKER)
        check("recipient defaults to maker", o.get("recipient") == MAKER)
        check("sellAmount fixed to request (exactOut)", o.get("sellAmount") == str(ONE))
        check("buyAmount = ceil(sell*mid*(1+20bps)) = 3006e6",
              o.get("buyAmount") == "3006000000", str(o.get("buyAmount")))
        check("fillWindow <= deadline", o.get("fillWindow") <= o.get("deadline"))
        check("ttl window is 45s, hot 30s (deadline-fillWindow == 15)",
              o.get("deadline") - o.get("fillWindow") == 15, str(o))
        check("marked settleable", r.get("settleable") is True and "dryRun" not in r)
        check("signature recovers to the maker under the deployed spender",
              _recovers(r, DEPLOYED).lower() == MAKER.lower())
        # inventory reserved
        _, h = srv.get("/health")
        check("inventory free reduced by permitted (1e18)",
              h["inventory"][SELL.lower()]["free"] == str(100 * ONE - ONE), str(h["inventory"]))
    finally:
        srv.close()


def test_exact_in_path():
    print("\nexactIn — maker gives at most, buyAmount fixed to request")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", req(buy_amount=3006000000))
        o = r["order"]
        check("exactIn accepted", code == 200, f"{code} {r}")
        check("buyAmount fixed to request", o["buyAmount"] == "3006000000")
        check("sellAmount = floor(buy/(mid*(1+20bps))) = 1e18", o["sellAmount"] == str(ONE),
              o["sellAmount"])
    finally:
        srv.close()


def test_decline_and_malformed():
    print("\nright to decline (404, no penalty) + malformed handling")
    srv = Live(cfg(), feed(pair=(SELL, BUY)), InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", {"sellToken": BUY, "buyToken": SELL, "sellAmount": "1"})
        check("unknown pair → 404 not quoting", code == 404 and "not quoting" in r.get("error", ""),
              f"{code} {r}")
        code, _ = srv.post("/quote", req())  # neither amount
        check("neither amount → 404", code == 404, str(code))
        code, _ = srv.post("/quote", req(sell_amount=ONE, buy_amount=ONE))  # both
        check("both amounts → 404", code == 404, str(code))
        code, _ = srv.post("/quote", {"sellToken": "nope", "buyToken": BUY, "sellAmount": "1"})
        check("bad address → 404", code == 404, str(code))
    finally:
        srv.close()


def test_spread_floor():
    print("\nspread floor — never quote tighter than the floor, even if the feed is tighter")
    srv = Live(cfg(spread_floor_bps=50), feed(spread_bps=1), InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", req(sell_amount=ONE))
        check("accepted", code == 200, f"{code} {r}")
        # 50 bps floor beats the feed's 1 bps: buy = ceil(3000e6 * 1.005) = 3015e6.
        check("buyAmount uses the 50 bps floor, not the feed's 1 bps",
              r["order"]["buyAmount"] == "3015000000", r["order"]["buyAmount"])
    finally:
        srv.close()


def test_feed_staleness():
    print("\nfeed staleness — a stale price is declined, never signed")
    stale = feed(spread_bps=20, as_of=int(time.time()) - 100)  # 100s old, max 5s
    srv = Live(cfg(feed_staleness_max=5), stale, InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", req(sell_amount=ONE))
        check("stale feed → 404 (not quoting: stale)", code == 404 and "stale" in r.get("reason", ""),
              f"{code} {r}")
    finally:
        srv.close()


def test_per_quote_notional_cap():
    print("\nper-quote notional cap — a single oversized quote is refused")
    ledger = InventoryLedger({SELL: 100 * ONE}, max_quote={SELL: ONE // 2})
    srv = Live(cfg(), feed(), ledger)
    try:
        code, r = srv.post("/quote", req(sell_amount=ONE))  # permitted 1e18 > cap 0.5e18
        check("over per-quote cap → 404", code == 404 and "per-quote" in r.get("reason", ""),
              f"{code} {r}")
    finally:
        srv.close()


def test_inventory_double_commit():
    print("\nINVENTORY DOUBLE-COMMIT — the money bug: each quote is individually valid, but")
    print("outstanding signed quotes reserve inventory so the third cannot be backed")
    # 2e18 inventory, three identical 1e18 requests. Each is well-formed on its own. Raise the
    # notional caps so the INVENTORY reservation is unambiguously the binding constraint.
    ledger = InventoryLedger({SELL: 2 * ONE}, max_quote={SELL: 1000 * ONE},
                             max_window={SELL: 1000 * ONE})
    srv = Live(cfg(), feed(), ledger)
    try:
        c1, r1 = srv.post("/quote", req(sell_amount=ONE))
        c2, r2 = srv.post("/quote", req(sell_amount=ONE))
        c3, r3 = srv.post("/quote", req(sell_amount=ONE))
        check("1st of 3 signed (200)", c1 == 200, f"{c1} {r1}")
        check("2nd of 3 signed (200)", c2 == 200, f"{c2} {r2}")
        check("3rd REFUSED — not double-committed (404)", c3 == 404, f"{c3} {r3}")
        check("refusal names insufficient free inventory",
              "insufficient free inventory" in r3.get("reason", ""), str(r3))
        check("the two signed quotes have DISTINCT nonces (both would be valid on-chain)",
              r1["nonce"] != r2["nonce"])
        _, h = srv.get("/health")
        check("free inventory is exactly zero after the two reservations",
              h["inventory"][SELL.lower()]["free"] == "0", str(h["inventory"]))
    finally:
        srv.close()


def test_inventory_concurrent():
    print("\nINVENTORY under CONCURRENCY — N threads, inventory for M<N: the lock must hold")
    print("(sequential posting proves accounting; only parallel posting proves 'atomically')")
    # 8 threads, each a 1e18 quote, against 2e18 inventory. Notional caps raised so the
    # inventory reservation is the sole gate. The relay fans out to makers in parallel, so
    # this is the real scenario — exactly 2 may be granted, never 3+.
    ledger = InventoryLedger({SELL: 2 * ONE}, max_quote={SELL: 1000 * ONE},
                             max_window={SELL: 1000 * ONE})
    srv = Live(cfg(), feed(), ledger)
    try:
        n = 8
        results: list[Optional[int]] = [None] * n

        def worker(i: int) -> None:
            code, _ = srv.post("/quote", req(sell_amount=ONE))
            results[i] = code

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        granted = sum(1 for c in results if c == 200)
        refused = sum(1 for c in results if c == 404)
        check("exactly 2 quotes granted (inventory backs exactly 2)", granted == 2,
              f"granted={granted} results={results}")
        check("the other 6 refused — no double-commit under concurrency", refused == 6,
              f"refused={refused} results={results}")
        _, h = srv.get("/health")
        check("free inventory is exactly zero after concurrent contention",
              h["inventory"][SELL.lower()]["free"] == "0", str(h["inventory"]))
    finally:
        srv.close()


def test_inventory_released_at_deadline():
    print("\ninventory released at deadline — a reservation frees up once the quote expires")
    # ttl 1s, hot 0s (fillWindow == now <= deadline). Inventory backs exactly one quote; raise the
    # notional caps so only the inventory reservation gates. Prune is on integer seconds
    # (released when now > deadline), so sleep well past the boundary.
    ledger = InventoryLedger({SELL: ONE}, max_quote={SELL: 1000 * ONE},
                             max_window={SELL: 1000 * ONE})
    srv = Live(cfg(quote_ttl=1, hot_window=0), feed(), ledger)
    try:
        c1, _ = srv.post("/quote", req(sell_amount=ONE))
        c2, _ = srv.post("/quote", req(sell_amount=ONE))
        check("1st signed", c1 == 200, str(c1))
        check("2nd refused while the 1st is outstanding", c2 == 404, str(c2))
        time.sleep(2.5)  # cross the integer-second deadline boundary → reservation released
        c3, _ = srv.post("/quote", req(sell_amount=ONE))
        check("3rd signed after the reservation expired (inventory released)", c3 == 200, str(c3))
    finally:
        srv.close()


def test_per_window_cap_distinct_from_inventory():
    print("\nper-window cap — bounds signed notional per window even when inventory is ample")
    # Inventory 10e18 (plenty free), but window cap 1.5e18: the second 1e18 exceeds it.
    ledger = InventoryLedger({SELL: 10 * ONE}, max_window={SELL: 15 * 10**17})
    srv = Live(cfg(), feed(), ledger)
    try:
        c1, _ = srv.post("/quote", req(sell_amount=ONE))
        c2, r2 = srv.post("/quote", req(sell_amount=ONE))
        check("1st within the window cap (200)", c1 == 200, str(c1))
        check("2nd exceeds the window cap despite ample inventory (404)",
              c2 == 404 and "per-window" in r2.get("reason", ""), f"{c2} {r2}")
    finally:
        srv.close()


def test_no_last_look():
    print("\nNO LAST-LOOK — there is no route to cancel/revoke a signed quote")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        for path in ("/cancel", "/revoke", "/quote/cancel", "/unsign"):
            code, _ = srv.post(path, {})
            check(f"POST {path} → 404 (no last-look path)", code == 404, str(code))
        code, _ = srv.request("DELETE", "/quote")
        check("DELETE /quote → not honoured", code in (404, 501), str(code))
        _, h = srv.get("/health")
        check("health declares lastLook: false", h["guardrails"]["lastLook"] is False, str(h))
    finally:
        srv.close()


def test_nonce_randomness():
    print("\nnonce randomness — 256-bit random, never sequential (OZ Across lesson)")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        _, r1 = srv.post("/quote", req(sell_amount=ONE))
        _, r2 = srv.post("/quote", req(sell_amount=ONE))
        n1, n2 = int(r1["nonce"]), int(r2["nonce"])
        check("nonces are distinct", n1 != n2)
        check("nonces are not sequential", abs(n1 - n2) != 1)
        check("nonces occupy the high 256-bit space (>= 2**64)", n1 >= 2**64 and n2 >= 2**64,
              f"{n1} {n2}")
    finally:
        srv.close()


def test_dry_run_and_refuse_start():
    print("\nplacebo guard — refuse to start without a deployed spender; DRY_RUN marks non-settleable")
    # Refuse to start: no address, no DRY_RUN.
    refused = False
    try:
        cfg(spartan1=None, dry_run=False)
    except SystemExit:
        refused = True
    check("refuses to start with no deployed spender and no DRY_RUN", refused)

    # DRY_RUN: starts on the placeholder, every quote marked non-settleable.
    dry = cfg(spartan1=None, dry_run=True)
    check("DRY_RUN uses the placeholder spender", dry.spartan1 == PLACEHOLDER_SPENDER)
    check("DRY_RUN is not settleable", dry.settleable is False)
    srv = Live(dry, feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        code, r = srv.post("/quote", req(sell_amount=ONE))
        check("dry-run quote returns 200", code == 200, f"{code} {r}")
        check("dry-run quote marked settleable:false + dryRun:true",
              r.get("settleable") is False and r.get("dryRun") is True, str(r))
        check("dry-run quote carries a non-settleable warning", "warning" in r)
        check("signature binds to the PLACEHOLDER (recovers to maker there)",
              _recovers(r, PLACEHOLDER_SPENDER).lower() == MAKER.lower())
        check("signature does NOT bind to a real deployed spender (cannot settle)",
              _recovers(r, DEPLOYED).lower() != MAKER.lower())
    finally:
        srv.close()


def test_relay_accepts_maker_signature():
    print("\nintegration — the relay's P1 accepts a maker signature (settleable config)")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 100 * ONE}))
    try:
        _, r = srv.post("/quote", req(sell_amount=ONE))
        o = _order_from_json(r["order"])
        rcfg = R.Config(spartan1=DEPLOYED, chain_id=CHAIN_ID, rpc_url=None)
        ok, how, why = R.check_signature(o, int(r["nonce"]),
                                         bytes.fromhex(r["signature"][2:]), rcfg, R.Rpc(None))
        check("relay P1 verifies the maker signature as ecdsa", ok and how == "ecdsa", why)
    finally:
        srv.close()


def test_health_and_tokens():
    print("\n/health and /tokens")
    srv = Live(cfg(), feed(), InventoryLedger({SELL: 5 * ONE}))
    try:
        code, tokens = srv.get("/tokens")
        check("/tokens lists the advertised pair", code == 200
              and {"sellToken": SELL, "buyToken": BUY} in tokens.get("pairs", []), str(tokens))
        _, h = srv.get("/health")
        for key in ("maker", "spartan1", "settleable", "guardrails", "inventory"):
            check(f"/health exposes {key}", key in h)
        check("/health shows the deployed spender", h["spartan1"] == DEPLOYED)
        check("/health reports total + free inventory",
              h["inventory"][SELL.lower()]["total"] == str(5 * ONE))
    finally:
        srv.close()


# ══════════════════════════════ runner ═══════════════════════════════════
def main() -> None:
    print("Spartan1 maker — conformance gate (openapi.yaml is the reference)")
    for fn in (
        test_happy_maker_centric_and_signature,
        test_exact_in_path,
        test_decline_and_malformed,
        test_spread_floor,
        test_feed_staleness,
        test_per_quote_notional_cap,
        test_inventory_double_commit,
        test_inventory_concurrent,
        test_inventory_released_at_deadline,
        test_per_window_cap_distinct_from_inventory,
        test_no_last_look,
        test_nonce_randomness,
        test_dry_run_and_refuse_start,
        test_relay_accepts_maker_signature,
        test_health_and_tokens,
    ):
        fn()

    total = len(PASS) + len(FAIL)
    print(f"\n{'=' * 60}")
    print(f"RESULT: {len(PASS)}/{total} passed, {len(FAIL)} failed")
    if FAIL:
        for name in FAIL:
            print(f"  FAILED: {name}")
        sys.exit(1)
    print("ALL GREEN")


if __name__ == "__main__":
    main()
