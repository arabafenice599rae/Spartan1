#!/usr/bin/env python3
"""Conformance gate for the Spartan1 reference executor.

Same method as the relay/maker suites: for every guardrail, a test that VIOLATES it and asserts the
refusal — a guardrail with no red-path test is decoration. The money-critical one is the TAKER GUARD
(an order addressed to a stranger must be refused, never settled).

WHAT THE END-TO-END TEST PROVES — and what it does NOT:
    test_end_to_end_loop wires maker -> relay -> executor in-process with a stub RPC. It proves the
    OFF-CHAIN loop: sign, pool, poll, re-verify, guardrail, simulate. It does NOT prove settlement.
    On-chain settlement is Foundry's job, and the real fork gate (test 10, needs L2_RPC) is still
    OPEN. 100% green here must not be read as "settlement works".

    python3 test_executor.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from fractions import Fraction

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_account import Account  # noqa: E402

import executor as X  # noqa: E402
import maker as M  # noqa: E402  — used only by the off-chain e2e
import relay as R  # noqa: E402
from order import Order, order_hash, sign_order  # noqa: E402

# ───────────────────────────── fixtures ──────────────────────────────────
SPARTAN1 = "0x000000000000000000000000000000000000dEaD"   # a non-placeholder "deployed" spender
CHAIN_ID = 8453
MAKER_PK = "0x" + hex(0xA11CE)[2:].rjust(64, "0")
MAKER = Account.from_key(MAKER_PK).address
EXECUTOR_PK = "0x" + hex(0xE0)[2:].rjust(64, "0")
EXECUTOR = Account.from_key(EXECUTOR_PK).address
STRANGER = "0x000000000000000000000000000000000000BaBe"
SELL = "0x2222222222222222222222222222222222222222"
BUY = "0x3333333333333333333333333333333333333333"
MID = Fraction(3000 * 10**6, 10**18)   # 3000 BUY-atomic per 1 SELL-atomic
ONE = 10**18

PRICE = X.reference_price_fn({(SELL, BUY): MID})
NOPRICE = X.reference_price_fn({})

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {extra}" if extra and not cond else ""))


class StubRpc(R.Rpc):
    """One stub for both roles. `eth_call` is disambiguated by selector: balanceOf/allowance/1271
    (used by a relay's P6/P7/P1) return canned values; anything else is a settle() simulation."""

    def __init__(self, *, simulate_ok: bool = True, block_ok: bool = True):
        super().__init__(url="stub://")
        self.simulate_ok, self.block_ok = simulate_ok, block_ok
        self.sent: list[str] = []

    def call(self, method, params):
        if method == "eth_call":
            sel = params[0].get("data", "")[2:10]
            if sel in (R.SEL_BALANCE_OF, R.SEL_ALLOWANCE):
                return "0x" + "f" * 64                       # huge → relay P6/P7 pass
            if sel == R.SEL_IS_VALID_SIG:
                return "0x" + R.ERC1271_MAGIC + "00" * 28
            if self.simulate_ok:
                return "0x"                                  # settle() simulation OK
            raise RuntimeError("execution reverted")
        if method == "eth_getCode":
            return "0x"
        if method == "eth_getBlockByNumber":
            if self.block_ok:
                return {"number": "0xbc614e", "hash": "0x" + "cd" * 32}
            raise RuntimeError("node unreachable")
        if method == "eth_getTransactionCount":
            return "0x0"
        if method == "eth_estimateGas":
            return "0x5208"
        if method == "eth_gasPrice":
            return "0x3b9aca00"
        if method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            return "0x" + "ab" * 32
        raise RuntimeError(f"unexpected rpc {method} {params}")


def cfg(**kw) -> X.Config:
    return X.Config.build(spartan1=SPARTAN1, private_key=EXECUTOR_PK,
                          relays=kw.pop("relays", ()), chain_id=CHAIN_ID, **kw)


def make_order(base: int, *, taker=R.ZERO_ADDRESS, sell=ONE, buy=3000 * 10**6, tip=10**16,
               fill_offset=-5, deadline_offset=3600) -> Order:
    return Order(maker=MAKER, taker=taker, sellToken=SELL, buyToken=BUY, sellAmount=sell,
                 buyAmount=buy, recipient=MAKER, maxTip=tip,
                 fillWindow=base + fill_offset, deadline=base + deadline_offset)


def sign(order: Order, nonce: int, pk: str = MAKER_PK) -> bytes:
    return sign_order(order, nonce, SPARTAN1, CHAIN_ID, pk)


class LiveRelay:
    def __init__(self, rpc=None):
        self.cfg = R.Config(spartan1=SPARTAN1, chain_id=CHAIN_ID,
                            rpc_url="stub://" if rpc else None, host="127.0.0.1", port=0)
        self.server = R.build_server(self.cfg, rpc=rpc or R.Rpc(None))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def post(self, body):
        req = urllib.request.Request(self.url + "/order", data=json.dumps(body).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def post_order(self, order, nonce):
        return self.post({"order": R.order_to_json(order), "nonce": str(nonce),
                          "signature": "0x" + sign(order, nonce).hex()})

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ══════════════════════════════ tests ════════════════════════════════════
def test_settle_selector():
    print("\nsettle() selector — asserted, not hardcoded blind")
    check("SETTLE_SELECTOR == 0x0560694d",
          "0x" + X.SETTLE_SELECTOR.hex() == "0x0560694d", "0x" + X.SETTLE_SELECTOR.hex())


def test_happy_open_order():
    print("\nhappy path — open order, profitable via the tip, simulation OK → would settle")
    base = int(time.time())
    o = make_order(base)
    d = X.evaluate(cfg(), PRICE, StubRpc(), o, 1, sign(o, 1), base)
    check("open order → settle", d.action == "settle", f"{d.action}: {d.reason}")
    check("dry-run wording", "would settle" in d.reason)
    check("decision carries the recomputed orderHash",
          d.order_hash == "0x" + order_hash(o).hex())


def test_taker_guard_third_party():
    print("\nTAKER GUARD (money) — order addressed to a stranger MUST be refused, never settled")
    base = int(time.time())
    o = make_order(base, taker=STRANGER)
    d = X.evaluate(cfg(), PRICE, StubRpc(), o, 2, sign(o, 2), base)
    check("addressed-to-stranger → refuse", d.action == "refuse", f"{d.action}: {d.reason}")
    check("reason is the taker guard", "taker guard" in d.reason, d.reason)


def test_addressed_to_self_ok():
    print("\naddressed to self — allowed (executor IS the taker)")
    base = int(time.time())
    o = make_order(base, taker=EXECUTOR)
    d = X.evaluate(cfg(), PRICE, StubRpc(), o, 3, sign(o, 3), base)
    check("addressed-to-self → settle", d.action == "settle", f"{d.action}: {d.reason}")


def test_expired_and_margin():
    print("\ndeadline — expired and within-margin both refused")
    base = int(time.time())
    o_exp = make_order(base, deadline_offset=-1)
    d = X.evaluate(cfg(), PRICE, StubRpc(), o_exp, 4, sign(o_exp, 4), base)
    check("expired → refuse", d.action == "refuse" and "expired" in d.reason, d.reason)

    o_margin = make_order(base, deadline_offset=5)   # 5s left, margin default 8s
    d = X.evaluate(cfg(), PRICE, StubRpc(), o_margin, 5, sign(o_margin, 5), base)
    check("within deadline margin → refuse", d.action == "refuse" and "margin" in d.reason, d.reason)


def test_hot_window_skipped():
    print("\nhot window — maker-only, skipped without spending an RPC")
    base = int(time.time())
    o = make_order(base, fill_offset=+30)   # fillWindow in the future → hot
    d = X.evaluate(cfg(), PRICE, StubRpc(), o, 6, sign(o, 6), base)
    check("hot window → skip", d.action == "skip" and "hot window" in d.reason, d.reason)


def test_tampered_signature_refused():
    print("\nre-verification — a tampered field is caught locally (relay sigCheck is not trusted)")
    base = int(time.time())
    o = make_order(base)
    sig = sign(o, 7)
    tampered = Order(**{**o.__dict__, "buyAmount": o.buyAmount - 1})   # signature no longer matches
    d = X.evaluate(cfg(), PRICE, StubRpc(), tampered, 7, sig, base)
    check("tampered order → refuse (signature not verified)",
          d.action == "refuse" and "signature not verified" in d.reason, d.reason)


def test_below_min_profit():
    print("\nmin-profit floor — a quote below the floor is refused")
    base = int(time.time())
    o = make_order(base)   # profit is ~100 bps (from the tip)
    d = X.evaluate(cfg(min_profit_bps=200), PRICE, StubRpc(), o, 8, sign(o, 8), base)
    check("below min-profit floor → refuse", d.action == "refuse" and "min-profit" in d.reason, d.reason)


def test_over_max_notional():
    print("\nmax notional — a settle above the cap is refused")
    base = int(time.time())
    o = make_order(base)
    d = X.evaluate(cfg(max_notional=o.buyAmount - 1), PRICE, StubRpc(), o, 9, sign(o, 9), base)
    check("over max notional → refuse", d.action == "refuse" and "max notional" in d.reason, d.reason)


def test_no_price_skips():
    print("\nno price for the pair → skip (never guess a price)")
    base = int(time.time())
    o = make_order(base)
    d = X.evaluate(cfg(), NOPRICE, StubRpc(), o, 10, sign(o, 10), base)
    check("no price → skip", d.action == "skip" and "no price" in d.reason, d.reason)


def test_simulation_reverts_not_sent():
    print("\nsimulation — a reverting eth_call refuses, and nothing is sent")
    base = int(time.time())
    o = make_order(base)
    rpc = StubRpc(simulate_ok=False)
    d = X.evaluate(cfg(), PRICE, rpc, o, 11, sign(o, 11), base)
    check("simulation revert → refuse", d.action == "refuse" and "simulation reverted" in d.reason,
          d.reason)
    check("nothing broadcast on a failed simulation", rpc.sent == [])


def test_dry_run_vs_submit():
    print("\ndry-run default vs explicit submit — real send only with the flag AND a green simulation")
    base = int(time.time())
    relay = LiveRelay(rpc=StubRpc())     # relay accepts (P6/P7 pass via stub balances)
    try:
        o = make_order(base, fill_offset=-1)
        code, _ = relay.post_order(o, 20)
        assert code == 200, code

        # dry-run (default): would-settle, nothing sent.
        rpc = StubRpc()
        ds = X.run_once(cfg(relays=(relay.url,)), PRICE, rpc, now=base)
        settle = [d for d in ds if d.action == "settle"]
        check("dry-run → would settle", len(settle) == 1 and not settle[0].sent, str(ds))
        check("dry-run broadcasts nothing", rpc.sent == [])

        # submit=True + green simulation → exactly one raw tx broadcast.
        rpc2 = StubRpc()
        ds2 = X.run_once(cfg(relays=(relay.url,), submit=True), PRICE, rpc2, now=base)
        check("submit → one settle sent", len(rpc2.sent) == 1 and ds2[0].sent, str(ds2))
    finally:
        relay.close()


def test_poll_all_relays_and_dedup():
    print("\npoll ALL relays, dedup by recomputed hash — order on relay B alone is still found")
    base = int(time.time())
    a, b = LiveRelay(rpc=StubRpc()), LiveRelay(rpc=StubRpc())
    try:
        o = make_order(base, fill_offset=-1)
        b.post_order(o, 30)                       # only on relay B
        ds = X.run_once(cfg(relays=(a.url, b.url)), PRICE, StubRpc(), now=base)
        check("order on relay B is found (all relays polled)",
              len([d for d in ds if d.action == "settle"]) == 1, str(ds))

        a.post_order(o, 30)                        # now on BOTH relays (same order)
        ds2 = X.run_once(cfg(relays=(a.url, b.url)), PRICE, StubRpc(), now=base)
        check("same order across two relays is deduped to one", len(ds2) == 1, str(ds2))
    finally:
        a.close(); b.close()


def test_relay_orderhash_lie_ignored():
    print("\nzero trust — a relay lying about orderHash is ignored (executor recomputes)")
    base = int(time.time())
    o = make_order(base, fill_offset=-1)
    entry = {"order": R.order_to_json(o), "nonce": "40", "signature": "0x" + sign(o, 40).hex(),
             "orderHash": "0x" + "de" * 32, "sigCheck": "ecdsa"}   # bogus hash + claimed sigCheck
    orig = X._http_get_json
    X._http_get_json = lambda url, timeout: {"orders": [entry], "count": 1}
    try:
        cands = X.poll_relays(cfg(relays=("http://fake",)))
        recomputed = "0x" + order_hash(o).hex()
        check("relay's orderHash claim ignored; executor recomputes",
              len(cands) == 1 and "0x" + order_hash(cands[0][0]).hex() == recomputed
              and recomputed != entry["orderHash"])
    finally:
        X._http_get_json = orig


def test_freshness_challenge_skips_mute_relay():
    print("\nfreshness challenge — a relay that can't echo a current blockhash is skipped")
    base = int(time.time())
    fresh = LiveRelay(rpc=StubRpc(block_ok=True))
    mute = LiveRelay(rpc=StubRpc(block_ok=False))
    try:
        fresh.post_order(make_order(base, fill_offset=-1), 50)
        mute.post_order(make_order(base, fill_offset=-1, buy=3001 * 10**6), 51)  # a different order
        cands = X.poll_relays(cfg(relays=(fresh.url, mute.url), freshness_challenge=True))
        check("only the fresh relay's order is polled (mute relay skipped)", len(cands) == 1,
              f"{len(cands)} candidates")
    finally:
        fresh.close(); mute.close()


def test_unknown_relay_field_tolerated():
    print("\nforward-compat — an unknown top-level field from a relay is tolerated, never trusted")
    base = int(time.time())
    o = make_order(base, fill_offset=-1)
    entry = {"order": R.order_to_json(o), "nonce": "60", "signature": "0x" + sign(o, 60).hex(),
             "someFutureField": {"x": 1}}
    orig = X._http_get_json
    X._http_get_json = lambda url, timeout: {"orders": [entry], "count": 1}
    try:
        cands = X.poll_relays(cfg(relays=("http://fake",)))
        check("order with an unknown field still parses", len(cands) == 1)
    finally:
        X._http_get_json = orig


def test_end_to_end_loop():
    print("\nEND-TO-END (off-chain only) — maker signs → relay pools → executor decides")
    print("  NB: proves the OFF-CHAIN loop; settlement is Foundry's job, fork gate 10 is still open")
    base = int(time.time())
    # The maker must offer a tip that beats its own spread, else a third-party executor has no edge
    # (it would just pay the maker's spread). max_tip_bps=50 vs a 20 bps spread → ~30 bps for the executor.
    mcfg = M.Config.build(spartan1=SPARTAN1, private_key=MAKER_PK, chain_id=CHAIN_ID,
                          hot_window=0, quote_ttl=3600, max_tip_bps=50, port=0)
    feed = M.reference_quote_fn({(SELL, BUY): M.Quote(mid=MID, spread_bps=20)})
    ledger = M.InventoryLedger({SELL: 10**24})
    open_q = M.make_signed_quote(mcfg, feed, ledger,
                                 {"sellToken": SELL, "buyToken": BUY, "sellAmount": str(ONE)}, base)
    stranger_q = M.make_signed_quote(mcfg, feed, ledger,
                                     {"sellToken": SELL, "buyToken": BUY, "sellAmount": str(ONE),
                                      "taker": STRANGER}, base)

    # Part A — the honest loop through a real relay. A well-behaved relay serves only OPEN orders to a
    # non-taker poller (addressed orders stay private), so this is the open order end to end.
    relay = LiveRelay(rpc=StubRpc())
    try:
        code, _ = relay.post({k: open_q[k] for k in ("order", "nonce", "signature")})
        assert code == 200, code
        ds = {d.order_hash: d for d in X.run_once(cfg(relays=(relay.url,)), PRICE, StubRpc(), now=base + 1)}
        open_hash = "0x" + order_hash(_order(open_q)).hex()
        check("open order flows maker→relay→executor to a would-settle",
              ds.get(open_hash) and ds[open_hash].action == "settle", str(ds.get(open_hash)))
    finally:
        relay.close()

    # Part B — the taker guard's real job: even if a MISBEHAVING relay serves the executor an order
    # addressed to someone else, the executor refuses it (it would pay buyAmount and get only tip).
    entry = {k: stranger_q[k] for k in ("order", "nonce", "signature")}
    orig = X._http_get_json
    X._http_get_json = lambda url, timeout: {"orders": [entry], "count": 1}
    try:
        ds = X.run_once(cfg(relays=("http://over-serving-relay",)), PRICE, StubRpc(), now=base + 1)
        check("a relay over-serving a stranger's order → executor refuses (taker guard)",
              len(ds) == 1 and ds[0].action == "refuse" and "taker guard" in ds[0].reason, str(ds))
    finally:
        X._http_get_json = orig


def _order(q) -> Order:
    d = q["order"]
    return Order(maker=d["maker"], taker=d["taker"], sellToken=d["sellToken"], buyToken=d["buyToken"],
                 sellAmount=int(d["sellAmount"]), buyAmount=int(d["buyAmount"]), recipient=d["recipient"],
                 maxTip=int(d["maxTip"]), fillWindow=d["fillWindow"], deadline=d["deadline"])


# ══════════════════════════════ runner ═══════════════════════════════════
def main() -> None:
    print("Spartan1 executor — conformance gate (openapi.yaml is the reference)")
    for fn in (
        test_settle_selector,
        test_happy_open_order,
        test_taker_guard_third_party,
        test_addressed_to_self_ok,
        test_expired_and_margin,
        test_hot_window_skipped,
        test_tampered_signature_refused,
        test_below_min_profit,
        test_over_max_notional,
        test_no_price_skips,
        test_simulation_reverts_not_sent,
        test_dry_run_vs_submit,
        test_poll_all_relays_and_dedup,
        test_relay_orderhash_lie_ignored,
        test_freshness_challenge_skips_mute_relay,
        test_unknown_relay_field_tolerated,
        test_end_to_end_loop,
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
