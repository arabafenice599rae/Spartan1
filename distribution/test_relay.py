#!/usr/bin/env python3
"""Conformance gate for the Spartan1 reference relay.

Method mirrors the contract suite: for every predicate, a test that VIOLATES it
and asserts the rejection — not just a happy path. Runs against a real HTTP
server on a real socket, with a stub RPC, so the wire format is exercised end to
end rather than by calling functions directly.

    python3 test_relay.py
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client"))

from eth_account import Account  # noqa: E402

import relay as R  # noqa: E402
from order import Order, order_hash, sign_order  # noqa: E402

# ───────────────────────────── fixtures ──────────────────────────────────
SPARTAN1 = "0x1111111111111111111111111111111111111111"   # placeholder spender
CHAIN_ID = 8453
MAKER_PK = "0x" + hex(0xA11CE)[2:].rjust(64, "0")
MAKER = Account.from_key(MAKER_PK).address
SELL = "0x2222222222222222222222222222222222222222"
BUY = "0x3333333333333333333333333333333333333333"
RECIPIENT = "0x4444444444444444444444444444444444444444"
TAKER = "0x000000000000000000000000000000000000007A"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {extra}" if extra and not cond else ""))


SKIP: list[str] = []


def skip(name: str, reason: str) -> None:
    # A declared SKIP, never a silent PASS (same discipline as the fork gate).
    SKIP.append(name)
    print(f"  [SKIP] {name} — {reason}")


class StubRpc(R.Rpc):
    """Deterministic stand-in for a node. Lets P6/P7 and the ERC-1271 branch be
    exercised without a live chain; the real thing is covered by the fork gate."""

    def __init__(self, *, balance=10**30, allowance=2**256 - 1, code=""):
        super().__init__(url="stub://")
        self.balance, self.allowance, self.code = balance, allowance, code
        self.calls = 0

    def eth_call(self, to, data):
        self.calls += 1
        sel = data[2:10]
        if sel == R.SEL_BALANCE_OF:
            return hex(self.balance)
        if sel == R.SEL_ALLOWANCE:
            return hex(self.allowance)
        if sel == R.SEL_IS_VALID_SIG:
            return "0x" + R.ERC1271_MAGIC + "00" * 28
        raise RuntimeError(f"unexpected selector {sel}")

    def code_at(self, address):
        return self.code or "0x"

    def latest_block(self):
        return 12345678, "0x" + "ab" * 32


def make_order(**over) -> Order:
    now = int(time.time())
    base = dict(
        maker=MAKER, taker=R.ZERO_ADDRESS, sellToken=SELL, buyToken=BUY,
        sellAmount=10**18, buyAmount=3000 * 10**6, recipient=RECIPIENT,
        maxTip=10**16, fillWindow=now + R.HOT_WINDOW, deadline=now + R.QUOTE_TTL,
    )
    base.update(over)
    return Order(**base)


def signed_payload(order: Order, nonce: int = 777, *, pk=MAKER_PK) -> dict:
    sig = sign_order(order, nonce, SPARTAN1, CHAIN_ID, pk)
    return {"order": R.order_to_json(order), "nonce": str(nonce),
            "signature": "0x" + sig.hex()}


# ─────────────────────────── live server ─────────────────────────────────
class Live:
    def __init__(self, rpc=None, webhooks=()):
        self.cfg = R.Config(spartan1=SPARTAN1, chain_id=CHAIN_ID,
                            rpc_url="stub://" if rpc else None,
                            maker_webhooks=tuple(webhooks), host="127.0.0.1", port=0)
        self.server = R.build_server(self.cfg, rpc=rpc or R.Rpc(None))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def request(self, method, path, body=None):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def post(self, path, body):
        return self.request("POST", path, body)

    def get(self, path):
        return self.request("GET", path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ══════════════════════════════ tests ════════════════════════════════════
def test_happy_and_P5_idempotence():
    print("\nhappy path + P5 (dedup is idempotent, never an error)")
    srv = Live(rpc=StubRpc())
    try:
        o = make_order()
        payload = signed_payload(o)
        code, body = srv.post("/order", payload)
        check("accepted with 200", code == 200, f"{code} {body}")
        check("sigCheck == ecdsa", body.get("sigCheck") == "ecdsa", str(body))
        expected_hash = "0x" + order_hash(o).hex()
        check("orderHash matches local recomputation",
              body.get("orderHash") == expected_hash, str(body))
        check("duplicate == false on first post", body.get("duplicate") is False)

        code2, body2 = srv.post("/order", payload)
        check("re-post returns 200, not an error", code2 == 200, f"{code2}")
        check("re-post flags duplicate", body2.get("duplicate") is True, str(body2))

        code3, listing = srv.get("/orders")
        check("pool holds exactly one copy", listing.get("count") == 1, str(listing))
        check("listed order round-trips amounts as strings",
              listing["orders"][0]["order"]["sellAmount"] == str(o.sellAmount))
        check("listed orderHash matches", listing["orders"][0]["orderHash"] == expected_hash)
    finally:
        srv.close()


def test_P1_signature():
    print("\nP1 — signature")
    srv = Live(rpc=StubRpc())
    try:
        o = make_order()
        good = signed_payload(o)

        bad_sig = dict(good, signature="0x" + "11" * 65)
        code, body = srv.post("/order", bad_sig)
        check("garbage signature rejected", code == 422 and "P1" in body.get("failed", []),
              f"{code} {body}")

        wrong_signer = signed_payload(o, pk="0x" + "42" * 32)
        code, body = srv.post("/order", wrong_signer)
        check("signature by another key rejected",
              code == 422 and "P1" in body.get("failed", []), f"{code} {body}")

        # Tampering ANY field changes the witness, hence the digest, hence P1.
        for field, value in (("buyAmount", str(o.buyAmount + 1)),
                             ("recipient", "0x" + "de" * 20),
                             ("deadline", o.deadline + 1)):
            tampered = json.loads(json.dumps(good))
            tampered["order"][field] = value
            code, body = srv.post("/order", tampered)
            check(f"tampered {field} rejected",
                  code == 422 and "P1" in body.get("failed", []), f"{code} {body}")

        # Nonce is inside the signed digest too: changing it invalidates the sig.
        code, body = srv.post("/order", dict(good, nonce="778"))
        check("altered nonce rejected", code == 422 and "P1" in body.get("failed", []),
              f"{code} {body}")

        # A signature bound to a different spender must not verify here — this is
        # the anti-Permit2-#250 binding: valid for one deployed address only.
        other = sign_order(o, 777, "0x9999999999999999999999999999999999999999",
                           CHAIN_ID, MAKER_PK)
        code, body = srv.post("/order", {**good, "signature": "0x" + other.hex()})
        check("signature for a different spender rejected",
              code == 422 and "P1" in body.get("failed", []), f"{code} {body}")

        # ...and one bound to another chain.
        other_chain = sign_order(o, 777, SPARTAN1, 1, MAKER_PK)
        code, body = srv.post("/order", {**good, "signature": "0x" + other_chain.hex()})
        check("signature for a different chainId rejected",
              code == 422 and "P1" in body.get("failed", []), f"{code} {body}")
    finally:
        srv.close()


def test_P1_erc1271_and_deferred():
    print("\nP1 — contract makers: erc1271 verified, or deferred and DECLARED")
    srv = Live(rpc=StubRpc(code="0x60006000f3"))
    try:
        # Recovery will not match (maker has code), so the 1271 branch decides.
        o = make_order()
        code, body = srv.post("/order", signed_payload(o, pk="0x" + "42" * 32))
        check("contract maker accepted via erc1271",
              code == 200 and body.get("sigCheck") == "erc1271", f"{code} {body}")
    finally:
        srv.close()

    # No RPC: the relay cannot verify a contract-maker signature. It must say
    # `deferred` rather than imply a check it never ran, and must not censor.
    srv = Live(rpc=None)
    try:
        o = make_order()
        code, body = srv.post("/order", signed_payload(o, pk="0x" + "42" * 32))
        check("no-RPC contract signature marked deferred, not silently passed",
              code == 200 and body.get("sigCheck") == "deferred", f"{code} {body}")
        code, health = srv.get("/health")
        check("health declares P6/P7 NOT enforced without RPC",
              "P6" not in health["predicates"] and "P7" not in health["predicates"],
              str(health))
        check("health still declares P1-P5 enforced",
              all(p in health["predicates"] for p in ("P1", "P2", "P3", "P4", "P5")))
    finally:
        srv.close()


def test_P2_deadline_semantics():
    print("\nP2 — deadline uses <=, matching Permit2's strict >")
    now = int(time.time())
    cfg = R.Config(spartan1=SPARTAN1, chain_id=CHAIN_ID, rpc_url="stub://")
    rpc = StubRpc()

    o = make_order(deadline=now, fillWindow=now - 5)
    sig = sign_order(o, 1, SPARTAN1, CHAIN_ID, MAKER_PK)

    v_at = R.evaluate(o, 1, sig, cfg, rpc, known_hash=False, now=now)
    check("valid AT the deadline second (not < but <=)", "P2" not in v_at.failed,
          str(v_at.detail))

    v_after = R.evaluate(o, 1, sig, cfg, rpc, known_hash=False, now=now + 1)
    check("expired one second later", "P2" in v_after.failed, str(v_after.detail))

    # Served listings never include expired orders.
    srv = Live(rpc=StubRpc())
    try:
        short = make_order(deadline=int(time.time()), fillWindow=int(time.time()) - 5)
        srv.post("/order", signed_payload(short, nonce=2))
        time.sleep(1.2)
        _, listing = srv.get("/orders")
        check("expired order pruned from /orders", listing.get("count") == 0, str(listing))
        _, health = srv.get("/health")
        check("ordersOpen reflects pruning", health.get("ordersOpen") == 0, str(health))
    finally:
        srv.close()


def test_P3_fillwindow():
    print("\nP3 — fillWindow <= deadline")
    srv = Live(rpc=StubRpc())
    try:
        now = int(time.time())
        o = make_order(fillWindow=now + 100, deadline=now + 45)
        code, body = srv.post("/order", signed_payload(o, nonce=3))
        check("fillWindow > deadline rejected",
              code == 422 and "P3" in body.get("failed", []), f"{code} {body}")
    finally:
        srv.close()


def test_P4_wellformed():
    print("\nP4 — well-formed")
    srv = Live(rpc=StubRpc())
    try:
        o = make_order()
        good = signed_payload(o, nonce=4)

        cases = {
            "missing field": {"order": {k: v for k, v in good["order"].items()
                                        if k != "maxTip"},
                              "nonce": "4", "signature": good["signature"]},
            "unknown field": {"order": {**good["order"], "extra": "1"},
                              "nonce": "4", "signature": good["signature"]},
            "bad address": {"order": {**good["order"], "maker": "0xnope"},
                            "nonce": "4", "signature": good["signature"]},
            "amount as float": {"order": {**good["order"], "sellAmount": 1.5},
                                "nonce": "4", "signature": good["signature"]},
            "amount as bool": {"order": {**good["order"], "sellAmount": True},
                               "nonce": "4", "signature": good["signature"]},
            "missing signature": {"order": good["order"], "nonce": "4"},
            "signature not hex": {**good, "signature": "0xzz"},
        }
        for name, payload in cases.items():
            code, body = srv.post("/order", payload)
            check(f"{name} → P4", code == 422 and body.get("failed") == ["P4"],
                  f"{code} {body}")

    finally:
        srv.close()

    # A uint256 arriving as a JSON number above 2**53 would round; the schema
    # mandates decimal strings, and large values must survive the round trip.
    # Own server: the amount is astronomically large, so P6 needs a balance to match
    # (P6 firing on the default stub is the relay being right, not a bug).
    big = 2**200 + 12345
    srv = Live(rpc=StubRpc(balance=2**255))
    try:
        o_big = make_order(sellAmount=big, maxTip=0)
        code, body = srv.post("/order", signed_payload(o_big, nonce=5))
        check("2**200 amount accepted and exact", code == 200, f"{code} {body}")
        _, listing = srv.get("/orders")
        got = [e for e in listing["orders"] if e["nonce"] == "5"][0]
        check("2**200 amount round-trips without loss",
              got["order"]["sellAmount"] == str(big), got["order"]["sellAmount"])
    finally:
        srv.close()


def test_P6_P7_antispam():
    print("\nP6 / P7 — anti-spam filters (never guarantees: TOCTOU)")
    o = make_order()
    payload = signed_payload(o, nonce=6)

    srv = Live(rpc=StubRpc(balance=o.permitted() - 1))
    try:
        code, body = srv.post("/order", payload)
        check("balance < permitted → P6", code == 422 and "P6" in body.get("failed", []),
              f"{code} {body}")
    finally:
        srv.close()

    srv = Live(rpc=StubRpc(balance=o.permitted()))
    try:
        code, body = srv.post("/order", payload)
        check("balance == permitted accepted (boundary, not off-by-one)", code == 200,
              f"{code} {body}")
    finally:
        srv.close()

    srv = Live(rpc=StubRpc(allowance=o.permitted() - 1))
    try:
        code, body = srv.post("/order", payload)
        check("allowance < permitted → P7", code == 422 and "P7" in body.get("failed", []),
              f"{code} {body}")
    finally:
        srv.close()

    # Cost budget: the spec says ~2 RPC reads per order, no simulation.
    rpc = StubRpc()
    cfg = R.Config(spartan1=SPARTAN1, chain_id=CHAIN_ID, rpc_url="stub://")
    sig = sign_order(o, 6, SPARTAN1, CHAIN_ID, MAKER_PK)
    R.evaluate(o, 6, sig, cfg, rpc, known_hash=False)
    check("exactly 2 eth_call per order (balance + allowance)", rpc.calls == 2,
          f"{rpc.calls} calls")


def test_multiple_failures_reported_together():
    print("\npredicate reporting — all failures at once, so a maker can fix the cause")
    srv = Live(rpc=StubRpc(balance=0, allowance=0))
    try:
        now = int(time.time())
        o = make_order(fillWindow=now + 500, deadline=now + 45)
        code, body = srv.post("/order", signed_payload(o, nonce=7))
        failed = set(body.get("failed", []))
        check("P3, P6 and P7 all reported", {"P3", "P6", "P7"} <= failed, str(body))
        check("detail explains each failure",
              all(k in body.get("detail", {}) for k in ("P3", "P6", "P7")), str(body))
    finally:
        srv.close()


def test_orders_filtering():
    print("\nGET /orders — filters, and addressed orders stay private to their taker")
    srv = Live(rpc=StubRpc())
    try:
        open_order = make_order()
        addressed = make_order(taker=TAKER, maxTip=5 * 10**15)
        srv.post("/order", signed_payload(open_order, nonce=10))
        srv.post("/order", signed_payload(addressed, nonce=11))

        _, anon = srv.get("/orders")
        check("anonymous listing shows only the open order", anon["count"] == 1, str(anon))
        check("the open one is the one shown",
              anon["orders"][0]["order"]["taker"] == R.ZERO_ADDRESS)

        _, mine = srv.get(f"/orders?taker={TAKER}")
        check("taker sees open + addressed", mine["count"] == 2, str(mine))

        other = "0x00000000000000000000000000000000000000bb"
        _, theirs = srv.get(f"/orders?taker={other}")
        check("another taker does not see the addressed order", theirs["count"] == 1,
              str(theirs))

        _, filtered = srv.get(f"/orders?sellToken={SELL}&buyToken={BUY}")
        check("token filter matches maker-centric fields", filtered["count"] >= 1)
        _, empty = srv.get(f"/orders?sellToken={BUY}&buyToken={SELL}")
        check("inverted token filter matches nothing (no accidental symmetry)",
              empty["count"] == 0, str(empty))
    finally:
        srv.close()


def test_perspective_inversion():
    print("\nperspective inversion — the mapping that would silently flip a swap")
    o = make_order(sellAmount=10**18, buyAmount=3000 * 10**6)
    tv = R.taker_view(o)
    check("taker sells order.buyToken", tv["sellToken"] == o.buyToken)
    check("taker buys order.sellToken", tv["buyToken"] == o.sellToken)
    check("taker pays order.buyAmount", tv["sellAmount"] == str(o.buyAmount))
    check("taker receives order.sellAmount", tv["buyAmount"] == str(o.sellAmount))
    check("inversion is not the identity (would hide the bug)",
          tv["sellToken"] != o.sellToken)

    req = R.maker_view_request(sell_token="0xAA" + "00" * 19, buy_token="0xBB" + "00" * 19,
                              sell_amount=500, buy_amount=None)
    check("taker sellToken becomes maker buyToken", req["buyToken"] == "0xAA" + "00" * 19)
    check("taker buyToken becomes maker sellToken", req["sellToken"] == "0xBB" + "00" * 19)
    check("taker sellAmount becomes maker buyAmount", req["buyAmount"] == "500")
    check("maker sellAmount left open", req["sellAmount"] is None)

    # Round trip: taker_view(maker_view_request(x)) must return x.
    round_tripped = R.taker_view(make_order(
        sellToken="0xBB" + "00" * 19, buyToken="0xAA" + "00" * 19,
        sellAmount=1, buyAmount=500))
    check("round trip restores the taker's own view",
          round_tripped["sellToken"] == "0xAA" + "00" * 19
          and round_tripped["sellAmount"] == "500")


def test_best_quote_selection():
    print("\nRFQ best-quote selection — mechanical, no discretion")
    def cand(sell, buy):
        return (make_order(sellAmount=sell, buyAmount=buy), 0, b"\x00")

    cands = [cand(10**18, 3010 * 10**6), cand(10**18, 2990 * 10**6),
             cand(10**18, 3000 * 10**6)]
    best = R.best_quote(cands, exact_out=True)
    check("exactOut picks the lowest buyAmount (caller pays least)",
          best[0].buyAmount == 2990 * 10**6, str(best[0].buyAmount))

    cands2 = [cand(10**18, 3000 * 10**6), cand(11 * 10**17, 3000 * 10**6),
              cand(9 * 10**17, 3000 * 10**6)]
    best2 = R.best_quote(cands2, exact_out=False)
    check("exactIn picks the highest sellAmount (caller receives most)",
          best2[0].sellAmount == 11 * 10**17, str(best2[0].sellAmount))

    check("no candidates → None", R.best_quote([], exact_out=True) is None)

    tie = [cand(10**18, 3000 * 10**6), cand(10**18, 3000 * 10**6)]
    check("ties break by arrival order", R.best_quote(tie, exact_out=True) is tie[0])


def test_rfq_endpoints():
    print("\n/rfq/quote and /quote — 404 means 'not quoting', not an error")
    srv = Live(rpc=StubRpc())          # no maker webhooks registered
    try:
        code, _ = srv.post("/rfq/quote", {"sellToken": SELL, "buyToken": BUY,
                                          "sellAmount": "1000"})
        check("no makers → 404", code == 404, str(code))

        code, _ = srv.post("/rfq/quote", {"sellToken": SELL, "buyToken": BUY})
        check("neither amount → 422", code == 422, str(code))
        code, _ = srv.post("/rfq/quote", {"sellToken": SELL, "buyToken": BUY,
                                          "sellAmount": "1", "buyAmount": "1"})
        check("both amounts → 422", code == 422, str(code))
        code, _ = srv.post("/rfq/quote", {"sellToken": "nope", "buyToken": BUY,
                                          "sellAmount": "1"})
        check("bad address → 422", code == 422, str(code))

        code, _ = srv.get(f"/quote?sellToken={BUY}&buyToken={SELL}")
        check("/quote without an amount → 422", code == 422, str(code))

        # /quote falls back to the resting pool, with the inversion applied.
        o = make_order()
        srv.post("/order", signed_payload(o, nonce=20))
        code, q = srv.get(f"/quote?sellToken={BUY}&buyToken={SELL}"
                          f"&buyAmount={o.sellAmount}")
        check("/quote serves a resting order via the pool", code == 200, f"{code} {q}")
        if code == 200:
            check("/quote sellToken is what the TAKER pays", q["sellToken"] == o.buyToken)
            check("/quote buyAmount is what the TAKER receives",
                  q["buyAmount"] == str(o.sellAmount))
            check("/quote carries the settleable order + signature",
                  q["order"]["maker"] == MAKER and q["signature"].startswith("0x"))
            check("allowanceTarget is Spartan1 (executor capital, bounded)",
                  q["allowanceTarget"] == SPARTAN1)

        code, tokens = srv.get("/rfq/tokens")
        check("/rfq/tokens responds with a pairs array",
              code == 200 and isinstance(tokens.get("pairs"), list), str(tokens))
    finally:
        srv.close()


def test_health_challenge():
    print("\n/health — freshness challenge (anti-Sybil rule 3)")
    srv = Live(rpc=StubRpc())
    try:
        _, plain = srv.get("/health")
        check("no nonce → no challenge block", "challenge" not in plain, str(plain))
        for key in ("chainId", "permit2", "spartan1", "ordersOpen", "uptime", "predicates"):
            check(f"health exposes {key}", key in plain)
        check("permit2 is the canonical singleton", plain["permit2"] == R.PERMIT2)

        _, ch = srv.get("/health?nonce=abc123")
        check("nonce echoed verbatim", ch["challenge"]["nonce"] == "abc123", str(ch))
        check("challenge carries a current block number",
              ch["challenge"]["blockNumber"] == 12345678)
        check("challenge carries a block hash",
              ch["challenge"]["blockHash"].startswith("0x") and
              len(ch["challenge"]["blockHash"]) == 66)
    finally:
        srv.close()

    # A relay whose RPC is dead must report the failure, not fake a blockhash.
    class DeadRpc(StubRpc):
        def latest_block(self):
            raise RuntimeError("node unreachable")

    srv = Live(rpc=DeadRpc())
    try:
        _, ch = srv.get("/health?nonce=xyz")
        check("dead RPC → challenge is null plus an error, never fabricated",
              ch.get("challenge") is None and "challengeError" in ch, str(ch))
    finally:
        srv.close()


def test_fanout_uniformity():
    print("\nclient fan-out — uniform random, structurally democratic")
    relays = [f"https://r{i}.example" for i in range(20)]
    picked = R.select_relays(relays, target=R.FANOUT_TARGET)
    check("selects exactly FANOUT_TARGET", len(picked) == 8, str(len(picked)))
    check("no duplicates in a selection", len(set(picked)) == len(picked))

    few = relays[:5]
    check("fewer relays than target → all of them",
          set(R.select_relays(few, target=8)) == set(few))
    check("duplicate entries collapse", R.select_relays(["a", "a", "b"], target=8) == ["a", "b"])

    # Uniformity: over many draws every relay should appear ~equally often.
    rng = random.Random(1234)
    counts = {r: 0 for r in relays}
    trials = 4000
    for _ in range(trials):
        for r in R.select_relays(relays, target=8, rng=rng):
            counts[r] += 1
    expected = trials * 8 / len(relays)
    worst = max(abs(c - expected) / expected for c in counts.values())
    check("empirical selection is uniform within 10% (no emergent centralisation)",
          worst < 0.10, f"worst deviation {worst:.3%}")

    check("first relay has no advantage over the last",
          abs(counts[relays[0]] - counts[relays[-1]]) / expected < 0.10,
          f"{counts[relays[0]]} vs {counts[relays[-1]]}")


def test_relay_cannot_forge():
    print("\nmother principle — a malicious relay can only omit, never forge")
    srv = Live(rpc=StubRpc())
    try:
        o = make_order()
        srv.post("/order", signed_payload(o, nonce=30))
        _, listing = srv.get("/orders")
        served = listing["orders"][0]

        # Whatever a relay serves, the receiver recomputes the witness from the
        # fields and compares. An altered amount changes the hash and the digest,
        # so the forgery cannot survive local re-verification — let alone settle().
        rebuilt = Order(
            maker=served["order"]["maker"], taker=served["order"]["taker"],
            sellToken=served["order"]["sellToken"], buyToken=served["order"]["buyToken"],
            sellAmount=int(served["order"]["sellAmount"]),
            buyAmount=int(served["order"]["buyAmount"]),
            recipient=served["order"]["recipient"], maxTip=int(served["order"]["maxTip"]),
            fillWindow=served["order"]["fillWindow"], deadline=served["order"]["deadline"],
        )
        check("served fields recompute to the served hash",
              "0x" + order_hash(rebuilt).hex() == served["orderHash"])

        forged = Order(**{**rebuilt.__dict__, "buyAmount": rebuilt.buyAmount - 1})
        check("a relay bumping buyAmount produces a different witness",
              order_hash(forged) != order_hash(rebuilt))
        recovered = Account._recover_hash(
            R.signing_digest(forged, 30, SPARTAN1, CHAIN_ID),
            signature=bytes.fromhex(served["signature"][2:]),
        )
        check("the maker's signature does not verify over forged fields",
              recovered.lower() != MAKER.lower(), recovered)
    finally:
        srv.close()


def test_unknown_routes():
    print("\nrouting")
    srv = Live(rpc=StubRpc())
    try:
        code, _ = srv.get("/orders/../secret")
        check("unknown GET route → 404", code == 404, str(code))
        code, _ = srv.post("/settle", {})
        check("unknown POST route → 404", code == 404, str(code))
        code, body = srv.get("/orders/")
        check("trailing slash tolerated", code == 200, f"{code} {body}")
    finally:
        srv.close()


def test_schema_conformance():
    print("\nschema conformance — openapi.yaml is the layer SPOF; PARSING IT is the test")
    print("(the behavioural suites never load the YAML — this is the gate that catches a broken schema)")
    here = os.path.dirname(os.path.abspath(__file__))
    spec_path = os.path.join(here, "openapi.yaml")
    try:
        import yaml
    except ImportError:
        for name in ("openapi.yaml parses as valid YAML",
                     "declared endpoints == implemented routes",
                     "Order property order == ORDER_TYPEHASH field order",
                     "settleable maker response keys subset of SignedOrder",
                     "DRY_RUN maker response keys subset of SignedOrder"):
            skip(name, "pyyaml not installed (schema gate needs it)")
        return

    # 1. The PARSE itself is the test — a stray unquoted `: ` (yaml sees a nested mapping) raises here.
    parsed = False
    try:
        with open(spec_path) as fh:
            spec = yaml.safe_load(fh)
        parsed = isinstance(spec, dict)
    except yaml.YAMLError as exc:
        print(f"    YAML ERROR: {exc}")
    check("openapi.yaml parses as valid YAML", parsed)
    if not parsed:
        return

    # 2. Every declared path is implemented, and vice versa (I did this by hand before; now it's a test).
    declared = set(spec["paths"].keys())
    implemented = {"/order", "/orders", "/rfq/quote", "/rfq/tokens", "/quote", "/health"}
    check("declared endpoints == implemented routes", declared == implemented,
          f"symmetric diff: {declared ^ implemented}")

    # 3. Order property order == the ORDER_TYPEHASH preimage (reorder → different typehash → dead sigs).
    from order import ORDER_TYPE
    inside = ORDER_TYPE[ORDER_TYPE.index("(") + 1:ORDER_TYPE.rindex(")")]
    typehash_fields = [seg.split()[1] for seg in inside.split(",")]
    order_props = list(spec["components"]["schemas"]["Order"]["properties"].keys())
    check("Order property order == ORDER_TYPEHASH field order",
          order_props == typehash_fields, f"{order_props} vs {typehash_fields}")

    # 4. A LIVE maker response's keys ⊆ SignedOrder's declared properties — the exact regression this
    #    gate exists for (maker emits settleable/dryRun/warning; the schema must admit them).
    signed_props = set(spec["components"]["schemas"]["SignedOrder"]["properties"].keys())
    import maker as M
    from fractions import Fraction
    body = {"sellToken": SELL, "buyToken": BUY, "sellAmount": str(10**18)}

    def _feed():
        return M.reference_quote_fn({(SELL, BUY): M.Quote(mid=Fraction(3000 * 10**6, 10**18),
                                                          spread_bps=20)})
    cfg_ok = M.Config.build(spartan1="0x000000000000000000000000000000000000dEaD",
                            private_key=MAKER_PK, chain_id=CHAIN_ID, port=0)
    resp_ok = M.make_signed_quote(cfg_ok, _feed(), M.InventoryLedger({SELL: 10**24}), body, 1_900_000_000)
    check("settleable maker response keys ⊆ SignedOrder", set(resp_ok) <= signed_props,
          f"undeclared: {set(resp_ok) - signed_props}")

    cfg_dry = M.Config.build(spartan1=None, private_key=MAKER_PK, chain_id=CHAIN_ID,
                             dry_run=True, port=0)
    resp_dry = M.make_signed_quote(cfg_dry, _feed(), M.InventoryLedger({SELL: 10**24}), body, 1_900_000_000)
    check("DRY_RUN maker response keys ⊆ SignedOrder (settleable/dryRun/warning declared)",
          set(resp_dry) <= signed_props, f"undeclared: {set(resp_dry) - signed_props}")


def test_cross_leg_coherence():
    print("\ncross-leg coherence — the frozen literals must be the SAME BYTES in every leg")
    print("(each suite asserts its own literal; only this gate asserts they agree + match recomputation)")
    import subprocess
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts",
                          "check_coherence.py")
    proc = subprocess.run([sys.executable, script], capture_output=True, text=True)
    check("witness/digest/spender literals coherent across all legs (and == recomputed truth)",
          proc.returncode == 0, "\n" + proc.stdout + proc.stderr)


def test_coherence_gate_exits_nonzero_on_divergent_sentinel():
    """The gate must FAIL, not merely report. Both consumers key off the EXIT CODE — this suite
    (returncode == 0 above) and the CI step — so a refactor that turned a `problems.append` into a
    bare `print` would leave a gate that narrates a broken sentinel while the build stays green.
    Hermetic: monkeypatches extract() in memory, mutates no file, then restores."""
    print("\ncoherence gate self-test — a divergent placebo sentinel must EXIT NON-ZERO")
    scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
    sys.path.insert(0, scripts_dir)
    import io
    from contextlib import redirect_stdout

    import check_coherence as C

    original = C.extract
    try:
        def divergent():
            found, errors = original()
            # One derived leg moves off the frozen sentinel; every other leg stays put.
            found["sentinel"] = [
                (f, "0x2222222222222222222222222222222222222222" if i == 0 else v)
                for i, (f, v) in enumerate(found["sentinel"])
            ]
            return found, errors

        C.extract = divergent
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = C.main()
        out = buf.getvalue()
        check("divergent sentinel -> exit code 1 (fails the build, not just the log)", rc == 1,
              f"returned {rc}\n{out}")
        check("...and the failure names the divergent leg", "INCOHERENT" in out, out)

        # Control: with extract() restored the very same call path must exit 0, so the assertion
        # above cannot pass for an unrelated reason (a gate that always fails proves nothing).
        C.extract = original
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            rc_ok = C.main()
        check("control: unmodified tree -> exit code 0", rc_ok == 0, f"returned {rc_ok}\n{buf2.getvalue()}")
    finally:
        C.extract = original


# ══════════════════════════════ runner ═══════════════════════════════════
def main() -> None:
    print("Spartan1 relay — conformance gate (openapi.yaml is the reference)")
    for fn in (
        test_happy_and_P5_idempotence,
        test_P1_signature,
        test_P1_erc1271_and_deferred,
        test_P2_deadline_semantics,
        test_P3_fillwindow,
        test_P4_wellformed,
        test_P6_P7_antispam,
        test_multiple_failures_reported_together,
        test_orders_filtering,
        test_perspective_inversion,
        test_best_quote_selection,
        test_rfq_endpoints,
        test_health_challenge,
        test_fanout_uniformity,
        test_relay_cannot_forge,
        test_unknown_routes,
        test_schema_conformance,
        test_cross_leg_coherence,
        test_coherence_gate_exits_nonzero_on_divergent_sentinel,
    ):
        fn()

    total = len(PASS) + len(FAIL)
    print(f"\n{'=' * 60}")
    print(f"RESULT: {len(PASS)}/{total} passed, {len(FAIL)} failed"
          + (f", {len(SKIP)} skipped" if SKIP else ""))
    if FAIL:
        for name in FAIL:
            print(f"  FAILED: {name}")
        sys.exit(1)
    print("ALL GREEN")


if __name__ == "__main__":
    main()
