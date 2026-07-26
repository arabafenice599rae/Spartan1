#!/usr/bin/env python3
"""Cross-leg coherence gate — the referee over every frozen literal in the repo.

THE HOLE THIS CLOSES: the frozen witness/digest are hardcoded independently in FOUR files and
the vector spender in FIVE places (plus two placebo-sentinel occurrences). Each leg asserts
against ITS OWN literal, so every suite can be green while the legs disagree — e.g. a re-freeze
that updates some legs but not others leaves an incoherent system fully green. Nothing, until
this script, asserted the literals are the same bytes.

TWO SPENDER GROUPS — semantically different, and the distinction is load-bearing:
  * VECTOR spender (the canonical vector's `spender`): moves on re-freeze to the deployed
    address. Legs: Spartan1.t.sol VEC_SPENDER · client/test_spartan1.py SPENDER ·
    sdk/test/sdk.test.ts SPENDER · distribution/test_relay.py SPARTAN1 · index.html input value.
  * PLACEBO SENTINEL (`PLACEHOLDER_SPENDER` in maker.py, `PLACEHOLDER` in index.html): the
    anti-placebo guard compares the configured spender against THIS value. It must remain
    0x1111…1111 FOREVER — rewriting it to the deployed address would INVERT the guard
    (`settleable` would become false for the real deployment).

Checks:
  1. every witness literal byte-identical across legs;
  2. every digest literal byte-identical across legs;
  3. vector-spender group byte-identical;
  4. sentinel group byte-identical AND equal to the frozen sentinel;
  5. REFEREE: recompute witness/digest from client/order.py (the single source) with the
     extracted vector spender and the canonical vector, and require the literals to equal the
     computed truth — coherence by recomputation, not by majority vote.

Exit 0 = coherent. Non-zero = the report names every leg and its value.
Wired into distribution/test_relay.py so it runs by default.
"""

from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "client"))

FROZEN_SENTINEL = "0x1111111111111111111111111111111111111111"

HEX64 = r"(0x[0-9a-fA-F]{64})"
ADDR = r"(0x[0-9a-fA-F]{40})"

# (kind, file, anchored regex). Extraction is by ANCHOR (variable name / label), never by
# expected value — the checker must find drifted values, not only the ones it expects.
SPEC: list[tuple[str, str, str]] = [
    # witness
    ("witness", "test/Spartan1.t.sol",        r"EXPECT_WITNESS\s*=\s*" + HEX64),
    ("witness", "client/test_spartan1.py",    r'EXPECT_WITNESS\s*=\s*"' + HEX64 + r'"'),
    ("witness", "sdk/test/sdk.test.ts",       r'const EXPECT_WITNESS\s*=\s*"' + HEX64 + r'"'),
    ("witness", "README.md",                  r"witness \(keccak256\(abi\.encode\(ORDER_TYPEHASH, order\)\)\):\s*\n\s*" + HEX64),
    # digest
    ("digest", "test/Spartan1.t.sol",         r"EXPECT_DIGEST\s*=\s*" + HEX64),
    ("digest", "client/test_spartan1.py",     r'EXPECT_DIGEST\s*=\s*"' + HEX64 + r'"'),
    ("digest", "sdk/test/sdk.test.ts",        r'const EXPECT_DIGEST\s*=\s*"' + HEX64 + r'"'),
    ("digest", "README.md",                   r"digest  \(EIP-712 PermitWitnessTransferFrom signing hash\):\s*\n\s*" + HEX64),
    # vector spender (moves on re-freeze)
    ("vector_spender", "test/Spartan1.t.sol",     r"VEC_SPENDER\s*=\s*" + ADDR),
    ("vector_spender", "client/test_spartan1.py", r'\nSPENDER\s*=\s*"' + ADDR + r'"'),
    ("vector_spender", "sdk/test/sdk.test.ts",    r'const SPENDER\s*=\s*"' + ADDR + r'"'),
    ("vector_spender", "distribution/test_relay.py", r'\nSPARTAN1\s*=\s*"' + ADDR + r'"'),
    ("vector_spender", "distribution/index.html",    r'id="spartan1" value="' + ADDR + r'"'),
    # placebo sentinel (frozen forever). The SDK legs are GENERATED from client/order.py by
    # gen_constants.py — the drift gate keeps them byte-identical to a regeneration, and here the
    # sentinel gate keeps their VALUE pinned to 0x1111…1111 so a re-freeze can never move them.
    ("sentinel", "distribution/maker.py",         r'PLACEHOLDER_SPENDER\s*=\s*"' + ADDR + r'"'),
    ("sentinel", "distribution/index.html",       r'const PLACEHOLDER\s*=\s*"' + ADDR + r'"'),
    ("sentinel", "sdk/src/generated/constants.ts", r'PLACEHOLDER_SPENDER\s*=\s*"' + ADDR + r'"'),
    ("sentinel", "sdk/src/generated/constants.js", r'PLACEHOLDER_SPENDER\s*=\s*"' + ADDR + r'"'),
]


def extract() -> tuple[dict[str, list[tuple[str, str]]], list[str]]:
    """kind -> [(file, value)], plus a list of extraction errors."""
    found: dict[str, list[tuple[str, str]]] = {}
    errors: list[str] = []
    for kind, rel, pattern in SPEC:
        path = os.path.join(ROOT, rel)
        try:
            text = open(path).read()
        except OSError as exc:
            errors.append(f"{rel}: unreadable ({exc})")
            continue
        matches = re.findall(pattern, text)
        if len(matches) != 1:
            errors.append(f"{rel}: anchor for {kind} matched {len(matches)} times (expected 1)")
            continue
        found.setdefault(kind, []).append((rel, matches[0]))
    return found, errors


DEPLOYMENTS = os.path.join(ROOT, "distribution", "deployments.json")
CANONICAL_CHAIN = 8453  # the frozen vector's chain (Base); its deployment must match the vector spender


def _check_deployments(spender: str | None, problems: list[str]) -> str:
    """Validate distribution/deployments.json; cross-check the canonical chain against the vector
    spender. Returns a short human summary for the OK line. Appends to `problems` on any issue."""
    try:
        with open(DEPLOYMENTS) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"deployments.json: unreadable/invalid JSON ({exc})")
        return "unreadable"
    chains = data.get("chains")
    if not isinstance(chains, dict) or not chains:
        problems.append("deployments.json: 'chains' must be a non-empty object of chainId -> address|null")
        return "bad shape"
    live = 0
    for cid, val in chains.items():
        if not re.fullmatch(r"[0-9]+", str(cid)):
            problems.append(f"deployments.json: chain key {cid!r} is not a numeric chain id")
        if val is None:
            continue
        if not (isinstance(val, str) and re.fullmatch(ADDR, val)):
            problems.append(f"deployments.json: chain {cid} value {val!r} is not a 0x-address or null")
            continue
        live += 1
        # The canonical chain's deployed address IS the spender the frozen vector signs against.
        if int(cid) == CANONICAL_CHAIN and spender is not None and val.lower() != spender.lower():
            problems.append(
                f"deployments.json: chain {cid} address {val} != the frozen vector spender {spender} "
                f"(signatures are bound to the vector spender; a divergent deployment is unsettleable)")
    return f"{live}/{len(chains)} chains deployed" if live else f"all {len(chains)} chains null (not deployed)"


def main() -> int:
    found, problems = extract()

    def uniform(kind: str, label: str) -> str | None:
        legs = found.get(kind, [])
        values = {v.lower() for (_f, v) in legs}
        if len(values) != 1:
            problems.append(f"{label} INCOHERENT across legs:")
            for f, v in legs:
                problems.append(f"    {f:35} -> {v}")
            return None
        return legs[0][1]

    witness = uniform("witness", "frozen WITNESS")
    digest = uniform("digest", "frozen DIGEST")
    spender = uniform("vector_spender", "canonical-vector SPENDER")
    sentinel = uniform("sentinel", "placebo SENTINEL")

    if sentinel is not None and sentinel.lower() != FROZEN_SENTINEL:
        problems.append(
            f"placebo SENTINEL must remain {FROZEN_SENTINEL} forever (anti-placebo guard would "
            f"invert), found {sentinel}")

    # 5. Referee: recompute from the single source with the extracted vector spender.
    if witness and digest and spender:
        from order import order_hash, signing_digest  # client/order.py
        from test_spartan1 import CANONICAL_ORDER, CHAIN_ID, NONCE  # canonical vector fields

        computed_witness = "0x" + order_hash(CANONICAL_ORDER).hex()
        computed_digest = "0x" + signing_digest(CANONICAL_ORDER, NONCE, spender, CHAIN_ID).hex()
        if computed_witness.lower() != witness.lower():
            problems.append(
                f"WITNESS literals ({witness}) != recomputed from client/order.py "
                f"({computed_witness})")
        if computed_digest.lower() != digest.lower():
            problems.append(
                f"DIGEST literals ({digest}) != recomputed from client/order.py with the "
                f"extracted spender {spender} ({computed_digest})")

    # 6. deployments.json — the AUTHORITATIVE address registry. Validate shape and cross-check:
    #    every non-null value is a well-formed address, and the canonical chain's value (once set)
    #    must equal the frozen vector spender (a deployed address that disagrees with the signatures
    #    frozen against it is worse than null). null = not deployed, legal today.
    deployed = _check_deployments(spender, problems)

    if problems:
        print("COHERENCE: FAIL")
        for p in problems:
            print("  " + p)
        return 1

    print("COHERENCE: OK")
    print(f"  witness  {witness}  ({len(found['witness'])} legs)")
    print(f"  digest   {digest}  ({len(found['digest'])} legs)")
    print(f"  spender  {spender}  ({len(found['vector_spender'])} vector legs; "
          f"sentinel frozen at {FROZEN_SENTINEL}, {len(found['sentinel'])} legs)")
    print(f"  deployments.json: {deployed}")
    print("  referee: literals == recomputation from client/order.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
