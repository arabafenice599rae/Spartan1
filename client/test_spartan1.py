"""Triple-digest harness — the project's single most critical check (Across M-06 / OIF class).

Reproduces a FROZEN canonical vector and asserts the witness and the full Permit2 signing
digest byte-for-byte across two independent code paths:

  * ``digest_client``  — the manual construction in ``order.py`` from the literal Permit2
                         type strings frozen in ``src/Spartan1.sol``.
  * ``digest_oracle``  — ``eth_account``'s canonical EIP-712 encoder from a typed-data dict
                         (independent type-string derivation: it sorts referenced types
                         alphabetically, which must land on the same encodeType).

The digest is a PURE function of its inputs — the vector is reproduced and asserted, never
regenerated. The on-chain (forge) leg is asserted separately by test 1 of the Foundry suite.

    client == oracle == <frozen constants>   →   forge (Spartan1.t.sol test 1) closes the loop.

Run:  python client/test_spartan1.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_hash.auto import keccak

from order import (
    PERMIT2,
    Order,
    order_hash,
    signing_digest,
)

# ─────────────────────────── FROZEN canonical vector ───────────────────────────
# Placeholder spender: the contract is not deployed yet. Pre-mainnet, replace SPENDER with
# the real deployed Spartan1 address and RE-FREEZE the two constants below.

CHAIN_ID = 8453  # Base
SPENDER = "0x1111111111111111111111111111111111111111"
MAKER_PK = "0x" + format(0xA11CE, "064x")
MAKER = "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7"  # == Account.from_key(MAKER_PK)
NONCE = 777

CANONICAL_ORDER = Order(
    maker=MAKER,
    taker="0x0000000000000000000000000000000000000000",
    sellToken="0x2222222222222222222222222222222222222222",
    buyToken="0x3333333333333333333333333333333333333333",
    sellAmount=10**18,
    buyAmount=3000 * 10**6,
    recipient="0x4444444444444444444444444444444444444444",
    maxTip=10**16,
    fillWindow=1900000000,
    deadline=1900000045,
)

EXPECT_WITNESS = "0xcd06eda903e77bb9f5b8b5fd77566d10bfd03e0a68d483411f90b7f6b0465c58"
EXPECT_DIGEST = "0xbbb89e334fb04f3e32eecb7e77b2a812437ad7dcdaa0101fa3334f1d91daa63b"


# ───────────────────────────── independent oracle ──────────────────────────────


def _typed_data(order: Order):
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TokenPermissions": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "Order": [
                {"name": "maker", "type": "address"},
                {"name": "taker", "type": "address"},
                {"name": "sellToken", "type": "address"},
                {"name": "buyToken", "type": "address"},
                {"name": "sellAmount", "type": "uint256"},
                {"name": "buyAmount", "type": "uint256"},
                {"name": "recipient", "type": "address"},
                {"name": "maxTip", "type": "uint256"},
                {"name": "fillWindow", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
            # Member order MUST mirror Permit2's stub:
            # permitted, spender, nonce, deadline, witness.
            "PermitWitnessTransferFrom": [
                {"name": "permitted", "type": "TokenPermissions"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "witness", "type": "Order"},
            ],
        },
        "primaryType": "PermitWitnessTransferFrom",
        "domain": {"name": "Permit2", "chainId": CHAIN_ID, "verifyingContract": PERMIT2},
        "message": {
            "permitted": {"token": order.sellToken, "amount": order.permitted()},
            "spender": SPENDER,
            "nonce": NONCE,
            "deadline": order.deadline,
            "witness": {
                "maker": order.maker,
                "taker": order.taker,
                "sellToken": order.sellToken,
                "buyToken": order.buyToken,
                "sellAmount": order.sellAmount,
                "buyAmount": order.buyAmount,
                "recipient": order.recipient,
                "maxTip": order.maxTip,
                "fillWindow": order.fillWindow,
                "deadline": order.deadline,
            },
        },
    }


def digest_oracle(order: Order) -> bytes:
    sm = encode_typed_data(full_message=_typed_data(order))
    # SignableMessage: version b'\x01', header = domainSeparator, body = hashStruct(message).
    return keccak(b"\x19\x01" + sm.header + sm.body)


# ──────────────────────────────── the harness ──────────────────────────────────


def main() -> int:
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        ok = ok and cond

    print("Spartan1 triple-digest harness — frozen vector")

    # 0. vector self-consistency: the private key really derives the maker address.
    derived = Account.from_key(MAKER_PK).address
    check(f"maker derives from MAKER_PK ({derived})", derived.lower() == MAKER.lower())

    # 1. witness (order.py) == frozen constant.
    w_client = "0x" + order_hash(CANONICAL_ORDER).hex()
    print(f"  witness (client) = {w_client}")
    check("witness == EXPECT_WITNESS", w_client == EXPECT_WITNESS)

    # 2. digest client == oracle (two independent type-string derivations).
    d_client = "0x" + signing_digest(CANONICAL_ORDER, NONCE, SPENDER, CHAIN_ID).hex()
    d_oracle = "0x" + digest_oracle(CANONICAL_ORDER).hex()
    print(f"  digest  (client) = {d_client}")
    print(f"  digest  (oracle) = {d_oracle}")
    check("digest client == oracle", d_client == d_oracle)

    # 3. digest == frozen constant.
    check("digest == EXPECT_DIGEST", d_client == EXPECT_DIGEST)

    # 4. negative tamper — flip one field, both witness and digest must move.
    tampered = Order(**{**CANONICAL_ORDER.__dict__, "deadline": CANONICAL_ORDER.deadline + 1})
    check(
        "tamper(deadline+1) changes witness",
        order_hash(tampered).hex() != order_hash(CANONICAL_ORDER).hex(),
    )
    check(
        "tamper(deadline+1) changes digest",
        signing_digest(tampered, NONCE, SPENDER, CHAIN_ID)
        != signing_digest(CANONICAL_ORDER, NONCE, SPENDER, CHAIN_ID),
    )

    print("RESULT:", "ALL GREEN" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
