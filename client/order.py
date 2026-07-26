"""Spartan1 maker-side signing core.

Builds an ``Order``, its witness, and the exact Permit2 ``PermitWitnessTransferFrom``
EIP-712 digest, then signs it. The type strings here are byte-for-byte copies of the
ones frozen in ``src/Spartan1.sol`` — this file is the single off-chain source of the
witness type string (Across M-06 / OIF failure class). Do NOT re-derive them by hand.

Semantics propagated from the on-chain / Permit2 rules:
  * ``permit.deadline == order.deadline``      (expiry delegated to Permit2)
  * strict ``>`` expiry — an order is valid *at* the deadline second
  * ``nonce`` is a random 256-bit unordered value chosen by the maker
  * ``permitted = sellAmount + maxTip``        (single computation, mirrored on-chain)

Dependencies: eth-account, eth-abi, eth-hash[pycryptodome]  (web3 optional).
"""

from dataclasses import dataclass

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_hash.auto import keccak

# ─────────────────────────────── constants ───────────────────────────────

# Canonical Permit2 singleton (same address on every chain).
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# Frozen — identical to Spartan1.ORDER_TYPEHASH's preimage.
ORDER_TYPE = (
    "Order(address maker,address taker,address sellToken,address buyToken,"
    "uint256 sellAmount,uint256 buyAmount,address recipient,uint256 maxTip,"
    "uint256 fillWindow,uint256 deadline)"
)
ORDER_TYPEHASH = keccak(ORDER_TYPE.encode())

# Frozen — identical to Spartan1.WITNESS_TYPE_STRING. Referenced structs alphabetical
# (Order < TokenPermissions). Byte-exact; never edit.
WITNESS_TYPE_STRING = (
    "Order witness)Order(address maker,address taker,address sellToken,address buyToken,"
    "uint256 sellAmount,uint256 buyAmount,address recipient,uint256 maxTip,"
    "uint256 fillWindow,uint256 deadline)TokenPermissions(address token,uint256 amount)"
)

# Permit2 internals (PermitHash.sol / EIP712.sol), reproduced exactly.
PERMIT_WITNESS_TRANSFER_FROM_STUB = (
    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,"
    "uint256 nonce,uint256 deadline,"
)
TOKEN_PERMISSIONS_TYPEHASH = keccak(b"TokenPermissions(address token,uint256 amount)")
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,uint256 chainId,address verifyingContract)"
)
PERMIT2_HASHED_NAME = keccak(b"Permit2")


# ──────────────────────────────── data ───────────────────────────────────


@dataclass
class Order:
    maker: str
    taker: str          # address(0) => open order (taker == executor / msg.sender)
    sellToken: str
    buyToken: str
    sellAmount: int     # atomic
    buyAmount: int      # atomic
    recipient: str
    maxTip: int         # atomic, in sellToken
    fillWindow: int     # unix timestamp
    deadline: int       # unix timestamp; MUST equal the permit deadline

    def permitted(self) -> int:
        """Single computation, mirrored on-chain: Permit2 `permitted.amount`."""
        return self.sellAmount + self.maxTip


# ───────────────────────────── digest pieces ─────────────────────────────


def order_hash(order: Order) -> bytes:
    """The witness: keccak256(abi.encode(ORDER_TYPEHASH, order)) — the full Order bound."""
    return keccak(
        abi_encode(
            [
                "bytes32", "address", "address", "address", "address",
                "uint256", "uint256", "address", "uint256", "uint256", "uint256",
            ],
            [
                ORDER_TYPEHASH,
                order.maker, order.taker, order.sellToken, order.buyToken,
                order.sellAmount, order.buyAmount, order.recipient,
                order.maxTip, order.fillWindow, order.deadline,
            ],
        )
    )


def permit2_domain_separator(chain_id: int) -> bytes:
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "uint256", "address"],
            [EIP712_DOMAIN_TYPEHASH, PERMIT2_HASHED_NAME, chain_id, PERMIT2],
        )
    )


def _witness_type_hash() -> bytes:
    # keccak256(abi.encodePacked(stub, witnessTypeString)) — Permit2 PermitHash.hashWithWitness.
    return keccak(
        PERMIT_WITNESS_TRANSFER_FROM_STUB.encode() + WITNESS_TYPE_STRING.encode()
    )


def permit_struct_hash(order: Order, nonce: int, spender: str) -> bytes:
    """hashWithWitness(permit, witness, WITNESS_TYPE_STRING, spender)."""
    token_permissions_hash = keccak(
        abi_encode(
            ["bytes32", "address", "uint256"],
            [TOKEN_PERMISSIONS_TYPEHASH, order.sellToken, order.permitted()],
        )
    )
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "address", "uint256", "uint256", "bytes32"],
            [
                _witness_type_hash(),
                token_permissions_hash,
                spender,
                nonce,
                order.deadline,
                order_hash(order),
            ],
        )
    )


def signing_digest(order: Order, nonce: int, spender: str, chain_id: int) -> bytes:
    """The EIP-712 digest the maker signs: keccak256(0x1901 || domainSeparator || structHash).

    `spender` MUST be the deployed Spartan1 address — it binds the signature to this
    contract and nowhere else (re-verify pre-mainnet).
    """
    return keccak(
        b"\x19\x01"
        + permit2_domain_separator(chain_id)
        + permit_struct_hash(order, nonce, spender)
    )


# ─────────────────────────────── signing ─────────────────────────────────


def sign_order(order: Order, nonce: int, spender: str, chain_id: int, private_key) -> bytes:
    """Return a 65-byte EOA signature over the Permit2 witness digest."""
    digest = signing_digest(order, nonce, spender, chain_id)
    # unsafe_sign_hash is the public API for signing a precomputed 32-byte digest;
    # byte-identical to the legacy Account._sign_hash in the pinned eth-account 0.13.7.
    signed = Account.unsafe_sign_hash(digest, private_key)
    return signed.signature


if __name__ == "__main__":
    # Convenience: print the canonical witness/digest for the frozen test vector.
    from test_spartan1 import CANONICAL_ORDER, CHAIN_ID, NONCE, SPENDER

    o = CANONICAL_ORDER
    print("witness:", "0x" + order_hash(o).hex())
    print("digest :", "0x" + signing_digest(o, NONCE, SPENDER, CHAIN_ID).hex())
