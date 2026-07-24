// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/// @notice Minimal Permit2 SignatureTransfer surface used by Spartan1.
/// Struct layout MUST match Uniswap Permit2 exactly (ABI-compatible).
interface ISignatureTransfer {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    function permitWitnessTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external;
}

/// @title Spartan1 — exact-settlement RFQ primitive on Permit2.
/// @notice One contract, one function, zero trust added.
///         Authorization (who / how much / until when) is enforced by Permit2 via a witness
///         binding the entire Order. Settlement (how) is enforced here: the atomic two-of-two
///         delta postcondition I6 proves on-chain that both parties received exactly the
///         signed amounts — or the whole transaction reverts.
/// @dev    No owner, no proxy, no governance, no storage, no fees, no oracle.
///         Delegated to Permit2 (verified source ordering — SignatureExpired first, then
///         InvalidAmount, then nonce, then signature, then transfer):
///           - expiry            (I2-del: permit.deadline == order.deadline; maker pull is FIRST)
///           - amount upper bound (I5-hi: InvalidAmount, pre-nonce — over-pull never burns an order)
///           - replay / chainId  (I3' unordered nonce / I2b domain separator)
///           - Order integrity + maker identity (I1' witness; ecrecover or ERC-1271)
///         Absorbed into I6 (Solady balanceOf returns 0 for codeless addresses → delta 0 → revert):
///           - token code-existence check.
contract Spartan1 is ReentrancyGuardTransient {
    // ────────────────────────────── data ──────────────────────────────

    struct Order {
        address maker;       // permit owner; signer
        address taker;       // counterparty; address(0) = open (taker ≡ msg.sender)
        address sellToken;   // what the maker gives  (== permitted.token)
        address buyToken;    // what the maker receives
        uint256 sellAmount;  // exact, atomic — received by the taker
        uint256 buyAmount;   // exact, atomic — received by the maker
        address recipient;   // maker-side buyToken destination
        uint256 maxTip;      // cap on third-party executor compensation, in sellToken
        uint256 fillWindow;  // timestamp splitting hot (maker-only) / fallback (anyone)
        uint256 deadline;    // absolute expiry — MUST equal permit.deadline
    }

    /// @dev keccak256 of the Order EIP-712 type. Field order is frozen.
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,address recipient,uint256 maxTip,uint256 fillWindow,uint256 deadline)"
    );

    /// @dev Appended by Permit2 after its stub
    ///      "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,".
    ///      Referenced structs in alphabetical order (Order < TokenPermissions). Byte-exact; never edit.
    string public constant WITNESS_TYPE_STRING =
        "Order witness)Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,address recipient,uint256 maxTip,uint256 fillWindow,uint256 deadline)TokenPermissions(address token,uint256 amount)";

    /// @notice Canonical Permit2 singleton (immutable constructor arg; code asserted at deploy).
    ISignatureTransfer public immutable PERMIT2;

    // ───────────────────────────── errors ─────────────────────────────

    error BadWindow();      // fillWindow > deadline                  (I2c)
    error SameToken();      // sellToken == buyToken                  (I9)
    error ZeroAmount();     // sellAmount == 0                        (I10)
    error ZeroRecipient();  // recipient == address(0)                (I11)
    error NotMaker();       // hot-window caller is not the maker     (W)
    error BadAmount();      // requestedAmount != window-derived amount (W)
    error DeltaMismatch();  // I6 postcondition failed — total revert
    error NoCode();         // Permit2 address has no code (deploy-time only)

    // ─────────────────────────── constructor ──────────────────────────

    constructor(ISignatureTransfer permit2_) {
        if (address(permit2_).code.length == 0) revert NoCode();
        PERMIT2 = permit2_;
    }

    // ───────────────────────────── settle ─────────────────────────────

    /// @notice Settles a signed Order. Anyone may call in the fallback window; only the maker
    ///         in the hot window. The caller supplies `buyAmount` from its own funds
    ///         (msg.sender-bound — the confused-deputy class is removed by construction).
    /// @param order           The maker-signed Order (bound in full inside the Permit2 witness).
    /// @param requestedAmount Must equal sellAmount (hot) or sellAmount + maxTip (fallback).
    /// @param nonce           Permit2 unordered nonce chosen by the maker (inside the signed digest).
    /// @param makerSig        Maker signature over PermitWitnessTransferFrom (EOA or ERC-1271).
    function settle(
        Order calldata order,
        uint256 requestedAmount,
        uint256 nonce,
        bytes calldata makerSig
    ) external nonReentrant {
        // 1. static checks — no ts<deadline here (delegated to Permit2, fork-test-gated),
        //    no code.length here (absorbed by I6, fork-test-gated).
        if (order.fillWindow > order.deadline) revert BadWindow();     // I2c
        if (order.sellToken == order.buyToken) revert SameToken();     // I9
        if (order.sellAmount == 0) revert ZeroAmount();                // I10
        if (order.recipient == address(0)) revert ZeroRecipient();     // I11

        // 2. derive taker — never a free parameter.                     I4
        address takerAddr = order.taker == address(0) ? msg.sender : order.taker;

        // 3. window → amount + caller. Single `permitted` computation    W
        //    (used for BOTH Permit.amount and requested — no divergence possible).
        uint256 permitted = order.sellAmount + order.maxTip;           // 0.8: overflow reverts
        uint256 requested =
            block.timestamp >= order.fillWindow ? permitted : order.sellAmount;
        if (block.timestamp < order.fillWindow && msg.sender != order.maker) revert NotMaker();
        if (requestedAmount != requested) revert BadAmount();

        // 4. balance snapshots (Solady balanceOf: codeless → 0, never reverts).
        uint256 bRecipient = SafeTransferLib.balanceOf(order.buyToken, order.recipient);
        uint256 bTaker = SafeTransferLib.balanceOf(order.sellToken, takerAddr);

        // 5. pull maker FIRST — fail-closed: deadline / amount / nonce / signature are all
        //    verified inside Permit2 BEFORE any executor funds move.
        PERMIT2.permitWitnessTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: order.sellToken,
                    amount: permitted
                }),
                nonce: nonce,
                deadline: order.deadline
            }),
            ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: requestedAmount
            }),
            order.maker,
            keccak256(abi.encode(ORDER_TYPEHASH, order)),              // witness = full Order
            WITNESS_TYPE_STRING,
            makerSig
        );
        //    pull taker — source bound to msg.sender, never an arbitrary address.
        SafeTransferLib.safeTransferFrom(
            order.buyToken, msg.sender, order.recipient, order.buyAmount
        );

        // 6. payout: sellAmount → taker; tip (if any) → caller.
        SafeTransferLib.safeTransfer(order.sellToken, takerAddr, order.sellAmount);
        if (requestedAmount > order.sellAmount) {
            SafeTransferLib.safeTransfer(
                order.sellToken, msg.sender, requestedAmount - order.sellAmount
            );
        }

        // 7. I6 — atomic two-of-two delta postcondition: both sides exact, or total revert.
        if (
            SafeTransferLib.balanceOf(order.buyToken, order.recipient) - bRecipient
                != order.buyAmount
        ) revert DeltaMismatch();
        if (
            SafeTransferLib.balanceOf(order.sellToken, takerAddr) - bTaker
                != order.sellAmount
        ) revert DeltaMismatch();
    }
}