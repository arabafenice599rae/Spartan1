# Spartan1 — specification

The Order, the `settle()` lifecycle, the invariants, the frozen scope, and the canonical test vector.
For *what this is and why*, see the [README](README.md); for the adversary analysis see
[THREAT_MODEL.md](THREAT_MODEL.md); for the off-chain layer see [ARCHITECTURE.md](ARCHITECTURE.md).

- [The Order](#the-order)
- [`settle()` lifecycle](#settle-lifecycle)
- [Invariants](#invariants)
- [Scope](#scope)
- [Canonical test vector](#canonical-test-vector)

---

## The Order

```solidity
struct Order {
    address maker;       // permit owner; signer
    address taker;       // counterparty; address(0) = open (taker ≡ msg.sender)
    address sellToken;   // what the maker gives  (== Permit2 permitted.token)
    address buyToken;    // what the maker receives
    uint256 sellAmount;  // exact, atomic — received by the taker
    uint256 buyAmount;   // exact, atomic — received by the maker
    address recipient;   // maker-side buyToken destination (≠ maker ⇒ quoting/treasury split)
    uint256 maxTip;      // cap on third-party executor compensation, in sellToken
    uint256 fillWindow;  // timestamp splitting hot (maker-only) / fallback (anyone)
    uint256 deadline;    // absolute expiry — MUST equal permit.deadline (delegated to Permit2)
}
```

Amounts are always atomic; human/atomic conversion lives only in clients. The taker's payout address is **derived, never a free parameter** (I4). There are zero free parameters over funds.

The Permit2 witness typehash includes `address spender`, forced to Spartan1's deployed address — a maker signature is bound to *this* contract and reusable nowhere else. The byte-exact witness type string lives in **one place** (the SDK), tested in CI against a known digest (defense against the Across M-06 / OIF class of bugs).

**Permit2 ordering** (read from source — the foundation for delegating expiry and amount bounds):

```solidity
if (block.timestamp > permit.deadline) revert SignatureExpired(...);   // 1  ← expiry first
if (requestedAmount > permit.permitted.amount) revert InvalidAmount(); // 2  ← pre-nonce
_useUnorderedNonce(owner, permit.nonce);                               // 3
signature.verify(_hashTypedData(dataHash), owner);                     // 4
ERC20(token).safeTransferFrom(owner, to, requestedAmount);             // 5  ← transfer last
```

Consequences: an expired order consumes **no nonce** and moves **no funds**; an over-pull attempt does **not burn** the order; strict `>` means an order is valid *at* the deadline second (semantics propagated to every off-chain component).

---

## `settle()` lifecycle

A sequence diagram of the same flow is in the [README](README.md#how-settle-works).

```text
settle(Order order, uint256 requestedAmount, uint256 nonce, bytes makerSig)
  [nonReentrant — Solady, non-removable]
  1. static checks     fillWindow ≤ deadline · sellToken ≠ buyToken
                       sellAmount > 0 · recipient ≠ 0
  2. derive taker      taker == 0 ? msg.sender : order.taker
  3. window → amount   permitted = sellAmount + maxTip        (single computation)
                       requested = ts ≥ fillWindow ? permitted : sellAmount
                       hot window ⇒ caller must be maker
  4. snapshot          balanceOf(buyToken, recipient) · balanceOf(sellToken, takerAddr)
  5. pull maker FIRST  Permit2.permitWitnessTransferFrom(...)  ← fail-closed:
                       deadline/amount/nonce/signature all verified inside Permit2
                       BEFORE any executor funds move
     pull taker        safeTransferFrom(buyToken, msg.sender, recipient, buyAmount)
  6. payout            sellAmount → takerAddr · tip (if any) → msg.sender
  7. I6 postcondition  Δ(recipient, buyToken)  == buyAmount
                    ∧  Δ(takerAddr, sellToken) == sellAmount
                       both — or total revert (DeltaMismatch)
```

No storage. The nonce lives in Permit2; the reentrancy lock lives in a Solady slot cleared at tx end. **I6 is the source of truth on quantities**: it reverts fee-on-transfer tokens instead of silently under-delivering. A codeless "token" is caught one layer earlier — Solady's `safeTransferFrom` reverts `TransferFromFailed` because `extcodesize` is 0 — so no explicit code-length check is needed on the path (proven by gate 5, not deduced).

**Fees & gasless.** Hot path (ts < fillWindow, maker only): spread is the fee, tip = 0. Fallback (anyone): tip = maxTip flows to `msg.sender` out of the maker's margin; the taker always receives exactly `sellAmount`. Makers sign off-chain and pay zero gas. No ERC-4337, no paymaster.

**Executor risk — declared in full.** In this taker model the executor supplies `buyAmount` from its own funds. It therefore carries gas risk (covered by the tip), inventory risk, and **volatility risk between signature and inclusion — which the tip does *not* cover**. Rational executors price it or stay out: execution is permissionless as a right, professional in practice. The optimal case is maker == executor (self-fill).

---

## Invariants

| ID | Guarantee | Enforced by |
|---|---|---|
| I1′ | Order integrity + maker identity (ecrecover / ERC-1271) | Permit2 witness |
| I3′ | Single-use / replay protection | Permit2 unordered nonce |
| I2b | Cross-chain replay protection | Permit2 domain separator |
| I5-hi | `requestedAmount ≤ permitted` (pre-nonce ⇒ over-pull doesn't burn the order) | Permit2 `InvalidAmount` |
| I2-del | Expiry — `SignatureExpired` before nonce & transfer | Permit2 |
| I0 | Reentrancy lock (cross-order delta confusion) — **non-removable** | Solady `ReentrancyGuardTransient` |
| I2c | `fillWindow ≤ deadline` | Spartan1 |
| W | Window → amount + caller rule (single `permitted` computation) | Spartan1 |
| I4 | Taker address derived, never a parameter | Spartan1 |
| **I6** | **Atomic two-of-two delta postcondition** — absorbs the code-length check | Spartan1 |
| I9–I11 | `sellToken ≠ buyToken` · `sellAmount > 0` · `recipient ≠ 0` | Spartan1 |

The two Permit2 delegations (I2-del) and the absorption of the code-length check into I6 are accepted through fork tests 2 and 5 of the [test gate](ARCHITECTURE.md#test-gate) — *deduced ≠ proven* is a project rule.

**Official project invariant**

```text
invariant_expiredOrderNoStateChange:
  ∀ order, ts > order.deadline:
    settle(order, …) reverts with SignatureExpired
    ∧ nonceBitmap unchanged
    ∧ no balance changed
```

**Why the reentrancy guard stays.** The threat is not storage — it is `snapshot(A) → token callback → settle(B) → return → delta(A)`: a reentrant settle of order B moves balances measured by order A's in-flight snapshot, letting A's check pass falsely (*cross-order delta confusion*). 0x Settler and UniswapX both keep an in-transaction guard. So does Spartan1.

---

## Scope

The contract surface described above is the **complete and final scope, by decision**. The contract is deployed once, immutable, and never extended. The freeze is a feature: integrators get a settlement target that cannot drift under them.

Permanently excluded — not "later", **never**:

- ❌ `settleBatch()` — surface and failure modes for a volume profile that doesn't justify them
- ❌ `settleCross()` / internal intent matching — would roughly double the audited surface; the accept-a-visible-order flow already works through `settle()` itself
- ❌ governance, owner, admin keys, upgradeability, proxies
- ❌ protocol fees, protocol token, relay rewards (anti-Sybil invariant #1)
- ❌ P-256 / secp256r1 signing (Permit2 has no P-256 path; unusable by construction)

One optional, isolated, additive path remains specified: `settleWith3009()` for **native USDC only** (ERC-3009/7597, `receiveWithAuthorization`, front-run-protected). It never touches the main path and ships only if the use case proves itself.

---

## Canonical test vector

Canonical test vector — reproduced (not regenerated) and asserted byte-for-byte across client
(`order.py`), an independent `eth_account` oracle, and forge (`Spartan1.t.sol` test 1). The vector uses
`chainId = 8453` and a **placeholder** `spender = 0x1111…1111`; before mainnet, replace `spender` with
the deployed Spartan1 address and re-freeze both values.

```text
witness (keccak256(abi.encode(ORDER_TYPEHASH, order))):
  0xcd06eda903e77bb9f5b8b5fd77566d10bfd03e0a68d483411f90b7f6b0465c58
digest  (EIP-712 PermitWitnessTransferFrom signing hash):
  0xbbb89e334fb04f3e32eecb7e77b2a812437ad7dcdaa0101fa3334f1d91daa63b
```

Keccak comes from `eth-hash` (audited), never reimplemented.

> These two literals are **policed by `scripts/check_coherence.py`**, which asserts they are the same
> bytes here, in `test/Spartan1.t.sol`, `client/test_spartan1.py` and `sdk/test/sdk.test.ts`, and that
> they equal a fresh recomputation from `client/order.py`. Do not hand-edit them: the deploy-day
> re-freeze is `scripts/refreeze_spender.py` (see [DEPLOY.md](DEPLOY.md)). The label formatting above
> is load-bearing — it is the gate's extraction anchor.
