<p align="center">
  <img src="assets/logo.png" alt="Spartan1" width="260"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-V1_(final)-A32E2E" alt="V1 final"/>
  <img src="https://img.shields.io/badge/status-spec--frozen_·_pre--audit-orange" alt="status"/>
  <img src="https://img.shields.io/badge/solidity-%5E0.8.24-363636?logo=solidity" alt="solidity"/>
  <img src="https://img.shields.io/badge/tested_with-Foundry-1c1c1c" alt="foundry"/>
  <img src="https://img.shields.io/badge/dependency-Solady_(pinned)-B8863B" alt="solady"/>
  <img src="https://img.shields.io/badge/auth-Permit2_canonical-FF007A" alt="permit2"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license"/>
</p>

<h3 align="center">Exact-settlement RFQ primitive on Permit2.<br/>One contract. One function. Zero trust added.</h3>

---

**Spartan1** is a thin enforcement adapter over the [Permit2](https://github.com/Uniswap/permit2) singleton for firm-quote token swaps. A maker signs an EIP-712 `Order` with exact amounts on both legs; the signature is a Permit2 *witness* that cryptographically binds the entire Order. Permissionless executors settle it on-chain. The contract holds no funds, validates no prices, and has no owner, proxy, oracle, governance, storage, or configurable fees.

> **Honest positioning.** Spartan1 offers *tighter guarantees on specific properties* — atomic exactness, per-operation blast radius, minimal surface — not overall superiority over 0x Settler, UniswapX, or CoW. Those systems optimize liquidity, routing, and ecosystem; Spartan1 deliberately does not. It is a more minimal settlement layer, not a better everything.

---

## Table of contents

- [Project status](#project-status)
- [Security model](#security-model)
- [The Order](#the-order)
- [`settle()` lifecycle](#settle-lifecycle)
- [Invariants](#invariants)
- [Threat model](#threat-model)
- [Distribution layer](#distribution-layer)
- [Wallet & aggregator integration](#wallet--aggregator-integration)
- [Versioning: V1 is final](#versioning-v1-is-final)
- [Test gate](#test-gate)
- [Repository layout](#repository-layout)
- [Build & test](#build--test)
- [Dependencies](#dependencies)
- [Security](#security)
- [License & disclaimer](#license--disclaimer)

---

## Project status

⚠️ **Specification frozen. Code not yet written. Not audited. Not deployed.**

| Milestone | State |
|---|---|
| Part I — contract & signing core spec | ✅ Frozen, source-verified against Permit2 & Solady |
| Part II — distribution layer spec | ✅ Design-frozen (validated against Jupiter / Bebop / 0x patterns) |
| `Spartan1.sol` + test suite | 🔜 Next step |
| Fork-test gate (tests 2 / 5 / 10) | ⏳ Blocks two pending code removals |
| External audit | ⏳ Blocks any mainnet capital |
| First real fill | ⏳ Blocks Part II "proven" status |

Two code removals (explicit deadline check, token code-length check) are **source-verified but pending**: they were confirmed by reading the live Permit2 and Solady sources, and become final only when fork tests pass on the real Permit2 contract. *Deduced ≠ proven* is a project rule.

---

## Security model

Security reduces to **two independent properties**:

| Property | Enforced by | Meaning |
|---|---|---|
| **Authorization** | Permit2 | The witness cryptographically binds the *entire* Order — who may spend, how much, until when. |
| **Settlement** | Spartan1 | Only the intended execution is accepted, and the contract *proves on-chain* (invariant **I6**) that both parties received exactly the signed amounts — or the whole transaction reverts. |

Permit2 guarantees *who/how much*; Spartan1 guarantees *how*. Protection from a bad quote is the signer's responsibility; protection from divergent execution is the contract's.

**Constitutive properties**

- **Non-custodial** — no balances between transactions, no TVL; tokens are in transit only inside a single tx.
- **Zero user allowance to Spartan1** — makers sign via Permit2; blast radius is one operation.
- **Price-agnostic** — no oracle, no fair-value logic, no fees.
- **Token-agnostic** — any ERC-20 via Permit2. Fee-on-transfer / rebasing tokens are *non-settleable by choice*: I6 reverts them, never a silent loss.
- **Chain-agnostic** — any EVM with canonical Permit2; Solady's reentrancy guard falls back to SSTORE off-mainnet automatically (no EIP-1153 required).
- **Minimal** — one file, one library (Solady, commit-pinned), one trust anchor (Permit2: audited, immutable, canonical at `0x000000000022D473030F116dDEE9F6B43aC78BA3`, zero exploits since its 2022 launch).
- **Permissionless in every role** — maker, taker, executor, relay. No whitelist, no vetting. Possible *because* no role has any capacity to harm third parties.

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

**Verified Permit2 ordering** (read from live source — the foundation for both pending removals):

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

No storage. The nonce lives in Permit2; the reentrancy lock lives in a Solady slot cleared at tx end. **I6 is the source of truth on quantities**: it absorbs the code-existence check (a codeless "token" yields Δ = 0 → revert) and reverts fee-on-transfer tokens instead of silently under-delivering.

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
| I2-del | Expiry (`SignatureExpired` before nonce & transfer) — **pending fork test 2** | Permit2 |
| I0 | Reentrancy lock (cross-order delta confusion) — **non-removable** | Solady `ReentrancyGuardTransient` |
| I2c | `fillWindow ≤ deadline` | Spartan1 |
| W | Window → amount + caller rule (single `permitted` computation) | Spartan1 |
| I4 | Taker address derived, never a parameter | Spartan1 |
| **I6** | **Atomic two-of-two delta postcondition** — absorbs code-length check (**pending fork test 5**) | Spartan1 |
| I9–I11 | `sellToken ≠ buyToken` · `sellAmount > 0` · `recipient ≠ 0` | Spartan1 |

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

## Threat model

| Threat | Outcome | Mechanism |
|---|---|---|
| Theft by relay / executor | impossible | exact signed amounts, W + I6 |
| Maker pulled without receiving `buyAmount` | impossible | I6 atomic two-of-two |
| Pulling third-party taker funds | impossible | buy-side source ≡ `msg.sender` — confused-deputy class removed by construction |
| Forged / altered Order · signature reuse | impossible | full Order bound in the witness |
| Fund redirection (Permit2 #250 class) | impossible | `recipient` in witness · `spender` = Spartan1 · taker derived |
| Replay / double-fill / cross-chain replay | impossible | Permit2 nonce + domain separator |
| Expired order side effects | impossible *(pending fork test 2)* | `SignatureExpired` first + maker-pull-first |
| Over-pull burning an order | impossible | `InvalidAmount` pre-nonce |
| Slippage / sandwich | impossible | zero band by construction |
| Arbitrary fee extraction | impossible | tip = `requested − sellAmount`, capped by signature |
| Reentrancy / cross-order delta confusion | impossible | I0, non-removable |
| Codeless address as token (EOA / precompile / empty) | impossible *(pending fork test 5)* | Solady `balanceOf` → 0 → `DeltaMismatch` |
| Fee-on-transfer silent loss | impossible | I6 reverts |
| dApp shows one order, user signs another | mitigated | Order hash displayed pre-signature (anti-phishing) |
| EIP-7702 maker with non-1271 delegate | clean revert | `InvalidContractSignature`, never a wrong signer |
| Relay censorship / downtime | liveness-only residual | fan-out ×8 + direct on-chain `settle()` bypass |
| Executor volatility between sign & inclusion | real, declared | priced by the executor; not covered by tip |
| Maker adverse selection on stale quotes | real, declared | tight TTL defaults, maker-side tooling guardrails |

The 2026 threat landscape around Permit2 is **signature phishing**, not contract vulnerabilities. Spartan1's shape is the structural mitigation: exact amounts (no open allowance to steal), mandatory short deadlines (~45 s), recipient & spender inside the witness, and the Order hash shown to the user before signing.

---

## Distribution layer

*Design-frozen; validated against production RFQ systems (Jupiter webhooks, Bebop PMM, 0x/Uniswap quote formats). Gate = adoption.*

**Mother principle** — every off-chain component, if malicious or compromised, can only **omit, delay, or show data the receiver re-verifies and discards**. Never: alter an amount, move funds, forge a signature, force unsigned execution. Receiver-side re-verification is mandatory; that is what makes a relay an accelerator instead of a gatekeeper.

**Interface (single-source `openapi.yaml`, code-gen for SDK / relay / executor / dApp):**

| Endpoint | Role |
|---|---|
| `POST /order` · `GET /orders` | order distribution (order-driven) |
| `POST /rfq/quote` · `GET /rfq/tokens` | request-driven quoting — relay fans out to all maker webhooks in parallel, returns the best signed Order; `404` = "not quoting", no penalty |
| `GET /quote` | 0x / Uniswap-compatible adapter for aggregator routing (EXACT_INPUT & EXACT_OUTPUT — Spartan1 is exact on both legs by construction) |
| `GET /health` | `{ chainId, permit2, spartan1, ordersOpen, uptime }` + freshness challenge |

**Expiry defaults** (calibrated on Jupiter's 55 s flow): `QUOTE_TTL = 45 s` · `HOT_WINDOW = 30 s` · re-quote every 5 s · maker sign budget 2 s. L1 doubles the TTL; per-chain floors documented. Loosening them is explicit and warned — longer TTL = more adverse selection.

**Relay validity predicate — closed list P1–P7**: signature valid · not expired (`≤ deadline`, matching Permit2's `>`) · `fillWindow ≤ deadline` · well-formed · local orderHash dedup (idempotent) · maker balance ≥ permitted · Permit2 allowance present. **P6/P7 are anti-spam filters, never guarantees** (TOCTOU) — the only fund guarantee is on-chain at settlement. ≈ 2 RPC reads per order, no simulation.

**Relay democracy & anti-Sybil (three rules that make Sybil *useless*, not impossible):**

1. **Relays are never paid.** No fee, reward, or token to relays — ever, by permanent invariant. No farming target ⇒ the primary Sybil motive does not exist. (Secondary motives closed too: zero-band orders carry no MEV; execution is already permissionless; there is nothing to custody.)
2. **Random redundancy.** Clients fan out each order to **8 relays chosen uniformly at random** among healthy ones (all of them if fewer than 8 exist). Censoring one order costs `f⁸`: an attacker needs **f ≈ 0.92** — 12× all honest relays combined — to censor half the flow, for zero revenue, and it's still bypassable.
3. **Guaranteed rendezvous.** Executors poll **all** live relays (their set ⊇ the 8 posted), so identity inflation can't hide an order; a stateless freshness challenge on `/health` (echo a client nonce + recent blockhash) discards phantom listings.

Per-identity costs (bonds, PoW, uptime history) are **deliberately excluded**: with the three rules above, Sybil confers no advantage, so making identities expensive would solve a problem that no longer pays to attempt.

Uniform-random selection is also what makes relay participation *structurally* democratic: every relay — new or old, big or small — has equal probability per order. `relays.json` lives in a forkable Git repo (convenience, not authority; inclusion verifies only that a relay is *real*, never who runs it), and a client-local list always takes precedence. **Total censorship fallback:** whoever holds a signed Order can call `settle()` directly on-chain, bypassing every relay.

---

## Wallet & aggregator integration

Wallets operate on the *signing side* (Part I, frozen), so distribution-layer evolution can never break a wallet.

| Level | Who | How |
|---|---|---|
| **1 — any wallet, today** | end users | Every `eth_signTypedData_v4` wallet (MetaMask, Rabby, Coinbase…) signs a Spartan1 Order with no Spartan1 awareness. Only prerequisite: the one-time `approve(Permit2)` per token — same UX as Uniswap. The dApp fans out transparently: one signature → 8 relay posts. |
| **2 — wallet/frontend as a venue** *(primary go-to-market)* | integrators | A wallet or aggregator consumes `GET /quote` (0x/Uniswap format) and routes flow to Spartan1 as a trust-minimized RFQ backend. Integration is the wallet's decision, one endpoint away. |
| **3 — smart-account makers** | pro makers | ERC-1271 signing via Permit2's contract branch. **V1 tested scope: EOA + Safe + common smart wallets.** Counterfactual EIP-6492 is out of scope; an EIP-7702 delegate without `isValidSignature` reverts cleanly, never mis-verifies. |

**Go-to-market is primitive-first, not aggregator-first**: the first "customer" is an existing frontend integrating `/quote`, behind which a professional maker quotes. The realistic bootstrap sequence: one professional maker → one reliable executor (often the same actor self-filling) → one frontend integration → proven fill rate. The project's real risk is market bootstrap, not code.

---

## Versioning: V1 is final

**There is no V2.** Spartan1 V1 is the complete and final scope of the contract, by decision, not by omission. The contract is designed to be deployed once, immutable, and never extended.

Permanently excluded — not "later", **never**:

- ❌ `settleBatch()` — surface and failure modes for a volume profile that doesn't justify them
- ❌ `settleCross()` / internal intent matching — would roughly double the audited surface; the accept-a-visible-order flow already works through `settle()` itself
- ❌ governance, owner, admin keys, upgradeability, proxies
- ❌ protocol fees, protocol token, relay rewards (anti-Sybil invariant #1)
- ❌ P-256 / secp256r1 signing (Permit2 has no P-256 path; unusable by construction)

One optional, isolated, additive path remains specified but unimplemented: `settleWith3009()` for **native USDC only** (ERC-3009/7597, `receiveWithAuthorization`, front-run-protected). It never touches the main path and ships only if the use case proves itself.

The freeze is a feature: integrators get a settlement target that cannot drift under them.

---

## Test gate

Pre-audit blocking gate — *not "tests we'll write", but "no deploy without green"*:

| # | Test | Unlocks |
|---|---|---|
| 1 | Witness digest harness (client == eth-account oracle == forge, byte-for-byte) | ✅ known vector |
| 2 | Expired order → `invariant_expiredOrderNoStateChange` | removal of local deadline check |
| 3 | Over-pull → `InvalidAmount`, nonce intact, order still settleable | — |
| 4 | ERC-777 callback → `nonReentrant` / `DeltaMismatch` | — |
| 5 | Codeless token ×3 (EOA, precompile `0x01`, empty address) → `DeltaMismatch` | removal of code-length check |
| 6 | Fee-on-transfer token → `DeltaMismatch` | — |
| 7 | `fillWindow ± 1` boundary | — |
| 8 | Fuzz on I6 delta invariants | — |
| 9 | Foundry invariant testing (`invariant_*`) on I6 | — |
| 10 | Fork against **real** Permit2 (tests 2 / 3 / 5 run on fork, not mocks) | both removals, together with 2 & 5 |

Canonical test vector (frozen Order digest, spender = deployed address re-verified pre-mainnet):

```text
5ff361376d4ddc05816a8b8bc3e711e0faba4dd7cc988d2f465cb150b246cb79
```

Keccak comes from `eth-hash` (audited), never reimplemented.

---

## Repository layout

```text
spartan1/
├── src/
│   └── Spartan1.sol          # the contract (~80–100 lines)
├── test/
│   └── Spartan1.t.sol        # Foundry: gate tests (2/3/5 first), fuzz, invariants, fork
├── client/
│   ├── order.py              # Order builder + witness + Permit2 signing (eth-account, eth-abi, eth-hash, web3.py)
│   └── test_spartan1.py      # triple-digest harness + conformance
├── distribution/             # Part II — built only after the fork-test gate is green
│   ├── openapi.yaml          # single-source interface schema (layer SPOF)
│   ├── relay.py              # stateless untrusted relay (P1–P7, RFQ fan-out, /health)
│   ├── maker.py              # reference maker webhook (TTL/spread/staleness guardrails ON by default)
│   ├── executor.py           # poll-all-relays, orderHash dedup, bounded allowance, private RPC
│   ├── index.html            # dApp: sign once, transparent 8-relay fan-out, Order-hash display
│   └── relays.json           # public forkable relay list (convenience, not authority)
├── sdk/                      # TypeScript SDK — the witness type string lives here, CI-tested vs known digest
├── assets/
│   └── logo.svg
├── foundry.toml              # Solady pinned to commit; Permit2 as immutable constructor arg
└── README.md
```

Build order is fixed: **core first** (`Spartan1.sol` + tests 2/3/5 written before the contract), fork gate green, *then* the distribution layer against the proven Order shape.

---

## Build & test

*(Once code lands — commands are part of the frozen plan.)*

```bash
# contract
forge build
forge test                    # unit + fuzz + invariant
forge test --fork-url $L2_RPC # gate tests 2/3/5/10 against real Permit2

# signing core
pip install eth-account eth-abi "eth-hash[pycryptodome]" web3
python client/test_spartan1.py   # triple-digest harness must print the canonical digest
```

CI enforces: `forge test` green · digest match (client == oracle == solidity) · schema conformance for every distribution component. Deployment is manual (`forge create`), never triggered by push. First chains: Base / Arbitrum (L2s with canonical Permit2).

---

## Dependencies

| Dependency | Role | Policy |
|---|---|---|
| [Permit2](https://github.com/Uniswap/permit2) | authorization: witness, nonce, deadline, chainId, pull | canonical `0x000000000022D473030F116dDEE9F6B43aC78BA3`, immutable constructor arg, `code.length > 0` asserted at deploy |
| [Solady](https://github.com/Vectorized/solady) | `ReentrancyGuardTransient` (SSTORE fallback off-mainnet by default) + `SafeTransferLib` (+ `balanceOf`) | **pinned to a commit**, re-read at pin time — sources are verified live, never from memory |

No other dependency. Ever.

---

## Security

- **Not audited yet.** Do not deploy with real capital before an external audit; the gate above is a *precondition* to the audit, not a substitute.
- The single most critical technical surface is the **witness type string / typehash** (Across M-06 / OIF failure class). Defense: single source in the SDK, known-digest CI check, negative tamper test.
- Found something? Open a private security advisory on this repository. No bug bounty is active pre-deployment.

---

## License & disclaimer

MIT — see [`LICENSE`](LICENSE).

This software is provided *as is*, without warranty of any kind. Nothing here is financial advice. Firm-quote market making carries adverse-selection risk; executing carries inventory and volatility risk. You are responsible for your own keys, allowances, and capital.

---

<p align="center"><sub><b>Spartan1</b> — exact settlement, nothing else. Ⲗ</sub></p>
