# Spartan1 — architecture

The off-chain layer around the contract: relays, wallet/aggregator integration, and the blocking test
gate. The contract itself is specified in [SPEC.md](SPEC.md).

- [Distribution layer](#distribution-layer)
- [Wallet & aggregator integration](#wallet--aggregator-integration)
- [Test gate](#test-gate)

---

## Distribution layer

**Mother principle** — every off-chain component, if malicious or compromised, can only **omit, delay, or show data the receiver re-verifies and discards**. Never: alter an amount, move funds, forge a signature, force unsigned execution. Receiver-side re-verification is mandatory; that is what makes a relay an accelerator instead of a gatekeeper. Interface patterns are aligned with production RFQ systems (Jupiter webhooks, Bebop PMM, 0x/Uniswap quote formats).

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

The deployed Spartan1 address is the opposite of convenience: it is **authoritative** — a wrong value produces signatures that can never settle. So it does not live in `relays.json`; it lives in `distribution/deployments.json` (chainId → address, `null` until deployed), which a consumer must verify on-chain (`eth_getCode != 0x`, matching the audited bytecode) before trusting. Every component refuses a `null`/placeholder/zero spender as loudly as it refuses a bad quote: the SDK's `signOrder` throws, the dApp shows the non-settleable banner and disables `settle`. The coherence gate asserts every non-null registry value equals the frozen vector spender; `scripts/refreeze_spender.py` writes it on deploy day.

---

## Wallet & aggregator integration

Wallets operate on the *signing side*, so distribution-layer evolution can never break a wallet.

| Level | Who | How |
|---|---|---|
| **1 — any wallet, today** | end users | Every `eth_signTypedData_v4` wallet (MetaMask, Rabby, Coinbase…) signs a Spartan1 Order with no Spartan1 awareness. Only prerequisite: the one-time `approve(Permit2)` per token — same UX as Uniswap. The dApp fans out transparently: one signature → 8 relay posts. |
| **2 — wallet/frontend as a venue** *(primary integration path)* | integrators | A wallet or aggregator consumes `GET /quote` (0x/Uniswap format) and routes flow to Spartan1 as a trust-minimized RFQ backend. Integration is the wallet's decision, one endpoint away. |
| **3 — smart-account makers** | pro makers | ERC-1271 signing via Permit2's contract branch. Tested scope: EOA + Safe + common smart wallets. Counterfactual EIP-6492 is out of scope; an EIP-7702 delegate without `isValidSignature` reverts cleanly, never mis-verifies. |

The natural adoption path is primitive-first, not aggregator-first: an existing frontend integrates `/quote`, behind which a professional maker quotes, with an executor (often the same actor self-filling) settling the flow.

---

## Test gate

Blocking gate — **the contract does not deploy without every row green**. Tests 2, 5 and 10 are the acceptance gate for the two Permit2 delegations.

| # | Test | Acceptance for |
|---|---|---|
| 1 | Witness digest harness (client == eth-account oracle == forge, byte-for-byte) | known vector |
| 2 | Expired order → `invariant_expiredOrderNoStateChange` | deadline delegation |
| 3 | Over-pull → `InvalidAmount`, nonce intact, order still settleable | — |
| 4 | ERC-777 callback → `nonReentrant` / `DeltaMismatch` | — |
| 5 | Codeless token ×3 (EOA, precompile `0x01`, empty address) → `TransferFromFailed` | no code-length check needed on the path |
| 6 | Fee-on-transfer token → `DeltaMismatch` | — |
| 7 | `fillWindow ± 1` boundary | — |
| 8 | Fuzz on I6 delta invariants | — |
| 9 | Foundry invariant testing (`invariant_*`) on I6 | — |
| 10 | Fork against **real** Permit2 (tests 2 / 3 / 5 run on fork, not mocks) | both delegations, with 2 & 5 |

Gate 1's frozen values are the [canonical test vector](SPEC.md#canonical-test-vector). Gate 10 needs an
L2 RPC and is a **declared SKIP** in CI, never a silent pass — see [DEPLOY.md](DEPLOY.md).
