# Spartan1 — threat model

What an adversary can and cannot do, and the two properties security reduces to. For the mechanisms
themselves see [SPEC.md](SPEC.md); for how to report a vulnerability see [SECURITY.md](SECURITY.md).

- [Security model](#security-model)
- [Threat model](#threat-model)

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
- **Minimal** — one file, one library (Solady, commit-pinned), one trust anchor (Permit2: audited, immutable, canonical at `0x000000000022D473030F116dDEE9F6B43aC78BA3`, zero exploits since launch).
- **Permissionless in every role** — maker, taker, executor, relay. No whitelist, no vetting. Possible *because* no role has any capacity to harm third parties.

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
| Expired order side effects | impossible | `SignatureExpired` first + maker-pull-first |
| Over-pull burning an order | impossible | `InvalidAmount` pre-nonce |
| Slippage / sandwich | impossible | zero band by construction |
| Arbitrary fee extraction | impossible | tip = `requested − sellAmount`, capped by signature |
| Reentrancy / cross-order delta confusion | impossible | I0, non-removable |
| Codeless address as token (EOA / precompile / empty) | impossible | Solady `safeTransferFrom` → `TransferFromFailed` (codeless: `extcodesize` 0) — proven by gate 5 |
| Fee-on-transfer silent loss | impossible | I6 reverts |
| dApp shows one order, user signs another | mitigated | Order hash displayed pre-signature (anti-phishing) |
| EIP-7702 maker with non-1271 delegate | clean revert | `InvalidContractSignature`, never a wrong signer |
| Relay censorship / downtime | liveness-only residual | fan-out ×8 + direct on-chain `settle()` bypass |
| Executor volatility between sign & inclusion | real, declared | priced by the executor; not covered by tip |
| Maker adverse selection on stale quotes | real, declared | tight TTL defaults, maker-side tooling guardrails |

The dominant threat around Permit2 in the wild is **signature phishing**, not contract vulnerabilities. Spartan1's shape is the structural mitigation: exact amounts (no open allowance to steal), mandatory short deadlines (~45 s), recipient & spender inside the witness, and the Order hash shown to the user before signing.
