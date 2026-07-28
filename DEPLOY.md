# Deploying Spartan1

Deployment is manual and deliberate. Spartan1 is a settlement primitive that moves real funds; the
canonical signing vector is frozen against a **placeholder** spender until the contract exists, so
the one irreversible step — binding every signing leg to the deployed address — is done by a single
audited script, never by hand.

This document is the exact order of operations. Do not improvise around it: the re-freeze touches the
spender in five places and the frozen digest in four, across four languages, and a hand-edit that
misses one leg fails **silently** (signatures that verify nowhere, or — worse — a quote that looks
settleable but is signed against the wrong contract).

---

## 0. Pre-flight: prove the tree green

Every gate must be green **before** you touch anything. The re-freeze script refuses to run on a red
tree, but check first so a failure is diagnosed in isolation, not mid-deploy.

```bash
pip install -r requirements.txt            # exact pins — supply-chain lock

export PATH="$HOME/.foundry/bin:$PATH"
forge test                                 # 21 passed; 1 skipped (gate 10 needs L2_RPC)
python3 client/test_spartan1.py            # triple-digest harness, tamper on all 10 fields
python3 distribution/test_relay.py         # relay conformance + schema + cross-leg coherence
python3 distribution/test_maker.py
python3 distribution/test_executor.py
( cd sdk && npm ci && npm run typecheck && npm test )
python3 scripts/check_coherence.py         # every spender/digest/witness leg agrees with order.py
```

---

## 1. Deploy the contract

Deploy on a chain with the **canonical** Permit2 already at
`0x000000000022D473030F116dDEE9F6B43aC78BA3` (Base, Arbitrum, mainnet, …). The constructor asserts
`permit2_.code.length > 0`, so it reverts on any chain where Permit2 is absent.

```bash
forge create src/Spartan1.sol:Spartan1 \
  --rpc-url "$L2_RPC" --private-key "$DEPLOYER_KEY" \
  --constructor-args 0x000000000022D473030F116dDEE9F6B43aC78BA3
```

Record the deployed address as `$SPARTAN1`. The canonical vector is frozen for **Base (chainId
8453)**; if you deploy to a different chain, that chain's id must be re-frozen too — see the note in
step 2.

---

## 1.5 Verify the deployment on-chain — BLOCKING

Do not proceed on a `forge create` log alone. The next step binds **every signing leg** to
`$SPARTAN1`; if that address is a typo, a wrong-chain paste, or a failed deploy, the result is a
whole tree of signatures that verify nowhere — discovered only when capital is at risk.

This is enforced, not advisory: `refreeze_spender.py` **refuses to write** without it.

```bash
export RPC_URL="$L2_RPC"          # the script reads --rpc-url or $RPC_URL
python3 scripts/refreeze_spender.py --check "$SPARTAN1"
```

With an RPC present, `--check` runs the same verification it will enforce on the write, so this is a
dry run of the blocking step. It asserts three things:

| # | Check | Why |
|---|---|---|
| a | `eth_getCode($SPARTAN1)` is non-empty | something is actually deployed there |
| b | runtime bytecode == the local `out/Spartan1.sol/Spartan1.json` | it is **this** contract, not merely *a* contract |
| c | `PERMIT2()` == `0x000000000022D473030F116dDEE9F6B43aC78BA3` | it is wired to the canonical singleton your signatures are bound to |

Two normalizations make (b) correct rather than merely strict — without them a **legitimate** deploy
would be rejected:
- **solc's CBOR metadata trailer** is stripped. It embeds an ipfs hash of the metadata, which depends
  on absolute source paths and compiler settings, so it legitimately differs between the deployer's
  machine and yours.
- **The immutable windows are masked.** `PERMIT2` is `immutable`, so solc splices the constructor
  argument straight into the runtime code while the local artifact keeps zeroed placeholders.

Because (b) masks the immutables it is deliberately **blind** to which Permit2 was wired in — which is
exactly why (c) is a separate assertion. A Spartan1 deployed against the wrong Permit2 passes (a) and
(b) and is caught only by (c).

> **This is not step 4.** Step 1.5 is cheap and local: *is the right code at that address?* Step 4
> (gate 10) forks the chain and exercises real settlement against real Permit2. Both are required;
> neither replaces the other.

**Air-gapped signer?** `--i-verified-manually` is the only bypass. It is loud on stdout and is
recorded permanently in the `CHANGELOG.md` release entry, which will state that the operator — not
the script — asserted (a), (b) and (c). Use it only if you genuinely performed those checks.

---

## 2. Re-freeze the vector spender — the one irreversible edit

The frozen digest is a pure function of `(order, nonce, spender, chainId)`. Until now `spender` has
been the placeholder `0x1111…1111`. Bind every leg to the real `$SPARTAN1` with the script — **never
by hand**. It is round-trip proven: re-freezing to a dummy address and back leaves a byte-identical
tree.

**First inspect the plan (writes nothing):**

```bash
python3 scripts/refreeze_spender.py --check "$SPARTAN1"
```

It prints the recomputed witness/digest, every leg it would rewrite, and the deploy-day artifacts it
would write (the `deployments.json` slot, the SDK version bump, the `CHANGELOG.md` entry). Read it.
Confirm the leg count, that only vector legs appear, and that the sentinel legs are listed as never
touched.

**Then write:**

```bash
RPC_URL="$L2_RPC" python3 scripts/refreeze_spender.py "$SPARTAN1"
```

In write mode the script:
1. **Verifies the deployment on-chain** (step 1.5's three checks) and **refuses to write** if no RPC
   was supplied — `--i-verified-manually` is the only bypass, and it is recorded in `CHANGELOG.md`.
   Re-freezing back *to* the placeholder sentinel skips this: nothing is deployed at `0x1111…1111`
   by definition, which is what keeps the round-trip proof runnable offline.
2. **Refuses a red tree** — re-runs all suites first and aborts if any is red.
3. Rewrites the **five vector-spender legs** and the **four frozen-digest legs** (the witness is
   spender-independent; it is recomputed and rewritten as a no-op so the flow has no special cases).
4. Regenerates `sdk/src/generated/constants.{ts,js}` from `client/order.py`.
5. Writes `distribution/deployments.json` `chains[8453] = "$SPARTAN1"` (the authoritative registry;
   the coherence gate then asserts it equals the frozen vector spender).
6. Bumps the SDK minor version in `sdk/package.json` and PREPENDS a `CHANGELOG.md` entry naming the
   chain that gained an address **and how the deployment was verified** (by the script, or by the
   operator via `--i-verified-manually`). These two are intentionally **monotonic** — a release is not
   reversible, so they are the one documented exclusion from the re-freeze round-trip identity (every
   signing leg and `deployments.json` ARE round-trip byte-identical; the version and changelog are not).
7. Re-runs the coherence gate + every suite, and aborts (leaving the tree for inspection) on any red.

The sentinel legs — `PLACEHOLDER_SPENDER` in `client/order.py` and `maker.py`, `PLACEHOLDER` in
`index.html`, and the generated `PLACEHOLDER_SPENDER` in the SDK constants — are NEVER rewritten (the
coherence gate pins all five to `0x1111…1111` forever; rewriting them would invert the anti-placebo
guard).

> **chainId note.** The vector is frozen for Base (8453). Deploying to a different chain means the
> digest changes with `chainId` too; re-freezing the spender alone is not enough. Re-freeze against
> the target chain and re-run gate 10 there (step 4). Base = the frozen chain, so a Base deployment
> needs only the spender re-freeze.

> **TODO — multi-chain is not a flag.** A `--chain-id` option would be misleading today: the frozen
> vector, `test/Spartan1.t.sol`, the SDK test and `check_coherence.py` all assume a **single** digest.
> Supporting a second chain means moving the coherence gate from "one value asserted across N legs" to
> "N values indexed by chain", and every leg with it. That is a separate round, to be opened when a
> second deployment (Arbitrum) is actually concrete — not a flag bolted onto this script.

---

## ⚠ NEVER touch the two sentinel legs

Two occurrences of `0x1111…1111` are **not** vector legs and must stay `0x1111…1111` **forever**:

| File | Symbol | Role |
|---|---|---|
| `distribution/maker.py` | `PLACEHOLDER_SPENDER` | value the maker's anti-placebo guard compares **against** |
| `distribution/index.html` | `const PLACEHOLDER` | value the dApp's anti-placebo banner compares **against** |

These are the sentinel the anti-placebo guard checks *against* (`settleable = spartan1 != PLACEHOLDER`).
Rewriting them to the deployed address would **invert the guard** — the real deployment would report
`settleable = false`, silently refusing to ever settle. The re-freeze script excludes them by design,
and `scripts/check_coherence.py` enforces that they stay pinned to the sentinel. Do **not** hand-edit
them, and do not "fix" a coherence failure by aligning them with the vector legs.

---

## 3. Commit the re-freeze

```bash
git add -A
git commit -m "chore: re-freeze canonical vector spender -> $SPARTAN1"
```

The diff should be exactly the nine vector/digest legs plus the regenerated SDK constants — and
nothing in the two sentinel legs.

---

## 4. Run gate 10 against real Permit2 — confirm the re-frozen digest on-chain

Gate 10 forks the target chain, runs gates 2/3/5 + a full settlement against the **real** deployed
Permit2, and rebuilds the domain separator for the fork's chainId. On Base (8453 = the frozen chain)
it also confirms the **re-frozen** digest end-to-end.

```bash
L2_RPC=https://mainnet.base.org forge test --match-test gate10 -vvv
```

This is the gate CI cannot run (no RPC secret — see below); it is a **hard precondition** for putting
capital behind the deployment, not an optional extra.

---

## 5. Configure the distribution layer

- `distribution/relays.json` — the relay set makers/executors fan out to.
- Maker/executor: set the real `$SPARTAN1` as the configured spender (they refuse to emit settleable
  quotes against the placeholder).
- `distribution/index.html` — set the Spartan1 address input to `$SPARTAN1`; the anti-placebo banner
  disappears once it is no longer the sentinel.

---

## 6. Audit before capital

100% green tests prove **coherence and the off-chain loop**, not economic safety. The off-chain e2e
proves the relay/maker/executor loop; **settlement correctness is Foundry's job**, and even a green
gate 10 is not a substitute for a security audit. Do not route real liquidity through an un-audited
deployment.
