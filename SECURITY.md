# Security policy

## Reporting a vulnerability

Report privately through GitHub's **[Security Advisories](https://github.com/arabafenice599rae/Spartan1/security/advisories/new)**
("Report a vulnerability" on the Security tab). Please do not open a public issue, and do not disclose
publicly until a fix is available.

Useful in a report: the affected component (contract, client, relay/maker/executor, SDK, dApp), a
concrete path to impact, and a reproduction — a failing test or a `forge test` case is ideal.

There is no bug bounty.

## Scope

| In scope | Out of scope |
|---|---|
| `src/Spartan1.sol` | Permit2 and Solady themselves — report upstream |
| `client/`, `distribution/`, `sdk/`, `scripts/` | Anything requiring a maker to sign an order they were shown correctly (see the phishing note in the threat model) |
| The frozen digest / coherence gates | Findings that depend on modifying the repo's own pinned dependencies |

## Status

**Not audited, not deployed.** The [test gate](ARCHITECTURE.md#test-gate) is a precondition for
deployment, not a substitute for an audit. Do not put capital behind this code yet.

The adversary analysis — what is impossible, what is mitigated, and the residual risks that are
*declared rather than solved* — lives in **[THREAT_MODEL.md](THREAT_MODEL.md)**. This file is only the
reporting policy.
