# Changelog

All notable changes to the Spartan1 SDK (`sdk/`) are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are ordinary semver.

Deploy-day note: `scripts/refreeze_spender.py`, when it re-freezes the canonical vector against a
real deployed Spartan1 address, bumps the SDK minor version and PREPENDS a release entry here naming
which chain(s) gained an address. The SDK version is per-package (chain-agnostic); the deployed
address is per-chain and lives in `distribution/deployments.json`, never in the version string.

## [0.1.0] — initial

- Order building, Permit2 witness signing, and the relay client.
- Constants generated from `client/order.py` (never retyped); drift + cross-language digest gates.
- Anti-placebo `PLACEHOLDER_SPENDER` sentinel: `signOrder` refuses the placeholder / empty / zero
  spender (a signature bound to it can never settle); `signingDigest` stays pure.
- No chain has a deployed Spartan1 address yet — every entry in `distribution/deployments.json` is
  `null`.
