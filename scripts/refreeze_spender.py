#!/usr/bin/env python3
"""Re-freeze the canonical vector's spender across every leg, atomically — for deploy day.

WHY A SCRIPT: the re-freeze touches the vector spender in FIVE places and the frozen digest in
FOUR, across four languages. Doing that by hand is exactly the multi-place edit that goes wrong,
and the failure mode is silent: signatures that verify nowhere. This script recomputes the truth
from client/order.py (the single source), rewrites every leg, and refuses to leave the tree in
any state the gates don't prove.

WHAT IT NEVER TOUCHES — the placebo sentinel: `PLACEHOLDER_SPENDER` in maker.py and
`const PLACEHOLDER` in index.html stay 0x1111…1111 forever. They are the value the anti-placebo
guard compares AGAINST; rewriting them to the deployed address would invert the guard
(settleable would report false for the real deployment). The coherence gate enforces this.

USAGE:
    python3 scripts/refreeze_spender.py --check 0xDEPLOYED    # report only, write nothing
    python3 scripts/refreeze_spender.py 0xDEPLOYED           # preflight -> rewrite -> gates

Write mode: refuses to run unless ALL suites are green first (never re-freeze a red tree);
after rewriting it regenerates sdk/src/generated/constants.{ts,js} and re-runs the coherence
gate plus every suite. The witness does NOT move (the spender is not an Order field) — it is
recomputed and rewritten anyway as a no-op, so the flow has no special cases.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "client"))
sys.path.insert(0, HERE)

from eth_utils import to_checksum_address  # via eth-account, already a dependency

# Single source for the leg map AND for the sentinel constant — never redefine the sentinel here:
# a second copy that drifted would make this script misclassify a placeholder re-freeze as a release.
from check_coherence import ADDR, FROZEN_SENTINEL, HEX64, SPEC, extract

# Deploy-day monotonic artifacts (see the round-trip note in main()).
CANONICAL_CHAIN = "8453"  # the frozen vector's chain (Base) — its deployment slot is what we set
DEPLOYMENTS = os.path.join(ROOT, "distribution", "deployments.json")
PACKAGE_JSON = os.path.join(ROOT, "sdk", "package.json")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")


def compute_frozen(spender: str) -> tuple[str, str]:
    from order import order_hash, signing_digest
    from test_spartan1 import CANONICAL_ORDER, CHAIN_ID, NONCE
    witness = "0x" + order_hash(CANONICAL_ORDER).hex()
    digest = "0x" + signing_digest(CANONICAL_ORDER, NONCE, spender, CHAIN_ID).hex()
    return witness, digest


def planned_rewrites(new_spender: str) -> list[tuple[str, str, str, str]]:
    """[(file, kind, old_value, new_value)] for every leg that must change (sentinel excluded)."""
    new_witness, new_digest = compute_frozen(new_spender)
    target = {"witness": new_witness, "digest": new_digest, "vector_spender": new_spender}
    found, errors = extract()
    if errors:
        raise SystemExit("cannot re-freeze, extraction errors:\n  " + "\n  ".join(errors))
    plan = []
    for kind, new_value in target.items():
        for rel, old_value in found[kind]:
            if old_value.lower() != new_value.lower():
                plan.append((rel, kind, old_value, new_value))
    return plan


def apply_rewrites(plan: list[tuple[str, str, str, str]]) -> None:
    # Group by file; replace anchored occurrences only (never blanket string replacement).
    by_file: dict[str, list[tuple[str, str, str]]] = {}
    for rel, kind, old, new in plan:
        by_file.setdefault(rel, []).append((kind, old, new))
    for rel, changes in by_file.items():
        path = os.path.join(ROOT, rel)
        text = open(path).read()
        for kind, old, new in changes:
            for spec_kind, spec_rel, pattern in SPEC:
                if spec_kind != kind or spec_rel != rel:
                    continue
                m = re.search(pattern, text)
                if not m:
                    raise SystemExit(f"{rel}: anchor for {kind} vanished mid-run")
                start, end = m.span(1)
                text = text[:start] + new + text[end:]
        open(path, "w").write(text)


# ────────────────────────────── suite runner ──────────────────────────────
def _forge() -> str:
    return shutil.which("forge") or os.path.expanduser("~/.foundry/bin/forge")


SUITES: list[tuple[str, list[str], str | None]] = [
    ("forge (offline)", [_forge(), "test", "--offline"], ROOT),
    ("client harness", [sys.executable, "client/test_spartan1.py"], ROOT),
    ("relay (incl. coherence gate)", [sys.executable, "test_relay.py"], os.path.join(ROOT, "distribution")),
    ("maker", [sys.executable, "test_maker.py"], os.path.join(ROOT, "distribution")),
    ("executor", [sys.executable, "test_executor.py"], os.path.join(ROOT, "distribution")),
    ("sdk", ["node", "--experimental-strip-types", "--test", "test/sdk.test.ts"], os.path.join(ROOT, "sdk")),
]


def run_suites(label: str) -> None:
    print(f"── suites: {label}")
    for name, cmd, cwd in SUITES:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        status = "green" if proc.returncode == 0 else "RED"
        print(f"   {name:32} {status}")
        if proc.returncode != 0:
            print(proc.stdout[-2000:] + proc.stderr[-2000:])
            raise SystemExit(f"suite '{name}' is red — refusing to continue ({label}).")


def run_coherence() -> None:
    proc = subprocess.run([sys.executable, os.path.join(HERE, "check_coherence.py")],
                          capture_output=True, text=True)
    print(proc.stdout, end="")
    if proc.returncode != 0:
        raise SystemExit("coherence gate red after re-freeze — tree left for inspection.")


# ───────────────────── deploy-day monotonic artifacts (registry + release) ─────────────────────
# deployments.json IS reversible (placeholder -> null); the SDK version + CHANGELOG are NOT — a
# release cannot be un-released. So the round-trip byte-identity proof covers every signing leg AND
# deployments.json, and EXCLUDES sdk/package.json + CHANGELOG.md (documented, not ambiguous).

def _bumped_minor() -> str:
    text = open(PACKAGE_JSON).read()
    m = re.search(r'"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)"', text)
    if not m:
        raise SystemExit("refreeze: cannot find a semver \"version\" in sdk/package.json")
    return f"{int(m.group(1))}.{int(m.group(2)) + 1}.0"


def write_deployment(address_or_none: str | None) -> None:
    """Set deployments.json chains[CANONICAL_CHAIN] by a SURGICAL value swap (not json.dump, which
    would reformat the file and break round-trip byte-identity). Preserves all other formatting."""
    text = open(DEPLOYMENTS).read()
    new_val = "null" if address_or_none is None else f'"{address_or_none}"'
    pattern = r'("' + re.escape(CANONICAL_CHAIN) + r'"\s*:\s*)(null|"0x[0-9a-fA-F]{40}")'
    new_text, n = re.subn(pattern, r"\g<1>" + new_val.replace("\\", "\\\\"), text, count=1)
    if n != 1:
        raise SystemExit(f"deployments.json: could not find chain {CANONICAL_CHAIN} value to set")
    # Sanity: the result must still parse and carry the intended value.
    if json.loads(new_text)["chains"][CANONICAL_CHAIN] != address_or_none:
        raise SystemExit("deployments.json: surgical write produced an unexpected value")
    open(DEPLOYMENTS, "w").write(new_text)


def bump_sdk_version(new_version: str) -> None:
    text = open(PACKAGE_JSON).read()
    text = re.sub(r'("version"\s*:\s*")\d+\.\d+\.\d+(")', r"\g<1>" + new_version + r"\g<2>", text, count=1)
    open(PACKAGE_JSON, "w").write(text)


def prepend_changelog(new_version: str, address: str, today: str) -> None:
    text = open(CHANGELOG).read()
    entry = (
        f"## [{new_version}] — {today}\n\n"
        f"- Chain {CANONICAL_CHAIN}: Spartan1 deployed at `{address}`; canonical vector re-frozen "
        f"against it. `distribution/deployments.json` updated; verify code exists on-chain before "
        f"trusting.\n\n"
    )
    marker = "\n## ["  # insert before the first existing release section
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("refreeze: CHANGELOG.md has no '## [' release section to prepend before")
    insert_at = idx + 1  # keep the leading newline attached to the following section
    open(CHANGELOG, "w").write(text[:insert_at] + entry + text[insert_at:])


def main() -> None:
    args = [a for a in sys.argv[1:]]
    check_only = "--check" in args
    args = [a for a in args if a != "--check"]
    if len(args) != 1 or not re.fullmatch(r"0x[0-9a-fA-F]{40}", args[0]):
        raise SystemExit("usage: refreeze_spender.py [--check] 0x<40-hex deployed Spartan1 address>")
    new_spender = to_checksum_address(args[0])  # solc + viem both demand valid checksum literals

    plan = planned_rewrites(new_spender)
    new_witness, new_digest = compute_frozen(new_spender)
    print(f"re-freeze target spender: {new_spender}")
    print(f"  witness (spender-independent): {new_witness}")
    print(f"  digest  (recomputed)         : {new_digest}")
    if not plan:
        print("nothing to change — every leg already frozen at this spender.")
        return
    print(f"  {len(plan)} leg rewrites" + (" (CHECK MODE — nothing written):" if check_only else ":"))
    for rel, kind, old, new in plan:
        print(f"    {rel:35} {kind:14} {old} -> {new}")
    print("  sentinel legs (order.py + maker.py PLACEHOLDER_SPENDER, index.html PLACEHOLDER, "
          "sdk constants): NEVER touched.")

    # Deploy-day artifacts. A real deploy (target != the placeholder sentinel) is a release: write
    # the address into the registry, bump the SDK minor, prepend a CHANGELOG entry. Re-freezing back
    # TO the placeholder (e.g. the round-trip proof) sets the registry slot null and is NOT a release.
    is_release = new_spender.lower() != FROZEN_SENTINEL.lower()
    deploy_value = new_spender if is_release else None
    if is_release:
        new_version = _bumped_minor()
        print(f"  registry: deployments.json chains[{CANONICAL_CHAIN}] -> {new_spender}")
        print(f"  release : sdk/package.json version -> {new_version}; CHANGELOG.md += entry "
              f"(monotonic — excluded from round-trip identity)")
    else:
        new_version = None
        print(f"  registry: deployments.json chains[{CANONICAL_CHAIN}] -> null (placeholder = not deployed)")
        print("  release : none (re-freeze to placeholder is not a release)")

    if check_only:
        return

    run_suites("preflight — refuse to re-freeze a red tree")
    apply_rewrites(plan)
    subprocess.run([sys.executable, os.path.join(HERE, "gen_constants.py")], check=True,
                   capture_output=True)
    write_deployment(deploy_value)
    if is_release:
        bump_sdk_version(new_version)
        # datetime is fine here — this is a real deploy-time script, not a deterministic gate.
        prepend_changelog(new_version, new_spender, datetime.date.today().isoformat())
    run_coherence()
    run_suites("post-re-freeze — every leg re-proven")
    print("RE-FREEZE COMPLETE: all legs rewritten, registry updated, coherence + all suites green.")


if __name__ == "__main__":
    main()
