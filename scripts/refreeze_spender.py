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

ON-CHAIN VERIFICATION IS MANDATORY BEFORE ANY WRITE: the script refuses to bind every signing
leg to an address it has not confirmed. It checks (a) code exists there, (b) the runtime bytecode
equals the local artifact — normalizing away solc's CBOR metadata trailer AND the immutable
windows, both of which legitimately differ on a real deploy — and (c) PERMIT2() reads back as the
canonical singleton. Because (b) masks the immutables it is deliberately blind to which Permit2
was wired in, which is exactly why (c) is a separate assertion and not redundant.

USAGE:
    python3 scripts/refreeze_spender.py --check 0xDEPLOYED            # report only, offline
    RPC_URL=https://… python3 scripts/refreeze_spender.py 0xDEPLOYED  # verify -> preflight -> write
    python3 scripts/refreeze_spender.py --rpc-url https://… 0xDEPLOYED
    python3 scripts/refreeze_spender.py --i-verified-manually 0xDEPLOYED   # air-gapped only

No silent bypass: without an RPC the write is REFUSED. `--i-verified-manually` is the only
escape hatch, it is loud, and it is recorded in the CHANGELOG entry. Re-freezing back TO the
placeholder sentinel skips verification — nothing is deployed at 0x1111…1111 by definition.

Write mode: refuses to run unless ALL suites are green first (never re-freeze a red tree);
after rewriting it regenerates sdk/src/generated/constants.{ts,js} and re-runs the coherence
gate plus every suite. The witness does NOT move (the spender is not an Order field) — it is
recomputed and rewritten anyway as a no-op, so the flow has no special cases.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "client"))
sys.path.insert(0, os.path.join(ROOT, "distribution"))
sys.path.insert(0, HERE)

from eth_utils import to_checksum_address  # via eth-account, already a dependency

# Single source for the leg map AND for the sentinel constant — never redefine the sentinel here:
# a second copy that drifted would make this script misclassify a placeholder re-freeze as a release.
from check_coherence import ADDR, FROZEN_SENTINEL, HEX64, SPEC, extract
from order import PERMIT2 as CANONICAL_PERMIT2  # single source; never retype the address
from relay import Rpc  # stdlib urllib JSON-RPC (code_at / eth_call) — no new dependency

# Deploy-day monotonic artifacts (see the round-trip note in main()).
CANONICAL_CHAIN = "8453"  # the frozen vector's chain (Base) — its deployment slot is what we set
DEPLOYMENTS = os.path.join(ROOT, "distribution", "deployments.json")
PACKAGE_JSON = os.path.join(ROOT, "sdk", "package.json")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
ARTIFACT = os.path.join(ROOT, "out", "Spartan1.sol", "Spartan1.json")


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


HEAD_LINES = 40
TAIL_LINES = 40


def _dump_failure(name: str, stdout: str, stderr: str) -> str:
    """Persist the FULL combined output and echo both ends of it.

    A tail-only excerpt loses the single most common failure: a compile error, which is printed
    FIRST and then buried under a wall of downstream noise. So write everything to a temp file,
    print its path, and show the head as well as the tail with the elision made explicit.
    """
    combined = ""
    if stdout:
        combined += "───── stdout ─────\n" + stdout
    if stderr:
        combined += ("\n" if combined else "") + "───── stderr ─────\n" + stderr
    fd, path = tempfile.mkstemp(prefix=f"refreeze-{name.split()[0]}-", suffix=".log")
    with os.fdopen(fd, "w") as fh:
        fh.write(combined)

    lines = combined.splitlines()
    print(f"   full output ({len(lines)} lines): {path}")
    if len(lines) <= HEAD_LINES + TAIL_LINES:
        for ln in lines:
            print("   | " + ln)
    else:
        for ln in lines[:HEAD_LINES]:
            print("   | " + ln)
        print(f"   | … {len(lines) - HEAD_LINES - TAIL_LINES} lines elided "
              f"(full log at {path}) …")
        for ln in lines[-TAIL_LINES:]:
            print("   | " + ln)
    return path


def run_suites(label: str) -> None:
    print(f"── suites: {label}")
    for name, cmd, cwd in SUITES:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        status = "green" if proc.returncode == 0 else "RED"
        print(f"   {name:32} {status}")
        if proc.returncode != 0:
            _dump_failure(name, proc.stdout, proc.stderr)
            raise SystemExit(f"suite '{name}' is red — refusing to continue ({label}).")


def run_coherence() -> None:
    proc = subprocess.run([sys.executable, os.path.join(HERE, "check_coherence.py")],
                          capture_output=True, text=True)
    print(proc.stdout, end="")
    if proc.returncode != 0:
        # stderr was previously dropped entirely here — same defect class as the tail-only excerpt.
        _dump_failure("coherence", proc.stdout, proc.stderr)
        raise SystemExit("coherence gate red after re-freeze — tree left for inspection.")


# ──────────────────── on-chain verification (mandatory before any write) ────────────────────
# README already promises this invariant for deployments.json ("verify code exists on-chain,
# matching the audited bytecode, before trusting"); nothing enforced it. Re-freezing binds every
# signing leg to an address — a typo, a wrong-chain paste, or a failed deploy would otherwise
# produce a whole tree of signatures that verify nowhere, discovered only with capital at risk.


def load_artifact() -> dict:
    """The locally compiled Spartan1. `out/` is gitignored, so build it if it isn't there."""
    if not os.path.exists(ARTIFACT):
        print("   artifact missing — running `forge build` …")
        subprocess.run([_forge(), "build"], cwd=ROOT, capture_output=True, text=True)
    if not os.path.exists(ARTIFACT):
        raise SystemExit(
            f"on-chain verification: no compiled artifact at {ARTIFACT}. Run `forge build` first "
            "(out/ is gitignored, so a fresh clone has none).")
    with open(ARTIFACT) as fh:
        return json.load(fh)


def _strip_metadata(code: bytes) -> bytes:
    """Drop solc's trailing CBOR blob (its last two bytes are the blob's big-endian length).

    The blob embeds an ipfs hash of the metadata, which depends on absolute source paths and
    compiler settings — it legitimately differs between the deployer's machine and ours, so
    comparing it would reject a perfectly good deployment.
    """
    if len(code) < 2:
        return code
    n = int.from_bytes(code[-2:], "big")
    if n + 2 > len(code):
        return code  # not a well-formed trailer; compare the whole thing rather than mangle it
    return code[: -(n + 2)]


def _mask_immutables(code: bytes, artifact: dict) -> bytes:
    """Zero the immutable windows so the compare ignores values spliced in at deploy time.

    Spartan1 stores PERMIT2 as `immutable`, so solc writes the constructor argument DIRECTLY into
    the runtime code, while the artifact keeps zeroed placeholders. Without this, a byte compare
    rejects EVERY legitimate deploy — the same trap as the metadata trailer, from a second source.
    The masking makes the compare blind to which Permit2 was wired in, which is precisely why the
    PERMIT2() check below is a separate, independently load-bearing assertion.
    """
    refs = artifact.get("deployedBytecode", {}).get("immutableReferences") or {}
    out = bytearray(code)
    for windows in refs.values():
        for w in windows:
            start, length = w["start"], w["length"]
            if start + length <= len(out):
                out[start:start + length] = bytes(length)
    return bytes(out)


def _normalize(code: bytes, artifact: dict) -> bytes:
    return _strip_metadata(_mask_immutables(code, artifact))


def verify_deployment(address: str, rpc: Rpc, artifact: dict) -> None:
    """Refuse unless the address really holds THIS contract, wired to the canonical Permit2.

    (a) code exists  (b) runtime bytecode == local artifact (metadata + immutables normalized)
    (c) PERMIT2() reads back as the canonical singleton.
    Raises SystemExit on any failure — there is no partial pass.
    """
    print(f"── on-chain verification of {address}")

    # (a) something is deployed there at all.
    raw = rpc.code_at(address)
    onchain = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    if not onchain:
        raise SystemExit(
            f"on-chain verification FAILED: no code at {address} (eth_getCode returned empty). "
            "Nothing is deployed there — refusing to bind every signing leg to a dead address.")
    print(f"   (a) code present            : {len(onchain)} bytes")

    # (b) it is OUR contract, not merely some contract.
    local = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
    got, want = _normalize(onchain, artifact), _normalize(local, artifact)
    if got != want:
        first = next((i for i in range(min(len(got), len(want))) if got[i] != want[i]),
                     min(len(got), len(want)))
        raise SystemExit(
            "on-chain verification FAILED: bytecode at "
            f"{address} does not match the local artifact.\n"
            f"  normalized on-chain: {len(got)} bytes\n"
            f"  normalized local   : {len(want)} bytes\n"
            f"  first difference at byte {first}\n"
            "  (metadata trailer and immutable windows were already excluded, so this is a real "
            "difference — wrong address, wrong chain, or a different/older contract.)")
    print(f"   (b) bytecode matches local  : {len(want)} bytes normalized "
          "(CBOR metadata + immutables excluded)")

    # (c) the immutable the compare is deliberately blind to. Selector from the artifact, not typed.
    selector = artifact.get("methodIdentifiers", {}).get("PERMIT2()")
    if not selector:
        raise SystemExit("on-chain verification: artifact has no PERMIT2() in methodIdentifiers")
    ret = rpc.eth_call(address, "0x" + selector)
    word = ret[2:] if ret.startswith("0x") else ret
    if len(word) < 40:
        raise SystemExit(f"on-chain verification FAILED: PERMIT2() returned {ret!r}")
    got_permit2 = to_checksum_address("0x" + word[-40:])
    if got_permit2.lower() != CANONICAL_PERMIT2.lower():
        raise SystemExit(
            f"on-chain verification FAILED: the contract at {address} is wired to Permit2 "
            f"{got_permit2}, not the canonical {CANONICAL_PERMIT2}. Signatures are bound to the "
            "canonical singleton; this deployment could never settle them.")
    print(f"   (c) PERMIT2() == canonical  : {got_permit2}")
    print("   on-chain verification PASSED")


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


def prepend_changelog(new_version: str, address: str, today: str, manual: bool = False) -> None:
    verification = (
        "on-chain verification BYPASSED via `--i-verified-manually` (air-gapped deploy): code "
        "presence, bytecode match and `PERMIT2()` were asserted by the operator, NOT by the script"
        if manual else
        "on-chain verified by the script: code present, runtime bytecode matches the local artifact "
        "(metadata + immutables excluded), `PERMIT2()` == the canonical singleton"
    )
    text = open(CHANGELOG).read()
    entry = (
        f"## [{new_version}] — {today}\n\n"
        f"- Chain {CANONICAL_CHAIN}: Spartan1 deployed at `{address}`; canonical vector re-frozen "
        f"against it. `distribution/deployments.json` updated.\n"
        f"- Verification: {verification}.\n\n"
    )
    marker = "\n## ["  # insert before the first existing release section
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("refreeze: CHANGELOG.md has no '## [' release section to prepend before")
    insert_at = idx + 1  # keep the leading newline attached to the following section
    open(CHANGELOG, "w").write(text[:insert_at] + entry + text[insert_at:])


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Re-freeze the canonical vector's spender across every leg, atomically.")
    ap.add_argument("address", help="the deployed Spartan1 address (0x + 40 hex)")
    ap.add_argument("--check", action="store_true",
                    help="report the plan and write nothing (works offline)")
    ap.add_argument("--rpc-url", default=os.environ.get("RPC_URL"),
                    help="JSON-RPC endpoint for the mandatory on-chain verification "
                         "(defaults to $RPC_URL)")
    ap.add_argument("--i-verified-manually", action="store_true",
                    help="AIR-GAPPED ESCAPE HATCH: skip the on-chain verification because you "
                         "performed it yourself. Recorded in CHANGELOG.md. Do not use casually.")
    args = ap.parse_args()
    check_only = args.check
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.address):
        ap.error("address must be 0x followed by 40 hex characters")
    new_spender = to_checksum_address(args.address)  # solc + viem both demand valid checksum literals

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

    # ── ON-CHAIN VERIFICATION — mandatory, and it runs BEFORE anything is written or built.
    # Skipped only when the target IS the sentinel: there is no contract at 0x1111…1111 by
    # definition, so the placeholder round-trip stays runnable offline. That is not a bypass.
    if not is_release:
        print("── on-chain verification: skipped — target is the placeholder sentinel "
              "(nothing is deployed there, by definition)")
    elif check_only:
        pass  # handled below: --check never writes, so it never *requires* an RPC
    elif args.i_verified_manually:
        print("── on-chain verification: SKIPPED via --i-verified-manually (air-gapped).")
        print("   You are asserting: code exists at the address, its runtime bytecode is this")
        print("   contract, and PERMIT2() is the canonical singleton. Recorded in CHANGELOG.md.")
    elif not args.rpc_url:
        raise SystemExit(
            "refusing to re-freeze: on-chain verification is mandatory before any write.\n"
            "  Pass --rpc-url <endpoint> (or set RPC_URL) so the script can confirm that the\n"
            "  address really holds this contract wired to the canonical Permit2.\n"
            "  Air-gapped? Re-run with --i-verified-manually — it is recorded in CHANGELOG.md.")
    else:
        verify_deployment(new_spender, Rpc(args.rpc_url, timeout=15.0), load_artifact())

    if check_only:
        # Offline by design (DEPLOY.md: "inspect the plan, writes nothing"). If an endpoint was
        # supplied anyway, verify opportunistically so deploy day can rehearse the check.
        if is_release and args.rpc_url:
            verify_deployment(new_spender, Rpc(args.rpc_url, timeout=15.0), load_artifact())
        elif is_release:
            print("  note: the WRITE will require --rpc-url/$RPC_URL (or --i-verified-manually).")
        return

    run_suites("preflight — refuse to re-freeze a red tree")
    apply_rewrites(plan)
    subprocess.run([sys.executable, os.path.join(HERE, "gen_constants.py")], check=True,
                   capture_output=True)
    write_deployment(deploy_value)
    if is_release:
        bump_sdk_version(new_version)
        # datetime is fine here — this is a real deploy-time script, not a deterministic gate.
        prepend_changelog(new_version, new_spender, datetime.date.today().isoformat(),
                          manual=args.i_verified_manually)
    run_coherence()
    run_suites("post-re-freeze — every leg re-proven")
    print("RE-FREEZE COMPLETE: all legs rewritten, registry updated, coherence + all suites green.")


if __name__ == "__main__":
    main()
