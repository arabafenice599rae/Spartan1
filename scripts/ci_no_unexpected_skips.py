#!/usr/bin/env python3
"""CI enforcement: gate 10 is the ONLY skip allowed anywhere in the suite.

WHY THIS EXISTS: a suite can turn green on tests that never ran. The relay conformance suite
declares SKIP for its schema/coherence gates when `pyyaml` is absent — it prints
`97/97 passed, 0 failed, 5 skipped` and exits 0. The forge suite legitimately skips exactly
`test_gate10_fork_realPermit2` (no L2_RPC in CI). Surfacing those skips in the job summary is
not enough: a green badge over five silently-disabled conformance gates is the same regression
class as a placebo PASS. This gate turns any UNEXPECTED skip into a hard CI failure.

THE RULE: across all of CI there is exactly one permitted skip, and it is
`test_gate10_fork_realPermit2` (the on-chain fork gate, run manually per DEPLOY.md). Everything
else must actually run.

USAGE (from repo root, in CI):
    forge test --json > forge.json
    python3 scripts/ci_no_unexpected_skips.py --forge forge.json \\
        client/test_spartan1.py distribution/test_relay.py \\
        distribution/test_maker.py distribution/test_executor.py

- `--forge <file>`: a `forge test --json` dump. Asserts the set of Skipped tests is EXACTLY
  {test_gate10_fork_realPermit2} — an EXTRA skip or a MISSING gate 10 (removed/renamed → empty
  set) both fail. Also fails on any non-Success/non-Skipped test. Writes the authoritative
  contract-gate summary to $GITHUB_STEP_SUMMARY when that env var is set.
- positional args: python suite files (AT LEAST ONE is required — the script refuses to report
  OK over an empty suite list, so a workflow edit that silently drops the paths fails loudly
  instead of passing vacuously). Each is run; it must exit 0 AND its `RESULT:` summary line must
  not report a skip. (We anchor to the `^RESULT` line on purpose: a suite may print the word
  "skipped" inside a test *description* — e.g. the executor's "(mute relay skipped)" — which must
  not trip the gate.)

Exit 0 only if every check passes; otherwise print every violation and exit 1.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# The one and only skip permitted anywhere in CI. forge --json reports names with the "()" suffix.
ALLOWED_FORGE_SKIP = "test_gate10_fork_realPermit2()"


def check_forge(path: str, violations: list[str]) -> None:
    """Assert forge's skip set is exactly {gate 10} and nothing failed; emit the job summary."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        violations.append(f"forge: could not read {path} ({exc}) — did `forge test --json` run?")
        return

    status_by_test: dict[str, str] = {}
    for suite in data.values():
        for name, result in suite.get("test_results", {}).items():
            status_by_test[name] = result.get("status", "Unknown")

    if not status_by_test:
        violations.append(f"forge: {path} contained no test results")
        return

    skipped = sorted(n for n, s in status_by_test.items() if s == "Skipped")
    failed = sorted(n for n, s in status_by_test.items() if s not in ("Success", "Skipped"))
    passed = sum(1 for s in status_by_test.values() if s == "Success")

    if failed:
        violations.append("forge: failing tests: " + ", ".join(failed))
    if skipped != [ALLOWED_FORGE_SKIP]:
        violations.append(
            f"forge: skip set is {skipped}, expected exactly [{ALLOWED_FORGE_SKIP!r}] — "
            "a stray skip, or a missing/renamed gate 10, disables coverage silently"
        )

    _write_summary(passed, failed, skipped)


def _write_summary(passed: int, failed: list[str], skipped: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## Contract gate (forge test)",
        "",
        "```",
        f"{passed} passed, {len(failed)} failed, {len(skipped)} skipped",
        "```",
        "",
        "> **Gate 10 (`test_gate10_fork_realPermit2`) is the ONE allowed SKIP — and CI enforces "
        "that.**",
        "> It forks a real L2 to run gates 2/3/5 + settlement against the canonical Permit2. No RPC",
        "> secret is configured here (flaky, and buys nothing on a public repo), so it does not run",
        "> in CI. Any OTHER skip — in forge or the Python conformance suites — fails this job. Run",
        "> gate 10 before deploying capital, per DEPLOY.md: "
        "`L2_RPC=<base-rpc> forge test --match-test gate10`.",
    ]
    with open(summary_path, "a") as fh:
        fh.write("\n".join(lines) + "\n")


def check_python_suite(path: str, violations: list[str]) -> None:
    """Run a python suite; it must exit 0 and its RESULT summary line must report no skip."""
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.abspath(__file__)) + "/..",
    )
    sys.stdout.write(proc.stdout)
    sys.stdout.write(proc.stderr)
    if proc.returncode != 0:
        violations.append(f"{path}: exited {proc.returncode} (suite is red)")
        return
    # Anchor to the RESULT summary line — NOT any line: a test description may contain "skipped".
    result_lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT")]
    if not result_lines:
        violations.append(f"{path}: no RESULT summary line found — cannot confirm skip count")
        return
    for ln in result_lines:
        if "skipped" in ln.lower():
            violations.append(
                f"{path}: RESULT reports a skip ({ln.strip()!r}) — a conformance gate did not run "
                "(e.g. pyyaml missing → schema/coherence gates silently disabled)"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--forge", help="path to a `forge test --json` dump")
    ap.add_argument("suites", nargs="*", help="python suite files that must run with no skips")
    args = ap.parse_args()

    # Refuse to report OK over nothing. `suites` is nargs="*", so an invocation that lost its suite
    # paths — e.g. a future workflow edit dropping the `\` line-continuation — would otherwise print
    # "skip gate OK" and exit 0 while checking nothing on the Python side. That silent-green shape is
    # the very failure this gate exists to prevent, so make it loud instead.
    if not args.suites:
        ap.error("no suites given — refusing to report OK over nothing (pass the conformance suites)")

    violations: list[str] = []
    if args.forge:
        check_forge(args.forge, violations)
    for suite in args.suites:
        check_python_suite(suite, violations)

    if violations:
        print("\n=== UNEXPECTED SKIP / FAILURE — CI must fail ===", file=sys.stderr)
        for v in violations:
            print(f"::error::{v}", file=sys.stderr)
        return 1
    print("\nskip gate OK: gate 10 is the only skip; every conformance gate ran.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
