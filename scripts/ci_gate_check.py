#!/usr/bin/env python3
"""Fail-closed aggregator for the issue #9 CI tiers (the ``CI gate`` job).

GitHub treats a *skipped* job as satisfying a required status check, and a
workflow-level ``paths`` filter can leave required checks pending forever.
Neither may silently green-light a run, so this script — not the per-job
conclusions — is the single honest verdict:

* the fast lanes (fake-acp, upstream-hermes-compat, catalog-floor-gate)
  must be ``success`` on every event, no exceptions;
* when the change scope required the OS lanes, each OS lane must be
  ``success`` — a skipped or missing OS lane when required is a failure;
* same for the extended ARM lanes and ``extended_arm``;
* a lane that ran anyway and failed is a failure even when not required;
* any other result (cancelled, action_required, neutral, timing_out,
  stale, missing) is a failure — only ``success`` and, for unrequired
  lanes, ``skipped`` are acceptable;
* if ``change-scope`` itself did not succeed, nothing is trustworthy and
  the gate fails.

Input is the Actions ``needs`` context serialized with ``toJSON`` plus the
``change-scope`` outputs; the verdict is exit code 0/1 and a summary table.
"""
from __future__ import annotations

import argparse
import json
import sys

FAST_LANES = ("fake-acp", "upstream-hermes-compat", "catalog-floor-gate")
OS_LANES = ("acp-clean-room", "windows-x64", "macos-arm64")
ARM_LANES = ("windows-arm64", "linux-aarch64")


def evaluate(expected: dict[str, str], results: dict[str, dict]) -> tuple[bool, list[str]]:
    """Return (ok, report_lines). Pure; unit-tested in tests/."""
    lines: list[str] = []
    ok = True

    scope_result = (results.get("change-scope") or {}).get("result")
    if scope_result != "success":
        ok = False
        lines.append(f"FAIL change-scope: result={scope_result!r} (scope detection is mandatory)")
    expected_os = str(expected.get("os_lanes", "")).lower() == "true"
    expected_arm = str(expected.get("extended_arm", "")).lower() == "true"

    def check(lane: str, required: bool, tier: str) -> None:
        nonlocal ok
        result = (results.get(lane) or {}).get("result")
        if result == "success":
            lines.append(f"PASS {lane} ({tier}): success")
            return
        if result == "skipped" and not required:
            lines.append(f"ok   {lane} ({tier}): skipped, not required by scope")
            return
        ok = False
        verdict = "required by scope but" if required else "not required by scope but"
        lines.append(f"FAIL {lane} ({tier}): result={result!r} ({verdict} not success)")

    for lane in FAST_LANES:
        check(lane, True, "fast")
    for lane in OS_LANES:
        check(lane, expected_os, "os")
    for lane in ARM_LANES:
        check(lane, expected_arm, "arm")

    header = (
        f"scope: os_lanes={expected_os} extended_arm={expected_arm} "
        f"reason={expected.get('reason', 'unknown')}"
    )
    return ok, [header, *lines, "verdict: " + ("PASS" if ok else "FAIL")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed CI tier aggregator (issue #9)")
    parser.add_argument("--expected-json", required=True, help="toJSON(needs.change-scope.outputs)")
    parser.add_argument("--results-json", required=True, help="toJSON(needs)")
    parser.add_argument("--summary", default=None, help="optional step-summary file to append")
    args = parser.parse_args(argv)

    try:
        expected = json.loads(args.expected_json)
        results = json.loads(args.results_json)
        if not isinstance(expected, dict) or not isinstance(results, dict):
            raise ValueError("both inputs must be JSON objects")
    except (ValueError, TypeError) as exc:
        print(f"CI gate input malformed; failing closed: {exc}", file=sys.stderr)
        return 1

    ok, lines = evaluate(expected, results)
    report = "\n".join(lines)
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write("### CI gate verdict\n\n```text\n" + report + "\n```\n")
    if not ok:
        print(
            "One or more lanes failed, were skipped while required, or never "
            "reported. A skipped or missing check is never a pass.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
