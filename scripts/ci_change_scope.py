#!/usr/bin/env python3
"""Classify a CI change set into the tier scopes defined by issue #9.

The workflow's ``change-scope`` job runs this once per run; every conditional
lane reads its outputs. The classifier is deliberately conservative:

* documentation-only changes take the fast route;
* install-surface changes (registry, installers, plugin payload, scripts,
  CI itself) additionally trigger the real-binary OS lanes;
* packaging-surface changes additionally trigger the extended ARM lanes
  (Windows ARM64, Linux aarch64);
* ANY path the classifier does not recognize, an empty diff, a missing
  base commit, or a git failure falls back to the STRONGEST scope
  (os_lanes + extended_arm true). A change detector can only ever widen
  validation, never narrow it below what an unknown change deserves.

Scope semantics consumed by ``scripts/ci_gate_check.py``:
  os_lanes=true      -> acp-clean-room, windows-x64, macos-arm64 required
  extended_arm=true  -> windows-arm64, linux-aarch64 required
Fast lanes (fake-acp, upstream-hermes-compat, catalog-floor-gate) are not
gated here; they run on every event and the gate always requires them.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

# Paths that ship or drive what ships on a platform: changing them must
# re-execute the real-binary lifecycle lanes.
OS_TRIGGER_PREFIXES = (
    "antigravity_acp/",
    "hermes-plugin/",
    "scripts/",
    ".github/",
)
OS_TRIGGER_EXACT = (
    "install-windows.cmd",
    ".python-version",
)

# Packaging surface: the bytes/architecture selection itself. Only these
# changes (or a manual dispatch / main push) pull the slow ARM lanes in.
ARM_TRIGGER_EXACT = (
    "antigravity_acp/registry.py",
    "install-windows.cmd",
    "scripts/install_acp.py",
    "scripts/install_official.py",
    "scripts/install_mux.py",
    "scripts/antigravity-acp-mux",
    "scripts/antigravity-acp-mux.py",
    ".github/workflows/ci.yml",
    ".python-version",
)

# Documentation-only surface. fnmatch semantics: ``*`` crosses ``/``.
FAST_ONLY_PATTERNS = (
    "*.md",
    "docs/*",
    "LICENSE",
    "NOTICE.md",
)


@dataclass(frozen=True)
class Scope:
    os_lanes: bool
    extended_arm: bool
    reason: str
    unknown_paths: tuple[str, ...] = ()


@dataclass
class _Accumulator:
    os_lanes: bool = False
    extended_arm: bool = False
    unknown: list[str] = field(default_factory=list)


def classify_paths(paths: list[str]) -> Scope:
    """Widen-only classification; see module docstring for the contract."""
    if not paths:
        # An empty diff on a real event is anomalous (wrong base, shallow
        # fetch, force-push): treat it as fully unknown, never as "nothing
        # to validate".
        return Scope(True, True, "empty-diff-fail-closed")
    acc = _Accumulator()
    for path in paths:
        if path in ARM_TRIGGER_EXACT:
            acc.os_lanes = True
            acc.extended_arm = True
        elif path.startswith(OS_TRIGGER_PREFIXES) or path in OS_TRIGGER_EXACT:
            acc.os_lanes = True
        elif any(fnmatch.fnmatch(path, pattern) for pattern in FAST_ONLY_PATTERNS):
            continue
        else:
            acc.os_lanes = True
            acc.extended_arm = True
            acc.unknown.append(path)
    reason = "path-classified"
    if acc.unknown:
        reason = f"unknown-paths-fail-closed ({len(acc.unknown)} path(s))"
    if acc.os_lanes and acc.extended_arm and not acc.unknown:
        reason = "packaging-surface-change"
    elif acc.os_lanes and not acc.extended_arm:
        reason = "install-surface-change"
    return Scope(acc.os_lanes, acc.extended_arm, reason, tuple(acc.unknown))


def _commit_exists(rev: str) -> bool:
    if not rev or set(rev) <= {"0"}:
        return False
    return (
        subprocess.run(
            ["git", "cat-file", "-e", f"{rev}^{{commit}}"],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )


def _changed_files(base: str, head: str) -> list[str]:
    diff = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in diff.stdout.splitlines() if line.strip()]


def scope_for_event(env: Mapping[str, str]) -> Scope:
    event = env.get("CI_EVENT", "")
    if event == "workflow_dispatch":
        return Scope(True, True, "workflow-dispatch-full-matrix")
    if event == "push":
        # Every main push is the post-merge full-audit run that release
        # trust is built on; it never narrows.
        return Scope(True, True, "post-merge-full-audit")
    if event == "pull_request":
        base = env.get("CI_BASE_SHA", "")
        head = env.get("CI_HEAD_SHA", "")
        try:
            if not (_commit_exists(base) and _commit_exists(head)):
                return Scope(True, True, "detection-failed-missing-base")
            return classify_paths(_changed_files(base, head))
        except (OSError, subprocess.SubprocessError):
            return Scope(True, True, "detection-failed-git-error")
    return Scope(True, True, f"unknown-event-fail-closed ({event or 'unset'})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify CI change scope (issue #9 tiers)")
    parser.add_argument("--output", type=Path, default=None, help="$GITHUB_OUTPUT file")
    parser.add_argument("--summary", type=Path, default=None, help="$GITHUB_STEP_SUMMARY file")
    args = parser.parse_args(argv)

    scope = scope_for_event(os.environ)

    lines = [
        f"os_lanes={'true' if scope.os_lanes else 'false'}",
        f"extended_arm={'true' if scope.extended_arm else 'false'}",
        f"reason={scope.reason}",
    ]
    if args.output is not None:
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)
    if args.summary is not None:
        lanes = []
        if scope.os_lanes:
            lanes.append("acp-clean-room, windows-x64, macos-arm64")
        if scope.extended_arm:
            lanes.append("windows-arm64, linux-aarch64")
        body = ["### Change scope", f"- reason: `{scope.reason}`"]
        body.append(
            "- required conditional lanes: "
            + (", ".join(f"`{name}`" for name in ", ".join(lanes).split(", ")) if lanes else "none (fast route)")
        )
        for path in scope.unknown_paths[:20]:
            body.append(f"- unknown path (fail-closed): `{path}`")
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(body) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
