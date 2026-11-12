#!/usr/bin/env python3
"""Bind a release-candidate SHA to repository history (issue #28 Phase B).

The ``candidate-identity`` job runs this on a ``workflow_dispatch`` that
carries ``candidate_sha``. It fails closed (non-zero exit) unless:

* the input is a full 40-hex commit SHA (abbreviations are ambiguous and
  never acceptable as a release identity);
* that exact commit object exists in the repository (fetched by full SHA);
* the commit is reachable from at least one advertised branch tip — release
  candidates come from repository history, not from an orphaned object.

It records the candidate tree, the current ``main`` head, and whether the
candidate IS that head, so the release gate and any later tag-time check can
see the exact binding without re-deriving it. It never writes to the
repository, never tags, and never releases.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


class IdentityError(Exception):
    pass


def _git(*args: str, cwd: Path | None, capture: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=capture,
        text=True,
        cwd=cwd,
    )
    if proc.returncode != 0:
        raise IdentityError(f"git {' '.join(args[:2])} failed (exit {proc.returncode})")
    return (proc.stdout or "").strip()


def resolve_identity(candidate: str, remote: str = "origin", cwd: Path | None = None) -> dict[str, str]:
    """Resolve inside ``cwd`` (the repository checkout under CI); never a
    caller-independent ambient git directory."""
    candidate = candidate.strip().lower()
    if not HEX40_RE.fullmatch(candidate):
        raise IdentityError("candidate is not a full 40-hex commit SHA")
    # Fetch the exact object by full SHA; GitHub serves it only when it is
    # reachable from an advertised ref, which is itself part of the contract.
    _git("fetch", "--quiet", remote, candidate, cwd=cwd)
    kind = _git("cat-file", "-t", candidate, cwd=cwd)
    if kind != "commit":
        raise IdentityError("candidate object is not a commit")
    tree = _git("rev-parse", f"{candidate}^{{tree}}", cwd=cwd)
    ls = _git("ls-remote", "--heads", remote, cwd=cwd)
    tips: dict[str, str] = {}
    for line in ls.splitlines():
        sha, _, ref = line.partition("\t")
        tips[ref.removeprefix("refs/heads/")] = sha
    if not tips:
        raise IdentityError("repository advertises no branches")
    reachable_branches: list[str] = []
    for branch, tip in sorted(tips.items()):
        if tip == candidate:
            reachable_branches.append(branch)
            continue
        try:
            _git("fetch", "--quiet", remote, f"+refs/heads/{branch}:refs/remotes/phaseb/{branch}", cwd=cwd)
        except IdentityError:
            continue
        probe = subprocess.run(
            ["git", "merge-base", "--is-ancestor", candidate, tip],
            check=False,
            capture_output=True,
            cwd=cwd,
        )
        if probe.returncode == 0:
            reachable_branches.append(branch)
    if not reachable_branches:
        raise IdentityError("candidate is not reachable from any advertised branch")
    main_head = tips.get("main", "")
    return {
        "candidate": candidate,
        "candidate_tree": tree,
        "main_head": main_head,
        "candidate_on_main": (
            "true"
            if main_head
            and (
                main_head == candidate
                or subprocess.run(
                    ["git", "merge-base", "--is-ancestor", candidate, main_head],
                    check=False,
                    capture_output=True,
                    cwd=cwd,
                ).returncode
                == 0
            )
            else "false"
        ),
        "candidate_is_main_head": "true" if main_head == candidate else "false",
        "candidate_reachable": "true",
        "reachable_branches": ",".join(reachable_branches[:20]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind a release-candidate SHA (issue #28 Phase B)")
    parser.add_argument("--candidate-sha", default=os.environ.get("CANDIDATE_SHA", ""))
    parser.add_argument("--cwd", type=Path, default=None, help="repository checkout to resolve inside")
    parser.add_argument("--output", type=Path, default=None, help="$GITHUB_OUTPUT file")
    parser.add_argument("--summary", type=Path, default=None, help="$GITHUB_STEP_SUMMARY file")
    args = parser.parse_args(argv)
    try:
        identity = resolve_identity(args.candidate_sha, cwd=args.cwd)
    except IdentityError as exc:
        print(f"candidate identity rejected: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("candidate identity rejected: git failure", file=sys.stderr)
        return 1
    lines = [f"{key}={value}" for key, value in sorted(identity.items())]
    if args.output is not None:
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(
                "### Release candidate identity\n\n"
                + "\n".join(f"- `{item}`" for item in lines)
                + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
