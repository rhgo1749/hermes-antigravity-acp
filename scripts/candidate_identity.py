#!/usr/bin/env python3
"""Bind a release-candidate SHA to repository history (issue #28 Phase B).

The ``candidate-identity`` job runs this on a ``workflow_dispatch`` that
carries ``candidate_sha``. It fails closed (non-zero exit) unless:

* the input is a full 40-hex commit SHA (abbreviations are ambiguous and
  never acceptable as a release identity);
* that exact commit object exists in the repository (fetched by full SHA);
* Actions execution SHA, actual checkout and the selected remote branch
  HEAD are the candidate, not merely a reachable ancestor.

The same stdlib-only checkout attestation runs in all test lanes. The
release gate resolves remote identity again after verification. History,
tree and main relation are metadata, never substitutes for branch freshness.
Only Git fetch metadata/output files are written; no tracked source, tag,
release or deployment is changed.
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
        timeout=45,
    )
    if proc.returncode != 0:
        raise IdentityError(f"git {' '.join(args[:2])} failed (exit {proc.returncode})")
    return (proc.stdout or "").strip()


def resolve_identity(candidate: str, remote: str = "origin", cwd: Path | None = None) -> dict[str, str]:
    """Resolve inside ``cwd`` (the repository checkout under CI); never a
    caller-independent ambient git directory."""
    if not isinstance(candidate, str) or not HEX40_RE.fullmatch(candidate):
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


def attest_checkout(candidate: str, github_sha: str, cwd: Path | None = None) -> dict[str, str]:
    """One stdlib-only identity driver shared by every native/fast runner."""
    if not isinstance(candidate, str) or not HEX40_RE.fullmatch(candidate):
        raise IdentityError("candidate is not a full lowercase 40-hex commit SHA")
    if github_sha != candidate:
        raise IdentityError("GitHub Actions execution SHA differs from candidate")
    checkout = _git("rev-parse", "HEAD", cwd=cwd)
    if checkout != candidate:
        raise IdentityError("actual checkout SHA differs from candidate")
    # A matching HEAD is not proof that the commands tested that commit's
    # bytes. Test/install steps must not mutate this repository's sources.
    _git("diff", "--quiet", "HEAD", "--", cwd=cwd)
    _git("diff", "--cached", "--quiet", cwd=cwd)
    return {"sha": checkout, "github_sha": github_sha, "checkout_sha": checkout}


def resolve_release_identity(
    candidate: str,
    github_sha: str,
    target_ref: str,
    remote: str = "origin",
    cwd: Path | None = None,
) -> dict[str, str]:
    """Require the dispatch branch, Actions SHA and checkout to agree NOW.

    Called at the beginning and again in the final Release gate; an ancestor
    of a moved branch is not a valid release candidate for that dispatch.
    """
    checkout = attest_checkout(candidate, github_sha, cwd)
    if not isinstance(target_ref, str) or not target_ref.startswith("refs/heads/"):
        raise IdentityError("candidate must name a fully qualified branch ref")
    _git("check-ref-format", target_ref, cwd=cwd)
    # Retain the existing history/tree/main provenance, without treating
    # reachability from ANY branch as the selected branch's freshness proof.
    identity = resolve_identity(candidate, remote=remote, cwd=cwd)
    advertised = _git("ls-remote", "--refs", "--exit-code", remote, target_ref, cwd=cwd)
    if advertised.splitlines() != [f"{candidate}\t{target_ref}"]:
        raise IdentityError("candidate branch HEAD moved or does not match candidate")
    return {
        **identity,
        "github_sha": checkout["github_sha"],
        "checkout_sha": checkout["checkout_sha"],
        "target_ref": target_ref,
        "ref_head_start": candidate,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind a release-candidate SHA (issue #28 Phase B)")
    parser.add_argument("--candidate-sha", default=os.environ.get("CANDIDATE_SHA", ""))
    parser.add_argument("--attest-checkout", action="store_true", help="attest one tested lane, without remote calls")
    parser.add_argument("--cwd", type=Path, default=None, help="repository checkout to resolve inside")
    parser.add_argument("--output", type=Path, default=None, help="$GITHUB_OUTPUT file")
    parser.add_argument("--summary", type=Path, default=None, help="$GITHUB_STEP_SUMMARY file")
    args = parser.parse_args(argv)
    try:
        if args.attest_checkout:
            bound = attest_checkout(args.candidate_sha, os.environ.get("GITHUB_SHA", ""), args.cwd)
            identity = {"sha": bound["sha"]}
            stages = os.environ.get("ATTESTED_STAGES", "")
            if stages:
                if not re.fullmatch(r"[a-z0-9_]+(?:,[a-z0-9_]+)*", stages):
                    raise IdentityError("malformed stage attestation")
                identity["stages"] = stages
        else:
            identity = resolve_release_identity(
                args.candidate_sha,
                os.environ.get("GITHUB_SHA", ""),
                os.environ.get("GITHUB_REF", ""),
                cwd=args.cwd,
            )
    except IdentityError as exc:
        print(f"candidate identity rejected: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("candidate identity rejected: git failure", file=sys.stderr)
        return 1
    lines = [f"{key}={value}" for key, value in sorted(identity.items())]
    output = args.output or (Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None)
    if output is not None:
        with output.open("a", encoding="utf-8") as handle:
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
