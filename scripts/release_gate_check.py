#!/usr/bin/env python3
"""Fail-closed release-candidate gate (issue #28 Phase B).

The ``Release gate`` job runs this ONLY for a ``workflow_dispatch`` carrying
an explicit ``candidate_sha``. It certifies one thing: every lane the
version-controlled verification matrix requires executed against THIS EXACT
SHA and succeeded. Concretely it fails closed when:

* the candidate is not a full 40-hex commit SHA, or the ``candidate-identity``
  job did not succeed, or it resolved a different SHA than was requested;
* the candidate is not reachable from an advertised repository branch
  (release candidates come from repository history, not from nowhere);
* any required lane is missing, failed, skipped, cancelled, timed out, or
  reported anything other than ``success``;
* any required lane's attested checkout SHA (``git rev-parse HEAD`` executed
  inside the lane after checkout) differs from the candidate — evidence from
  another SHA, from an older green run, or from a moved branch head can
  never be substituted;
* a required lane attested fewer verification stages than the matrix
  requires for its target — an unexecuted stage is never counted green, and
  an optional PASS never substitutes for a required gap;
* a job the matrix and tier policy do not know was wired into the gate —
  an unaudited job is never a pass.

The verdict is exit code 0/1 plus a summary table with evidence URLs. This
gate never creates a release, tag, or deployment; it only withholds or
grants the SHA-bound verification record a release decision consumes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    from candidate_identity import IdentityError, resolve_release_identity
    from ci_gate_check import ARM_LANES, FAST_LANES, OS_LANES
    from release_matrix import Matrix, MatrixError, load_matrix
except ImportError:  # Imported as scripts.release_gate_check by repository tests.
    from scripts.candidate_identity import IdentityError, resolve_release_identity
    from scripts.ci_gate_check import ARM_LANES, FAST_LANES, OS_LANES
    from scripts.release_matrix import Matrix, MatrixError, load_matrix

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")

try:
    from gateway_attestation import check_outputs as check_gateway_outputs
except ImportError:
    from scripts.gateway_attestation import check_outputs as check_gateway_outputs

NATIVE_LANES = (*OS_LANES, *ARM_LANES)
INFRA_JOBS = ("change-scope", "candidate-identity", "ci-gate")


def _lane_result(results: dict, lane: str) -> str:
    entry = results.get(lane)
    return str(entry.get("result", "missing")) if isinstance(entry, dict) else "missing"


def _lane_output(results: dict, lane: str, key: str) -> str:
    entry = results.get(lane)
    outputs = entry.get("outputs") if isinstance(entry, dict) else None
    value = outputs.get(key) if isinstance(outputs, dict) else None
    return value if isinstance(value, str) else ""


def evaluate(
    candidate: str,
    identity: dict,
    results: dict,
    matrix: Matrix,
) -> tuple[bool, list[str]]:
    """Return (ok, report_lines). Pure; unit-tested in tests/."""
    lines: list[str] = []
    ok = True

    def fail(message: str) -> None:
        nonlocal ok
        ok = False
        lines.append(f"FAIL {message}")

    if not isinstance(candidate, str) or not HEX40_RE.fullmatch(candidate):
        fail(f"candidate {candidate!r} is not a full 40-hex commit SHA")
        return False, ["release gate verdict: FAIL"] + lines

    if not isinstance(identity, dict) or not isinstance(results, dict):
        return False, ["FAIL identity and results must be JSON objects", "verdict: FAIL"]

    if _lane_result(results, "candidate-identity") != "success":
        fail(
            "candidate-identity: result="
            f"{_lane_result(results, 'candidate-identity')!r} (identity binding is mandatory)"
        )
    else:
        reported = identity.get("candidate", "") if isinstance(identity, dict) else ""
        if reported != candidate:
            fail(f"candidate-identity resolved {reported!r}, not the requested {candidate!r}")
        if identity.get("candidate_reachable", "") != "true":
            fail("candidate is not reachable from an advertised repository branch")

    for field in ("github_sha", "checkout_sha", "ref_head_start", "ref_head_end"):
        if identity.get(field) != candidate:
            fail(f"{field}: missing or not the exact candidate SHA")
    target_ref = identity.get("target_ref")
    if not isinstance(target_ref, str) or not target_ref.startswith("refs/heads/") or not target_ref.removeprefix("refs/heads/"):
        fail("target_ref: a fully qualified candidate branch is mandatory")
    for job in INFRA_JOBS:
        if _lane_result(results, job) != "success":
            fail(f"{job}: required control job did not succeed")

    known = {*INFRA_JOBS, *FAST_LANES, *NATIVE_LANES}
    for lane in sorted(set(results) - known):
        fail(f"{lane}: wired into release-gate needs but unknown to the release policy")

    def check_lane(lane: str, tier: str) -> bool:
        result = _lane_result(results, lane)
        if result != "success":
            fail(f"{lane} ({tier}): result={result!r} (only success is a pass; skipped is never green)")
            return False
        attested = _lane_output(results, lane, "attested_sha")
        if attested != candidate:
            fail(
                f"{lane} ({tier}): attested checkout SHA {attested!r} != candidate "
                f"{candidate!r} (evidence from any other SHA is never reusable)"
            )
            return False
        return True

    lane_ok: dict[str, bool] = {}
    for lane in FAST_LANES:
        lane_ok[lane] = check_lane(lane, "fast")
    for lane in sorted(set(matrix.lanes) | set(NATIVE_LANES)):
        if lane not in lane_ok:
            lane_ok[lane] = check_lane(lane, "native")

    for (target, stage), lane in sorted(matrix.required_stage_lanes().items()):
        entry = matrix.targets[target][stage]
        if not lane_ok.get(lane, False):
            fail(f"{target}/{stage}: covering lane {lane} did not attest this SHA")
            continue
        attested_stages = {
            item.strip()
            for item in _lane_output(results, lane, "stages").split(",")
            if item.strip()
        }
        if stage not in attested_stages:
            fail(
                f"{target}/{stage}: required stage not attested by lane {lane} "
                f"(attested: {sorted(attested_stages) or 'none'}) — not executed is never PASS"
            )

    gateway_outputs = (results.get("upstream-hermes-compat") or {}).get("outputs") or {}
    for problem in check_gateway_outputs(gateway_outputs, required=True, candidate=candidate):
        fail("gateway_e2e: " + problem)

    for entry in matrix.cells():
        if not entry.required:
            lines.append(
                f"note {entry.target}/{entry.stage}: optional, status={entry.status}"
                + (f" ({entry.limitation})" if entry.limitation else "")
            )

    identity_outputs = identity if isinstance(identity, dict) else {}
    lines.append(
        "identity: "
        f"candidate={candidate} "
        f"main_head={identity_outputs.get('main_head', 'unknown')} "
        f"on_main={identity_outputs.get('candidate_on_main', 'unknown')} "
        f"is_main_head={identity_outputs.get('candidate_is_main_head', 'unknown')}"
    )
    if identity_outputs.get("candidate_is_main_head") == "false":
        lines.append(
            "note: candidate is not the current main head; this verification binds "
            "the selected candidate branch, whose HEAD must remain unchanged"
        )
    lines.append("verdict: " + ("PASS" if ok else "FAIL"))
    return ok, lines


def _evidence_lines() -> list[str]:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if repo and run_id:
        return [f"evidence run: {server}/{repo}/actions/runs/{run_id}"]
    return ["evidence run: unavailable outside GitHub Actions"]


def _bind_final_identity(candidate: str, identity: dict) -> dict:
    """Re-read the actual checkout and advertised branch NOW, not from needs."""
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise IdentityError("release approval requires a workflow_dispatch execution")
    if os.environ.get("GITHUB_WORKFLOW_SHA") != candidate:
        raise IdentityError("workflow definition SHA differs from candidate")
    if not all(os.environ.get(key, "").isdigit() and int(os.environ[key]) > 0 for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")):
        raise IdentityError("GitHub run identity is missing")
    fresh = resolve_release_identity(
        candidate, os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_REF", "")
    )
    for field in ("github_sha", "checkout_sha", "target_ref"):
        if identity.get(field) != fresh[field]:
            raise IdentityError(f"start/end {field} binding differs")
    return {**identity, "ref_head_end": fresh["ref_head_start"]}


def evidence_document(candidate: str, identity: dict, results: dict, matrix: Matrix, matrix_path: Path) -> dict:
    """A run-bound result, not the checked-in matrix's historical status."""
    ok, _ = evaluate(candidate, identity, results, matrix)
    if not ok:
        raise IdentityError("failed verification cannot create a PASS record")
    cells = []
    for entry in matrix.cells():
        stages = _lane_output(results, entry.lane, "stages").split(",")
        executed = (
            _lane_result(results, entry.lane) == "success"
            and _lane_output(results, entry.lane, "attested_sha") == candidate
            and entry.stage in stages
        )
        cells.append({
            "target": entry.target, "stage": entry.stage, "required": entry.required,
            "status": "PASS" if executed else "NOT_RUN", "lane": entry.lane,
            "evidence_class": entry.evidence_class if executed else "not_executed",
            "evidence": entry.evidence if executed else entry.limitation,
        })
    return {
        "schema_version": 1, "verdict": "PASS", "candidate_sha": candidate,
        "identity": identity, "matrix_sha256": hashlib.sha256(matrix_path.read_bytes()).hexdigest(),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "jobs": results, "platform_checks": cells,
        "gateway_e2e": json.loads(_lane_output(results, "upstream-hermes-compat", "gateway_record")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed release-candidate gate (issue #28 Phase B)")
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--identity-json", required=True, help="toJSON(needs.candidate-identity.outputs)")
    parser.add_argument("--results-json", required=True, help="toJSON(needs)")
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--summary", default=None)
    parser.add_argument("--evidence-output", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        matrix = load_matrix(args.matrix)
    except MatrixError as exc:
        print(f"release gate matrix invalid; failing closed: {exc}", file=sys.stderr)
        return 1
    try:
        identity = json.loads(args.identity_json)
        results = json.loads(args.results_json)
        if not isinstance(identity, dict) or not isinstance(results, dict):
            raise ValueError("identity and results must be JSON objects")
    except (ValueError, TypeError) as exc:
        print(f"release gate input malformed; failing closed: {exc}", file=sys.stderr)
        return 1

    try:
        identity = _bind_final_identity(args.candidate_sha, identity)
    except (IdentityError, OSError, ValueError) as exc:
        print(f"release gate identity rejected; failing closed: {exc}", file=sys.stderr)
        return 1
    ok, lines = evaluate(args.candidate_sha, identity, results, matrix)
    report = "\n".join([*_evidence_lines(), *lines])
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write("### Release gate verdict\n\n```text\n" + report + "\n```\n")
    if not ok:
        print(
            "Release verification is not certifiable for this SHA: a required "
            "lane failed, skipped, never reported, attested a different SHA, or "
            "left a required stage unattested.",
            file=sys.stderr,
        )
        return 1
    if args.evidence_output:
        evidence = evidence_document(args.candidate_sha, identity, results, matrix, args.matrix)
        args.evidence_output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
