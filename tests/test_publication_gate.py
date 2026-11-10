from __future__ import annotations

import base64
import json
import subprocess
import sys

import pytest
from pathlib import Path
from urllib.parse import urlsplit

from scripts import audit_exposure as audit
from scripts import publication_gate as gate


class FakeTransport:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url: str, headers: dict[str, str], limit: int) -> audit.HttpResponse:
        return self.handler(url, headers, limit)


def response(payload, content_type: str = "application/json") -> audit.HttpResponse:
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode()
    else:
        body = json.dumps(payload).encode()
    return audit.HttpResponse(200, {"content-type": content_type}, body)


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def make_repo(path: Path, files: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(path)], check=True)
    git(path, "config", "user.name", "Synthetic Gate")
    git(path, "config", "user.email", "synthetic@example.invalid")
    for name, content in (files or {"README.md": "safe example\n"}).items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git(path, "add", "--all")
    git(path, "commit", "--quiet", "-m", "synthetic fixture")
    return path


def blob_response(content: bytes):
    return response(
        {"encoding": "base64", "size": len(content), "content": base64.b64encode(content).decode()}
    )


PREFIX = "/repos/example/project"
COMMIT_SHA = "1" * 40
TREE_SHA = "2" * 40
BLOB_SHA = "3" * 40


def _git_graph_routes(path: str):
    if path == f"{PREFIX}/git/matching-refs/":
        return response([{"ref": "refs/heads/main", "object": {"sha": COMMIT_SHA, "type": "commit"}}])
    if path == f"{PREFIX}/git/commits/{COMMIT_SHA}":
        return response({"sha": COMMIT_SHA, "message": "synthetic", "tree": {"sha": TREE_SHA}, "parents": []})
    if path == f"{PREFIX}/git/trees/{TREE_SHA}":
        return response({"tree": [{"path": "notes.txt", "type": "blob", "sha": BLOB_SHA}], "truncated": False})
    if path == f"{PREFIX}/git/blobs/{BLOB_SHA}":
        return blob_response(b"benign remote file\n")
    return None


def clean_transport() -> FakeTransport:
    def handler(url: str, _headers: dict[str, str], _limit: int) -> audit.HttpResponse:
        path = urlsplit(url).path
        graph = _git_graph_routes(path)
        if graph is not None:
            return graph
        if path == f"{PREFIX}/issues":
            return response([{"number": 1, "title": "synthetic", "body": "ordinary text"}])
        if path == f"{PREFIX}/issues/1/comments":
            return response([])
        if path == f"{PREFIX}/actions/runs":
            return response({"workflow_runs": [{"id": 700}]})
        if path == f"{PREFIX}/actions/runs/700/jobs":
            return response({"jobs": []})
        if path == f"{PREFIX}/actions/runs/700/logs":
            return response("safe workflow output", content_type="text/plain")
        if path == f"{PREFIX}/actions/runs/700/artifacts":
            return response({"artifacts": []})
        if path == f"{PREFIX}/releases":
            return response([])
        raise AssertionError(f"unexpected route: {path}")

    return FakeTransport(handler)


def gappy_transport() -> FakeTransport:
    """Remote surfaces with one expired artifact, one missing log, one external link."""

    def handler(url: str, _headers: dict[str, str], _limit: int) -> audit.HttpResponse:
        path = urlsplit(url).path
        graph = _git_graph_routes(path)
        if graph is not None:
            return graph
        if path == f"{PREFIX}/issues":
            return response(
                [
                    {
                        "number": 1,
                        "title": "synthetic",
                        "body": "ordinary text; see https://outside.example.invalid/archive.tgz",
                    }
                ]
            )
        if path == f"{PREFIX}/issues/1/comments":
            return response([])
        if path == f"{PREFIX}/actions/runs":
            return response({"workflow_runs": [{"id": 700}]})
        if path == f"{PREFIX}/actions/runs/700/jobs":
            return response({"jobs": []})
        if path == f"{PREFIX}/actions/runs/700/logs":
            raise audit.AuditFailure("http_404")
        if path == f"{PREFIX}/actions/runs/700/artifacts":
            return response({"artifacts": [{"id": 800, "name": "expired", "expired": True}]})
        if path == f"{PREFIX}/releases":
            return response([])
        raise AssertionError(f"unexpected route: {path}")

    return FakeTransport(handler)


def finding_transport(secret: str, sensitive_path: str, username: str) -> FakeTransport:
    def handler(url: str, _headers: dict[str, str], _limit: int) -> audit.HttpResponse:
        path = urlsplit(url).path
        graph = _git_graph_routes(path)
        if graph is not None:
            return graph
        if path == f"{PREFIX}/issues":
            return response(
                [
                    {
                        "number": 1,
                        "title": "synthetic",
                        "body": f"rotate {secret} at {sensitive_path}; pinged {username}",
                        "user": {"login": username},
                    }
                ]
            )
        if path == f"{PREFIX}/issues/1/comments":
            return response([])
        if path == f"{PREFIX}/actions/runs":
            return response({"workflow_runs": []})
        if path == f"{PREFIX}/releases":
            return response([])
        raise AssertionError(f"unexpected route: {path}")

    return FakeTransport(handler)


def run_remote_audit(repo: Path, transport: FakeTransport) -> dict:
    return audit.run_audit(repo, "example/project", transport=transport)


def write_external_report(tmp_path: Path, report: dict) -> Path:
    report_path = tmp_path / "sanitized-audit.json"
    report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    return report_path


def decide(repo: Path, report: dict, *, authorization=None, authorization_status="not_recorded", github_repository=None):
    return gate.evaluate_decision(
        report,
        current_tree_rules={},
        authorization=authorization,
        authorization_status=authorization_status,
        authorization_digest=None,
        github_repository=github_repository,
        report_digest="0" * 64,
        identity_probe=gate.snapshot_git_identity(repo),
    )


def test_expired_inaccessible_and_external_material_cannot_satisfy_clean_coverage(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, gappy_transport())

    reasons = {
        reason
        for source in report["sources"].values()
        for reason in source["not_verified_reasons"]
    }
    assert {"artifact_expired", "http_404", "external_reference_not_fetched"} <= reasons
    assert gate.clean_coverage_satisfied(report) is False

    decision = decide(repo, report)
    assert decision["verdict"] == "NO-GO"
    assert decision["coverage"]["clean_coverage_satisfied"] is False
    assert "unverified_items_present" in decision["coverage"]["gap_reasons"]
    in_place = decision["routes"][gate.SCOPE_IN_PLACE]
    assert in_place["verdict"] == gate.VERDICT_NO_GO
    assert "unverified_items_present" in in_place["blocking_reasons"]


def test_dangling_object_boundary_alone_blocks_clean_coverage(tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "safe\n"})
    loose = repo / "unreferenced.txt"
    loose.write_text("never committed\n", encoding="utf-8")
    git(repo, "hash-object", "-w", "unreferenced.txt")
    loose.unlink()

    report = audit.run_audit(repo)

    assert gate.clean_coverage_satisfied(report) is False
    decision = decide(repo, report)
    assert "outside_verified_scope_present" in decision["coverage"]["gap_reasons"]
    assert gate.VERDICT_NO_GO == decision["routes"][gate.SCOPE_IN_PLACE]["verdict"]
    assert "outside_verified_scope_present" in decision["routes"][gate.SCOPE_IN_PLACE]["blocking_reasons"]


def test_gate_rejects_in_place_publicization_with_unverified_gaps_even_when_authorized(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, gappy_transport())
    authorization = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_IN_PLACE,
        "source_repository": "example/project",
    }

    decision = decide(repo, report, authorization=authorization, authorization_status="recorded", github_repository="example/project")

    in_place = decision["routes"][gate.SCOPE_IN_PLACE]
    assert in_place["verdict"] == gate.VERDICT_NO_GO
    assert "unverified_items_present" in in_place["blocking_reasons"]
    assert decision["verdict"] == "NO-GO"
    assert decision["approval_granted_by_gate"] is False


def test_gate_records_no_approval_for_clean_room_export_without_maintainer_authorization(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, gappy_transport())

    decision = decide(repo, report, github_repository="example/project")

    clean_room = decision["routes"][gate.SCOPE_CLEAN_ROOM]
    assert clean_room["verdict"] == gate.VERDICT_NOT_AUTHORIZED
    assert "maintainer_authorization_not_recorded" in clean_room["blocking_reasons"]
    assert decision["maintainer_authorization"]["status"] == "not_recorded"
    assert decision["approval_granted_by_gate"] is False
    assert clean_room["residual_gap_policy"] == "NOT_VERIFIED_AND_OUTSIDE_VERIFIED_SCOPE_REMAIN_OPEN"


def test_clean_room_route_only_conditionally_eligible_with_explicit_authorization(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, gappy_transport())
    authorization = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_CLEAN_ROOM,
        "source_repository": "example/project",
    }

    decision = decide(repo, report, authorization=authorization, authorization_status="recorded", github_repository="example/project")

    clean_room = decision["routes"][gate.SCOPE_CLEAN_ROOM]
    assert clean_room["verdict"] == gate.VERDICT_CONDITIONALLY_ELIGIBLE
    # The unresolved historical gaps still reject in-place publicization.
    assert decision["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_NO_GO
    assert decision["verdict"] == "NO-GO"


def test_fully_clean_and_authorized_is_eligible_but_never_approved_by_gate(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())
    assert gate.clean_coverage_satisfied(report) is True
    authorization = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_IN_PLACE,
        "source_repository": "example/project",
    }

    decision = decide(repo, report, authorization=authorization, authorization_status="recorded", github_repository="example/project")

    assert decision["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_CONDITIONALLY_ELIGIBLE
    # The single authorization record binds only the in-place scope; the
    # clean-room route remains unapproved, and the gate never grants anything.
    assert decision["routes"][gate.SCOPE_CLEAN_ROOM]["verdict"] == gate.VERDICT_NOT_AUTHORIZED
    assert decision["approval_granted_by_gate"] is False
    assert decision["verdict"] == "NOT-AUTHORIZED"


def test_authorization_must_bind_repository_and_scope(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())
    wrong_repo = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_IN_PLACE,
        "source_repository": "someone/else",
    }
    wrong_scope = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_CLEAN_ROOM,
        "source_repository": "example/project",
    }

    repo_mismatch = decide(repo, report, authorization=wrong_repo, authorization_status="recorded", github_repository="example/project")
    assert repo_mismatch["maintainer_authorization"]["repository_match"] is False
    assert "maintainer_authorization_repository_mismatch" in repo_mismatch["routes"][gate.SCOPE_IN_PLACE]["blocking_reasons"]

    scope_mismatch = decide(repo, report, authorization=wrong_scope, authorization_status="recorded", github_repository="example/project")
    in_place = scope_mismatch["routes"][gate.SCOPE_IN_PLACE]
    assert in_place["verdict"] == gate.VERDICT_NOT_AUTHORIZED
    assert "maintainer_authorization_scope_mismatch" in in_place["blocking_reasons"]
    assert scope_mismatch["routes"][gate.SCOPE_CLEAN_ROOM]["verdict"] == gate.VERDICT_CONDITIONALLY_ELIGIBLE


def test_load_authorization_rejects_untrusted_records(tmp_path):
    cases = [
        {"schema": "publication-authorization-v1", "authorized": False, "scope": gate.SCOPE_IN_PLACE, "source_repository": "example/project"},
        {"schema": "made-up-authorization", "authorized": True, "scope": gate.SCOPE_IN_PLACE, "source_repository": "example/project"},
        {"schema": gate.AUTHORIZATION_SCHEMA, "authorized": True, "scope": "flip_visibility", "source_repository": "example/project"},
        {"schema": gate.AUTHORIZATION_SCHEMA, "authorized": True, "scope": gate.SCOPE_IN_PLACE, "source_repository": "not a repo"},
    ]
    for index, record in enumerate(cases):
        record_path = tmp_path / f"authorization-{index}.json"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        parsed, status, _digest = gate.load_authorization(record_path)
        assert parsed is None
        assert status == "invalid"

    valid_path = tmp_path / "authorization-valid.json"
    valid_path.write_text(
        json.dumps(
            {
                "schema": gate.AUTHORIZATION_SCHEMA,
                "authorized": True,
                "scope": gate.SCOPE_CLEAN_ROOM,
                "source_repository": "example/project",
                "authorized_by": "synthetic-maintainer-identity",
            }
        ),
        encoding="utf-8",
    )
    parsed, status, digest = gate.load_authorization(valid_path)
    assert status == "recorded"
    assert parsed is not None and parsed["scope"] == gate.SCOPE_CLEAN_ROOM
    assert len(digest) == 64


def test_report_replay_from_another_repository_is_blocked(tmp_path):
    source = make_repo(tmp_path / "source", {"README.md": "safe source repo\n"})
    other = make_repo(tmp_path / "other", {"notes.md": "different repo\n"})
    report = run_remote_audit(source, clean_transport())

    foreign = decide(other, report, github_repository="example/project")

    binding = foreign["report_binding"]
    assert binding["head_match"] is False
    assert binding["ref_snapshot_match"] is False
    assert "report_head_mismatch" in binding["blockers"]
    assert "report_ref_snapshot_mismatch" in binding["blockers"]
    assert foreign["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_NO_GO
    assert foreign["approval_granted_by_gate"] is False


def test_report_bound_to_another_repository_cannot_satisfy_the_gate(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())

    mismatch = decide(repo, report, github_repository="someone/else")
    assert mismatch["report_binding"]["repository_match"] is False
    assert "report_repository_mismatch" in mismatch["report_binding"]["blockers"]
    assert mismatch["routes"][gate.SCOPE_CLEAN_ROOM]["verdict"] == gate.VERDICT_NO_GO

    local_report = audit.run_audit(repo)
    unbound = decide(repo, local_report)
    assert "report_repository_unbound" in unbound["report_binding"]["blockers"]
    assert "repository_identity_unbound" in unbound["report_binding"]["blockers"]
    assert unbound["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_NO_GO


def test_omitted_repository_identity_fails_closed_against_foreign_authorization(tmp_path):
    """A bound report plus a foreign authorization must not become eligible.

    Without an explicit target repository identity the report-target and
    authorization-source repository comparisons are unverifiable; the gate
    must fail closed instead of leaving the clean-room route
    CONDITIONALLY_ELIGIBLE on an unverified identity binding.
    """
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())  # bound to example/project
    foreign_authorization = {
        "schema": gate.AUTHORIZATION_SCHEMA,
        "authorized": True,
        "scope": gate.SCOPE_CLEAN_ROOM,
        "source_repository": "someone/else",
    }

    decision = decide(
        repo,
        report,
        authorization=foreign_authorization,
        authorization_status="recorded",
    )

    binding = decision["report_binding"]
    assert "repository_identity_unbound" in binding["blockers"]
    assert binding["repository_match"] is None
    assert decision["maintainer_authorization"]["repository_match"] is None
    for route_name, route in decision["routes"].items():
        assert route["verdict"] != gate.VERDICT_CONDITIONALLY_ELIGIBLE, route_name
        assert "repository_identity_unbound" in route["blocking_reasons"]
    assert decision["routes"][gate.SCOPE_CLEAN_ROOM]["verdict"] == gate.VERDICT_NO_GO
    assert decision["verdict"] == "NO-GO"
    assert decision["approval_granted_by_gate"] is False

    # The explicit-identity path is unchanged: the same foreign authorization
    # is rejected as a repository mismatch, not as an omitted identity.
    with_identity = decide(
        repo,
        report,
        authorization=foreign_authorization,
        authorization_status="recorded",
        github_repository="example/project",
    )
    assert with_identity["report_binding"]["repository_match"] is True
    assert "repository_identity_unbound" not in with_identity["report_binding"]["blockers"]
    assert "maintainer_authorization_repository_mismatch" in with_identity["routes"][gate.SCOPE_CLEAN_ROOM]["blocking_reasons"]
    assert with_identity["routes"][gate.SCOPE_CLEAN_ROOM]["verdict"] == gate.VERDICT_NOT_AUTHORIZED


def test_stale_head_report_cannot_satisfy_an_advanced_repository(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())
    (repo / "next.txt").write_text("advance head\n", encoding="utf-8")
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", "advance head")

    decision = decide(repo, report, github_repository="example/project")

    assert decision["report_binding"]["head_match"] is False
    assert "report_head_mismatch" in decision["report_binding"]["blockers"]
    assert decision["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_NO_GO


def _tampered(tmp_path: Path, report: dict) -> Path:
    path = tmp_path / "tampered-report.json"
    path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    return path


def test_load_report_rejects_negative_partition_counts(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = audit.run_audit(repo)
    name = sorted(report["sources"])[0]
    report["sources"][name]["partition"][gate.STATUS_FINDING] = -1

    with pytest.raises(gate.GateFailure) as failure:
        gate.load_report(_tampered(tmp_path, report))
    assert failure.value.reason == "report_invalid"


def test_load_report_rejects_partition_total_mismatch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = audit.run_audit(repo)
    name = sorted(report["sources"])[0]
    report["sources"][name]["total"] -= 1

    with pytest.raises(gate.GateFailure) as failure:
        gate.load_report(_tampered(tmp_path, report))
    assert failure.value.reason == "report_partition_inconsistent"


def test_load_report_rejects_reason_sum_mismatch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = audit.run_audit(repo)
    name = next(
        surface_name
        for surface_name, surface in report["sources"].items()
        if surface["not_verified_reasons"]
    )
    reasons = report["sources"][name]["not_verified_reasons"]
    key = sorted(reasons)[0]
    reasons[key] -= 1

    with pytest.raises(gate.GateFailure) as failure:
        gate.load_report(_tampered(tmp_path, report))
    assert failure.value.reason == "report_partition_inconsistent"


def test_load_report_rejects_reason_and_class_sum_mismatch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = audit.run_audit(repo)
    name = sorted(report["sources"])[0]
    report["sources"][name]["finding_classes"]["synthetic_class"] = 1

    with pytest.raises(gate.GateFailure) as failure:
        gate.load_report(_tampered(tmp_path, report))
    assert failure.value.reason == "report_partition_inconsistent"


def test_load_report_rejects_malformed_target_binding(tmp_path):
    repo = make_repo(tmp_path / "repo")
    report = audit.run_audit(repo)
    report["target"]["head_oid"] = None

    with pytest.raises(gate.GateFailure) as failure:
        gate.load_report(_tampered(tmp_path, report))
    assert failure.value.reason == "report_invalid"


def test_live_credential_finding_opens_separate_response_route_without_execution(tmp_path):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "L" * 40
    report = run_remote_audit(
        repo, finding_transport(secret, "/home/private-user/.env.local", "synthetic-person")
    )

    decision = decide(repo, report)

    credential = decision["credential_response_route"]
    assert credential["live_credential_review_required"] is True
    assert credential["route"] == "separate_authorized_deactivation_rotation_plan"
    assert credential["execution"] == "not_performed_by_gate"
    assert "live_credential_review_open" in decision["routes"][gate.SCOPE_IN_PLACE]["blocking_reasons"]
    assert decision["verdict"] == "NO-GO"
    assert secret not in json.dumps(decision)


def test_gate_cli_rejects_report_output_and_authorization_inside_repository_or_worktree(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    worktree = tmp_path / "linked-worktree"
    git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
    report_path = tmp_path / "sanitized-audit.json"
    report_path.write_text(json.dumps(audit.run_audit(repo)), encoding="utf-8")
    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text(
        json.dumps(
            {
                "schema": gate.AUTHORIZATION_SCHEMA,
                "authorized": True,
                "scope": gate.SCOPE_CLEAN_ROOM,
                "source_repository": "example/project",
            }
        ),
        encoding="utf-8",
    )

    attempts = (
        (["--report", str(repo / ".git" / "report.json")], "report.json"),
        (["--report", str(report_path), "--authorization", str(worktree / "authorization.json")], "authorization.json"),
        (
            ["--report", str(report_path), "--output", str(worktree / "gate-decision.json")],
            "gate-decision.json",
        ),
    )
    for arguments, name in attempts:
        status = gate.main(["--root", str(repo), *arguments])
        captured = capsys.readouterr()
        assert status == 2
        assert "gate paths must be outside the repository" in captured.err
        assert str(repo) not in captured.err + captured.out
        assert not (worktree / name).exists()
        assert not (repo / ".git" / name).exists()


def test_gate_cli_writes_sanitized_decision_and_holds_nothing_back_to_console(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "C" * 40
    sensitive_path = "/home/private-user/.env.local"
    username = "synthetic-person-identifier"
    report = run_remote_audit(repo, finding_transport(secret, sensitive_path, username))
    report_path = write_external_report(tmp_path, report)
    decision_path = tmp_path / "gate-decision.json"

    status = gate.main(
        [
            "--root",
            str(repo),
            "--report",
            str(report_path),
            "--github",
            "example/project",
            "--format",
            "json",
            "--output",
            str(decision_path),
        ]
    )
    captured = capsys.readouterr()
    rendered = decision_path.read_text(encoding="utf-8")

    assert status == 0
    assert captured.out == "sanitized publication-gate decision written; raw values and paths suppressed\n"
    assert captured.err == ""
    decision = json.loads(rendered)
    assert decision["verdict"] == "NO-GO"
    assert decision["routes"][gate.SCOPE_IN_PLACE]["verdict"] == gate.VERDICT_NO_GO
    assert decision["maintainer_authorization"]["status"] == "not_recorded"
    for hidden in (secret, sensitive_path, username, str(repo), str(tmp_path), "outside.example"):
        assert hidden not in rendered


def test_gate_cli_without_github_identity_fails_closed_with_no_eligible_route(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    report = run_remote_audit(repo, clean_transport())  # bound to example/project
    report_path = write_external_report(tmp_path, report)
    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text(
        json.dumps(
            {
                "schema": gate.AUTHORIZATION_SCHEMA,
                "authorized": True,
                "scope": gate.SCOPE_CLEAN_ROOM,
                "source_repository": "someone/else",
            }
        ),
        encoding="utf-8",
    )
    decision_path = tmp_path / "gate-decision.json"

    status = gate.main(
        [
            "--root",
            str(repo),
            "--report",
            str(report_path),
            "--authorization",
            str(authorization_path),
            "--output",
            str(decision_path),
        ]
    )
    captured = capsys.readouterr()

    assert status == 0
    assert captured.err == ""
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert "repository_identity_unbound" in decision["report_binding"]["blockers"]
    assert decision["report_binding"]["repository_match"] is None
    assert decision["maintainer_authorization"]["repository_match"] is None
    for route_name, route in decision["routes"].items():
        assert route["verdict"] != gate.VERDICT_CONDITIONALLY_ELIGIBLE, route_name
        assert "repository_identity_unbound" in route["blocking_reasons"]
    assert decision["verdict"] == "NO-GO"
    assert decision["approval_granted_by_gate"] is False


def test_gate_markdown_is_a_safe_summary(tmp_path):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "M" * 40
    report = run_remote_audit(repo, finding_transport(secret, "/home/private-user/.env.local", "synthetic-person"))

    markdown = gate.render_markdown(decide(repo, report))

    assert "Overall verdict: NO-GO" in markdown
    assert "NOT_VERIFIED" in markdown and "OUTSIDE_VERIFIED_SCOPE" in markdown
    assert "digest sha256" in markdown
    assert "private verification authority" in markdown
    assert "Approval granted by this gate: no" in markdown
    assert "live credential review required: yes" in markdown
    assert "separate authorized deactivation/rotation plan" in markdown
    for hidden in (secret, "private-user", "synthetic-person", str(repo)):
        assert hidden not in markdown


def test_gate_cli_rejects_unsupported_report_without_echoing_content(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    sentinel = "ghp_" + "U" * 40
    stale_report = tmp_path / "stale-report.json"
    stale_report.write_text(
        json.dumps({"schema_version": 3, "note": f"legacy report referencing {sentinel}"}),
        encoding="utf-8",
    )

    status = gate.main(["--root", str(repo), "--report", str(stale_report)])
    captured = capsys.readouterr()

    assert status == 2
    assert captured.out == ""
    assert "gate input could not be evaluated; details suppressed" in captured.err
    assert sentinel not in captured.err
    assert str(stale_report) not in captured.err


def test_gate_cli_help_remains_available_in_subprocess(tmp_path):
    result = subprocess.run(
        [sys.executable, str(Path(gate.__file__)), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.startswith("usage:")
    assert "--report" in result.stdout
    assert result.stderr == ""
