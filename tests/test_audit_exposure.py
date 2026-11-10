from __future__ import annotations

import base64
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import pytest

from scripts import audit_exposure as audit
from scripts import audit_public_tree


class FakeTransport:
    def __init__(self, handler):
        self.handler = handler
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, headers: dict[str, str], limit: int) -> audit.HttpResponse:
        self.requests.append((url, headers))
        return self.handler(url, headers, limit)


def response(payload, *, link: str = "", content_type: str = "application/json"):
    headers = {"content-type": content_type}
    if link:
        headers["link"] = link
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode()
    else:
        body = json.dumps(payload).encode()
    return audit.HttpResponse(200, headers, body)


def next_page(url: str, page: int = 2) -> str:
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    query["page"] = [str(page)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), ""))


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def make_repo(path: Path, files: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(path)], check=True)
    git(path, "config", "user.name", "Synthetic Audit")
    git(path, "config", "user.email", "synthetic@example.invalid")
    for name, content in (files or {"README.md": "safe example\n"}).items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git(path, "add", "--all")
    git(path, "commit", "--quiet", "-m", "synthetic fixture")
    return path


def commit(path: Path, message: str) -> None:
    git(path, "add", "--all")
    git(path, "commit", "--quiet", "-m", message)


def zip_bytes(files: dict[str, str]) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return target.getvalue()


def make_github_transport(secret: str, sensitive_path: str, username: str) -> FakeTransport:
    repo_prefix = "/repos/example/project"
    commit_sha = "a" * 40
    tree_sha = "b" * 40
    blob_sha = "c" * 40

    def handler(url: str, headers: dict[str, str], _limit: int) -> audit.HttpResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        path = parsed.path
        page = query.get("page", ["1"])[0]
        if path == f"{repo_prefix}/git/matching-refs/":
            if page == "1":
                return response(
                    [{"ref": "refs/heads/main", "object": {"sha": commit_sha, "type": "commit"}}],
                    link=f'<{next_page(url)}>; rel="next"',
                )
            return response([{"ref": "refs/pull/1/head", "object": {"sha": commit_sha, "type": "commit"}}])
        if path == f"{repo_prefix}/git/commits/{commit_sha}":
            return response({"sha": commit_sha, "message": "synthetic commit", "tree": {"sha": tree_sha}, "parents": []})
        if path == f"{repo_prefix}/git/trees/{tree_sha}":
            return response({"tree": [{"path": "docs.txt", "type": "blob", "sha": blob_sha}], "truncated": False})
        if path == f"{repo_prefix}/git/blobs/{blob_sha}":
            content = b"benign remote file"
            return response({"encoding": "base64", "size": len(content), "content": base64.b64encode(content).decode()})
        if path == f"{repo_prefix}/issues":
            if page == "1":
                return response(
                    [{"number": 1, "title": "Synthetic issue", "body": "ordinary text"}],
                    link=f'<{next_page(url)}>; rel="next"',
                )
            return response(
                [{"number": 2, "title": "Synthetic pull request", "body": "ordinary PR text", "pull_request": {"url": "https://api.github.com"}}]
            )
        if path == f"{repo_prefix}/issues/1/comments":
            return response(
                [{
                    "body": f"{secret} at {sensitive_path}; see https://outside.example/private.zip and "
                    "https://github.com/user-attachments/assets/fixture-id",
                    "user": {"login": username},
                }]
            )
        if path == f"{repo_prefix}/issues/2/comments":
            return response([])
        if path == f"{repo_prefix}/pulls/2/reviews":
            return response([{"body": "A harmless review."}])
        if path == f"{repo_prefix}/pulls/2/comments":
            return response([{"body": "Inline note", "path": ".env.local"}])
        if path == f"{repo_prefix}/actions/runs":
            if page == "1":
                return response(
                    {"workflow_runs": [{"id": 100, "name": "Synthetic workflow"}]},
                    link=f'<{next_page(url)}>; rel="next"',
                )
            return response({"workflow_runs": [{"id": 101, "name": "Second workflow"}]})
        if path == f"{repo_prefix}/actions/runs/100/jobs" or path == f"{repo_prefix}/actions/runs/101/jobs":
            return response({"jobs": [{"id": 900, "name": "safe job"}]})
        if path == f"{repo_prefix}/actions/runs/100/logs":
            return response(
                zip_bytes({"step.log": f"workflow output {secret} https://logs.example.invalid/run/one"}),
                content_type="application/zip",
            )
        if path == f"{repo_prefix}/actions/runs/101/logs":
            return response(zip_bytes({"step.txt": "safe workflow output"}), content_type="application/zip")
        if path == f"{repo_prefix}/actions/runs/100/artifacts":
            return response({"artifacts": [
                {"id": 200, "name": "expired", "expired": True},
                {"id": 201, "name": "limited", "expired": False},
            ]})
        if path == f"{repo_prefix}/actions/runs/101/artifacts":
            return response({"artifacts": []})
        if path == f"{repo_prefix}/actions/artifacts/201/zip":
            raise audit.AuditFailure("http_403")
        if path == f"{repo_prefix}/releases":
            if page == "1":
                return response(
                    [{"id": 300, "name": "Synthetic release", "body": "release notes"}],
                    link=f'<{next_page(url)}>; rel="next"',
                )
            return response([{"id": 301, "name": "Second release", "body": "notes"}])
        if path == f"{repo_prefix}/releases/300/assets":
            return response([{"id": 401, "name": "release.zip", "state": "uploaded"}])
        if path == f"{repo_prefix}/releases/301/assets":
            return response([])
        if path == f"{repo_prefix}/releases/assets/401":
            return response(zip_bytes({"notes.txt": "safe release attachment"}), content_type="application/zip")
        if path == "/user-attachments/assets/fixture-id":
            return response(f"attachment {secret}", content_type="text/plain")
        raise AssertionError(f"unexpected route: {path}")

    return FakeTransport(handler)


def test_historical_secret_is_found_when_current_tree_is_clean(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo", {"README.md": "safe\n"})
    secret = "ghp_" + "A" * 32
    (repo / "legacy-private.log").write_text(f"old credential {secret}\n", encoding="utf-8")
    commit(repo, "add historical fixture")
    (repo / "legacy-private.log").unlink()
    commit(repo, "remove historical fixture")

    assert audit_public_tree.scan_repository(repo) == []
    result = audit.run_audit(repo)
    rendered = json.dumps(result, sort_keys=True)
    history = result["sources"]["local_git_history"]

    assert history["partition"][audit.STATUS_FINDING] >= 1
    assert "github_token" in history["finding_rules"]
    assert secret not in rendered
    assert "legacy-private.log" not in rendered
    assert history["partition_valid"] is True
    assert capsys.readouterr().out == ""


def test_shallow_history_is_not_reported_as_clean(tmp_path):
    source = make_repo(tmp_path / "source", {"old.txt": "older state\n"})
    (source / "old.txt").write_text("newer state\n", encoding="utf-8")
    commit(source, "second state")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--quiet", "--depth=1", f"file://{source}", str(shallow)],
        check=True,
        capture_output=True,
    )

    source_report = audit.run_audit(shallow)["sources"]["local_git_history"]

    assert source_report["partition"][audit.STATUS_NOT_VERIFIED] >= 1
    assert source_report["not_verified_reasons"]["shallow_history_boundary"] == 1
    assert source_report["partition_valid"] is True


def test_detached_head_history_is_included_without_named_refs(tmp_path):
    repo = make_repo(tmp_path / "repo", {"private-history.log": "ordinary synthetic file\n"})
    secret = "ghp_" + "D" * 40
    (repo / "private-history.log").write_text(f"old credential {secret}\n", encoding="utf-8")
    commit(repo, "detached fixture")
    branch = git(repo, "branch", "--show-current")
    git(repo, "checkout", "--quiet", "--detach")
    git(repo, "branch", "-D", branch)

    report = audit.run_audit(repo)
    history = report["sources"]["local_git_history"]
    rendered = json.dumps(report)

    assert report["reachability"]["local_ref_count"] == 0
    assert report["reachability"]["local_reachable_commit_count"] >= 1
    assert "github_token" in history["finding_rules"]
    assert secret not in rendered
    assert "private-history.log" not in rendered


def test_missing_git_blob_is_not_verified_and_path_is_suppressed(tmp_path):
    repo = make_repo(tmp_path / "repo", {"private-history.log": "ordinary synthetic file\n"})
    blob = git(repo, "hash-object", "private-history.log")
    object_path = repo / ".git" / "objects" / blob[:2] / blob[2:]
    assert object_path.exists()
    object_path.unlink()

    result = audit.run_audit(repo)
    history = result["sources"]["local_git_history"]
    rendered = json.dumps(result)

    assert history["partition"][audit.STATUS_NOT_VERIFIED] >= 1
    assert history["not_verified_reasons"]["missing_git_object"] >= 1
    assert "private-history.log" not in rendered
    assert history["partition_valid"] is True


def test_dangling_object_store_items_are_outside_verified_scope_not_clean(tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "safe current file\n"})
    secret = "ghp_" + "Z" * 40
    loose = repo / "unreferenced-secret.txt"
    loose.write_text(f"never committed {secret}\n", encoding="utf-8")
    git(repo, "hash-object", "-w", "unreferenced-secret.txt")
    loose.unlink()

    report = audit.run_audit(repo)
    boundary = report["sources"]["local_object_store_boundary"]
    rendered = json.dumps(report, sort_keys=True)

    assert boundary["partition"][audit.STATUS_OUTSIDE_VERIFIED_SCOPE] >= 1
    assert boundary["outside_verified_scope_reasons"]["dangling_object_not_traversed"] >= 1
    assert boundary["partition"][audit.STATUS_CLEAN] == 0
    assert boundary["partition_valid"] is True
    assert boundary["finding_rules"] == {}
    assert "not_requested" not in boundary["not_verified_reasons"]
    assert report["summary"]["partition"][audit.STATUS_OUTSIDE_VERIFIED_SCOPE] >= 1
    assert report["reachability"]["local_dangling_object_count"] >= 1
    for hidden in (secret, "unreferenced-secret.txt"):
        assert hidden not in rendered
        assert hidden not in audit._markdown(report)


def test_report_binds_head_and_ref_snapshot(tmp_path):
    repo = make_repo(tmp_path / "repo")
    head = git(repo, "rev-parse", "HEAD")

    report = audit.run_audit(repo)

    assert report["schema_version"] == 5
    target = report["target"]
    assert target["binding_status"] == "bound"
    assert target["repository"] is None
    assert target["head_oid"] == head
    assert target["ref_count"] >= 1
    assert len(target["ref_digest_sha256"]) == 64
    rendered = audit._markdown(report)
    assert head in rendered
    assert target["ref_digest_sha256"] in rendered


def test_remote_report_records_bound_repository(tmp_path):
    repo = make_repo(tmp_path / "repo")

    def handler(url, _headers, _body):
        path = urlsplit(url).path
        if path == "/repos/example/project/git/matching-refs/":
            return response([])
        if path == "/repos/example/project/issues":
            return response([])
        if path == "/repos/example/project/actions/runs":
            return response({"workflow_runs": []})
        if path == "/repos/example/project/releases":
            return response([])
        if path == "/repos/example/project/secret-scanning/alerts":
            return response([])
        raise AssertionError(f"unexpected path {path}")

    report = audit.run_audit(repo, "example/project", transport=FakeTransport(handler))

    assert report["target"]["repository"] == "example/project"
    assert report["target"]["binding_status"] == "bound"
    assert report["target"]["head_oid"] == git(repo, "rev-parse", "HEAD")


def test_reflog_only_commit_is_outside_verified_scope(tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "safe\n"})
    secret = "ghp_" + "F" * 40
    (repo / "discarded.txt").write_text(f"reflog only {secret}\n", encoding="utf-8")
    commit(repo, "discarded history")
    git(repo, "reset", "--hard", "HEAD~1")

    report = audit.run_audit(repo)
    boundary = report["sources"]["local_object_store_boundary"]
    rendered = json.dumps(report, sort_keys=True)

    assert boundary["outside_verified_scope_reasons"]["unreachable_history_not_traversed"] >= 1
    assert report["reachability"]["local_unreachable_object_count"] >= 1
    assert boundary["partition"][audit.STATUS_CLEAN] == 0
    assert boundary["partition_valid"] is True
    for hidden in (secret, "discarded.txt"):
        assert hidden not in rendered
        assert hidden not in audit._markdown(report)


def test_no_reflogs_fsck_failure_is_not_verified_without_raw_output(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    real_run = audit.subprocess.run

    def fail_no_reflogs(command, *args, **kwargs):
        if "fsck" in command and "--no-reflogs" in command:
            return audit.subprocess.CompletedProcess(command, 1, b"", b"synthetic fsck detail")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(audit.subprocess, "run", fail_no_reflogs)
    report = audit.run_audit(repo)
    boundary = report["sources"]["local_object_store_boundary"]

    assert boundary["not_verified_reasons"] == {"git_fsck_no_reflogs_failed": 1}
    assert "synthetic fsck detail" not in json.dumps(report, sort_keys=True)


def test_object_store_boundary_probe_failure_is_not_verified(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    real_run = audit.subprocess.run

    def fail_fsck(command, *args, **kwargs):
        if "fsck" in command:
            return audit.subprocess.CompletedProcess(command, 1, b"", b"synthetic fsck detail")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(audit.subprocess, "run", fail_fsck)
    report = audit.run_audit(repo)
    boundary = report["sources"]["local_object_store_boundary"]
    rendered = json.dumps(report)

    assert boundary["partition"][audit.STATUS_NOT_VERIFIED] == 1
    assert boundary["not_verified_reasons"] == {"git_fsck_failed": 1}
    assert boundary["partition"][audit.STATUS_CLEAN] == 0
    assert boundary["outside_verified_scope_reasons"] == {}
    assert boundary["partition_valid"] is True
    assert "synthetic fsck detail" not in rendered


@pytest.mark.parametrize(
    ("archive_name", "expected_rule"),
    (("synthetic-release.zip", "local_artifact_filename"), ("synthetic-release.bin", None)),
)
def test_local_deflated_archive_blob_keeps_unverified_boundary(tmp_path, capsys, archive_name, expected_rule):
    secret = "ghp_" + "Q" * 40
    raw_path = f"synthetic-private/{archive_name}"
    content = zip_bytes({"payload.txt": secret})
    assert secret.encode() not in content
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.infolist()[0].compress_type == zipfile.ZIP_DEFLATED

    repo = make_repo(tmp_path / "repo")
    archive_path = repo / raw_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(content)
    commit(repo, "add synthetic archive fixture")

    report = audit.run_audit(repo)
    history = report["sources"]["local_git_history"]
    json_output = json.dumps(report, sort_keys=True)
    markdown_output = audit._markdown(report)

    assert history["not_verified_reasons"]["binary_content"] == 1
    assert history["partition"][audit.STATUS_NOT_VERIFIED] >= 1
    assert history["finding_rules"] == ({expected_rule: 1} if expected_rule else {})
    assert history["partition"][audit.STATUS_FINDING] == (1 if expected_rule else 0)
    assert history["partition_valid"] is True
    assert history["total"] == sum(history["partition"].values())
    for hidden in (secret, raw_path):
        assert hidden not in json_output
        assert hidden not in markdown_output

    assert audit.main(["--root", str(repo), "--format", "markdown"]) == 0
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert raw_path not in captured.out + captured.err


def test_annotated_tags_and_direct_tree_blob_refs_are_scanned(tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "safe current file\n"})
    secret = "ghp_" + "T" * 40
    git(repo, "tag", "-a", "synthetic-tag", "-m", f"tag message {secret}")
    blob = git(repo, "hash-object", "README.md")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    git(repo, "update-ref", "refs/audit/blob", blob)
    git(repo, "update-ref", "refs/audit/tree", tree)

    report = audit.run_audit(repo)
    history = report["sources"]["local_git_history"]
    rendered = json.dumps(report)

    assert report["reachability"]["local_ref_count"] >= 3
    assert "github_token" in history["finding_rules"]
    assert secret not in rendered
    assert history["partition_valid"] is True


def test_local_history_external_urls_are_not_silently_ignored(tmp_path):
    secret = "ghp_" + "E" * 40
    url = f"https://example.invalid/share/{secret}"
    repo = make_repo(tmp_path / "repo", {"README.md": f"Reference: {url}\n"})

    report = audit.run_audit(repo)
    external = report["sources"]["external_references"]
    rendered = json.dumps(report)

    assert external["partition"][audit.STATUS_NOT_VERIFIED] > 0
    assert "external_reference_not_fetched" in external["not_verified_reasons"]
    assert url not in rendered
    assert secret not in rendered


def test_paginated_github_audit_covers_assets_and_redacts_all_outputs(tmp_path):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "S" * 40
    sensitive_path = "/home/private-user/.env.local"
    username = "synthetic-person-identifier"
    transport = make_github_transport(secret, sensitive_path, username)

    report = audit.run_audit(
        repo,
        "example/project",
        token="synthetic-read-only-token",
        transport=transport,
    )
    json_output = json.dumps(report, sort_keys=True)
    markdown_output = audit._markdown(report)
    report_artifact = tmp_path / "sanitized-report.json"
    report_artifact.write_text(json_output, encoding="utf-8")

    assert report["reachability"]["github_ref_count"] == 2
    assert report["reachability"]["github_reachable_commit_count"] == 1
    assert report["sources"]["github_refs"]["pages"] == {"requested": 2, "succeeded": 2}
    assert report["sources"]["github_discussions"]["pages"]["requested"] >= 4
    assert report["sources"]["github_reviews"]["partition"][audit.STATUS_FINDING] == 0
    assert report["sources"]["github_inline_comments"]["partition"][audit.STATUS_FINDING] == 1
    assert report["sources"]["github_action_logs"]["partition"][audit.STATUS_FINDING] == 1
    assert report["sources"]["github_action_artifacts"]["not_verified_reasons"]["artifact_expired"] == 1
    assert report["sources"]["github_action_artifacts"]["not_verified_reasons"]["http_403"] == 1
    assert report["sources"]["github_releases"]["pages"] == {"requested": 2, "succeeded": 2}
    assert report["sources"]["external_references"]["partition"][audit.STATUS_FINDING] == 1
    assert report["sources"]["external_references"]["partition"][audit.STATUS_NOT_VERIFIED] == 2
    assert all(source["partition_valid"] for source in report["sources"].values())
    assert "external_reference_not_fetched" in report["sources"]["external_references"]["not_verified_reasons"]
    for hidden in (
        secret,
        sensitive_path,
        username,
        "outside.example",
        "logs.example.invalid",
        "fixture-id",
        "synthetic-read-only-token",
    ):
        assert hidden not in json_output
        assert hidden not in markdown_output
        assert hidden not in report_artifact.read_text(encoding="utf-8")
    assert all("Authorization" in headers for url, headers in transport.requests if "api.github.com" in url)
    attachment_headers = [headers for url, headers in transport.requests if "user-attachments" in url]
    assert attachment_headers and all("Authorization" not in headers for headers in attachment_headers)
    assert len([url for url, _ in transport.requests if "page=2" in url]) >= 3


def test_pagination_permission_failure_counts_an_unverified_boundary():
    surface = audit.AuditSurface("fixture")
    calls = 0

    def handler(url, _headers, _limit):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response([{"id": 1}], link=f'<{next_page(url)}>; rel="next"')
        raise audit.AuditFailure("http_403")

    client = audit.GitHubClient("example/project", transport=FakeTransport(handler))
    pages = list(client.pages(client.api_url("/issues?per_page=100"), surface))

    assert pages == [[{"id": 1}]]
    assert surface.pages_requested == 2
    assert surface.pages_succeeded == 1
    assert surface.collections_incomplete == 1
    assert surface.not_verified == 1
    assert surface.reasons == {"http_403": 1}
    assert surface.total == surface.checked_no_finding + surface.finding + surface.not_verified


def test_inaccessible_remote_ref_collection_is_not_verified(tmp_path):
    repo = make_repo(tmp_path / "repo")

    def handler(url, _headers, _limit):
        path = urlsplit(url).path
        if path.endswith("/git/matching-refs/"):
            raise audit.AuditFailure("http_403")
        if path.endswith(("/issues", "/releases")):
            return response([])
        if path.endswith("/actions/runs"):
            return response({"workflow_runs": []})
        raise AssertionError(path)

    report = audit.run_audit(
        repo,
        "example/project",
        transport=FakeTransport(handler),
    )

    refs = report["sources"]["github_refs"]
    assert refs["not_verified_reasons"]["http_403"] == 1
    assert refs["partition"][audit.STATUS_CLEAN] == 0
    assert refs["partition_valid"] is True


def test_remote_blob_size_mismatch_preserves_path_finding_and_gap():
    content = b"truncated synthetic blob"
    transport = FakeTransport(
        lambda _url, _headers, _limit: response(
            {
                "encoding": "base64",
                "size": len(content) + 1,
                "content": base64.b64encode(content).decode(),
            }
        )
    )
    surfaces = audit._new_surfaces()
    tracker = audit.ExternalReferenceTracker(surfaces["external_references"])
    client = audit.GitHubClient("example/project", transport=transport)
    remote = audit.GitHubAuditor(client, surfaces, tracker)

    remote._scan_remote_blob("a" * 40, ".env.local", surfaces["github_history"])
    history = surfaces["github_history"].to_dict()

    assert history["partition"][audit.STATUS_FINDING] == 1
    assert history["partition"][audit.STATUS_NOT_VERIFIED] == 1
    assert history["finding_rules"] == {"sensitive_filename": 1}
    assert history["finding_classes"] == {
        "assoc=general_path__env_name|ctx=general_path|fam=env_name|locator=remote_blob_path": 1
    }
    assert history["not_verified_reasons"]["invalid_blob_content"] == 1
    assert history["partition_valid"] is True


@pytest.mark.parametrize(
    ("archive_name", "expected_rule"),
    (("synthetic-release.zip", "local_artifact_filename"), ("synthetic-release.bin", None)),
)
def test_remote_deflated_archive_blob_keeps_unverified_boundary(
    tmp_path, capsys, monkeypatch, archive_name, expected_rule
):
    secret = "ghp_" + "V" * 40
    raw_path = f"synthetic-private/{archive_name}"
    content = zip_bytes({"payload.txt": secret})
    assert secret.encode() not in content
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.infolist()[0].compress_type == zipfile.ZIP_DEFLATED

    repo = make_repo(tmp_path / "repo")
    transport = FakeTransport(
        lambda _url, _headers, _limit: response(
            {"encoding": "base64", "size": len(content), "content": base64.b64encode(content).decode()}
        )
    )
    surfaces = audit._new_surfaces()
    tracker = audit.ExternalReferenceTracker(surfaces["external_references"])
    client = audit.GitHubClient("example/project", transport=transport)
    remote = audit.GitHubAuditor(client, surfaces, tracker)

    remote._scan_remote_blob("a" * 40, raw_path, surfaces["github_history"])
    local = audit.GitHistoryAuditor(repo, surfaces["local_git_history"], tracker)
    report = audit._report(
        surfaces,
        local,
        repository_requested=True,
        authenticated=False,
        remote=remote,
    )
    history = report["sources"]["github_history"]
    json_output = json.dumps(report, sort_keys=True)
    markdown_output = audit._markdown(report)

    assert history["not_verified_reasons"]["binary_content"] == 1
    assert history["partition"][audit.STATUS_NOT_VERIFIED] == 1
    assert history["finding_rules"] == ({expected_rule: 1} if expected_rule else {})
    assert history["partition"][audit.STATUS_FINDING] == (1 if expected_rule else 0)
    assert history["partition_valid"] is True
    assert history["total"] == sum(history["partition"].values())
    for hidden in (secret, raw_path):
        assert hidden not in json_output
        assert hidden not in markdown_output

    monkeypatch.setattr(audit, "run_audit", lambda *_args, **_kwargs: report)
    assert audit.main(["--root", str(repo), "--format", "markdown"]) == 0
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert raw_path not in captured.out + captured.err


def test_redirect_drops_credentials_cross_host_and_rejects_unknown_hosts():
    handler = audit._SafeRedirectHandler()
    client = audit.GitHubClient("example/project", transport=FakeTransport(lambda *_: response("")))
    assert not client._validated_url(
        "https://github.com/user-attachments/files/123/report.pdf",
        allow_attachment=True,
    )
    request = audit.Request(
        "https://api.github.com/repos/example/project/actions",
        headers={"Authorization": "Bearer synthetic-token"},
        method="GET",
    )

    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://release-assets.githubusercontent.com/archive.zip",
    )

    assert redirected is not None
    assert all(key.lower() != "authorization" for key, _ in redirected.header_items())
    with pytest.raises(audit.AuditFailure) as failure:
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://untrusted.example/archive.zip",
        )
    assert failure.value.reason == "unsafe_redirect"


def test_cli_suppresses_unexpected_exception_details(tmp_path, capsys, monkeypatch):
    secret = "ghp_" + "R" * 40
    raw_path = "private-user/.env.local"

    def fail(*_args, **_kwargs):
        raise RuntimeError(f"{secret} {raw_path}")

    monkeypatch.setattr(audit, "run_audit", fail)
    result = audit.main(["--root", str(tmp_path)])
    captured = capsys.readouterr()

    assert result == 2
    assert captured.out == ""
    assert "audit failed; details suppressed" in captured.err
    assert secret not in captured.err
    assert raw_path not in captured.err


def _run_audit_cli(cwd, *arguments):
    result = subprocess.run(
        [sys.executable, str(Path(audit.__file__)), *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result


def _audit_cli_error_is_sanitized(cwd, arguments, sentinels=()):
    result = _run_audit_cli(cwd, *arguments)
    output_is_sanitized = (
        result.stdout == ""
        and result.stderr == "audit arguments invalid; details suppressed\n"
        and not any(sentinel in result.stdout + result.stderr for sentinel in sentinels)
    )

    return result.returncode == 2 and output_is_sanitized


def test_cli_suppresses_invalid_choice_value_in_subprocess(tmp_path):
    token_sentinel = "ghp_" + "T" * 40
    error_is_sanitized = _audit_cli_error_is_sanitized(
        tmp_path,
        ("--format", token_sentinel),
        (token_sentinel,),
    )
    del token_sentinel

    assert error_is_sanitized, "argparse diagnostics must use the fixed safe message"


def test_cli_suppresses_unknown_option_and_private_path_in_subprocess(tmp_path):
    private_path_sentinel = "/synthetic-home/private-user/.config/credentials.json"
    error_is_sanitized = _audit_cli_error_is_sanitized(
        tmp_path,
        ("--unexpected-option", private_path_sentinel),
        ("--unexpected-option", private_path_sentinel),
    )
    del private_path_sentinel

    assert error_is_sanitized, "argparse diagnostics must use the fixed safe message"


def test_cli_suppresses_missing_value_error_in_subprocess(tmp_path):
    error_is_sanitized = _audit_cli_error_is_sanitized(tmp_path, ("--github",))

    assert error_is_sanitized, "argparse diagnostics must use the fixed safe message"


def test_cli_help_remains_available_in_subprocess(tmp_path):
    result = _run_audit_cli(tmp_path, "--help")
    help_is_available = (
        result.returncode == 0
        and result.stdout.startswith("usage:")
        and "--format" in result.stdout
        and result.stderr == ""
    )

    assert help_is_available, "argparse --help must remain available"


def test_cli_rejects_report_output_inside_repository(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    worktree = tmp_path / "linked-worktree"
    git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
    outputs = (
        (worktree, worktree / "linked-worktree-report.json"),
        (repo, worktree / "sibling-worktree-report.json"),
        (worktree, repo / ".git" / "sanitized-report.json"),
    )

    for root, output in outputs:
        result = audit.main(["--root", str(root), "--output", str(output)])
        captured = capsys.readouterr()

        assert result == 2
        assert not output.exists()
        assert "audit output path must be outside the repository" in captured.err
        assert str(repo) not in captured.err


def test_cli_fails_closed_when_linked_worktree_inventory_is_unavailable(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    worktree = tmp_path / "linked-worktree"
    git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
    output = worktree / "sanitized-report.json"
    real_run = audit.subprocess.run

    def fail_worktree_list(command, *args, **kwargs):
        if "worktree" in command and "list" in command:
            return audit.subprocess.CompletedProcess(command, 1, "", "unavailable")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(audit.subprocess, "run", fail_worktree_list)
    result = audit.main(["--root", str(repo), "--output", str(output)])
    captured = capsys.readouterr()

    assert result == 2
    assert not output.exists()
    assert "audit output location could not be validated" in captured.err
    assert "unavailable" not in captured.err


def test_truncated_remote_tree_and_missing_logs_remain_not_verified(tmp_path):
    repo = make_repo(tmp_path / "repo")
    commit_sha = "d" * 40
    tree_sha = "e" * 40
    blob_sha = "f" * 40
    prefix = "/repos/example/project"

    def handler(url, _headers, _limit):
        path = urlsplit(url).path
        if path == f"{prefix}/git/matching-refs/":
            return response([{"ref": "refs/heads/main", "object": {"sha": commit_sha, "type": "commit"}}])
        if path == f"{prefix}/git/commits/{commit_sha}":
            return response({"tree": {"sha": tree_sha}, "parents": []})
        if path == f"{prefix}/git/trees/{tree_sha}":
            return response({"tree": [{"path": "item.txt", "type": "blob", "sha": blob_sha}], "truncated": True})
        if path == f"{prefix}/git/blobs/{blob_sha}":
            content = b"visible part"
            return response({"encoding": "base64", "size": len(content), "content": base64.b64encode(content).decode()})
        if path == f"{prefix}/issues":
            return response([])
        if path == f"{prefix}/actions/runs":
            return response({"workflow_runs": [{"id": 500}]})
        if path == f"{prefix}/actions/runs/500/jobs":
            return response({"jobs": []})
        if path == f"{prefix}/actions/runs/500/logs":
            raise audit.AuditFailure("http_404")
        if path == f"{prefix}/actions/runs/500/artifacts":
            raise audit.AuditFailure("http_403")
        if path == f"{prefix}/releases":
            return response([])
        raise AssertionError(path)

    report = audit.run_audit(
        repo,
        "example/project",
        transport=FakeTransport(handler),
    )

    assert report["sources"]["github_history"]["not_verified_reasons"]["truncated_tree"] == 1
    assert report["sources"]["github_action_logs"]["not_verified_reasons"]["http_404"] == 1
    assert report["sources"]["github_action_artifacts"]["not_verified_reasons"]["http_403"] == 1
    assert all(source["partition_valid"] for source in report["sources"].values())


def test_external_exception_text_and_current_tree_ci_output_are_sanitized(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "Q" * 40
    raw_path = "logs/private-runtime.log"

    class LeakyTransport:
        def get(self, _url, _headers, _limit):
            raise RuntimeError(f"{secret} {raw_path}")

    surface = audit.AuditSurface("safe-errors")
    client = audit.GitHubClient("example/project", transport=LeakyTransport())
    with pytest.raises(audit.AuditFailure) as failure:
        client.get_json(client.api_url("/issues"), surface)
    assert failure.value.reason == "transport_error"
    assert secret not in str(failure.value)
    assert raw_path not in str(failure.value)

    (repo / ".env.local").write_text(f"{secret}\n", encoding="utf-8")
    assert audit_public_tree.main(["--root", str(repo)]) == 1
    output = capsys.readouterr().out

    assert "sensitive_filename=1" in output
    assert secret not in output
    assert ".env.local" not in output
    assert "private-runtime.log" not in output


def test_benign_examples_are_not_reported_as_findings():
    benign = "https://github.com/agentclientprotocol/registry and YOUR_API_KEY"
    assert audit._text_rules(benign) == set()
    report = audit.AuditSurface("benign")
    report.record(audit._text_rules(benign))
    assert report.checked_no_finding == 1
    assert report.finding == 0
    assert report.total == report.checked_no_finding + report.finding + report.not_verified


MIXED_CLASS_FIXTURE_FILES = {
    "examples/credentials.json": '{"client": "synthetic-public-example"}\n',
    "tests/fixtures/.env.test": "SYNTHETIC_VALUE=not-a-real-secret\n",
    "reports/nightly.log": "ordinary build output\n",
    "tls/deploy.pem": "synthetic placeholder body\n",
    ".env": "SYNTHETIC_DEPLOY_MARKER=definitely-not-a-real-secret\n",
    "docs/notes.md": "The runtime watches client_secret.json during deployment.\n",
}

MIXED_CLASS_LOCAL_SIGNATURES = {
    "assoc=example_fixture_path__credential_json_name|ctx=example_fixture_path|fam=credential_json_name|locator=git_blob_content",
    "assoc=example_fixture_path__env_name|ctx=example_fixture_path|fam=env_name|locator=git_blob_content",
    "assoc=general_path__credential_json_name|ctx=general_path|fam=credential_json_name|locator=git_blob_content",
    "assoc=general_path__env_name|ctx=general_path|fam=env_name|locator=git_blob_content",
    "assoc=general_path__key_material_suffix|ctx=general_path|fam=key_material_suffix|locator=git_blob_content",
    "assoc=general_path__ordinary_artifact_suffix|ctx=general_path|fam=ordinary_artifact_suffix|locator=git_blob_content",
}

MIXED_CLASS_HIDDEN_VALUES = (
    "examples/credentials.json",
    "credentials.json",
    "tests/fixtures",
    ".env.test",
    ".env",
    "tls/deploy.pem",
    "deploy.pem",
    "reports/nightly.log",
    "nightly.log",
    "SYNTHETIC_VALUE",
    "SYNTHETIC_DEPLOY_MARKER",
    "not-a-real-secret",
    "definitely-not-a-real-secret",
    "client_secret.json",
)


def assert_sanitized_audit_rendering(report: dict, tmp_path: Path) -> str:
    rendered = json.dumps(report, sort_keys=True)
    markdown = audit._markdown(report)
    for hidden in (*MIXED_CLASS_HIDDEN_VALUES, str(tmp_path)):
        assert hidden not in rendered
        assert hidden not in markdown
    return rendered


def test_item_classes_separate_example_paths_from_potential_indicators(tmp_path):
    repo = make_repo(tmp_path / "repo", MIXED_CLASS_FIXTURE_FILES)

    report = audit.run_audit(repo)

    history = report["sources"]["local_git_history"]
    classes = history["finding_classes"]
    assert history["partition"][audit.STATUS_FINDING] == len(MIXED_CLASS_LOCAL_SIGNATURES)
    assert sum(classes.values()) == history["partition"][audit.STATUS_FINDING]
    assert set(classes) == MIXED_CLASS_LOCAL_SIGNATURES
    assert all(count == 1 for count in classes.values())
    # Example/test-fixture naming is separated from general-context indicators,
    # and key material is separated from ordinary artifact suffixes.
    assert classes[
        "assoc=example_fixture_path__env_name|ctx=example_fixture_path|fam=env_name|locator=git_blob_content"
    ] == 1
    assert classes[
        "assoc=general_path__env_name|ctx=general_path|fam=env_name|locator=git_blob_content"
    ] == 1
    assert classes[
        "assoc=general_path__key_material_suffix|ctx=general_path|fam=key_material_suffix|locator=git_blob_content"
    ] == 1
    assert classes[
        "assoc=general_path__ordinary_artifact_suffix|ctx=general_path|fam=ordinary_artifact_suffix|locator=git_blob_content"
    ] == 1
    assert history["partition_valid"] is True
    assert sum(report["summary"]["finding_classes"].values()) == report["summary"]["partition"][
        audit.STATUS_FINDING
    ]
    assert_sanitized_audit_rendering(report, tmp_path)


def test_per_match_context_association_prevents_context_swap(tmp_path, capsys):
    secret_value = "SYNTHETIC_CONTEXT_SWAP_VALUE"
    files = {
        "config/credentials.json": f"{secret_value} See examples/nightly.log\n",
        "examples/credentials.json": f"{secret_value} See config/nightly.log\n",
    }
    repo = make_repo(tmp_path / "repo", files)

    report = audit.run_audit(repo)
    assert report["schema_version"] == 5
    history = report["sources"]["local_git_history"]
    signatures = history["finding_classes"]

    assert capsys.readouterr().out == ""
    assert len(signatures) == 2
    assert sum(signatures.values()) == history["partition"][audit.STATUS_FINDING] == 2
    assert all(count == 1 for count in signatures.values())

    by_association = {
        frozenset(token for token in signature.split("|") if token.startswith("assoc=")): count
        for signature, count in signatures.items()
    }
    assert by_association == {
        frozenset(
            {
                "assoc=general_path__credential_json_name",
                "assoc=example_fixture_path__ordinary_artifact_suffix",
            }
        ): 1,
        frozenset(
            {
                "assoc=example_fixture_path__credential_json_name",
                "assoc=general_path__ordinary_artifact_suffix",
            }
        ): 1,
    }
    flattened_signatures = {
        frozenset(token for token in signature.split("|") if not token.startswith("assoc="))
        for signature in signatures
    }
    assert len(flattened_signatures) == 1

    json_output = json.dumps(report, sort_keys=True)
    markdown_output = audit._markdown(report)
    assert "assoc=general_path__credential_json_name" in markdown_output
    assert "assoc=example_fixture_path__credential_json_name" in markdown_output
    output_path = tmp_path / "sanitized-context-swap.json"
    status = audit.main(["--root", str(repo), "--format", "json", "--output", str(output_path)])
    captured = capsys.readouterr()
    cli_output = output_path.read_text(encoding="utf-8")

    assert status == 0
    assert captured.out == "sanitized audit report written; raw values and paths suppressed\n"
    assert captured.err == ""
    for rendered in (json_output, markdown_output, cli_output, captured.out, captured.err):
        for hidden in (
            secret_value,
            "config/credentials.json",
            "examples/credentials.json",
            "examples/nightly.log",
            "config/nightly.log",
            str(repo),
            str(tmp_path),
        ):
            assert hidden not in rendered


def test_bare_text_name_inherits_source_path_context(tmp_path):
    repo = make_repo(
        tmp_path / "repo",
        {
            "config/notes.md": "Synthetic documentation mentions .env in an example.\n",
            "examples/notes.md": "Synthetic documentation mentions .env in an example.\n",
        },
    )

    report = audit.run_audit(repo)
    classes = report["sources"]["local_git_history"]["finding_classes"]

    assert classes == {
        "assoc=example_fixture_path__env_name|ctx=example_fixture_path|fam=env_name|locator=git_blob_content": 1,
        "assoc=general_path__env_name|ctx=general_path|fam=env_name|locator=git_blob_content": 1,
    }


def test_cli_writes_item_classes_without_raw_paths_or_values(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo", MIXED_CLASS_FIXTURE_FILES)
    output = tmp_path / "sanitized-audit.json"

    status = audit.main(["--root", str(repo), "--format", "json", "--output", str(output)])
    captured = capsys.readouterr()
    text = output.read_text(encoding="utf-8")

    assert status == 0
    assert captured.out == "sanitized audit report written; raw values and paths suppressed\n"
    assert captured.err == ""
    assert "fam=key_material_suffix" in text
    assert "ctx=example_fixture_path" in text
    for hidden in (*MIXED_CLASS_HIDDEN_VALUES, str(repo), str(tmp_path)):
        assert hidden not in text


def test_github_item_classes_separate_examples_from_indicators_and_redact_values(tmp_path):
    repo = make_repo(tmp_path / "repo")
    secret = "ghp_" + "X" * 40
    prefix = "/repos/example/project"
    commit_sha = "1" * 40
    tree_sha = "2" * 40
    example_blob = "3" * 40
    key_blob = "4" * 40
    env_blob = "5" * 40

    def blob_response(content: bytes):
        return response(
            {"encoding": "base64", "size": len(content), "content": base64.b64encode(content).decode()}
        )

    def handler(url, _headers, _limit):
        path = urlsplit(url).path
        if path == f"{prefix}/git/matching-refs/":
            return response([{"ref": "refs/heads/main", "object": {"sha": commit_sha, "type": "commit"}}])
        if path == f"{prefix}/git/commits/{commit_sha}":
            return response({"sha": commit_sha, "message": "synthetic", "tree": {"sha": tree_sha}, "parents": []})
        if path == f"{prefix}/git/trees/{tree_sha}":
            return response(
                {
                    "tree": [
                        {"path": "tests/fixtures/credentials.json", "type": "blob", "sha": example_blob},
                        {"path": "secrets/deploy.pem", "type": "blob", "sha": key_blob},
                        {"path": "runtime/.env", "type": "blob", "sha": env_blob},
                    ],
                    "truncated": False,
                }
            )
        if path == f"{prefix}/git/blobs/{example_blob}":
            return blob_response(b"synthetic example fixture\n")
        if path == f"{prefix}/git/blobs/{key_blob}":
            return blob_response(b"placeholder body\n")
        if path == f"{prefix}/git/blobs/{env_blob}":
            return blob_response(b"SYNTHETIC_VALUE=placeholder\n")
        if path == f"{prefix}/issues":
            return response(
                [{"number": 1, "title": "mentions runtime/.env rotation", "body": f"rotate {secret} now"}]
            )
        if path == f"{prefix}/issues/1/comments":
            return response([])
        if path == f"{prefix}/actions/runs":
            return response({"workflow_runs": []})
        if path == f"{prefix}/releases":
            return response([])
        raise AssertionError(path)

    report = audit.run_audit(
        repo,
        "example/project",
        token="synthetic-read-only-token",
        transport=FakeTransport(handler),
    )

    history = report["sources"]["github_history"]
    discussions = report["sources"]["github_discussions"]
    assert history["finding_classes"][
        "assoc=example_fixture_path__credential_json_name|ctx=example_fixture_path|fam=credential_json_name|locator=remote_blob_content"
    ] == 1
    assert history["finding_classes"][
        "assoc=general_path__key_material_suffix|ctx=general_path|fam=key_material_suffix|locator=remote_blob_content"
    ] == 1
    assert history["finding_classes"][
        "assoc=general_path__env_name|ctx=general_path|fam=env_name|locator=remote_blob_content"
    ] == 1
    assert any(signature.endswith("locator=github_record") for signature in history["finding_classes"])
    assert sum(history["finding_classes"].values()) == history["partition"][audit.STATUS_FINDING]
    discussion_classes = discussions["finding_classes"]
    assert discussion_classes == {
        "assoc=general_path__env_name|ctx=general_path|fam=content_rule|fam=env_name|locator=github_record": 1
    }
    assert discussions["finding_rules"]["github_token"] == 1
    json_output = json.dumps(report, sort_keys=True)
    markdown_output = audit._markdown(report)
    for hidden in (
        secret,
        "tests/fixtures/credentials.json",
        "credentials.json",
        "secrets/deploy.pem",
        "deploy.pem",
        "runtime/.env",
        "SYNTHETIC_VALUE",
        "synthetic-read-only-token",
        str(tmp_path),
    ):
        assert hidden not in json_output
        assert hidden not in markdown_output
    assert all(source["partition_valid"] for source in report["sources"].values())


def test_unverified_items_never_gain_item_classes(tmp_path):
    repo = make_repo(tmp_path / "repo", MIXED_CLASS_FIXTURE_FILES)

    report = audit.run_audit(repo)

    for source in report["sources"].values():
        assert sum(source["finding_classes"].values()) == source["partition"][audit.STATUS_FINDING]
        if source["partition"][audit.STATUS_FINDING] == 0:
            assert source["finding_classes"] == {}
    history = report["sources"]["github_history"]
    assert history["partition"][audit.STATUS_NOT_VERIFIED] == 1
    assert history["not_verified_reasons"] == {"not_requested": 1}
    assert history["finding_classes"] == {}


def test_class_tokens_are_fixed_vocabulary_and_never_echo_raw_values():
    surface = audit.AuditSurface("classes")

    surface.record(
        {"sensitive_filename"},
        classes=[
            "locator=git_blob_content",
            "ctx=general_path",
            "assoc=general_path__credential_json_name",
            "assoc=general_path__private_user",
            "fam=/home/private-user/.env",
            "ghp_secrettoken",
        ],
    )
    surface.record_not_verified("http_403")
    payload = surface.to_dict()

    assert payload["finding_classes"] == {
        "assoc=general_path__credential_json_name|ctx=general_path|locator=git_blob_content": 1
    }
    assert "/home/private-user/.env" not in json.dumps(payload)
    assert "ghp_secrettoken" not in json.dumps(payload)
    assert payload["partition"][audit.STATUS_NOT_VERIFIED] == 1


# ---------------------------------------------------------------------------
# historical reference (Lane B): evidence-hygiene gate over the public repository audit.
# Planted SYNTHETIC credential material must be flagged; the CI-visible output
# must carry rule names and counts only - never the planted value, never the
# finding path; and a clean tree must exit 0 with zero findings.
# ---------------------------------------------------------------------------


def test_planted_synthetic_tokens_flagged_and_output_suppresses_paths_and_values(tmp_path, capsys):
    secret_access = "ya29." + "a" * 28
    secret_client = "GOCSPX-" + "b" * 20
    repo = make_repo(tmp_path / "repo", {"README.md": "safe example\n"})
    notes = repo / "src" / "release_notes.txt"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text(f"header\ntoken {secret_access} alt {secret_client}\n", encoding="utf-8")
    commit(repo, "plant synthetic credential fixtures")

    findings = audit_public_tree.scan_repository(repo)
    by_path = {finding.relative_path: finding.rule for finding in findings}
    assert by_path.get("src/release_notes.txt") == "google_access_token" or any(
        finding.relative_path == "src/release_notes.txt"
        and finding.rule == "google_access_token"
        for finding in findings
    ), findings
    assert any(
        finding.relative_path == "src/release_notes.txt"
        and finding.rule == "google_client_secret"
        for finding in findings
    ), findings

    capsys.readouterr()
    assert audit_public_tree.main(["--root", str(repo)]) == 1
    out = capsys.readouterr().out
    # Values and paths stay out of the emitted summary; only rule names/counts.
    assert secret_access not in out
    assert secret_client not in out
    assert "release_notes.txt" not in out
    assert "google_access_token" in out
    assert "google_client_secret" in out


def test_clean_public_tree_exits_zero_with_zero_findings(tmp_path, capsys):
    repo = make_repo(
        tmp_path / "repo",
        {
            "README.md": "safe example\n",
            "docs/guide.md": "no secrets here, only prose about the ACP protocol\n",
        },
    )
    assert audit_public_tree.scan_repository(repo) == []
    capsys.readouterr()
    assert audit_public_tree.main(["--root", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "clean" in out
