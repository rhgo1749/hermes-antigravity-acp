"""Issue #28 main-push policy: real Git ranges, not PR merge-base guesses."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from test_ci_tier_contract import _job_block, _make_scratch_repo, gate_mod, scope_mod


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = _make_scratch_repo(tmp_path)
    monkeypatch.chdir(root)
    return root


def git(root, *args):
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def commit(root, path, text="changed\n"):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "fixture change")
    return git(root, "rev-parse", "HEAD")


def event(before, after):
    return {
        "CI_EVENT": "push", "CI_BEFORE_SHA": before, "CI_AFTER_SHA": after,
        "CI_EXECUTION_SHA": after, "CI_PUSH_REF": "refs/heads/main",
        "CI_PUSH_FORCED": "false", "CI_PUSH_CREATED": "false",
        "CI_PUSH_DELETED": "false",
    }


@pytest.mark.parametrize("path,expected", (
    ("README.md", (False, False)),
    ("docs/한글 with spaces.md", (False, False)),
    ("tests/test_acp_thinking_level.py", (False, False)),
    ("hermes-plugin/antigravity-acp/client.py", (True, False)),
    ("hermes-plugin/antigravity-acp/process_teardown.py", (True, False)),
    ("scripts/acp_probe.py", (True, False)),
    ("scripts/install_official.py", (True, True)),
    ("install-windows.cmd", (True, True)),
    ("antigravity_acp/registry.py", (True, True)),
    (".github/workflows/ci.yml", (True, True)),
    ("tests/test_unknown_native.py", (True, True)),
    ("unknown/new-surface.py", (True, True)),
))
def test_main_push_reuses_reviewed_risk_policy(repo, path, expected):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, path)
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == expected


def test_plugin_with_reviewed_neutral_regression_does_not_pull_arm(repo):
    before = git(repo, "rev-parse", "HEAD")
    commit(repo, "hermes-plugin/antigravity-acp/client.py")
    after = commit(repo, "tests/test_model_surface_selection.py")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, False)


@pytest.mark.parametrize("field", ("CI_BEFORE_SHA", "CI_AFTER_SHA"))
@pytest.mark.parametrize("bad", ("", "0" * 40, "f" * 40, "HEAD", "abc1234", "A" * 40, "--help", None))
def test_invalid_or_missing_push_endpoints_fail_closed(repo, field, bad):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    env = event(before, after)
    env[field] = bad
    result = scope_mod.scope_for_event(env)
    assert (result.os_lanes, result.extended_arm) == (True, True)


@pytest.mark.parametrize("field", (
    "CI_PUSH_FORCED", "CI_PUSH_CREATED", "CI_PUSH_DELETED",
))
@pytest.mark.parametrize("value", ("true", "", "False", None))
def test_created_deleted_forced_or_missing_flags_never_narrow(repo, field, value):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    env = event(before, after)
    env[field] = value
    result = scope_mod.scope_for_event(env)
    assert (result.os_lanes, result.extended_arm) == (True, True)


@pytest.mark.parametrize("field,value", (
    ("CI_EXECUTION_SHA", ""), ("CI_EXECUTION_SHA", "f" * 40),
    ("CI_PUSH_REF", ""), ("CI_PUSH_REF", "refs/heads/other"),
    ("CI_PUSH_REF", "refs/tags/main"),
))
def test_push_execution_and_ref_binding_cannot_be_missing_or_substituted(repo, field, value):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    env = event(before, after)
    env[field] = value
    result = scope_mod.scope_for_event(env)
    assert (result.os_lanes, result.extended_arm) == (True, True)


def test_actual_checkout_must_equal_event_after(repo):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    git(repo, "checkout", "--detach", before)
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


def test_non_ancestor_fails_closed_even_if_forced_flag_claims_false(repo):
    common = git(repo, "rev-parse", "HEAD")
    before = commit(repo, "scripts/install_acp.py", "old side\n")
    git(repo, "checkout", "-qb", "divergent", common)
    after = commit(repo, "README.md")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)
    assert "non-fast-forward" in result.reason


def test_multi_commit_push_includes_sensitive_earlier_commit_not_only_head_parent(repo):
    before = git(repo, "rev-parse", "HEAD")
    commit(repo, "scripts/install_acp.py", "installer change\n")
    after = commit(repo, "README.md")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


def test_two_parent_merge_uses_full_before_after_delta(repo):
    before = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-qb", "feature")
    commit(repo, "scripts/install_acp.py", "feature installer change\n")
    commit(repo, "docs/final.md")
    git(repo, "checkout", "main")
    git(repo, "merge", "--no-ff", "feature", "-m", "fixture merge")
    after = git(repo, "rev-parse", "HEAD")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


@pytest.mark.parametrize("rename", (False, True))
def test_deleted_or_renamed_installer_cannot_hide_behind_docs(repo, rename):
    before = git(repo, "rev-parse", "HEAD")
    if rename:
        (repo / "docs").mkdir()
        git(repo, "mv", "scripts/install_acp.py", "docs/moved.md")
    else:
        git(repo, "rm", "scripts/install_acp.py")
    git(repo, "commit", "-qm", "fixture delete or rename")
    after = git(repo, "rev-parse", "HEAD")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


def test_shallow_repository_is_not_full_history_evidence(repo, tmp_path, monkeypatch):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    clone = tmp_path / "shallow"
    git(repo, "clone", "--quiet", "--depth=2", repo.as_uri(), str(clone))
    monkeypatch.chdir(clone)
    assert git(clone, "rev-parse", "--is-shallow-repository") == "true"
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)
    assert "shallow" in result.reason


def test_empty_push_diff_is_unknown_not_fast(repo):
    before = git(repo, "rev-parse", "HEAD")
    git(repo, "commit", "--allow-empty", "-qm", "fixture empty")
    after = git(repo, "rev-parse", "HEAD")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


@pytest.mark.parametrize("error", (OSError("git unavailable"), subprocess.TimeoutExpired("git", 45), UnicodeError("invalid path encoding")))
def test_push_git_or_decode_failure_falls_back_to_full(repo, monkeypatch, error):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    original = scope_mod.subprocess.run

    def broken(args, *a, **kw):
        if "diff" in args:
            raise error
        return original(args, *a, **kw)

    monkeypatch.setattr(scope_mod.subprocess, "run", broken)
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)
    assert result.reason == "detection-failed-git-error"


def test_annotated_tag_object_cannot_masquerade_as_push_before_commit(repo):
    git(repo, "tag", "-a", "fixture-tag", "-m", "fixture annotated tag")
    before = git(repo, "rev-parse", "fixture-tag")
    after = commit(repo, "README.md")
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)


@pytest.mark.parametrize("raw", ("README.md", "README.md\0\0"))
def test_malformed_diff_output_cannot_silently_drop_paths(repo, monkeypatch, raw):
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "README.md")
    original = scope_mod._push_git

    def output(*args):
        return raw if args[0] == "diff" else original(*args)

    monkeypatch.setattr(scope_mod, "_push_git", output)
    result = scope_mod.scope_for_event(event(before, after))
    assert (result.os_lanes, result.extended_arm) == (True, True)
    assert result.reason == "detection-failed-git-error"


@pytest.mark.parametrize("path", ("docs/name\nwith newline.md", "docs/name\r\nwith CRLF.md"))
def test_real_classifier_cli_outputs_optimized_scope_and_summary(repo, tmp_path, path):
    import os
    import sys

    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, path)
    assert scope_mod._push_git("diff", "--no-renames", "--name-only", "-z", before, after, "--") == path + "\0"
    output, summary = tmp_path / "outputs", tmp_path / "summary.md"
    script = Path(__file__).resolve().parents[1] / "scripts/ci_change_scope.py"
    result = subprocess.run(
        [sys.executable, str(script), "--output", str(output), "--summary", str(summary)],
        cwd=repo, env={**os.environ, **event(before, after)},
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "os_lanes=false\nextended_arm=false\n" in output.read_text()
    assert "none (fast route)" in summary.read_text()


def test_workflow_supplies_trusted_push_fields_and_complete_checkout():
    ci = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
    block = _job_block(ci, "change-scope")
    for setting in (
        "fetch-depth: 0", "ref: ${{ github.sha }}",
        "CI_BEFORE_SHA: ${{ github.event.before }}", "CI_AFTER_SHA: ${{ github.event.after }}",
        "CI_EXECUTION_SHA: ${{ github.sha }}", "CI_PUSH_REF: ${{ github.ref }}",
        "CI_PUSH_FORCED: ${{ toJSON(github.event.forced) }}",
        "CI_PUSH_CREATED: ${{ toJSON(github.event.created) }}",
        "CI_PUSH_DELETED: ${{ toJSON(github.event.deleted) }}",
    ):
        assert setting in block


@pytest.mark.parametrize("result", (None, "skipped", "cancelled", "failure"))
def test_optimized_os_push_still_fails_for_missing_or_skipped_required_lane(result):
    results = {name: {"result": "success"} for name in (
        "change-scope", *gate_mod.FAST_LANES, *gate_mod.OS_LANES,
    )}
    results.update({name: {"result": "skipped"} for name in gate_mod.ARM_LANES})
    if result is None:
        del results["macos-arm64"]
    else:
        results["macos-arm64"] = {"result": result}
    assert not gate_mod.evaluate({"os_lanes": "true", "extended_arm": "false"}, results)[0]
