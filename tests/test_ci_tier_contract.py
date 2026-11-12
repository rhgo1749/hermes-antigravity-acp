"""Issue #9 contract: the CI tier split must stay honest and fail-closed.

The workflow is deliberately text-asserted (no YAML parser dependency in
the credential-free lane, same style as test_hosted_clean_room_ci.py):

* the six pre-existing job display names are preserved verbatim so an
  existing required-check configuration keeps resolving during migration;
* `CI gate` always runs, needs every lane, and its checker script fails
  closed on any lane that the detected scope required and then failed,
  was skipped, or never reported;
* the extended ARM lanes (Windows ARM64, Linux aarch64) are conditional
  on the packaging-scope output, never unconditional on ordinary PRs;
* the change classifier only ever WIDENS validation: unknown paths, empty
  diffs, and detection failures fall back to the strongest scope;
* the distribution registry keeps all five native targets — CI tiers may
  not trim the support surface;
* test auto-discovery in the fake-acp lane is unchanged (single
  documented upstream-venv-only --ignore).
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


scope_mod = _load("ci_change_scope_contract", ROOT / "scripts" / "ci_change_scope.py")
gate_mod = _load("ci_gate_check_contract", ROOT / "scripts" / "ci_gate_check.py")
from antigravity_acp.registry import _DISTRIBUTIONS  # noqa: E402


@pytest.fixture(scope="module")
def ci() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def _job_block(ci: str, job_id: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_id)}:\n(?:.*\n)*?(?=^  \S|\Z)", ci, re.M
    )
    assert match, f"job '{job_id}' must exist in .github/workflows/ci.yml"
    return match.group(0)


# -- preserved check names (branch-protection migration safety) ---------

PRESERVED_NAMES = (
    "name: Fake ACP regressions and static checks",
    "name: Fresh-UID clean room with official ACP binary (ubuntu-24.04)",
    "name: Windows install and unauthenticated ACP (x64)",
    "name: Windows install and unauthenticated ACP (arm64)",
    "name: Vanilla NousResearch Hermes provider API",
    "name: Catalog admission + seam at Hermes floor v0.21.6",
)


def test_existing_check_names_are_preserved_verbatim(ci: str) -> None:
    for name in PRESERVED_NAMES:
        assert name in ci, f"required-check name drifted: {name!r}"


def test_gate_check_name_is_stable(ci: str) -> None:
    assert "name: CI gate" in ci


# -- tier wiring ---------------------------------------------------------

ALL_LANES = (
    "change-scope",
    "fake-acp",
    "acp-clean-room",
    "windows-x64",
    "windows-arm64",
    "macos-arm64",
    "linux-aarch64",
    "upstream-hermes-compat",
    "catalog-floor-gate",
)


def test_gate_always_runs_and_needs_every_lane(ci: str) -> None:
    block = _job_block(ci, "ci-gate")
    assert "if: always()" in block
    needs = re.search(r"needs:\s*\[([^\]]+)\]", block)
    assert needs, "ci-gate must declare a needs list"
    listed = {item.strip() for item in needs.group(1).split(",")}
    assert listed == set(ALL_LANES), listed


def test_fast_lanes_are_unconditional(ci: str) -> None:
    for job_id in ("fake-acp", "upstream-hermes-compat", "catalog-floor-gate"):
        block = _job_block(ci, job_id)
        assert "if: needs" not in block, f"{job_id} must not be conditional"


def test_os_lanes_gate_on_os_scope(ci: str) -> None:
    for job_id in ("acp-clean-room", "windows-x64", "macos-arm64"):
        block = _job_block(ci, job_id)
        assert "needs: change-scope" in block
        assert "if: needs.change-scope.outputs.os_lanes == 'true'" in block


def test_arm_lanes_gate_on_packaging_scope(ci: str) -> None:
    for job_id in ("windows-arm64", "linux-aarch64"):
        block = _job_block(ci, job_id)
        assert "needs: change-scope" in block
        assert "if: needs.change-scope.outputs.extended_arm == 'true'" in block


def test_native_runner_labels(ci: str) -> None:
    assert "runs-on: macos-15" in _job_block(ci, "macos-arm64")
    assert "runs-on: ubuntu-24.04-arm" in _job_block(ci, "linux-aarch64")
    assert "runs-on: windows-11-arm" in _job_block(ci, "windows-arm64")
    assert "runs-on: windows-2022" in _job_block(ci, "windows-x64")


def test_macos_and_linux_arm_lanes_execute_full_lifecycle(ci: str) -> None:
    for job_id in ("macos-arm64", "linux-aarch64"):
        block = _job_block(ci, job_id)
        for step in (
            "install_official.py --prefix",
            "--status",
            "--verify",
            "acp_probe.py --timeout",
            "--uninstall",
        ):
            assert step in block, f"{job_id} missing lifecycle step fragment {step!r}"
        assert "NOT executed" in block, f"{job_id} must state its evidence boundary"


def test_no_secret_expressions_and_checkout_persistence(ci: str) -> None:
    assert "${{ secrets" not in ci
    # Every checkout step carries persist-credentials: false in its own
    # step block (walk the indented continuation of each `- uses:` item).
    lines = ci.splitlines()
    offenders = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s*- uses: actions/checkout@", line):
            continue
        indent = len(line) - len(line.lstrip())
        block: list[str] = []
        for follow in lines[index + 1 :]:
            if follow.strip() == "":
                break
            if (len(follow) - len(follow.lstrip())) <= indent:
                break
            block.append(follow)
        if "persist-credentials: false" not in "\n".join(block):
            offenders.append(line.strip())
    assert offenders == []


def test_fake_acp_discovery_contract_unchanged(ci: str) -> None:
    block = _job_block(ci, "fake-acp")
    assert "python -m pytest -q tests" in block
    assert (
        "--ignore=tests/test_upstream_hermes_runtime_contracts.py" in block
    )
    assert block.count("--ignore=") == 1, "no new silent test exclusions allowed"


def test_dispatch_supports_full_matrix_with_recorded_reason(ci: str) -> None:
    header = ci.split("jobs:", 1)[0]
    assert "workflow_dispatch:" in header
    scope_block = _job_block(ci, "change-scope")
    assert "CI_DISPATCH_REASON" in scope_block


# -- change classifier: widen-only ---------------------------------------


def test_docs_only_changes_take_the_fast_route() -> None:
    scope = scope_mod.classify_paths(
        ["README.md", "docs/clean-env-e2e-smoke.md", "AGENTS.md", "LICENSE"]
    )
    assert (scope.os_lanes, scope.extended_arm) == (False, False)


def test_install_surface_changes_trigger_os_lanes_only() -> None:
    scope = scope_mod.classify_paths(["antigravity_acp/client.py", "hermes-plugin/antigravity-acp/__init__.py"])
    assert (scope.os_lanes, scope.extended_arm) == (True, False)


def test_packaging_surface_changes_trigger_everything() -> None:
    for path in (
        "antigravity_acp/registry.py",
        "install-windows.cmd",
        "scripts/install_official.py",
        ".github/workflows/ci.yml",
    ):
        scope = scope_mod.classify_paths([path])
        assert (scope.os_lanes, scope.extended_arm) == (True, True), path


def test_unknown_paths_fail_closed_to_the_strongest_scope() -> None:
    scope = scope_mod.classify_paths(["weird/new-surface.sh"])
    assert (scope.os_lanes, scope.extended_arm) == (True, True)
    assert scope.unknown_paths == ("weird/new-surface.sh",)


def test_empty_diff_fails_closed() -> None:
    scope = scope_mod.classify_paths([])
    assert (scope.os_lanes, scope.extended_arm) == (True, True)
    assert scope.reason == "empty-diff-fail-closed"


def test_events_outside_pull_requests_never_narrow() -> None:
    for env in (
        {"CI_EVENT": "workflow_dispatch"},
        {"CI_EVENT": "push"},
        {"CI_EVENT": "schedule"},
        {},
    ):
        scope = scope_mod.scope_for_event(env)
        assert (scope.os_lanes, scope.extended_arm) == (True, True), env


def test_pr_detection_failure_falls_back_to_strongest_scope() -> None:
    scope = scope_mod.scope_for_event(
        {"CI_EVENT": "pull_request", "CI_BASE_SHA": "", "CI_HEAD_SHA": ""}
    )
    assert (scope.os_lanes, scope.extended_arm) == (True, True)
    assert scope.reason == "detection-failed-missing-base"


# -- gate: skipped-is-never-green -----------------------------------------

ALL_SUCCESS = {lane: {"result": "success"} for lane in ALL_LANES}


def _results(**overrides: str) -> dict:
    results = {lane: {"result": "success"} for lane in ALL_LANES}
    for lane, result in overrides.items():
        results[lane] = {"result": result}
    return results


FAST_ONLY = {"os_lanes": "false", "extended_arm": "false", "reason": "docs"}
FULL = {"os_lanes": "true", "extended_arm": "true", "reason": "dispatch"}


def test_gate_passes_when_everything_required_succeeded() -> None:
    ok, report = gate_mod.evaluate(FULL, ALL_SUCCESS)
    assert ok, report
    ok, _ = gate_mod.evaluate(FAST_ONLY, _results(**{k: "skipped" for k in ("acp-clean-room", "windows-x64", "macos-arm64", "windows-arm64", "linux-aarch64")}))
    assert ok


def test_gate_fails_when_a_required_lane_was_skipped() -> None:
    ok, report = gate_mod.evaluate(FULL, _results(**{"windows-arm64": "skipped"}))
    assert not ok
    assert any("windows-arm64" in line and line.startswith("FAIL") for line in report)
    ok, _ = gate_mod.evaluate(FULL, _results(**{"acp-clean-room": "skipped"}))
    assert not ok


def test_gate_fails_when_an_unrequired_lane_ran_and_failed() -> None:
    ok, _ = gate_mod.evaluate(FAST_ONLY, _results(**{"windows-arm64": "failure"}))
    assert not ok


def test_gate_fails_on_any_non_success_non_skip_result() -> None:
    for result in ("cancelled", "action_required", "timed_out", "neutral", "stale"):
        ok, _ = gate_mod.evaluate(FAST_ONLY, _results(**{"fake-acp": result}))
        assert not ok, result


def test_gate_fails_when_a_lane_never_reported() -> None:
    results = {lane: {"result": "success"} for lane in ALL_LANES}
    del results["macos-arm64"]
    ok, _ = gate_mod.evaluate(FULL, results)
    assert not ok


def test_gate_fails_when_scope_detection_itself_failed() -> None:
    ok, _ = gate_mod.evaluate(
        {"os_lanes": "true", "extended_arm": "true"},
        _results(**{"change-scope": "failure"}),
    )
    assert not ok


def test_gate_cli_fails_closed_on_malformed_input(tmp_path) -> None:
    code = gate_mod.main(
        ["--expected-json", "not-json", "--results-json", "{}"]
    )
    assert code == 1


def test_gate_cli_end_to_end_verdict(tmp_path, capsys) -> None:
    summary = tmp_path / "summary.md"
    code = gate_mod.main(
        [
            "--expected-json",
            json.dumps(FAST_ONLY),
            "--results-json",
            json.dumps(_results(**{"catalog-floor-gate": "failure"})),
            "--summary",
            str(summary),
        ]
    )
    assert code == 1
    assert "verdict: FAIL" in capsys.readouterr().out
    assert "verdict: FAIL" in summary.read_text(encoding="utf-8")


# -- registry surface is never trimmed for CI convenience -----------------


def test_registry_keeps_all_five_native_targets() -> None:
    assert set(_DISTRIBUTIONS) == {
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("darwin", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    }
