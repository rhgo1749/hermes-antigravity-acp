"""Issue #28 Phase B contract: the release gate must bind verification to
the EXACT release-candidate SHA and fail closed on every substitution path.

Covered surfaces:

* ``release/verification-matrix.json`` — the version-controlled
  target x stage matrix loads strictly; a PASS without a citation, a
  required cell held NOT_RUN/FAIL, vocabulary drift, or lane collisions
  are loader errors (fail-closed before any verdict).
* ``scripts/release_gate_check.py`` — pure evaluation: wrong SHA format,
  failed/missing/skipped/cancelled required lanes, attested SHA !=
  candidate, missing stage attestations, unknown jobs, and unreachable
  candidates all FAIL; only all-green + exact-SHA + full-stage attestation
  passes. Optional gaps are reported, never counted green, and never
  substituted by another lane's success.
* ``.github/workflows/ci.yml`` wiring — the candidate_sha dispatch input,
  the candidate-identity job, per-lane checkout pinning and SHA
  attestation, the Release gate needs list, and the drift guard that the
  stages each lane ATTESTS are exactly the stages the matrix requires of
  it AND that the implementing command fragments are present in that same
  lane block (an attest string that lies about its steps is rejected).
* ``scripts/candidate_identity.py`` — full-SHA-only, exists-in-remote,
  reachable-from-a-branch, against a real scratch git remote.
* ``scripts/ci_change_scope.py`` — the new release-control scripts are
  reviewed non-packaging; the matrix file itself is unknown-path
  fail-closed full-matrix.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MATRIX_PATH = ROOT / "release" / "verification-matrix.json"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


matrix_mod = _load("release_matrix_contract", ROOT / "scripts" / "release_matrix.py")
gate_mod = _load("release_gate_check_contract", ROOT / "scripts" / "release_gate_check.py")
identity_mod = _load("candidate_identity_contract", ROOT / "scripts" / "candidate_identity.py")
scope_mod = _load("ci_change_scope_phaseb", ROOT / "scripts" / "ci_change_scope.py")

CANDIDATE = "ab" * 20
OTHER_SHA = "cd" * 20


@pytest.fixture(scope="module")
def ci() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def matrix():
    return matrix_mod.load_matrix(MATRIX_PATH)


def _job_block(ci: str, job_id: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_id)}:\n(?:.*\n)*?(?=^  \S|\Z)", ci, re.M
    )
    assert match, f"job '{job_id}' must exist in .github/workflows/ci.yml"
    return match.group(0)


# -- matrix: strict, honest, five targets ----------------------------------


def test_matrix_declares_exactly_the_five_native_targets(matrix) -> None:
    assert set(matrix.targets) == matrix_mod.DECLARED_TARGETS


def test_matrix_required_cells_all_carry_a_covering_lane(matrix) -> None:
    for (target, stage), lane in matrix.required_stage_lanes().items():
        assert lane, (target, stage)


def test_matrix_unexecuted_cells_are_never_marked_pass(matrix) -> None:
    for entry in matrix.cells():
        if entry.evidence_class == "not_executed":
            assert entry.status in {"BLOCKED", "NOT_RUN"}, entry
        if entry.status == "PASS":
            assert entry.evidence.strip(), entry


def test_matrix_blocked_cells_declare_their_limitation(matrix) -> None:
    for entry in matrix.cells():
        if entry.status in {"BLOCKED", "NOT_RUN", "FAIL"}:
            assert entry.limitation.strip(), (entry.target, entry.stage)


def _write_matrix(tmp_path, mutate) -> Path:
    raw = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    mutate(raw)
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_matrix_pass_without_citation_is_rejected(tmp_path) -> None:
    def mutate(raw):
        cell = raw["targets"][0]["stages"]["binary_publisher_pin_sha256"]
        cell["evidence"] = ""

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


def test_matrix_pass_with_not_executed_class_is_rejected(tmp_path) -> None:
    def mutate(raw):
        cell = raw["targets"][0]["stages"]["binary_publisher_pin_sha256"]
        cell["evidence_class"] = "not_executed"

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


def test_matrix_required_cell_holding_not_run_is_rejected(tmp_path) -> None:
    def mutate(raw):
        cell = raw["targets"][0]["stages"]["acp_initialize_unauthenticated"]
        cell["required"] = True
        cell["status"] = "NOT_RUN"

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


def test_matrix_target_set_drift_is_rejected(tmp_path) -> None:
    def mutate(raw):
        raw["targets"] = raw["targets"][:4]

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


def test_matrix_primary_lane_collision_is_rejected(tmp_path) -> None:
    def mutate(raw):
        raw["targets"][1]["lane"] = raw["targets"][0]["lane"]

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


def test_matrix_unknown_status_is_rejected(tmp_path) -> None:
    def mutate(raw):
        raw["targets"][0]["stages"]["acp_initialize_unauthenticated"]["status"] = "GREEN"

    with pytest.raises(matrix_mod.MatrixError):
        matrix_mod.load_matrix(_write_matrix(tmp_path, mutate))


# -- gate: exact-SHA binding and fail-closed aggregation --------------------


def _identity(**overrides) -> dict:
    base = {
        "candidate": CANDIDATE,
        "candidate_tree": "ee" * 20,
        "main_head": CANDIDATE,
        "candidate_on_main": "true",
        "candidate_is_main_head": "true",
        "candidate_reachable": "true",
    }
    base.update(overrides)
    return base


def _results(matrix, *, candidate=CANDIDATE, **overrides) -> dict:
    results: dict = {
        "change-scope": {"result": "success"},
        "candidate-identity": {"result": "success", "outputs": _identity()},
    }
    for lane in matrix.lanes:
        stages = sorted(
            stage
            for (target, stage), owner in matrix.required_stage_lanes().items()
            if owner == lane
        )
        results[lane] = {
            "result": "success",
            "outputs": {"attested_sha": candidate, "stages": ",".join(stages)},
        }
    for lane in gate_mod.FAST_LANES:
        results.setdefault(
            lane, {"result": "success", "outputs": {"attested_sha": candidate}}
        )
    for lane, value in overrides.items():
        if value is None:
            del results[lane]
        elif isinstance(value, str):
            results[lane] = {"result": value}
        else:
            results[lane] = value
    return results


def test_gate_passes_only_for_exact_sha_full_attestation(matrix) -> None:
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), _results(matrix), matrix)
    assert ok, report
    assert report[-1] == "verdict: PASS"


@pytest.mark.parametrize("bad", ("", "abc", "z" * 40, "A" * 40, CANDIDATE[:39], CANDIDATE + "0"))
def test_gate_rejects_non_full_hex_candidate(matrix, bad) -> None:
    ok, _ = gate_mod.evaluate(bad, _identity(), _results(matrix), matrix)
    assert not ok


@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped", "timed_out"))
@pytest.mark.parametrize(
    "lane",
    (
        "fake-acp",
        "upstream-hermes-compat",
        "catalog-floor-gate",
        "acp-clean-room",
        "windows-x64",
        "windows-arm64",
        "macos-arm64",
        "linux-aarch64",
    ),
)
def test_gate_fails_on_any_required_lane_that_did_not_succeed(matrix, lane, result) -> None:
    ok, report = gate_mod.evaluate(
        CANDIDATE, _identity(), _results(matrix, **{lane: result}), matrix
    )
    assert not ok, (lane, result, report)


def test_gate_fails_on_a_missing_required_lane(matrix) -> None:
    ok, report = gate_mod.evaluate(
        CANDIDATE, _identity(), _results(matrix, **{"macos-arm64": None}), matrix
    )
    assert not ok
    assert any("macos-arm64" in line and line.startswith("FAIL") for line in report)


def test_gate_fails_when_one_platform_fails_among_otherwise_green_lanes(matrix) -> None:
    # "some platforms failed" must never aggregate to success.
    ok, report = gate_mod.evaluate(
        CANDIDATE,
        _identity(),
        _results(matrix, **{"linux-aarch64": "failure", "windows-arm64": "cancelled"}),
        matrix,
    )
    assert not ok
    assert sum(1 for line in report if line.startswith("FAIL")) >= 2


def test_gate_fails_on_attested_sha_that_differs_from_candidate(matrix) -> None:
    results = _results(matrix)
    results["windows-x64"]["outputs"]["attested_sha"] = OTHER_SHA
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
    assert not ok
    assert any("attested checkout SHA" in line for line in report)


def test_gate_fails_on_a_lane_that_never_attested_its_sha(matrix) -> None:
    results = _results(matrix)
    del results["macos-arm64"]["outputs"]["attested_sha"]
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
    assert not ok
    assert any("attested checkout SHA" in line for line in report)


def test_gate_fails_when_a_required_stage_is_not_attested(matrix) -> None:
    results = _results(matrix)
    outputs = results["macos-arm64"]["outputs"]
    outputs["stages"] = ",".join(
        stage
        for stage in outputs["stages"].split(",")
        if stage != "provider_registration_enabled"
    )
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
    assert not ok
    assert any(
        "provider_registration_enabled" in line and line.startswith("FAIL")
        for line in report
    )


def test_gate_other_lanes_cannot_substitute_a_missing_required_stage(matrix) -> None:
    # windows-arm64 attests provider_registration_enabled; that must NOT
    # cover the windows-x64 cell — stage coverage is per covering lane.
    results = _results(matrix)
    outputs = results["windows-x64"]["outputs"]
    outputs["stages"] = ",".join(
        stage
        for stage in outputs["stages"].split(",")
        if stage != "provider_selection_factory"
    )
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
    # windows-x64 provider_selection_factory is NOT required, so this alone
    # still passes; the substitution test is the required-cell variant:
    assert ok
    results2 = _results(matrix)
    results2["windows-x64"]["outputs"]["stages"] = ""
    ok2, report2 = gate_mod.evaluate(CANDIDATE, _identity(), results2, matrix)
    assert not ok2
    assert any("windows-x64" in line and line.startswith("FAIL") for line in report2)


def test_gate_fails_on_unknown_job_wired_into_the_release_gate(matrix) -> None:
    for result in ("success", "failure", "skipped"):
        results = _results(matrix, **{"synth-unknown": {"result": result}})
        ok, report = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
        assert not ok, result
        assert any("synth-unknown" in line and line.startswith("FAIL") for line in report)


@pytest.mark.parametrize(
    "identity_overrides",
    (
        {"candidate": OTHER_SHA},
        {"candidate_reachable": "false"},
    ),
)
def test_gate_fails_on_identity_binding_divergence(matrix, identity_overrides) -> None:
    ok, report = gate_mod.evaluate(
        CANDIDATE, _identity(**identity_overrides), _results(matrix), matrix
    )
    assert not ok


def test_gate_fails_when_identity_job_failed(matrix) -> None:
    results = _results(matrix, **{"candidate-identity": "failure"})
    ok, _ = gate_mod.evaluate(CANDIDATE, _identity(), results, matrix)
    assert not ok


def test_gate_reports_optional_gaps_without_counting_them_green(matrix) -> None:
    ok, report = gate_mod.evaluate(CANDIDATE, _identity(), _results(matrix), matrix)
    assert ok
    notes = [line for line in report if line.startswith("note ")]
    joined = "\n".join(notes)
    # The known Windows selection/factory gap must appear as an optional
    # note with its limitation, never as a PASS line.
    assert "windows-x64/provider_selection_factory" in joined
    assert not any(
        line.startswith("PASS") and "provider_selection_factory" in line for line in report
    )


def test_gate_notes_non_main_head_candidate_without_silently_passing_it(matrix) -> None:
    ok, report = gate_mod.evaluate(
        CANDIDATE,
        _identity(candidate_is_main_head="false", main_head="ff" * 20),
        _results(matrix),
        matrix,
    )
    # The SHA binding itself is what this gate certifies; the main-head
    # freshness binding is recorded for the tag-time policy, loudly.
    assert ok
    assert any("not the current main head" in line for line in report)


def test_gate_cli_fails_closed_on_malformed_input(tmp_path, matrix) -> None:
    code = gate_mod.main(
        [
            "--candidate-sha", CANDIDATE,
            "--identity-json", "not-json",
            "--results-json", "{}",
            "--matrix", str(MATRIX_PATH),
        ]
    )
    assert code == 1


def test_gate_cli_end_to_end_verdict(tmp_path, capsys) -> None:
    summary = tmp_path / "summary.md"
    matrix = matrix_mod.load_matrix(MATRIX_PATH)
    code = gate_mod.main(
        [
            "--candidate-sha", CANDIDATE,
            "--identity-json", json.dumps(_identity(candidate_is_main_head="false")),
            "--results-json",
            json.dumps(_results(matrix, **{"catalog-floor-gate": "failure"})),
            "--matrix", str(MATRIX_PATH),
            "--summary", str(summary),
        ]
    )
    assert code == 1
    out = capsys.readouterr().out
    assert "verdict: FAIL" in out
    assert "verdict: FAIL" in summary.read_text(encoding="utf-8")


def test_gate_cli_passes_for_full_attestation(capsys) -> None:
    matrix = matrix_mod.load_matrix(MATRIX_PATH)
    code = gate_mod.main(
        [
            "--candidate-sha", CANDIDATE,
            "--identity-json", json.dumps(_identity()),
            "--results-json", json.dumps(_results(matrix)),
            "--matrix", str(MATRIX_PATH),
        ]
    )
    assert code == 0
    assert "verdict: PASS" in capsys.readouterr().out


# -- candidate identity: real scratch git remote ---------------------------


def _make_scratch_remote(tmp_path) -> tuple[Path, Path, str]:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True)
    # Mirror GitHub's server policy: full-SHA fetch is served only for
    # objects reachable from an advertised ref.
    subprocess.run(
        ["git", "config", "uploadpack.allowReachableSHA1InWant", "true"],
        cwd=remote, check=True, capture_output=True,
    )
    work = tmp_path / "work"
    subprocess.run(
        ["git", "clone", "-q", str(remote), str(work)], check=True, capture_output=True
    )

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=work, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("config", "user.email", "identity@example.invalid")
    git("config", "user.name", "identity")
    (work / "README.md").write_text("# base\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    git("push", "-q", "origin", "HEAD:refs/heads/main")
    return remote, work, git("rev-parse", "HEAD")


def test_identity_binds_a_pushed_candidate(tmp_path) -> None:
    remote, work, sha = _make_scratch_remote(tmp_path)
    identity = identity_mod.resolve_identity(sha, remote=str(remote), cwd=work)
    assert identity["candidate"] == sha
    assert identity["candidate_is_main_head"] == "true"
    assert identity["candidate_on_main"] == "true"
    assert identity["candidate_reachable"] == "true"
    assert identity["main_head"] == sha


def test_identity_binds_an_ancestor_candidate(tmp_path) -> None:
    remote, work, base = _make_scratch_remote(tmp_path)
    (work / "next.md").write_text("# next\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "next"], cwd=work, check=True, capture_output=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "push", "-q", "origin", "HEAD:refs/heads/main"], cwd=work, check=True, capture_output=True)
    identity = identity_mod.resolve_identity(base, remote=str(remote), cwd=work)
    assert identity["candidate"] == base
    assert identity["candidate_is_main_head"] == "false"
    assert identity["candidate_on_main"] == "true"
    assert identity["main_head"] == head


@pytest.mark.parametrize("bad", ("", "abc", "z" * 40, "A" * 40, "ab" * 19 + "g" + "0" * 20))
def test_identity_rejects_malformed_sha(tmp_path, bad) -> None:
    with pytest.raises(identity_mod.IdentityError):
        identity_mod.resolve_identity(bad, remote=str(tmp_path))


def test_identity_rejects_nonexistent_object(tmp_path) -> None:
    remote, work, _ = _make_scratch_remote(tmp_path)
    with pytest.raises(identity_mod.IdentityError):
        identity_mod.resolve_identity("f" * 40, remote=str(remote), cwd=work)


def test_identity_rejects_unpushed_local_commit(tmp_path) -> None:
    remote, work, _ = _make_scratch_remote(tmp_path)
    (work / "local.md").write_text("# local\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "local only"], cwd=work, check=True, capture_output=True)
    local_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True
    ).stdout.strip()
    with pytest.raises(identity_mod.IdentityError):
        identity_mod.resolve_identity(local_sha, remote=str(remote), cwd=work)


# -- workflow wiring: candidate pinning, attestation, release gate ----------


def test_dispatch_exposes_candidate_sha_input(ci: str) -> None:
    header = ci.split("jobs:", 1)[0]
    assert "candidate_sha:" in header


def test_candidate_identity_job_is_dispatch_only(ci: str) -> None:
    block = _job_block(ci, "candidate-identity")
    assert "if: github.event_name == 'workflow_dispatch' && inputs.candidate_sha != ''" in block
    assert "scripts/candidate_identity.py" in block
    assert "${{ secrets" not in block


def test_release_gate_job_wiring(ci: str) -> None:
    block = _job_block(ci, "release-gate")
    assert "name: Release gate" in ci
    needs = re.search(r"needs:\s*\[([^\]]+)\]", block)
    assert needs
    listed = {item.strip() for item in needs.group(1).split(",")}
    assert listed == {
        "candidate-identity", "change-scope", "fake-acp", "acp-clean-room",
        "windows-x64", "windows-arm64", "macos-arm64", "linux-aarch64",
        "upstream-hermes-compat", "catalog-floor-gate",
    }, listed
    assert "if: always() && github.event_name == 'workflow_dispatch' && inputs.candidate_sha != ''" in block
    assert "scripts/release_gate_check.py" in block
    assert "release/verification-matrix.json" in block
    assert "${{ secrets" not in block


LANE_JOBS = (
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


@pytest.mark.parametrize("job_id", LANE_JOBS)
def test_every_lane_checkout_is_pinned_to_the_candidate(ci, job_id) -> None:
    block = _job_block(ci, job_id)
    assert "ref: ${{ inputs.candidate_sha || github.sha }}" in block, job_id


@pytest.mark.parametrize("job_id", LANE_JOBS)
def test_every_attesting_lane_compares_its_head_to_the_candidate(ci, job_id) -> None:
    if job_id == "change-scope":
        pytest.skip("change-scope pins its checkout but is not a release evidence lane")
    block = _job_block(ci, job_id)
    assert "id: attest" in block
    assert "git rev-parse HEAD" in block
    assert "!= candidate" in block or "ne $env:CANDIDATE_SHA" in block


# Drift guard: the stages a lane ATTESTS in the workflow must equal the
# stages the matrix requires of that lane, and each attested stage must be
# implemented by a command fragment inside that same lane block. Removing
# an implementing step while keeping its attestation — or vice versa —
# fails here before it can produce a lying evidence record.
STAGE_IMPLEMENTATION_FRAGMENTS = {
    "binary_publisher_pin_sha256": {
        "acp-clean-room": "ACP_EXPECTED_SHA256",
        "windows-x64": "install-windows.cmd",
        "windows-arm64": "install-windows.cmd",
        "macos-arm64": "install_official.py --prefix",
        "linux-aarch64": "install_official.py --prefix",
    },
    "install_status_verify_uninstall": {
        "acp-clean-room": "hosted_clean_room_ci.py",
        "windows-x64": "install-windows.cmd",
        "windows-arm64": "install-windows.cmd",
        "macos-arm64": "--uninstall",
        "linux-aarch64": "--uninstall",
    },
    "provider_registration_enabled": {
        "acp-clean-room": "hosted_clean_room_ci.py",
        "windows-x64": "antigravity-acp-provider",
        "windows-arm64": "antigravity-acp-provider",
        "macos-arm64": "install_acp.py install --hermes-home",
        "linux-aarch64": "install_acp.py install --hermes-home",
    },
    "provider_selection_factory": {
        "acp-clean-room": "hosted_clean_room_ci.py",
        "macos-arm64": "run: upstream-hermes/.venv/bin/python scripts/clean_room_provider_probe.py",
        "linux-aarch64": "run: upstream-hermes/.venv/bin/python scripts/clean_room_provider_probe.py",
    },
    "acp_initialize_unauthenticated": {
        "acp-clean-room": "hosted_clean_room_ci.py",
        "windows-x64": "install_acp.py verify",
        "windows-arm64": "install_acp.py verify",
        "macos-arm64": "acp_probe.py --timeout",
        "linux-aarch64": "acp_probe.py --timeout",
    },
    "platform_security_hardening": {
        "acp-clean-room": "CLEAN_ROOM_USER",
        "windows-x64": "verify_process_tree_teardown.py",
    },
    "error_timeout_permission_failclosed": {"fake-acp": "pytest -q tests"},
    "session_resume_recovery": {"fake-acp": "pytest -q tests"},
}


def _attested_stages_in_block(block: str) -> set[str]:
    match = re.search(r'stages=([a-z0-9_,]+)"', block)
    assert match, "lane attest step must emit its stage list"
    return set(match.group(1).split(","))


@pytest.mark.parametrize("lane", ("acp-clean-room", "windows-x64", "windows-arm64", "macos-arm64", "linux-aarch64"))
def test_lane_attested_stages_match_the_matrix_and_its_own_steps(ci, matrix, lane) -> None:
    block = _job_block(ci, lane)
    attested = _attested_stages_in_block(block)
    # A lane may attest its required cells plus optional cells it actually
    # executes with PASS status (e.g. the x64 process-tree teardown); it
    # may never attest a NOT_RUN/BLOCKED cell and never fewer than required.
    expected = {
        entry.stage
        for entry in matrix.cells()
        if entry.lane == lane and (entry.required or entry.status == "PASS")
    }
    assert expected == attested, (lane, sorted(expected ^ attested))
    for stage in attested:
        fragment = STAGE_IMPLEMENTATION_FRAGMENTS.get(stage, {}).get(lane)
        assert fragment, (lane, stage)
        assert fragment in block, f"{lane} attests {stage} but no longer runs {fragment!r}"


def test_fake_acp_attests_the_protocol_stages(ci, matrix) -> None:
    block = _job_block(ci, "fake-acp")
    attested = _attested_stages_in_block(block)
    required = {
        stage for (target, stage), owner in matrix.required_stage_lanes().items() if owner == "fake-acp"
    }
    assert required == attested == {"error_timeout_permission_failclosed", "session_resume_recovery"}


def test_sabotage_removing_a_provider_step_breaks_the_drift_guard(ci, matrix) -> None:
    sabotaged = ci.replace(
        "        run: upstream-hermes/.venv/bin/python scripts/clean_room_provider_probe.py\n",
        "",
    )
    assert sabotaged != ci, "the probe invocation must exist to be sabotaged"
    block = _job_block(sabotaged, "macos-arm64")
    attested = _attested_stages_in_block(block)
    assert "provider_selection_factory" in attested
    # The guard above (test_lane_attested_stages_match...) would now fail:
    fragment = STAGE_IMPLEMENTATION_FRAGMENTS["provider_selection_factory"]["macos-arm64"]
    assert fragment not in block


# -- classifier: release-control scripts and the matrix file ----------------


@pytest.mark.parametrize(
    "path",
    (
        "scripts/release_gate_check.py",
        "scripts/release_matrix.py",
        "scripts/candidate_identity.py",
    ),
)
def test_release_control_scripts_are_reviewed_non_packaging(path) -> None:
    scope = scope_mod.classify_paths([path])
    assert (scope.os_lanes, scope.extended_arm) == (True, False), path
    assert scope.unknown_paths == ()


def test_matrix_file_edits_fail_closed_to_full_matrix() -> None:
    scope = scope_mod.classify_paths(["release/verification-matrix.json"])
    assert (scope.os_lanes, scope.extended_arm) == (True, True)
    assert scope.unknown_paths == ("release/verification-matrix.json",)


def test_this_contract_test_itself_keeps_full_matrix() -> None:
    scope = scope_mod.classify_paths(["tests/test_release_gate_contract.py"])
    assert (scope.os_lanes, scope.extended_arm) == (True, True)
