"""Contract v2: kernel boundary -> real driver, not a duplicate pytest gate.

All receipts/drivers here are explicit offline fixtures, not execution evidence.
"""
from copy import deepcopy
import os
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts import gateway_attestation as attest
from scripts import gateway_docker as docker
from scripts import gateway_e2e as gateway
from test_gateway_attestation import GatewayAttestationTests


def receipt():
    return GatewayAttestationTests().receipt()


def test_v2_boundary_does_not_claim_full_regression():
    record = receipt()
    assert "regression" not in record
    assert docker.validate_docker_receipt(record) == []


@pytest.mark.parametrize("field", ["regression", "regression_summary", "regression_memory", "regression_pids", "regression_processes"])
def test_legacy_regression_pass_is_contamination_not_a_v2_shortcut(field):
    record = receipt()
    record[field] = {"status": "PASS", "tests": 1693, "failures": 0}
    assert "legacy_regression_evidence" in docker.validate_docker_receipt(record)


@pytest.mark.parametrize("version", [None, 1, True, "2", 3])
def test_explicit_docker_contract_version_is_required(version):
    record = receipt()
    record["docker_contract_version"] = version
    assert "docker_contract_version_mismatch" in docker.validate_docker_receipt(record)


def test_checkout_and_independent_core_binding_are_required():
    record = receipt()
    record["checkout_sha"] = "c" * 40
    assert "docker_checkout_identity_mismatch" in docker.validate_docker_receipt(record)
    outputs = GatewayAttestationTests().outputs()
    outputs["gateway_core"] = "c" * 40
    assert "gateway_core_identity_mismatch" in attest.check_outputs(outputs, required=True)
    del outputs["gateway_core"]
    assert "gateway_core_identity_mismatch" in attest.check_outputs(outputs, required=True)


@pytest.mark.parametrize("record", [None, [], True, "PASS"])
def test_malformed_docker_receipts_fail_closed(record):
    assert docker.validate_docker_receipt(record)


@pytest.mark.parametrize("stage", gateway.REQUIRED_STAGES)
def test_v2_does_not_reduce_any_gateway_requirement(stage):
    record = receipt()
    record["stages"][stage]["status"] = "NOT_RUN"
    outputs = GatewayAttestationTests().outputs()
    outputs["gateway_record"] = json.dumps(record)
    assert attest.check_outputs(outputs, required=True)


def test_real_driver_wiring_has_no_pytest_or_diagnostic_framework():
    source = Path(docker.__file__).read_text()
    assert "run_regression" not in source
    assert "pytest" not in source
    assert "gateway_diagnostics" not in source


def test_boundary_pass_runs_driver_directly_and_preserves_cleanup(tmp_path):
    record = receipt()
    boundary = deepcopy(record["confinement"])
    policy = {"core": "/fixture/core", "candidate": "a" * 40}
    calls = []
    def driver(argv):
        calls.append(argv)
        (tmp_path / "verification.json").write_text(json.dumps(record))
        return 0
    module = SimpleNamespace(main=driver, validate_receipt=gateway.validate_receipt)
    psutil_fixture = SimpleNamespace(process_iter=lambda: [SimpleNamespace(pid=os.getpid(), status=lambda: "running")],
                                     STATUS_ZOMBIE="zombie")
    with patch.dict("sys.modules", {"gateway_e2e": module, "psutil": psutil_fixture}), patch.object(
        docker, "namespace_verified", return_value=True), patch.object(
        docker.os, "waitpid", side_effect=ChildProcessError), patch.object(
        docker.subprocess, "run", side_effect=AssertionError("no pre-Gateway subprocess")):
        assert docker.run_gateway(policy, boundary, tmp_path) == 0
    assert len(calls) == 1
    saved = json.loads((tmp_path / "verification.json").read_text())
    assert saved["docker_contract_version"] == 2 and saved["checkout_sha"] == policy["candidate"]
    assert saved["confinement"]["status"] == "PASS"
    assert saved["final_namespace_process_count"] == saved["final_namespace_live_count"] == 1
    assert "regression" not in saved


@pytest.mark.parametrize("broken", ["kernel", "namespace"])
def test_failed_boundary_never_invokes_gateway(tmp_path, broken):
    boundary = receipt()["confinement"]
    if broken == "kernel":
        boundary["checks"]["source_write_denied"] = False
    with patch.object(docker, "namespace_verified", return_value=broken != "namespace"), patch.dict(
        "sys.modules", {"gateway_e2e": SimpleNamespace(main=lambda _: pytest.fail("Gateway must not start"))}):
        assert docker.run_gateway({"core": "/fixture/core", "candidate": "a" * 40}, boundary, tmp_path) == 1
    assert not (tmp_path / "verification.json").exists()


def test_both_outer_gates_reject_v2_contamination_and_residue():
    from scripts import ci_gate_check, release_gate_check
    from scripts.release_matrix import load_matrix
    sha = "a" * 40
    matrix = load_matrix(Path(docker.__file__).parents[1] / "release/verification-matrix.json")
    identity = {"candidate": sha, "candidate_reachable": "true", "target_ref": "refs/heads/fixture",
                **{key: sha for key in ("github_sha", "checkout_sha", "ref_head_start", "ref_head_end")}}
    results = {name: {"result": "success", "outputs": {"attested_sha": sha}} for name in (
        *release_gate_check.INFRA_JOBS, *ci_gate_check.FAST_LANES, *ci_gate_check.OS_LANES, *ci_gate_check.ARM_LANES)}
    for lane in matrix.lanes:
        results[lane]["outputs"]["stages"] = ",".join(stage for (_, stage), owner in matrix.required_stage_lanes().items() if owner == lane)
    output = GatewayAttestationTests().outputs()
    results["upstream-hermes-compat"]["outputs"].update(output)
    flags = {"os_lanes": "true", "extended_arm": "true"}
    assert ci_gate_check.evaluate(flags, {k: v for k, v in results.items() if k not in {"candidate-identity", "ci-gate"}})[0]
    assert release_gate_check.evaluate(sha, identity, results, matrix)[0]
    for key, value in (("final_namespace_process_count", 2), ("final_namespace_live_count", True),
                       ("checkout_sha", "c" * 40), ("hermes_commit", "c" * 40),
                       ("candidate_source_dirty", True), ("regression", {"status": "PASS"})):
        changed = receipt()
        changed[key] = value
        results["upstream-hermes-compat"]["outputs"]["gateway_record"] = json.dumps(changed)
        assert not ci_gate_check.evaluate(flags, {k: v for k, v in results.items() if k not in {"candidate-identity", "ci-gate"}})[0]
        assert not release_gate_check.evaluate(sha, identity, results, matrix)[0]


def test_workflow_exports_independently_resolved_core_for_both_gates():
    ci = (Path(docker.__file__).parents[1] / ".github/workflows/ci.yml").read_text()
    block = ci.split("  upstream-hermes-compat:\n")[1].split("  catalog-floor-gate:\n")[0]
    assert "gateway_core: ${{ steps.hermes-target.outputs.commit }}" in block
