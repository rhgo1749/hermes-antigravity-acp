"""Phase C wiring and outer fail-closed gate negatives; synthetic inputs only."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from scripts.gateway_docker import CHECKS

from scripts import ci_gate_check, release_gate_check
from scripts.gateway_e2e import REQUIRED_STAGES
from scripts.release_matrix import load_matrix

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def good_outputs():
    return {"attested_sha": SHA, "gateway_result": "success", "gateway_record": json.dumps({
        "schema_version": 1, "candidate_sha": SHA, "hermes_commit": "b" * 40, "status": "PASS", "candidate_source_dirty": False,
                "scratch_cleanup": {"status": "PASS", "launch_count": 1},
                "shutdown_diagnostic": {"status": "PASS", "launch_count": 1},
                "confinement": {"status": "PASS", "checks": {name: True for name in CHECKS}, "pid_namespace_sha256": "1" * 64, "host_pid_namespace_sha256": "2" * 64},
                "docker_execution": {"status": "PASS", "config_verified": True, "owned_pid_namespace_verified": True, "outside_canary_unchanged": True,
                                     "container_removed": True, "image_removed": True},
                "regression": {"status": "PASS", "tests": 1, "failures": 0, "errors": 0, "skipped": 0},
                "final_namespace_live_count": 1, "final_namespace_process_count": 1,
        "stages": {name: {"status": "PASS"} for name in REQUIRED_STAGES}})}


class GatewayGateContractTests(unittest.TestCase):
    def test_stage_set_is_not_silently_reduced(self):
        self.assertEqual(set(REQUIRED_STAGES), {"isolation", "candidate_install", "enablement", "gateway_ready",
            "provider_factory", "initialize", "request_response", "permission_denial", "cancellation",
            "ownership_conflict", "owner_survives", "shutdown", "child_cleanup", "source_unchanged"})

    def test_only_existing_latest_linux_lane_executes_gateway(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(ci.count("python scripts/gateway_docker.py"), 1)
        block = ci.split("  upstream-hermes-compat:\n")[1].split("  catalog-floor-gate:\n")[0]
        for required in ("needs: [change-scope]", "id: gateway", "steps.gateway.outcome",
                         "steps.gateway-attest.outputs.record", "scripts/gateway_attestation.py",
                         "--core \"$CORE_SHA\"", "path: gateway-e2e-verification.json",
                         "if: needs.change-scope.outputs.os_lanes == 'true'"):
            self.assertIn(required, block)
        self.assertNotIn("python scripts/gateway_e2e.py", ci)
        self.assertNotIn("continue-on-error", block)
        self.assertIn("tests/test_upstream_hermes_runtime_contracts.py", block)
        self.assertIn("name: CI gate", ci)

    def test_ci_enclosing_success_cannot_hide_missing_or_skipped_gateway(self):
        results: dict = {name: {"result": "success"} for name in (
            "change-scope", *ci_gate_check.FAST_LANES, *ci_gate_check.OS_LANES, *ci_gate_check.ARM_LANES)}
        results["upstream-hermes-compat"]["outputs"] = good_outputs()
        expected: dict[str, object] = {"os_lanes": "true", "extended_arm": "true"}
        self.assertTrue(ci_gate_check.evaluate(expected, results)[0])
        for outputs in ({}, {"gateway_result": "skipped"}, {"gateway_result": "failure"},
                        {**good_outputs(), "gateway_record": "{}"}):
            results["upstream-hermes-compat"]["outputs"] = outputs
            self.assertFalse(ci_gate_check.evaluate(expected, results)[0])

    def test_release_full_native_success_without_gateway_receipt_fails(self):
        matrix = load_matrix(ROOT / "release/verification-matrix.json")
        identity = {"candidate": SHA, "candidate_reachable": "true", "target_ref": "refs/heads/test",
                    **{key: SHA for key in ("github_sha", "checkout_sha", "ref_head_start", "ref_head_end")}}
        results = {name: {"result": "success", "outputs": {"attested_sha": SHA}} for name in (
            *release_gate_check.INFRA_JOBS, *ci_gate_check.FAST_LANES, *ci_gate_check.OS_LANES, *ci_gate_check.ARM_LANES)}
        for lane in matrix.lanes:
            results[lane]["outputs"]["stages"] = ",".join(stage for (_, stage), owner in matrix.required_stage_lanes().items() if owner == lane)
        self.assertFalse(release_gate_check.evaluate(SHA, identity, results, matrix)[0])
        results["upstream-hermes-compat"]["outputs"].update(good_outputs())
        self.assertTrue(release_gate_check.evaluate(SHA, identity, results, matrix)[0])
        record = json.loads(good_outputs()["gateway_record"])
        record["scratch_cleanup"] = {"status": "BLOCKED"}
        results["upstream-hermes-compat"]["outputs"]["gateway_record"] = json.dumps(record)
        self.assertFalse(release_gate_check.evaluate(SHA, identity, results, matrix)[0])


if __name__ == "__main__":
    unittest.main()
