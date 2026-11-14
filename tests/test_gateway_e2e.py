"""Offline contract tests for the real-Gateway driver; no Core import or operating home."""
from __future__ import annotations

from copy import deepcopy
import unittest

from scripts.gateway_docker import CHECKS

from scripts import gateway_e2e as gateway


class GatewayEvidenceTests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": 1, "status": "PASS", "candidate_sha": "a" * 40,
                "hermes_commit": "b" * 40, "candidate_source_dirty": False,
                "provider_origin": {"status": "PASS", "candidate_sha": "a" * 40, "tree_sha256": "3" * 64,
                                    "home_sha256": "4" * 64, "frozen_copies": 0, "errors": []},
                "scratch_cleanup": {"status": "PASS", "launch_count": 1},
                "shutdown_diagnostic": {"status": "PASS", "launch_count": 1},
                "confinement": {"status": "PASS", "checks": {name: True for name in CHECKS}, "pid_namespace_sha256": "1" * 64, "host_pid_namespace_sha256": "2" * 64},
                "docker_execution": {"status": "PASS", "config_verified": True, "owned_pid_namespace_verified": True, "outside_canary_unchanged": True,
                                     "container_removed": True, "image_removed": True},
                "docker_contract_version": 2, "checkout_sha": "a" * 40,
                "final_namespace_live_count": 1, "final_namespace_process_count": 1,
                "stages": {name: {"status": "PASS", "detail": "executed"} for name in gateway.REQUIRED_STAGES}}

    def test_complete_receipt_is_accepted(self):
        self.assertEqual([], gateway.validate_receipt(self.receipt(), "a" * 40))

    def test_origin_missing_wrong_sha_unbound_home_or_bad_tree_never_passes(self):
        value = self.receipt()
        del value["provider_origin"]
        self.assertIn("provider_origin_not_verified", gateway.validate_receipt(value, "a" * 40))
        for key, bad in (("status", "NOT_RUN"), ("candidate_sha", "b" * 40), ("errors", ["drift"]),
                         ("tree_sha256", ""), ("home_sha256", None), ("frozen_copies", True), ("frozen_copies", -1)):
            with self.subTest(key=key, bad=bad):
                value = self.receipt()
                value["provider_origin"][key] = bad
                self.assertIn("provider_origin_not_verified", gateway.validate_receipt(value, "a" * 40))

    def test_every_required_stage_missing_or_nonpass_fails_closed(self):
        for stage in gateway.REQUIRED_STAGES:
            for status in (None, "FAIL", "BLOCKED", "NOT_RUN", "SKIP", "", True):
                with self.subTest(stage=stage, status=status):
                    receipt = self.receipt()
                    if status is None:
                        receipt["stages"].pop(stage)
                    else:
                        receipt["stages"][stage]["status"] = status
                    self.assertTrue(gateway.validate_receipt(receipt, "a" * 40))

    def test_wrong_candidate_core_and_malformed_receipts_rejected(self):
        for bad in (None, [], {}, True):
            self.assertTrue(gateway.validate_receipt(bad, "a" * 40))
        for key, value in (("candidate_sha", "c" * 40), ("hermes_commit", "main"),
                           ("status", "BLOCKED"), ("schema_version", True), ("stages", [])):
            receipt = deepcopy(self.receipt())
            receipt[key] = value
            self.assertTrue(gateway.validate_receipt(receipt, "a" * 40))

    def test_ready_requires_live_pid_and_ready_state_not_http200(self):
        good = {"pid": 101, "status": "ok", "gateway_state": "running"}
        self.assertTrue(gateway.is_ready(good, 101))
        for value in ({"status": "ok"}, {**good, "pid": 102}, {**good, "status": "starting"},
                      {**good, "gateway_state": "startup_failed"}, {**good, "pid": True}, None):
            self.assertFalse(gateway.is_ready(value, 101))

    def test_readiness_diagnostics_only_publish_fixed_statuses_not_payloads(self):
        secret = "credential-or-session-must-not-escape"
        value = {"pid": 101, "status": "degraded", "gateway_state": "running",
                 "prompt": secret, "readiness": {"status": "degraded", "checks": {
                     "state_db": {"status": "degraded", "detail": "OperationalError"},
                     "disk": {"status": "ok", "path": secret},
                     "config": {"status": secret, "detail": secret},
                     secret: {"status": "ok"}}}}
        actual = gateway.readiness_observation(value, 101, 200)
        self.assertEqual("degraded", actual["status"])
        self.assertTrue(actual["expected_pid"])
        self.assertEqual("degraded", actual["checks"]["state_db"])
        self.assertEqual("unrecognized", actual["checks"]["config"])
        self.assertNotIn(secret, str(actual))
        self.assertNotIn("detail", str(actual))

    def test_transport_diagnostics_distinguish_errors_without_exception_text(self):
        import urllib.error
        for error, expected in ((ConnectionRefusedError("secret"), "connection_refused"),
                                (ConnectionResetError("secret"), "connection_reset"),
                                (TimeoutError("secret"), "timeout"),
                                (OSError("secret"), "unavailable")):
            for wrapped in (error, urllib.error.URLError(error)):
                with self.subTest(expected=expected, wrapped=type(wrapped).__name__):
                    value = gateway.transport_observation(wrapped)
                    self.assertEqual({"transport": expected}, value)
                    self.assertNotIn("secret", str(value))

    def test_bad_readiness_observation_never_reports_expected_pid(self):
        for value in (None, [], {}, {"pid": True}, {"pid": 102}):
            with self.subTest(value=value):
                observation = gateway.readiness_observation(value, 101, 503)
                self.assertFalse(observation["expected_pid"])
                self.assertEqual(503, observation["http_status"])
                self.assertFalse(gateway.is_ready(value, 101))

    def test_stage_fails_instead_of_promoting_cleanup_or_ready_to_success(self):
        receipt = self.receipt()
        for stage in ("candidate_install", "gateway_ready", "provider_factory", "initialize",
                      "ownership_conflict", "permission_denial", "cancellation", "child_cleanup", "isolation"):
            bad = deepcopy(receipt)
            bad["stages"][stage] = {"status": "FAIL", "detail": "synthetic_negative"}
            self.assertTrue(gateway.validate_receipt(bad, "a" * 40))


if __name__ == "__main__":
    unittest.main()
