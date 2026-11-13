"""Offline contract tests for the real-Gateway driver; no Core import or operating home."""
from __future__ import annotations

from copy import deepcopy
import unittest

from scripts import gateway_e2e as gateway


class GatewayEvidenceTests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": 1, "status": "PASS", "candidate_sha": "a" * 40,
                "hermes_commit": "b" * 40,
                "stages": {name: {"status": "PASS", "detail": "executed"} for name in gateway.REQUIRED_STAGES}}

    def test_complete_receipt_is_accepted(self):
        self.assertEqual([], gateway.validate_receipt(self.receipt(), "a" * 40))

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

    def test_stage_fails_instead_of_promoting_cleanup_or_ready_to_success(self):
        receipt = self.receipt()
        for stage in ("candidate_install", "gateway_ready", "provider_factory", "initialize",
                      "ownership_conflict", "permission_denial", "cancellation", "child_cleanup", "isolation"):
            bad = deepcopy(receipt)
            bad["stages"][stage] = {"status": "FAIL", "detail": "synthetic_negative"}
            self.assertTrue(gateway.validate_receipt(bad, "a" * 40))


if __name__ == "__main__":
    unittest.main()
