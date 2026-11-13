"""CI consumes executed, same-SHA Gateway evidence, never an enclosing success alone."""
from __future__ import annotations

import json
import unittest

from scripts import gateway_attestation as attest
from scripts.gateway_e2e import REQUIRED_STAGES


class GatewayAttestationTests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": 1, "status": "PASS", "candidate_sha": "a" * 40,
                "hermes_commit": "b" * 40, "stages": {name: {"status": "PASS"} for name in REQUIRED_STAGES}}

    def outputs(self) -> dict[str, object]:
        return {"attested_sha": "a" * 40, "gateway_result": "success", "gateway_record": json.dumps(self.receipt())}

    def test_executed_same_sha_receipt_accepted(self):
        self.assertEqual([], attest.check_outputs(self.outputs(), required=True, candidate="a" * 40))

    def test_enclosing_job_success_without_executed_receipt_never_passes(self):
        for result in ("skipped", "failure", "cancelled", "", None):
            output = self.outputs()
            output["gateway_result"] = result
            self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))
        self.assertTrue(attest.check_outputs({"attested_sha": "a" * 40}, required=True, candidate="a" * 40))

    def test_wrong_sha_malformed_and_all_incomplete_stages_rejected(self):
        for record in ("", "{}", "null", "[]", "not json"):
            output = self.outputs()
            output["gateway_record"] = record
            self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))
        self.assertTrue(attest.check_outputs(self.outputs(), required=True, candidate="c" * 40))
        for name in REQUIRED_STAGES:
            for status in ("BLOCKED", "FAIL", "NOT_RUN", "skipped", True, None):
                receipt = self.receipt()
                receipt["stages"][name]["status"] = status
                output = self.outputs()
                output["gateway_record"] = json.dumps(receipt)
                self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))

    def test_only_explicit_unrequired_skip_is_accepted(self):
        self.assertEqual([], attest.check_outputs({"gateway_result": "skipped", "gateway_record": ""}, required=False))
        self.assertTrue(attest.check_outputs({}, required=False))
        self.assertTrue(attest.check_outputs({"gateway_result": "failure"}, required=False))


if __name__ == "__main__":
    unittest.main()
