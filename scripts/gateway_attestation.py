#!/usr/bin/env python3
"""Validate real executed Gateway receipts before CI/Release approval."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from gateway_e2e import validate_receipt
    from gateway_docker import validate_docker_receipt
except ImportError:
    from scripts.gateway_e2e import validate_receipt
    from scripts.gateway_docker import validate_docker_receipt


def check_outputs(outputs: dict, *, required: bool, candidate: str | None = None) -> list[str]:
    if not isinstance(outputs, dict):
        return ["gateway_outputs_malformed"]
    outcome = outputs.get("gateway_result")
    if outcome == "skipped" and not required and not outputs.get("gateway_record"):
        return []
    if outcome != "success":
        return ["gateway_execution_not_success"]
    try:
        record = json.loads(outputs.get("gateway_record", ""))
    except (TypeError, ValueError):
        return ["gateway_record_malformed"]
    sha = candidate if candidate is not None else outputs.get("attested_sha", "")
    if not isinstance(sha, str):
        return ["gateway_candidate_missing"]
    return [*validate_receipt(record, sha), *validate_docker_receipt(record)] if isinstance(record, dict) else ["gateway_record_malformed"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--core", required=True)
    args = parser.parse_args()
    record = json.loads(args.record.read_text(encoding="utf-8"))
    problems = validate_receipt(record, args.candidate)
    if not isinstance(record, dict):
        print("Gateway attestation refused: receipt_not_object")
        return 1
    problems.extend(validate_docker_receipt(record))
    if record.get("hermes_commit") != args.core:
        problems.append("gateway_core_identity_mismatch")
    if problems:
        print("Gateway attestation refused: " + ",".join(problems))
        return 1
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("record=" + json.dumps(record, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
