#!/usr/bin/env python3
"""Load and strictly validate the version-controlled release verification matrix.

The matrix (``release/verification-matrix.json``, issue #28 Phase B) is the
single source of truth for what a release candidate must prove on each of the
five declared native targets. This loader fails closed on any structural
drift: unknown enums, missing evidence citations, a ``PASS`` status without
an evidence string, duplicate lanes, or a required stage that names a lane
outside the workflow's lane set. ``scripts/release_gate_check.py`` consumes
the validated matrix; a malformed matrix can never widen a release.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

SCHEMA_VERSION = 1
STATUS_VALUES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT_RUN"})
EVIDENCE_CLASSES = frozenset(
    {
        "official_binary_clean_room",
        "official_binary_hosted",
        "real_core_integration",
        "fake_transport_protocol",
        "registry_pin_only",
        "not_executed",
    }
)
STAGE_IDS = frozenset(
    {
        "binary_publisher_pin_sha256",
        "install_status_verify_uninstall",
        "provider_registration_enabled",
        "provider_selection_factory",
        "acp_initialize_unauthenticated",
        "error_timeout_permission_failclosed",
        "session_resume_recovery",
        "platform_security_hardening",
    }
)
DECLARED_TARGETS = frozenset(
    {"linux-x86_64", "windows-x64", "windows-arm64", "macos-arm64", "linux-aarch64"}
)


class MatrixError(Exception):
    """The matrix file is structurally invalid; release verification must stop."""


@dataclass(frozen=True)
class StageEntry:
    target: str
    stage: str
    lane: str
    required: bool
    status: str
    evidence_class: str
    trigger: str
    evidence: str
    limitation: str


@dataclass(frozen=True)
class Matrix:
    targets: dict[str, dict[str, StageEntry]]

    @property
    def lanes(self) -> frozenset[str]:
        return frozenset(entry.lane for target in self.targets.values() for entry in target.values())

    def required_stage_lanes(self) -> dict[tuple[str, str], str]:
        """(target, stage) -> lane for every required cell."""
        return {
            (target, stage): entry.lane
            for target, stages in self.targets.items()
            for stage, entry in stages.items()
            if entry.required
        }

    def cells(self) -> list[StageEntry]:
        return [
            entry for stages in self.targets.values() for entry in stages.values()
        ]


def _entry(target_id: str, stage_id: str, raw: object) -> StageEntry:
    if not isinstance(raw, dict):
        raise MatrixError(f"{target_id}/{stage_id}: entry must be an object")
    required = raw.get("required")
    if not isinstance(required, bool):
        raise MatrixError(f"{target_id}/{stage_id}: required must be a bool")
    status = raw.get("status")
    if status not in STATUS_VALUES:
        raise MatrixError(f"{target_id}/{stage_id}: status {status!r} is not a known value")
    evidence_class = raw.get("evidence_class")
    if evidence_class not in EVIDENCE_CLASSES:
        raise MatrixError(
            f"{target_id}/{stage_id}: evidence_class {evidence_class!r} is not known"
        )
    evidence = raw.get("evidence", "")
    limitation = raw.get("limitation", "")
    if not isinstance(evidence, str) or not isinstance(limitation, str):
        raise MatrixError(f"{target_id}/{stage_id}: evidence/limitation must be strings")
    if status == "PASS" and not evidence.strip():
        # A PASS that cites nothing is exactly the fabricated-green this
        # matrix exists to prevent.
        raise MatrixError(f"{target_id}/{stage_id}: PASS requires an evidence citation")
    if status in {"BLOCKED", "NOT_RUN", "FAIL"} and not limitation.strip():
        raise MatrixError(f"{target_id}/{stage_id}: {status} requires a limitation")
    if status == "PASS" and evidence_class == "not_executed":
        raise MatrixError(f"{target_id}/{stage_id}: PASS cannot carry not_executed")
    trigger = raw.get("trigger")
    if not isinstance(trigger, str) or not trigger:
        raise MatrixError(f"{target_id}/{stage_id}: trigger must be a non-empty string")
    lane = raw.get("lane", "")
    if not isinstance(lane, str):
        raise MatrixError(f"{target_id}/{stage_id}: lane must be a string")
    return StageEntry(target_id, stage_id, lane, required, status, evidence_class, trigger, evidence, limitation)


def load_matrix(path: Path) -> Matrix:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MatrixError(f"matrix unreadable: {type(exc).__name__}") from None
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise MatrixError("matrix schema_version unsupported")
    stages_meta = raw.get("stages")
    if not isinstance(stages_meta, dict) or frozenset(stages_meta) != STAGE_IDS:
        raise MatrixError("matrix stage vocabulary drifted")
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list):
        raise MatrixError("matrix targets must be a list")
    targets: dict[str, dict[str, StageEntry]] = {}
    primary_lanes: dict[str, str] = {}
    for target in targets_raw:
        if not isinstance(target, dict):
            raise MatrixError("matrix target must be an object")
        target_id = target.get("id")
        if not isinstance(target_id, str) or target_id in targets:
            raise MatrixError("matrix target id invalid or duplicated")
        lane = target.get("lane")
        if not isinstance(lane, str) or not lane:
            raise MatrixError(f"{target_id}: primary lane must be a non-empty string")
        if lane in primary_lanes:
            raise MatrixError(f"{target_id}: lane {lane} already owned by {primary_lanes[lane]}")
        primary_lanes[lane] = target_id
        stages_raw = target.get("stages")
        if not isinstance(stages_raw, dict) or frozenset(stages_raw) != STAGE_IDS:
            raise MatrixError(f"{target_id}: stage vocabulary drifted")
        entries: dict[str, StageEntry] = {}
        for stage_id, stage_raw in stages_raw.items():
            entry = _entry(target_id, stage_id, stage_raw)
            # A cell without an explicit lane is covered by the target's
            # primary lane; an explicit lane may be a shared cross-cutting
            # lane (e.g. the fake-acp protocol lanes) but never another
            # target's PRIMARY lane.
            if entry.lane and entry.lane in primary_lanes and primary_lanes[entry.lane] != target_id:
                raise MatrixError(f"{target_id}/{stage_id}: lane {entry.lane} is owned by another target")
            entry = replace(entry, lane=entry.lane or lane)
            if entry.required and entry.status in {"NOT_RUN", "FAIL"}:
                # A required cell that is known-broken or never-run must be
                # reclassified to an explicit support limitation before a
                # release can proceed; the matrix itself stays fail-closed.
                raise MatrixError(
                    f"{target_id}/{stage_id}: required cell cannot hold status {entry.status}"
                )
            entries[stage_id] = entry
        targets[target_id] = entries
    if frozenset(targets) != DECLARED_TARGETS:
        raise MatrixError("matrix target set drifted from the five declared native targets")
    for target_id, entries in targets.items():
        for stage_id, entry in entries.items():
            # The first pass cannot see a later target's primary lane. Check
            # again with the complete owner map: one OS can never attest another.
            if entry.lane in primary_lanes and primary_lanes[entry.lane] != target_id:
                raise MatrixError(f"{target_id}/{stage_id}: lane {entry.lane} is owned by another target")
            if entry.required and not entry.lane:
                raise MatrixError(f"{target_id}/{stage_id}: required cell needs a covering lane")
    return Matrix(targets)


def known_lanes(matrix: Matrix) -> frozenset[str]:
    """Every lane the matrix references (primary or cross-cutting)."""
    return matrix.lanes


if __name__ == "__main__":
    import sys

    default = Path(__file__).resolve().parents[1] / "release" / "verification-matrix.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    try:
        loaded = load_matrix(path)
    except MatrixError as exc:
        print(f"matrix invalid: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(
        f"matrix ok: {len(loaded.targets)} targets, "
        f"{sum(len(v) for v in loaded.targets.values())} cells, "
        f"lanes={sorted(loaded.lanes)}"
    )
