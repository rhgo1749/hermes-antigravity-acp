#!/usr/bin/env python3
"""Privacy-preserving publication gate over a sanitized exposure-audit report.

The gate reads the sanitized JSON report written by scripts/audit_exposure.py
(schema version 5) together with a fresh credential-free current-tree check and
emits a fixed-vocabulary publication decision. Every report must carry the
target repository/HEAD/ref-snapshot binding the audit recorded; the gate
recomputes the identity of its own --root and fails closed on cross-repository
or stale-HEAD replay. An explicit target repository identity (--github) is
required for any route to reach eligibility: when it is omitted, the
report-target and authorization-source repository equality checks are
unverifiable and the gate fails closed with the repository_identity_unbound
blocker on every route. It never grants authorization:
an explicit human maintainer authorization record may only be *recorded* as an
external input, and absent that record both publication routes stay unapproved.
`NOT_VERIFIED` and `OUTSIDE_VERIFIED_SCOPE` items are unresolved gaps and are
never represented as clean. The gate performs no visibility change, history
rewrite, credential operation, export, or publication, and it refuses to read
or write any audit artifact inside the repository or its linked worktrees.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

try:
    from audit_exposure import (
        REPOSITORY_RE,
        SURFACE_NAMES,
        STATUS_CLEAN,
        STATUS_FINDING,
        STATUS_NOT_VERIFIED,
        STATUS_OUTSIDE_VERIFIED_SCOPE,
        AuditFailure,
        snapshot_git_identity,
        validate_report_destination,
    )
    from audit_public_tree import scan_repository
except ImportError:  # Imported as scripts.publication_gate by repository tests.
    from scripts.audit_exposure import (
        REPOSITORY_RE,
        SURFACE_NAMES,
        STATUS_CLEAN,
        STATUS_FINDING,
        STATUS_NOT_VERIFIED,
        STATUS_OUTSIDE_VERIFIED_SCOPE,
        AuditFailure,
        snapshot_git_identity,
        validate_report_destination,
    )
    from scripts.audit_public_tree import scan_repository

VERDICT_NO_GO = "NO_GO"
VERDICT_NOT_AUTHORIZED = "NOT_AUTHORIZED"
VERDICT_CONDITIONALLY_ELIGIBLE = "CONDITIONALLY_ELIGIBLE"
SUPPORTED_REPORT_SCHEMA_VERSION = 5
REPORT_MAX_AGE_HOURS = 168
HEX_OID_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
AUTHORIZATION_SCHEMA = "publication-authorization-v1"
SCOPE_IN_PLACE = "in_place_publication"
SCOPE_CLEAN_ROOM = "clean_room_minimum_code_export"
AUTHORIZATION_SCOPES = frozenset({SCOPE_IN_PLACE, SCOPE_CLEAN_ROOM})
LIVE_CREDENTIAL_RULES = frozenset(
    {
        "private_key",
        "google_access_token",
        "google_client_secret",
        "github_token",
        "slack_token",
        "bearer_token",
    }
)
REASON_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


@dataclass
class GateFailure(Exception):
    """An intentionally non-sensitive, machine-readable failure reason."""

    reason: str

    def __post_init__(self) -> None:
        if not REASON_TOKEN_RE.fullmatch(self.reason):
            self.reason = "gate_failure"
        Exception.__init__(self, self.reason)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _count_map(values: object) -> dict[str, int] | None:
    """Return the map when every key is a str and every value is a count."""
    if not isinstance(values, dict):
        return None
    result: dict[str, int] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not _is_count(value):
            return None
        result[key] = value
    return result


def _parse_audit_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _validate_report_target(target: object) -> None:
    """Structurally validate the audit-side repository/HEAD/ref binding."""
    if not isinstance(target, dict):
        raise GateFailure("report_invalid")
    binding_status = target.get("binding_status")
    if binding_status not in {"bound", "unavailable"}:
        raise GateFailure("report_invalid")
    repository = target.get("repository")
    if repository is not None and (
        not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository)
    ):
        raise GateFailure("report_invalid")
    head_oid = target.get("head_oid")
    ref_digest = target.get("ref_digest_sha256")
    ref_count = target.get("ref_count")
    if binding_status == "bound":
        if not isinstance(head_oid, str) or not HEX_OID_RE.fullmatch(head_oid):
            raise GateFailure("report_invalid")
        if not isinstance(ref_digest, str) or not HEX_SHA256_RE.fullmatch(ref_digest):
            raise GateFailure("report_invalid")
        if not _is_count(ref_count):
            raise GateFailure("report_invalid")
    elif head_oid is not None or ref_digest is not None or ref_count is not None:
        raise GateFailure("report_invalid")


def load_report(path: Path) -> dict[str, Any]:
    """Load and structurally validate a sanitized schema-v5 audit report.

    Every declared count must be a nonnegative integer and every declared
    total must match an independent recomputation, so a self-declared
    ``partition_valid`` is never trusted on its own.
    """
    try:
        report = json.loads(path.read_bytes())
    except (OSError, ValueError):
        raise GateFailure("report_unreadable") from None
    if not isinstance(report, dict) or report.get("schema_version") != SUPPORTED_REPORT_SCHEMA_VERSION:
        raise GateFailure("report_schema_unsupported")
    if report.get("read_only") is not True:
        raise GateFailure("report_invalid")
    _validate_report_target(report.get("target"))
    summary = report.get("summary")
    sources = report.get("sources")
    if not isinstance(summary, dict) or not isinstance(summary.get("partition"), dict):
        raise GateFailure("report_invalid")
    if not isinstance(sources, dict) or set(sources) != set(SURFACE_NAMES):
        raise GateFailure("report_invalid")
    statuses = (STATUS_CLEAN, STATUS_FINDING, STATUS_NOT_VERIFIED, STATUS_OUTSIDE_VERIFIED_SCOPE)
    aggregate = {status: 0 for status in statuses}
    for source in sources.values():
        if not isinstance(source, dict) or not isinstance(source.get("partition"), dict):
            raise GateFailure("report_invalid")
        if source.get("partition_valid") is not True:
            raise GateFailure("report_partition_invalid")
        if not _is_count(source.get("total")):
            raise GateFailure("report_invalid")
        partition_total = 0
        for status in statuses:
            if not _is_count(source["partition"].get(status)):
                raise GateFailure("report_invalid")
            partition_total += source["partition"][status]
        if source["total"] != partition_total:
            raise GateFailure("report_partition_inconsistent")
        for collection_key in ("not_verified_reasons", "finding_rules"):
            if _count_map(source.get(collection_key)) is None:
                raise GateFailure("report_invalid")
        if _count_map(source.get("finding_classes")) is None:
            raise GateFailure("report_invalid")
        outside_reasons = _count_map(source.get("outside_verified_scope_reasons"))
        if outside_reasons is None:
            raise GateFailure("report_invalid")
        if sum(source["not_verified_reasons"].values()) != source["partition"][STATUS_NOT_VERIFIED]:
            raise GateFailure("report_partition_inconsistent")
        if sum(outside_reasons.values()) != source["partition"][STATUS_OUTSIDE_VERIFIED_SCOPE]:
            raise GateFailure("report_partition_inconsistent")
        if sum(source["finding_classes"].values()) != source["partition"][STATUS_FINDING]:
            raise GateFailure("report_partition_inconsistent")
        for status in statuses:
            aggregate[status] += source["partition"][status]
    summary_partition = summary["partition"]
    for status in statuses:
        if not _is_count(summary_partition.get(status)):
            raise GateFailure("report_invalid")
        if summary_partition[status] != aggregate[status]:
            raise GateFailure("report_partition_inconsistent")
    if not _is_count(summary.get("total")) or summary["total"] != sum(aggregate.values()):
        raise GateFailure("report_partition_inconsistent")
    summary_classes = _count_map(summary.get("finding_classes"))
    if summary_classes is None or sum(summary_classes.values()) != aggregate[STATUS_FINDING]:
        raise GateFailure("report_partition_inconsistent")
    audit_time = report.get("audit_time_utc")
    if not isinstance(audit_time, str) or _parse_audit_time(audit_time) is None:
        raise GateFailure("report_invalid")
    return report


def report_age_hours(report: dict[str, Any], now: dt.datetime) -> int:
    parsed = _parse_audit_time(str(report["audit_time_utc"]))
    if parsed is None:
        raise GateFailure("report_invalid")
    age = int((now - parsed).total_seconds() // 3600)
    if age < 0:
        raise GateFailure("report_invalid")
    return age


def surface_open_items(partition: dict[str, int]) -> int:
    return (
        int(partition.get(STATUS_FINDING, 0))
        + int(partition.get(STATUS_NOT_VERIFIED, 0))
        + int(partition.get(STATUS_OUTSIDE_VERIFIED_SCOPE, 0))
    )


def coverage_status(report: dict[str, Any]) -> dict[str, Any]:
    """Aggregate the four typed partitions across every audited surface."""
    totals = {
        STATUS_CLEAN: 0,
        STATUS_FINDING: 0,
        STATUS_NOT_VERIFIED: 0,
        STATUS_OUTSIDE_VERIFIED_SCOPE: 0,
    }
    surfaces_with_open_gaps: list[str] = []
    for name in sorted(report["sources"]):
        partition = report["sources"][name]["partition"]
        for status in totals:
            totals[status] += int(partition.get(status, 0))
        if surface_open_items(partition) > 0:
            surfaces_with_open_gaps.append(name)
    gap_reasons: list[str] = []
    if totals[STATUS_FINDING] > 0:
        gap_reasons.append("findings_present")
    if totals[STATUS_NOT_VERIFIED] > 0:
        gap_reasons.append("unverified_items_present")
    if totals[STATUS_OUTSIDE_VERIFIED_SCOPE] > 0:
        gap_reasons.append("outside_verified_scope_present")
    return {
        "partition": totals,
        "gap_reasons": gap_reasons,
        "surfaces_with_open_gaps": surfaces_with_open_gaps,
        "clean_coverage_satisfied": not gap_reasons,
    }


def clean_coverage_satisfied(report: dict[str, Any]) -> bool:
    """True only when zero FINDING, NOT_VERIFIED, and OUTSIDE_VERIFIED_SCOPE items remain."""
    return coverage_status(report)["clean_coverage_satisfied"]


def load_authorization(path: Path) -> tuple[dict[str, Any] | None, str, str]:
    """Return (record_or_None, status, digest) without echoing the file content."""
    try:
        raw = path.read_bytes()
        record = json.loads(raw)
    except (OSError, ValueError):
        return None, "invalid", ""
    digest = hashlib.sha256(raw).hexdigest()
    if (
        not isinstance(record, dict)
        or record.get("schema") != AUTHORIZATION_SCHEMA
        or record.get("authorized") is not True
        or record.get("scope") not in AUTHORIZATION_SCOPES
        or not isinstance(record.get("source_repository"), str)
        or not REPOSITORY_RE.fullmatch(record["source_repository"])
    ):
        return None, "invalid", digest
    return record, "recorded", digest


def current_tree_rule_counts(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in scan_repository(root):
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    return counts


def evaluate_decision(
    report: dict[str, Any],
    *,
    current_tree_rules: dict[str, int],
    authorization: dict[str, Any] | None,
    authorization_status: str,
    authorization_digest: str | None,
    github_repository: str | None,
    report_digest: str,
    identity_probe: dict[str, Any] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    coverage = coverage_status(report)
    age_hours = report_age_hours(report, now)
    finding_rules: dict[str, int] = {}
    for source in report["sources"].values():
        for rule, count in source["finding_rules"].items():
            finding_rules[rule] = finding_rules.get(rule, 0) + int(count)
    live_rules = sorted(
        (set(finding_rules) | set(current_tree_rules)) & LIVE_CREDENTIAL_RULES
    )

    target = report.get("target") or {}
    binding_blockers: list[str] = []
    repository_match: bool | None = None
    head_match: bool | None = None
    ref_snapshot_match: bool | None = None
    if github_repository is None:
        # Fail closed: without an explicit target repository identity the
        # explicit-target, report-target, and authorization-source repository
        # equality checks are unverifiable, so no publication route may be
        # treated as eligible. The blocker is not a coverage-gap token and
        # therefore also survives the clean-room gap-waiver filter.
        binding_blockers.append("repository_identity_unbound")
    if target.get("binding_status") != "bound":
        binding_blockers.append("report_target_unbound")
    else:
        report_repository = target.get("repository")
        if github_repository is not None:
            repository_match = (
                isinstance(report_repository, str)
                and report_repository.casefold() == github_repository.casefold()
            )
            if not repository_match:
                binding_blockers.append("report_repository_mismatch")
        elif report_repository is None:
            binding_blockers.append("report_repository_unbound")
        if not isinstance(identity_probe, dict) or identity_probe.get("binding_status") != "bound":
            binding_blockers.append("root_identity_unavailable")
        else:
            head_match = target.get("head_oid") == identity_probe.get("head_oid")
            ref_snapshot_match = (
                target.get("ref_digest_sha256") == identity_probe.get("ref_digest_sha256")
            )
            if not head_match:
                binding_blockers.append("report_head_mismatch")
            if not ref_snapshot_match:
                binding_blockers.append("report_ref_snapshot_mismatch")

    authorization_blockers: list[str] = []
    authorization_scope: str | None = None
    authorization_repository_match: bool | None = None
    if authorization_status == "recorded" and authorization is not None:
        authorization_scope = str(authorization["scope"])
        if github_repository is not None:
            authorization_repository_match = (
                str(authorization["source_repository"]).casefold() == github_repository.casefold()
            )
            if not authorization_repository_match:
                authorization_blockers.append("maintainer_authorization_repository_mismatch")
    elif authorization_status == "invalid":
        authorization_blockers.append("maintainer_authorization_invalid")
    else:
        authorization_blockers.append("maintainer_authorization_not_recorded")

    gap_tokens = set(coverage["gap_reasons"])
    coverage_blockers = list(binding_blockers) + list(coverage["gap_reasons"])
    if current_tree_rules:
        coverage_blockers.append("current_tree_findings")
    if age_hours > REPORT_MAX_AGE_HOURS:
        coverage_blockers.append("audit_report_stale")
    if live_rules:
        coverage_blockers.append("live_credential_review_open")

    def route(scope: str, *, blocking: list[str]) -> dict[str, Any]:
        blockers = list(blocking)
        scope_blockers = list(authorization_blockers)
        if authorization_status == "recorded" and authorization_scope not in (None, scope):
            scope_blockers = ["maintainer_authorization_scope_mismatch"]
        if blockers:
            verdict = VERDICT_NO_GO
        elif scope_blockers:
            verdict = VERDICT_NOT_AUTHORIZED
        else:
            verdict = VERDICT_CONDITIONALLY_ELIGIBLE
        return {"verdict": verdict, "blocking_reasons": sorted(set(blockers + scope_blockers))}

    in_place = route(SCOPE_IN_PLACE, blocking=coverage_blockers)
    clean_room_blockers = [token for token in coverage_blockers if token not in gap_tokens]
    clean_room = route(SCOPE_CLEAN_ROOM, blocking=clean_room_blockers)

    route_verdicts = [in_place["verdict"], clean_room["verdict"]]
    if VERDICT_NO_GO in route_verdicts:
        overall = "NO-GO"
    elif VERDICT_NOT_AUTHORIZED in route_verdicts:
        overall = "NOT-AUTHORIZED"
    else:
        overall = "CONDITIONALLY-ELIGIBLE"

    return {
        "schema_version": 1,
        "gate_time_utc": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "verdict": overall,
        "audit_report": {
            "schema_version": SUPPORTED_REPORT_SCHEMA_VERSION,
            "audit_time_utc": report["audit_time_utc"],
            "age_hours": age_hours,
            "stale_limit_hours": REPORT_MAX_AGE_HOURS,
            "digest_sha256": report_digest,
        },
        "report_binding": {
            "status": "bound" if target.get("binding_status") == "bound" else "unbound",
            "target_repository": target.get("repository"),
            "target_head_oid": target.get("head_oid"),
            "repository_match": repository_match,
            "head_match": head_match,
            "ref_snapshot_match": ref_snapshot_match,
            "blockers": sorted(set(binding_blockers)),
        },
        "coverage": coverage,
        "current_tree": {
            "status": "FINDING" if current_tree_rules else "CHECKED_NO_FINDING",
            "rule_counts": dict(sorted(current_tree_rules.items())),
        },
        "maintainer_authorization": {
            "status": authorization_status,
            "scope": authorization_scope,
            "repository_match": authorization_repository_match,
            "record_digest_sha256": authorization_digest,
        },
        "routes": {
            SCOPE_IN_PLACE: in_place,
            SCOPE_CLEAN_ROOM: {
                **clean_room,
                "residual_gap_policy": "NOT_VERIFIED_AND_OUTSIDE_VERIFIED_SCOPE_REMAIN_OPEN",
            },
        },
        "credential_response_route": {
            "live_credential_review_required": bool(live_rules),
            "route": "separate_authorized_deactivation_rotation_plan",
            "execution": "not_performed_by_gate",
        },
        "approval_granted_by_gate": False,
        "invariants": [
            "reports_must_bind_target_repository_head_and_ref_snapshot",
            "current_tree_cleanliness_never_substitutes_for_history_and_remote_coverage",
            "not_verified_is_never_clean",
            "outside_verified_scope_is_never_clean",
            "gate_records_authorization_but_never_grants_it",
            "routes_fail_closed_without_explicit_repository_identity",
        ],
    }


def render_markdown(decision: dict[str, Any]) -> str:
    coverage = decision["coverage"]
    partition = coverage["partition"]
    in_place = decision["routes"][SCOPE_IN_PLACE]
    clean_room = decision["routes"][SCOPE_CLEAN_ROOM]
    authorization = decision["maintainer_authorization"]
    credential = decision["credential_response_route"]
    binding = decision.get("report_binding") or {}
    lines = [
        "# Publication gate decision (sanitized)",
        "",
        f"Gate time (UTC): {decision['gate_time_utc']}",
        (
            f"Audit report: schema {decision['audit_report']['schema_version']}, "
            f"time (UTC) {decision['audit_report']['audit_time_utc']}, "
            f"age {decision['audit_report']['age_hours']}h, "
            f"digest sha256 {decision['audit_report']['digest_sha256']}"
        ),
        "Read-only: yes",
        f"Overall verdict: {decision['verdict']}",
        "",
        "## Report binding",
        "",
        f"- Binding status: {binding.get('status', 'unbound')}",
        f"- Target repository: {binding.get('target_repository') or 'unbound'}",
        f"- Target HEAD: {binding.get('target_head_oid') or 'unbound'}",
        (
            "- Binding blockers: "
            + (", ".join(binding.get("blockers", [])) or "none")
        ),
        "",
        "## Scan scope",
        "",
        "- current tree via the credential-free fast check (scripts/audit_public_tree.py)",
        "- local advertised refs, reachable commits and blobs, and the object-store boundary",
        "- GitHub-visible refs, reachable history, Issue/PR discussions, comments, reviews,",
        "  Actions runs/logs/artifacts, releases/assets, and discovered GitHub attachments",
        "- arbitrary external links are recorded, not fetched",
        "",
        "## Coverage partition",
        "",
        f"- CHECKED_NO_FINDING: {partition[STATUS_CLEAN]}",
        f"- FINDING: {partition[STATUS_FINDING]}",
        f"- NOT_VERIFIED: {partition[STATUS_NOT_VERIFIED]}",
        f"- OUTSIDE_VERIFIED_SCOPE: {partition[STATUS_OUTSIDE_VERIFIED_SCOPE]}",
        f"- clean coverage satisfied: {'yes' if coverage['clean_coverage_satisfied'] else 'no'}",
        f"- surfaces with open gaps: {', '.join(coverage['surfaces_with_open_gaps']) or 'none'}",
        "",
        "## Route decisions",
        "",
        f"- In-place publicization: {in_place['verdict']}"
        + (f" ({', '.join(in_place['blocking_reasons'])})" if in_place["blocking_reasons"] else ""),
        f"- Clean-room scrubbed minimum-code export: {clean_room['verdict']}"
        + (f" ({', '.join(clean_room['blocking_reasons'])})" if clean_room["blocking_reasons"] else ""),
        f"- Maintainer authorization recorded: {authorization['status']}",
        "- Approval granted by this gate: no (the gate only records explicit human maintainer authorization)",
        "",
        "## Credential response route",
        "",
        "- live credential review required: " + ("yes" if credential["live_credential_review_required"] else "no"),
        "- route: separate authorized deactivation/rotation plan; never executed by the audit or gate",
        "",
        "NOT_VERIFIED and OUTSIDE_VERIFIED_SCOPE items are unresolved gaps and are never",
        "represented as clean. The private verification authority is the sanitized audit",
        "report identified by the digest above, kept outside the repository and its linked",
        "worktrees by the repository maintainer.",
        "",
    ]
    return "\n".join(lines)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        self.exit(2, "gate arguments invalid; details suppressed\n")


def main(argv: list[str] | None = None) -> int:
    parser = _SanitizedArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="sanitized schema-v4 audit report JSON (external)")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="checkout for the current-tree check (read-only)")
    parser.add_argument(
        "--github",
        metavar="OWNER/REPO",
        help="repository the decision and authorization bind to; required for any route to be eligible (the gate fails closed when omitted)",
    )
    parser.add_argument(
        "--authorization", type=Path, help="external maintainer authorization record (recorded, never required)"
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="write the sanitized decision to this external path")
    args = parser.parse_args(argv)
    if args.github and not REPOSITORY_RE.fullmatch(args.github):
        print("gate configuration invalid; details suppressed", file=sys.stderr)
        return 2
    gate_paths = [args.report]
    if args.authorization is not None:
        gate_paths.append(args.authorization)
    if args.output is not None:
        gate_paths.append(args.output)
    for candidate in gate_paths:
        try:
            validate_report_destination(args.root, candidate)
        except AuditFailure as exc:
            if exc.reason == "destination_inside_repository":
                print("gate paths must be outside the repository; details suppressed", file=sys.stderr)
            else:
                print("gate path location could not be validated; details suppressed", file=sys.stderr)
            return 2
    try:
        report = load_report(args.report)
        report_digest = hashlib.sha256(args.report.read_bytes()).hexdigest()
        authorization: dict[str, Any] | None = None
        authorization_status = "not_recorded"
        authorization_digest: str | None = None
        if args.authorization is not None:
            authorization, authorization_status, authorization_digest = load_authorization(args.authorization)
        try:
            rule_counts = current_tree_rule_counts(args.root)
        except Exception:  # noqa: BLE001 -- only a fixed failure token is retained.
            raise GateFailure("current_tree_check_failed") from None
        decision = evaluate_decision(
            report,
            current_tree_rules=rule_counts,
            authorization=authorization,
            authorization_status=authorization_status,
            authorization_digest=authorization_digest,
            github_repository=args.github,
            report_digest=report_digest,
            identity_probe=snapshot_git_identity(args.root),
        )
        rendered = render_markdown(decision) if args.format == "markdown" else (
            json.dumps(decision, indent=2, sort_keys=True) + "\n"
        )
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print("sanitized publication-gate decision written; raw values and paths suppressed")
        else:
            sys.stdout.write(rendered)
        return 0
    except GateFailure:
        print("gate input could not be evaluated; details suppressed", file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 -- CLI errors must not echo paths, values, or report content.
        print("gate failed; details suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
