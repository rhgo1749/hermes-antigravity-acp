"""historical reference: the official-binary clean-room evidence record is a contract.

The evidence document (`docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md`)
keeps two eras strictly separated (owner evidence-venue ruling, historical reference
historical reference): the 2026-11-07 private Debian-container attempt is a
historical observation log that is NOT EXECUTED as clean-room acceptance
evidence and is never retro-promoted (its env-only `env -i`/empty-HOME
scrub does not establish a separate OS UID or credential-state isolation),
while the accepted clean-room execution is the GitHub-hosted
dedicated-OS-UID `acp-clean-room` CI chain (download, publisher pin,
install, verify, real unauthenticated initialize, Hermes provider
selection, uninstall/reinstall, fail-closed diagnostics). This suite keeps
that record honest and machine-checkable WITHOUT network access:

- every archive digest quoted in the record must equal the CURRENT registry
  pin (the record cannot drift from the pinned supply chain);
- the executed/NOT-VERIFIED status tokens must keep their exact wording so
  no reader (or downstream doc) can silently promote a gated class or the
  superseded container era;
- the per-platform matrix must keep Linux x86_64 as the ONLY executed row
  (hosted venue only) and every unexecuted row explicitly NOT VERIFIED
  (no cross-platform implication from Linux);
- the prior private-container/Docker-era attempts must stay labeled
  historical and NOT EXECUTED, and env-only isolation must never be
  claimed as OS-user or credential-state isolation;
- the record must state the auth boundary it did not cross, the Gate C
  NO-GO, and the independence of historical reference/historical reference/historical reference;
- the record itself must pass the repository's own secret-content and
  credential-shape scanners and contain no personal host paths.

Credential-free: nothing here downloads, executes, or authenticates.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DOC = ROOT / "docs" / "official-server-1.4.4-clean-room-e2e-2026-11-07.md"

sys.path.insert(0, str(ROOT))
from antigravity_acp.registry import VERSION, resolve_distribution  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit = _load("apt_evidence_contract", "scripts/audit_public_tree.py")
install_acp = _load("ia_evidence_contract", "scripts/install_acp.py")


@pytest.fixture(scope="module")
def doc() -> str:
    assert EVIDENCE_DOC.is_file(), "the clean-room evidence record must exist"
    return EVIDENCE_DOC.read_text(encoding="utf-8")


def _table_row(doc: str, label: str) -> str:
    rows = [ln for ln in doc.splitlines() if ln.startswith(f"| {label} |")]
    assert rows, f"evidence record must contain a matrix row for {label!r}"
    return rows[0]


def test_evidence_record_names_official_hermes_core_commit(doc: str) -> None:
    assert "NousResearch/hermes-agent" in doc
    commits = re.findall(r"commit `([0-9a-f]{40})`", doc)
    assert len(commits) >= 1, "the official Hermes Core commit (40-hex) must be recorded"
    assert re.search(r"tree `[0-9a-f]{40}`", doc), "the Hermes Core tree object must be recorded"
    assert "uv sync --frozen" in doc, "the official frozen-lock install must be recorded"
    assert re.search(r"`uv\.lock` SHA-256 `[0-9a-f]{64}`", doc) or re.search(
        r"uv\.lock[^\n]*`[0-9a-f]{64}`", doc
    ), "the exact uv.lock digest must be recorded"


def test_evidence_digests_equal_current_registry_pins(doc: str) -> None:
    assert f"`{VERSION}`" in doc or f"{VERSION} binary" in doc
    linux = resolve_distribution("linux", "x86_64")
    assert linux.sha256 in doc, "the record must quote the CURRENT linux/x86_64 publisher pin in full"
    for label, system, machine in (
        ("Linux aarch64", "linux", "aarch64"),
        ("macOS arm64", "darwin", "arm64"),
        ("Windows x64", "windows", "amd64"),
        ("Windows arm64", "windows", "arm64"),
    ):
        dist = resolve_distribution(system, machine)
        row = _table_row(doc, label)
        assert "MATCH" in row, f"{label} must record its feed-vs-registry pin check"
        # The matrix references the same feed the registry pins came from;
        # the full digests live in registry.py (single source of truth).
        assert dist.sha256 != ""  # pin exists at all
    assert "baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a" in doc
    assert resolve_distribution("linux", "x86_64").sha256 == (
        "baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a"
    ), "this test itself must rotate with the registry pin"


def test_status_tokens_keep_exact_meaning(doc: str) -> None:
    block = re.search(r"```text\n(.*?)```", doc, re.DOTALL)
    assert block, "the record must carry a machine-readable token block"
    tokens = block.group(1)
    assert "FAKE-CI-SMOKE: VERIFIED" in tokens
    # The isolation requirement: the private-container era is never EXECUTED
    # as acceptance evidence — the accepted class-2 token is HOSTED-*.
    assert "REAL-INITIALIZE: NOT EXECUTED" in tokens
    assert "REAL-INITIALIZE: EXECUTED" not in tokens
    assert "UNAUTHENTICATED-MODEL-DISCOVERY: NOT VERIFIED" in tokens
    assert "AUTHENTICATED-SESSION: OUT OF SCOPE / NOT RUN" in tokens
    assert "REAL-INFERENCE: NOT RUN / NO-GO" in tokens
    assert "BLOCKER-CATALOG-PATH-A: NOT VERIFIED" in tokens
    assert "BLOCKER-FRESH-UID: NOT EXECUTED" in tokens
    assert "BLOCKER-FRESH-UID: APPROXIMATED" not in tokens
    # A truthful blocker is never presented as a pass.
    assert "not PASS" in doc


def test_platform_matrix_never_implies_cross_platform_proof(doc: str) -> None:
    linux_row = _table_row(doc, "Linux x86_64")
    assert "EXECUTED (2026-11-08, hosted" in linux_row
    assert "NOT EXECUTED as acceptance evidence" in linux_row, (
        "the Linux row must mark the private-container attempt non-acceptance"
    )
    assert "EXECUTED (2026-11-07" not in linux_row
    assert "NOT RUN / NO-GO" in linux_row, "even Linux inference stays NOT RUN"
    for label in ("Linux aarch64", "macOS arm64", "Windows x64", "Windows arm64"):
        row = _table_row(doc, label)
        assert row.count("NOT VERIFIED") >= 2, f"{label} execution rows stay explicitly NOT VERIFIED"
        assert "EXECUTED" not in row
    assert "implies runtime proof" in doc


def test_auth_boundary_is_recorded_and_not_crossed(doc: str) -> None:
    assert "code=-32000" in doc and "Authentication required" in doc
    assert "authenticate" in doc
    assert "zero `authenticate`/login/OAuth frames" in doc or "zero authenticate" in doc
    assert "no prompt was sent in this run" in doc


def test_evidence_and_publication_decisions_remain_separate(doc: str) -> None:
    section = " ".join(doc.split("## Evidence boundaries", 1)[1].split("## ", 1)[0].split())
    for independent in ("authenticated inference", "terms compliance", "catalog availability", "permission to publish"):
        assert independent in section
    assert "separate evidence and decisions" in section


def test_lifecycle_chain_steps_are_all_recorded(doc: str) -> None:
    for fragment in (
        "download/pin",
        "install",
        "status",
        "verify",
        "initialize",
        "uninstall",
        "reinstall",
        "provider select",
        "model discovery",
    ):
        assert fragment in doc.lower(), f"chain step {fragment!r} must be recorded"
    # Fail-closed ownership refusal was exercised for real.
    assert "Refusing to remove an unmanaged official ACP launcher" in doc
    assert "Refusing to replace an unmanaged official ACP launcher" in doc


def test_evidence_record_is_itself_sanitized(doc: str) -> None:
    # The repository's own secret-content rules find nothing in the record.
    assert audit.scan_text(doc) == []
    # No credential-shaped material by the runtime's own shape classes.
    offenders = sorted(
        name
        for name, pattern in install_acp._CREDENTIAL_SHAPES
        if any(pattern.search(line) for line in doc.splitlines())
    )
    assert offenders == [], f"evidence record trips credential-shape classes: {offenders}"
    # No personal host path identities.
    assert "/home/hermes" not in doc
    assert not re.search(r"(?i)/users/[a-z0-9_.-]+", doc)


def test_readme_and_smoke_docs_point_at_the_record(doc: str) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    heading = "## OS support and verification tiers"
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    assert EVIDENCE_DOC.name in section
    smoke = (ROOT / "docs" / "clean-env-e2e-smoke.md").read_text(encoding="utf-8")
    assert EVIDENCE_DOC.name in smoke
    # The suite never claims to have executed the real binary itself.
    assert "Real-server `initialize` executed by this suite: NOT EXECUTED" in smoke


# -- provenance regression (Reviewer review-record run 476) -----------------
# The isolation requirement forbids retro-promoting the prior in-container/
# Docker-era attempts and forbids presenting an env-only scrub as OS-user
# or credential-state isolation. These tests keep that correction true.


def test_prior_container_attempts_stay_historical_not_executed(doc: str) -> None:

    pre_hosted = doc.split("## Hosted fresh-UID clean-room CI", 1)[0]
    assert "historical" in pre_hosted.lower(), (
        "the private-container account must be framed as historical observation"
    )
    assert "NOT EXECUTED" in pre_hosted, (
        "the container era must stay NOT EXECUTED as acceptance evidence"
    )
    assert "does not establish" in pre_hosted, (
        "the record must deny that env-only scrub establishes OS-user/"
        "credential-state isolation"
    )
    # No retro-promoted EXECUTED labeling of the container era survives.
    assert "EXECUTED (2026-11-07" not in doc
    assert re.search(r"(?<!HOSTED-)REAL-INITIALIZE: EXECUTED", doc) is None
    assert "used instead of a separate OS user id" not in doc
    assert "separation the criterion protects" not in doc
    assert "stays exactly as recorded" not in doc


def test_hosted_acceptance_evidence_stays_intact(doc: str) -> None:
    # Historical status is not evidence for the current revision.
    assert "HOSTED-CI-CLEAN-ROOM: PASSED" in doc
    assert "HOSTED-FRESH-UID: VERIFIED" in doc
    assert "HOSTED-REAL-INITIALIZE: EXECUTED" in doc
    normalized = " ".join(doc.split())
    assert "not the status of the current revision" in normalized
    assert "green Actions run for that exact revision" in normalized
    assert "original job summary is not available in this recreated repository" in normalized
    assert "EXECUTED (2026-11-08, hosted" in _table_row(doc, "Linux x86_64")
    assert "baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a" in doc
    assert "a9ff9799e273f525b82718cdc69fdec71b1dca5a" in doc


def test_readme_and_smoke_docs_keep_container_era_not_executed() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    smoke = " ".join((ROOT / "docs" / "clean-env-e2e-smoke.md").read_text(encoding="utf-8").split())
    for name, text in (
        ("README.md", readme),
        ("docs/clean-env-e2e-smoke.md", smoke),
    ):
        assert "NOT EXECUTED" in text, f"{name} must keep the container era NOT EXECUTED"
        assert "does not establish a separate OS UID" in text, (
            f"{name} must not represent env-only isolation as OS-user isolation"
        )
    # Neither companion doc may re-assert the 2026-11-07 container lifecycle
    # as the executed acceptance lifecycle.
    assert "On 2026-11-07 the real-binary lifecycle" not in readme
    assert "was executed on 2026-11-07 in a disposable" not in smoke


# Each revision requires its own hosted run; inaccessible historical run
# links are not proof of acceptance on the recreated repository.


def test_chain_evidence_requires_an_exact_revision_run(doc: str) -> None:
    normalized = " ".join(doc.split())
    assert "an older run is never evidence for a newer head" in normalized
    assert "green Actions run for that exact revision" in normalized
    assert "Actions history for the `acp-clean-room` job" in normalized
    assert "cannot be independently verified from this repository" in normalized
