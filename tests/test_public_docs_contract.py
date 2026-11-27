"""Public documentation contracts: truthful disclosures, install commands, and links.

Check actual public docs plus fixed positive/negative claim examples. The
examples do not depend on the current wording of the README.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
NOTICE = ROOT / "NOTICE.md"

PUBLIC_DOCS = (
    "docs/quick-start.md",
    "docs/troubleshooting.md",
    "docs/data-and-permissions.md",
    "docs/terms-and-licensing.md",
    "docs/provider-runtime.md",
)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit = _load("apt_public_docs", "scripts/audit_public_tree.py")


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _collapsed(relative: str) -> str:
    """Whitespace-collapsed text for prose fragments that may line-wrap.

    Markdown blockquote markers are stripped so a quote that wraps across
    `> ` lines stays one contiguous sentence for literal witnesses.
    """
    lines = [
        line[2:] if line.startswith("> ") else line
        for line in _read(relative).splitlines()
    ]
    return " ".join(" ".join(lines).split())


def _section(text: str, heading_prefix: str) -> str:
    """Section body from a `## ` heading up to the next `## ` heading."""
    index = text.find(heading_prefix)
    assert index != -1, f"missing heading: {heading_prefix!r}"
    body = text[index:]
    end = body.find("\n## ", 1)
    return body if end == -1 else body[:end]


def test_public_docs_exist() -> None:
    assert README.is_file()
    for relative in PUBLIC_DOCS:
        assert (ROOT / relative).is_file(), relative
        assert len(_read(relative).strip()) > 500, relative


def test_readme_quick_start_lists_currently_reproducible_commands() -> None:
    readme = _read("README.md")
    quick = _section(readme, "## 5-minute Quick Start")
    for command in (
        "python3 scripts/install_acp.py install",
        "python3 scripts/install_acp.py status",
        "python3 scripts/install_acp.py verify",
        "hermes plugins validate hermes-plugin/antigravity-acp --install-deps",
    ):
        assert command in quick, command
    assert "**Antigravity ACP**" in quick
    assert "no published end-to-end authentication or inference result" in " ".join(quick.split())
    assert "hosted clean-room" in " ".join(quick.split())
    assert "docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md" in quick


def test_documented_installer_verbs_are_the_real_parser_choices() -> None:
    source = (ROOT / "scripts" / "install_acp.py").read_text(encoding="utf-8")
    match = re.search(
        r'"action",\s*choices=\(([^)]*)\)', source
    )
    assert match is not None, "installer verb set moved; update this witness"
    real_verbs = set(re.findall(r'"([a-z]+)"', match.group(1)))
    documented: set[str] = set()
    for relative in ("README.md", *PUBLIC_DOCS):
        documented.update(
            re.findall(r"scripts/install_acp\.py\s+([a-z]+)", _read(relative))
        )
    assert documented, "public docs must document installer verbs"
    unknown = documented - real_verbs
    assert unknown == set(), f"docs advertise non-existent installer verbs: {unknown}"


def test_standalone_and_catalog_install_routes_are_distinct() -> None:
    readme = _read("README.md")
    quick = _section(readme, "## 5-minute Quick Start")
    assert "hermes plugins install" not in quick, "the Quick Start is the standalone route"
    install_paths = _section(readme, "## Installation paths")
    catalog = install_paths.split("**Catalog path (Linux)", 1)[1]
    assert catalog.index("hermes plugins install antigravity-acp-provider") < catalog.index(
        "python3 scripts/install_official.py"
    )
    assert "This step installs no Google binary" in catalog
    assert "entry's exact `sha` (not `main`)" in catalog
    assert "Do not use `scripts/install_acp.py install` for this step" in catalog


def test_readme_status_table_states_floor_os_catalog_and_quota() -> None:
    readme = _read("README.md")
    status = _section(readme, "## Status at a glance")
    assert ">=0.21.6" in status
    assert "Ubuntu 24.04 x86_64" in status
    assert "native hosted-CI lifecycle evidence" in status
    assert "Listed for Linux" in status
    assert "plugin-catalog/antigravity-acp-provider.yaml" in status
    assert "Credential-free CI does not validate authentication or real inference" in status
    assert "no published end-to-end authentication or inference result" in status
    assert '"/quota"' in status or "`/quota`" in status
    assert "completion.usage=None" in status
    assert "1.5.2" in status
    assert "dl.google.com" in status


def test_credential_free_evidence_does_not_claim_current_live_validation() -> None:
    expected = {
        "README.md": "credential-free ci does not validate authentication or real inference",
        "docs/quick-start.md": "credential-free ci do not validate authentication or real inference",
        "docs/troubleshooting.md": "credential-free ci does not validate real authentication or inference",
        "docs/terms-and-licensing.md": "credential-free ci does not establish live authentication or model inference",
    }
    for relative, statement in expected.items():
        text = " ".join(_read(relative).lower().split())
        assert statement in text, relative
        assert "earlier" in text or "older" in text, relative


def test_quota_unavailable_and_usage_distinction_stated() -> None:
    readme = _collapsed("README.md")
    data_doc = _collapsed("docs/data-and-permissions.md")
    for relative, text in (("README.md", readme), ("docs/data-and-permissions.md", data_doc)):
        assert "/quota" in text, relative
        assert "unavailable" in text.lower(), relative
    assert "completion.usage=None" in readme
    assert "context_occupancy" in readme
    assert "never populate request usage" in readme
    assert "context-occupancy counters" in _collapsed("docs/troubleshooting.md").lower()


def test_public_registry_link_uses_current_path() -> None:
    readme = _read("README.md")
    terms = _read("docs/terms-and-licensing.md")
    for relative, text in (("README.md", readme), ("docs/terms-and-licensing.md", terms)):
        assert "agentclientprotocol/registry/tree/main/antigravity-acp" in text, relative
        assert "registry/tree/main/registry/antigravity-acp" not in text, relative


def test_terms_disclosure_is_conditional_and_offers_only_documented_routes() -> None:
    readme = _collapsed("README.md")
    terms = _collapsed("docs/terms-and-licensing.md")
    for text in (readme, terms):
        assert "antigravity.google/terms" in text
        assert "Google AI Studio" in text
        assert "Gemini Enterprise" in text
    assert "does **not** prove" in readme or "does not establish" in readme
    assert "automating account rotation" in terms
    assert "not supported under consumer plans" in terms
    for text in (readme, terms):
        assert "acp-accounts" not in text
        assert "rotation" in text  # only ever in a prohibition sentence form


def test_troubleshooting_covers_the_issue_failure_classes() -> None:
    doc = _read("docs/troubleshooting.md").lower()
    for fragment in (
        "authentication required",
        "auth failures",
        "missing server binary",
        "path launcher",
        "pinned-version mismatch",
        "tampered",
        "profile conflict",
        "non-interactive",
        "does not appear in hermes",
    ):
        assert fragment in doc, fragment


def test_quick_start_doc_covers_full_lifecycle_and_scoping() -> None:
    doc = _read("docs/quick-start.md")
    for fragment in (
        "scripts/install_acp.py install",
        "scripts/install_acp.py status",
        "scripts/install_acp.py verify",
        "delete",
        "--all-profiles",
        "--hermes-home",
        "install-provenance.json",
        "~/.hermes/plugin-backups/",
        "scripts/install_official.py",
        "SHA-256",
    ):
        assert fragment in doc, fragment
    assert "Available separately on Linux" in doc
    assert "provider and matching ACP server are installed in two steps" in doc
    assert "No published end-to-end authentication or inference result" in doc


def test_notices_preserve_non_affiliation_mit_and_original_author() -> None:
    notice = _read("NOTICE.md")
    assert "not affiliated with Google" in notice
    assert "does not redistribute" in notice
    assert "MIT License" in notice
    assert "Hermes Agent by Nous Research" in notice
    assert "Copyright (c) 2025 Nous Research" in notice
    assert "MIT licensed" in _read("README.md")


@pytest.mark.parametrize("relative", ("README.md", "NOTICE.md", *PUBLIC_DOCS))
def test_public_docs_pass_secret_and_personal_ops_scanners(relative: str) -> None:
    text = _read(relative)
    assert audit.scan_text(text) == [], f"{relative} trips secret-content rules"
    hits = [token for token in audit.PERSONAL_OPS_TOKENS if token in text]
    assert hits == [], f"{relative} references personal-ops assets: {hits}"
    assert re.search(r"[A-Za-z0-9._%+-]*[a-z0-9]{4,}@(?!example\.invalid)[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text) is None, relative


@pytest.mark.parametrize("relative", ("README.md", *PUBLIC_DOCS))
def test_relative_markdown_links_resolve(relative: str) -> None:
    base = (ROOT / relative).parent
    text = _read(relative)
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        assert (base / target.split("#", 1)[0]).is_file(), f"{relative}: broken link {target}"


BOUNDARY_DOCS = ("README.md", "docs/quick-start.md", "docs/data-and-permissions.md")

_BOUNDARY_REQUIRED_FRAGMENTS: dict[str, tuple[str, ...]] = {
    "README.md": (
        "its own code reads no credential stores",
        "no filesystem sandbox",
        "not observable from this repository",
        "neither claimed nor excluded",
    ),
    "docs/quick-start.md": (
        "reads no credential stores",
        "no filesystem sandbox",
        "is not observable from this repository",
        "neither claimed nor excluded",
    ),
    "docs/data-and-permissions.md": (
        "never reads vendor token stores",
        "no filesystem sandbox",
        "is not claimed, and is not excluded",
        "should be read as a sandbox or isolation guarantee",
    ),
}

_SANDBOX_ALLOWED_CONTEXTS = (
    "no filesystem sandbox",
    "no sandbox",
    "not a sandbox",
    "sandbox or isolation guarantee",
    "unsandboxed",
)

_VENDOR_FILE_SUBJECT_TOKENS = (
    "that process",
    "vendor binary",
    "the vendor",
    "binary",
    "child",
)
_FILE_ACCESS_PROMISE_TOKENS = (
    "read-only",
    "read only",
    "only reads",
    "never reads",
    "never accesses",
    "never touches",
    "never modifies",
    "cannot write",
    "cannot modify",
    "will not write",
    "will not modify",
    "does not write",
)
_HARNESS_SCOPE_TOKENS = (
    "its own code",
    "harness",
    "presence report",
    "not observed",
    "unobserved",
    "not observable",
    "no claim",
    "not claimed",
    "not excluded",
    "neither claimed nor excluded",
)

_ISOLATION_GUARANTEE = re.compile(
    r"\bisolat(?:e|es|ed|ing|ion)\b|\bsandboxed\b|\bquarantin\w*\b"
    r"|\bsegregat\w*\b|\bcontainer(?:s)?\b|\bchroot\b|\bjail\w*\b"
)
_CLAUSE_NEGATION = re.compile(
    r"\b(?:no|not|never|nothing|without|neither)\b|n't\b"
)

_COORDINATING_JOIN = re.compile(r"\s+(and|or|but)\s+")

_PREPOSITIONAL_NEGATIONS = frozenset({"without", "no"})


def _boundary_missing_fragments(relative: str, collapsed_text: str) -> list[str]:
    return [
        fragment
        for fragment in _BOUNDARY_REQUIRED_FRAGMENTS[relative]
        if fragment not in collapsed_text
    ]


_CLAUSE_BOUNDARY = re.compile(r"\.[\s]+|[;:,|]|\s+—\s+")


def _clause_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) spans of the boundary-delimited clauses in `text`."""
    spans: list[tuple[int, int]] = []
    last = 0
    for boundary in _CLAUSE_BOUNDARY.finditer(text):
        spans.append((last, boundary.start()))
        last = boundary.end()
    spans.append((last, len(text)))
    return spans


def _clause_containing(text: str, spans: list[tuple[int, int]], pos: int) -> str:
    for start, end in spans:
        if start <= pos < end:
            return text[start:end]
    return ""


def _predicate_negated(clause: str, pos: int) -> bool:
    """Negation binds to its predicate; only `or` extends it forward.

    Prepositional `no`/`without` cannot negate a preceding predicate.
    """
    segments: list[tuple[int, int, str]] = []
    last, join = 0, ""
    for coord in _COORDINATING_JOIN.finditer(clause):
        segments.append((last, coord.start(), join))
        last, join = coord.end(), coord.group(1)
    segments.append((last, len(clause), join))
    idx = max(i for i, (start, _end, _join) in enumerate(segments) if start <= pos)
    while True:
        start, end, coord = segments[idx]
        for negation in _CLAUSE_NEGATION.finditer(clause[start:end]):
            if (
                negation.group(0) in _PREPOSITIONAL_NEGATIONS
                and start + negation.start() >= pos
            ):
                continue
            return True
        if coord != "or" or idx == 0:
            return False
        idx -= 1


def _boundary_violations(collapsed_text: str) -> list[str]:
    """Boundary-contract violations in whitespace-collapsed doc text."""
    found: list[str] = []
    spans = _clause_spans(collapsed_text)
    for match in re.finditer(r"sandbox(?:ed|es)?\b", collapsed_text):
        clause = _clause_containing(collapsed_text, spans, match.start())
        if not any(allowed in clause.lower() for allowed in _SANDBOX_ALLOWED_CONTEXTS):
            found.append(f"unsupported-sandbox-claim: {clause.strip()}")
    clauses = [
        collapsed_text[start:end].strip(" .") for start, end in spans
    ]
    for clause in clauses:
        if not clause:
            continue
        low = clause.lower()
        if (
            any(t in low for t in _FILE_ACCESS_PROMISE_TOKENS)
            and any(t in low for t in _VENDOR_FILE_SUBJECT_TOKENS)
            and not any(t in low for t in _HARNESS_SCOPE_TOKENS)
        ):
            found.append(f"vendor-file-guarantee: {clause}")
        isolation_positions = [
            match.start() for match in _ISOLATION_GUARANTEE.finditer(low)
        ]
        if (
            isolation_positions
            and any(t in low for t in _VENDOR_FILE_SUBJECT_TOKENS)
            and not any(t in low for t in _HARNESS_SCOPE_TOKENS)
            and any(
                not _predicate_negated(low, position)
                for position in isolation_positions
            )
        ):
            found.append(f"vendor-isolation-guarantee: {clause}")
        if (
            re.search(r"\b(?:verify|probe)\b", low)
            and "credential" in low
            and re.search(
                r"\b(?:never|does\s+not|doesn'?t)\s+(?:reads?|access(?:es)?|touches?)\b", low
            )
            and not any(t in low for t in _HARNESS_SCOPE_TOKENS)
        ):
            found.append(f"unscoped-verify-credential-claim: {clause}")
    return found


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_public_docs_disclose_the_verify_filesystem_boundary(relative: str) -> None:
    missing = _boundary_missing_fragments(relative, _collapsed(relative))
    assert missing == [], (
        f"{relative} no longer states the harness/vendor "
        f"filesystem-boundary disclosure: {missing}"
    )


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_public_docs_make_no_sandbox_or_vendor_file_guarantees(relative: str) -> None:
    violations = _boundary_violations(_collapsed(relative))
    assert violations == [], (
        f"{relative} claims a filesystem sandbox or guarantees vendor-child "
        f"file behavior: {violations}"
    )


@pytest.mark.parametrize(
    "statement",
    (
        "The vendor child runs in an environment and a filesystem sandbox.",
        "The vendor child runs in an environment inside a filesystem sandbox.",
        "The vendor binary is read-only: that process never touches credential files.",
        "The verify probe is read-only and never reads credential files.",
        "The credential-free evidence confirms the vendor child stays read-only.",
        "no prompt, and no credential material. The vendor binary is read-only and never reads credential files.",
        "is not observed here, is not claimed, and is not excluded. The vendor binary is read-only and never reads credential files.",
        "its own code reads no credential stores. The vendor binary cannot write to user directories.",
        "environment and no filesystem sandbox, the vendor binary cannot write to user directories, so what that binary",
        "no filesystem sandbox — this is not the Hermes runtime path, the vendor binary cannot write to user directories",
        "environment and no filesystem sandbox, the vendor binary is read-only and never accesses credential files, so whatever file access that process",
        "see the vendor attribution in `docs/data-and-permissions.md`. The vendor binary starts Google's proprietary server in a secure sandbox.",
        "The vendor binary starts Google's proprietary server in a secure sandbox. It makes no claim about the vendor binary:",
        "should be read as a sandbox or isolation guarantee for that child. The vendor binary starts the official server in a secure sandbox.",
        "no prompt, and no credential material. The vendor binary is fully isolated from user files.",
        "its own code reads no credential stores. The vendor binary is fully isolated from user files.",
        "is not observed here, is not claimed, and is not excluded. The vendor binary is fully isolated from user files.",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files, so what that binary",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files, so whatever file access that process",
        "No self-update; no redistribution; the vendor binary is fully isolated from user files.",
        "Google's versioned server files as distributed, the vendor binary is fully isolated from user files",
        "no prompt, and no credential material. The vendor binary is fully isolated from user files and does not require credentials.",
        "its own code reads no credential stores. The vendor binary is fully isolated from user files and does not require credentials.",
        "is not observed here, is not claimed, and is not excluded. The vendor binary is fully isolated from user files and does not require credentials.",
        "no prompt, and no credential material. The vendor binary does not require credentials and is fully isolated from user files.",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files and does not require credentials, so what that binary",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files and does not require credentials, so whatever file access that process",
        "No self-update; no redistribution; the vendor binary is fully isolated from user files and does not require credentials.",
        "its own code reads no credential stores. The vendor binary is fully segregated from user files but needs no credentials.",
        "Google's versioned server files as distributed, the vendor binary is quarantined from user files and does not require credentials",
        "no prompt, and no credential material. The vendor binary is fully isolated from user files without requiring credentials.",
        "its own code reads no credential stores. The vendor binary is fully isolated from user files without requiring credentials.",
        "is not observed here, is not claimed, and is not excluded. The vendor binary is fully isolated from user files without requiring credentials.",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files without requiring credentials, so what that binary",
        "environment and no filesystem sandbox, the vendor binary is fully isolated from user files without requiring credentials, so whatever file access that process",
        "No self-update; no redistribution; the vendor binary is fully isolated from user files without requiring credentials.",
        "Google's versioned server files as distributed, the vendor binary is fully isolated from user files without requiring credentials",
        "its own code reads no credential stores. The vendor binary is fully segregated from user files without requiring credentials.",
        "is not observed here, is not claimed, and is not excluded. The vendor binary is quarantined from user files without any credential requirement.",
        "No self-update; no redistribution; the vendor binary is fully isolated from user files with no credential requirements.",
    ),
)
def test_filesystem_boundary_contracts_reject_mutated_docs(statement: str) -> None:
    assert _boundary_violations(statement), statement


@pytest.mark.parametrize(
    "statement",
    (
        "The vendor binary is fully isolated from user files and does not require credentials.",
        "The vendor binary does not require credentials and is fully isolated from user files.",
        "The vendor binary is fully isolated from user files, and it does not require credentials.",
        "The vendor binary is fully segregated from user files but needs no credentials.",
        "The vendor binary is quarantined from user files and does not require credentials.",
        "the vendor binary is fully isolated from user files and does not require credentials;",
        "| the vendor binary is fully isolated from user files and does not require credentials |",
        "The vendor binary is fully isolated from user files without requiring credentials.",
        "The vendor binary is fully isolated from user files, without requiring credentials.",
        "The vendor binary is fully segregated from user files without requiring credentials.",
        "The vendor binary is quarantined from user files without any credential requirement.",
        "The vendor binary is fully isolated from user files with no credential requirements.",
        "the vendor binary is fully isolated from user files without requiring credentials;",
        "| the vendor binary is fully isolated from user files without requiring credentials |",
    ),
)
def test_affirmative_isolation_guarantees_paired_with_negation_are_rejected(
    statement: str,
) -> None:
    violations = _boundary_violations(statement)
    assert any(
        violation.startswith("vendor-isolation-guarantee:")
        for violation in violations
    ), f"compound vendor-isolation guarantee escaped the contract: {statement}"


@pytest.mark.parametrize(
    "statement",
    (
        "The verify probe requires no credentials; its own code reads no credential stores.",
        "Harness behavior is observable, ours; it never reads credential stores.",
        "Whatever the vendor binary reads or writes is not observable from this repository — neither claimed nor excluded.",
        "What this repository observes of that child is not observed elsewhere, is not claimed, and is not excluded.",
        "The vendor child is unsandboxed; its file behavior is unknown.",
        "Whatever isolation the vendor binary may have is not observable and not claimed.",
        "Credential-state isolation is not established by an environment scrub of that child.",
        "The official server's file behavior is unknown; nothing here is an isolation guarantee for that child.",
        "The vendor binary is not isolated from user files and does not require credentials.",
        "No documentation here claims the vendor binary is isolated from user files or requires credentials.",
        "Nothing here presents the vendor binary as isolated from user files or segregated from credential stores.",
        "The vendor child is unsandboxed and does not run in a container.",
        "The vendor binary runs without establishing vendor isolation.",
        "No isolation of the vendor binary from user files is claimed or excluded.",
        "The vendor child operates with no isolation from user files, and its file behavior is unknown.",
    ),
)
def test_harness_scoped_and_vendor_unknown_statements_are_accepted(statement: str) -> None:
    assert _boundary_violations(statement) == [], statement


_CI_REAL_BINARY_SCOPE_TOKENS = (
    "fake-acp",
    "fake acp",
    "registry/regression",
    "clean-room",
    "clean room",
    "operating system",
    "macos",
    "windows",
    "arm64",
    "aarch64",
    "x86_64",
)


_CI_CLAIM_GROUP_BOUNDARY = re.compile(r"\.[\s]+|[;:|]|\s+—\s+")


def _claim_group_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    last = 0
    for boundary in _CI_CLAIM_GROUP_BOUNDARY.finditer(text):
        spans.append((last, boundary.start()))
        last = boundary.end()
    spans.append((last, len(text)))
    return spans


def _unscoped_ci_real_binary_groups(collapsed_text: str) -> set[str]:
    """Lowercased claim groups asserting CI-wide real-binary absence."""
    found: set[str] = set()
    for spans in (_clause_spans, _claim_group_spans):
        for start, end in spans(collapsed_text):
            low = collapsed_text[start:end].lower().replace("*", "")
            if not re.search(r"\bci\b", low):
                continue
            if not re.search(r"\bbinar\w*\b", low):
                continue
            if not re.search(r"\b(?:real|official)\b", low):
                continue
            if _CLAUSE_NEGATION.search(low) is None:
                continue
            if any(token in low for token in _CI_REAL_BINARY_SCOPE_TOKENS):
                continue
            found.add(low.strip())
    return found


def _ci_real_binary_claim_violations(collapsed_text: str) -> list[str]:
    """Claim groups claiming CI-wide real-binary absence."""
    return [
        f"unscoped-ci-no-real-binary-claim: {group}"
        for group in sorted(_unscoped_ci_real_binary_groups(collapsed_text))
    ]


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_ci_real_binary_disclosure_is_scoped_to_a_job_or_platform(
    relative: str,
) -> None:
    violations = _ci_real_binary_claim_violations(_collapsed(relative))
    assert violations == [], (
        f"{relative} claims this repository's CI as a whole never "
        f"executes/fetches the real binary, contradicting the executed "
        f"dedicated-UID acp-clean-room tier: {violations}"
    )


def test_readme_scopes_ci_no_real_binary_wording_and_names_clean_room() -> None:
    section = _section(_read("README.md"), "## OS support and verification tiers")
    text = " ".join(section.split())
    for fragment in ("fake-acp", "no live feed fetch", "no real-binary execution",
                     "acp-clean-room", "dedicated-UID", "platform install lanes"):
        assert fragment in text, fragment


@pytest.mark.parametrize(
    "statement",
    (
        "the CI performs no live feed fetch and never executes the real binary",
        "CI as a whole performs no live feed fetch, no authentication, and no real-binary execution.",
    ),
)
def test_unscoped_ci_real_binary_claim_is_rejected(statement: str) -> None:
    assert _ci_real_binary_claim_violations(statement), statement


@pytest.mark.parametrize(
    "statement",
    (
        "CI performs no live feed fetch and never executes the real binary",
        "this repository's CI never executes the real Google binary",
        "the CI pipeline does not execute the official binary",
        "CI does not fetch the real binary or authenticate",
    ),
)
def test_ci_wide_real_binary_denial_statements_are_rejected(statement: str) -> None:
    violations = _ci_real_binary_claim_violations(statement)
    assert any(
        violation.startswith("unscoped-ci-no-real-binary-claim:")
        for violation in violations
    ), f"CI-wide real-binary denial escaped the contract: {statement}"


@pytest.mark.parametrize(
    "statement",
    (
        "the credential-free fake-acp registry/regression job performs no live feed fetch, no authentication, and no real-binary execution",
        "the real Google binary on those operating systems has not been executed by this repository's CI",
        "on macOS, Windows, and Linux aarch64 the official binary has not been executed by CI",
        "Real-binary execution in CI belongs exclusively to the dedicated-UID `acp-clean-room` job",
        "the clean-room job on ubuntu x86_64 fetches and executes the official binary as a dedicated UID",
    ),
)
def test_job_scoped_and_platform_scoped_ci_disclosures_are_accepted(
    statement: str,
) -> None:
    assert _ci_real_binary_claim_violations(statement) == [], statement


_CHILD_ENV_SUBJECT = re.compile(
    r"\bmux\b|acp_mux|session[- ]identity|session tokens?"
)
_CHILD_ENV_PASSTHROUGH = re.compile(
    r"\bpas{1,2}(?:ed|es|ing)?\b|\bforward\w*|\bcarr\w*|\binherit\w*"
    r"|\bgiven\b|\breceiv\w*"
)
_CHILD_ENV_TRUTH_TOKENS = (
    "ambient",
    "inherited",
    "synthesiz",
    "deliberately",
    "routing metadata",
    "routing/session metadata",
    "mux metadata",
    "session metadata",
)


def _overbroad_child_env_groups(collapsed_text: str) -> set[str]:
    """Claim groups negating session/mux variables reaching the child."""
    found: set[str] = set()
    for spans in (_clause_spans, _claim_group_spans):
        for start, end in spans(collapsed_text):
            low = collapsed_text[start:end].lower().replace("*", "")
            if _CHILD_ENV_SUBJECT.search(low) is None:
                continue
            if "child" not in low:
                continue
            if _CLAUSE_NEGATION.search(low) is None:
                continue
            if _CHILD_ENV_PASSTHROUGH.search(low) is None:
                continue
            if any(token in low for token in _CHILD_ENV_TRUTH_TOKENS):
                continue
            found.add(low.strip())
    return found


_SINGLETON_COUNT = re.compile(r"\b(?:exactly|only|precisely) one\b")
_SERVER_CHILD_SUBJECT = re.compile(
    r"\bserver child(?:ren)?\b|\bacp server child\b"
)
_CHILD_LIFECYCLE_TOKENS = (
    "per acp session",
    "per session",
    "session/attempt",
    "session or attempt",
    "per attempt",
    "short-lived",
    "each session",
)


def _singleton_server_child_groups(collapsed_text: str) -> set[str]:
    """Claim groups promising a global exactly-one server child."""
    found: set[str] = set()
    for spans in (_clause_spans, _claim_group_spans):
        for start, end in spans(collapsed_text):
            low = collapsed_text[start:end].lower().replace("*", "")
            if _SINGLETON_COUNT.search(low) is None:
                continue
            if _SERVER_CHILD_SUBJECT.search(low) is None:
                continue
            if any(token in low for token in _CHILD_LIFECYCLE_TOKENS):
                continue
            found.add(low.strip())
    return found


_GOOGLE_TRAFFIC_SUBJECT = re.compile(r"\bgoogle-bound\b|\bto google\b")
_GOOGLE_ORIGIN = re.compile(
    r"\boriginat\w*|\bflows?\b|\bflowed\b|\btravels?\b|\bhandl\w*\b"
)
_GOOGLE_UNIVERSAL = re.compile(
    r"\ball\b|\bevery\b|\beverything\b|\bexclusively\b|\bentirely\b"
    r"|\bsolely\b"
)
_GOOGLE_SCOPE_TOKENS = (
    "runtime",
    "model",
    "protocol",
    "installer",
    "dl.google.com",
    "install",
)


def _unscoped_google_traffic_groups(collapsed_text: str) -> set[str]:
    """Reject unscoped origin claims, including bold Markdown sentences."""
    collapsed_text = collapsed_text.replace("**", "")
    found: set[str] = set()
    for spans in (_clause_spans, _claim_group_spans):
        for start, end in spans(collapsed_text):
            low = collapsed_text[start:end].lower().replace("*", "")
            if _GOOGLE_TRAFFIC_SUBJECT.search(low) is None:
                continue
            if _GOOGLE_ORIGIN.search(low) is None:
                continue
            if _GOOGLE_UNIVERSAL.search(low) is None:
                continue
            if any(token in low for token in _GOOGLE_SCOPE_TOKENS):
                continue
            found.add(low.strip())
    return found


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_public_docs_scope_the_child_environment_disclosure(
    relative: str,
) -> None:
    violations = sorted(_overbroad_child_env_groups(_collapsed(relative)))
    assert violations == [], (
        f"{relative} negates session identity/mux variables reaching the "
        f"ACP child without distinguishing the ambient/inherited "
        f"environment from the deliberately synthesized, bounded "
        f"ACP_MUX_* routing metadata (client.py::_spawn): {violations}"
    )


def test_child_environment_disclosure_separates_ambient_from_synthesized() -> None:
    for relative in ("README.md", "docs/data-and-permissions.md"):
        text = _collapsed(relative).lower()
        for fragment in ("ambient", "provider api keys", "gateway tokens",
                         "session identity variables", "bounded", "synthesized",
                         "acp_mux_", "routing/session metadata", "not google credentials"):
            assert fragment in text, (relative, fragment)
    dp = _collapsed("docs/data-and-permissions.md").lower()
    assert "`acp_mux_session_id` and `acp_mux_affinity`" in dp


@pytest.mark.parametrize(
    "statement",
    (
        "the ACP child receives a minimum-enumerated environment allowlist that never carries provider API keys or session tokens",
        "Provider API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`), Tier-1 gateway tokens, session identity variables, and operator mux configuration are **never** passed to the child",
    ),
)
def test_overbroad_child_env_never_claim_is_rejected(statement: str) -> None:
    assert _overbroad_child_env_groups(statement), statement


@pytest.mark.parametrize(
    "statement",
    (
        "Session identity variables and operator mux configuration are "
        "never passed to the child.",
        "The ACP child environment allowlist never carries provider API "
        "keys or session tokens.",
        "Operator mux configuration is never passed to the child.",
    ),
)
def test_unscoped_child_env_never_claim_statements_are_rejected(
    statement: str,
) -> None:
    violations = _overbroad_child_env_groups(statement)
    assert violations, (
        f"unscoped child-environment negation escaped the contract: "
        f"{statement}"
    )


@pytest.mark.parametrize(
    "statement",
    (
        "Ambient session identity variables and inherited operator "
        "`ACP_MUX_*` configuration are never passed to the child.",
        "The plugin deliberately synthesizes a bounded set of "
        "`ACP_MUX_*` routing/session metadata for each child.",
        "Ambient session identity variables are never passed to the "
        "child; the plugin only synthesizes bounded routing metadata.",
    ),
)
def test_ambient_scoped_child_env_statements_are_accepted(
    statement: str,
) -> None:
    assert _overbroad_child_env_groups(statement) == set(), statement


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_public_docs_make_no_singleton_server_child_claim(
    relative: str,
) -> None:
    violations = sorted(_singleton_server_child_groups(_collapsed(relative)))
    assert violations == [], (
        f"{relative} promises a global exactly-one official server child "
        f"without per-ACP-session/attempt qualification, contradicting "
        f"client.py::_session() spawning and lifecycle cleanup: {violations}"
    )


def test_child_process_disclosure_is_per_session_attempt() -> None:
    for relative in ("README.md", "docs/data-and-permissions.md"):
        text = _collapsed(relative).lower().replace("*", "")
        for fragment in ("per acp session or attempt", "parked", "reused"):
            assert fragment in text, (relative, fragment)
        assert "per hermes process" not in text
        assert "daemonized service" in text
    assert "more than one child" in _collapsed("README.md").lower()


@pytest.mark.parametrize(
    "statement",
    (
        "launches exactly one official server child per Hermes process",
        "launches **exactly one** official ACP server child process per Hermes process",
        "and launches exactly one official Antigravity ACP server child process",
    ),
)
def test_singleton_server_child_claim_is_rejected(statement: str) -> None:
    assert _singleton_server_child_groups(statement), statement


@pytest.mark.parametrize(
    "statement",
    (
        "The default topology launches exactly one official ACP server "
        "child process per Hermes process using the provider.",
        "The public provider launches exactly one official Antigravity "
        "ACP server child process.",
        "The plugin starts only one server child for the whole Hermes "
        "process.",
    ),
)
def test_global_singleton_child_statements_are_rejected(statement: str) -> None:
    violations = _singleton_server_child_groups(statement)
    assert violations, (
        f"global singleton child claim escaped the contract: {statement}"
    )


@pytest.mark.parametrize(
    "statement",
    (
        "The default topology launches one short-lived official server "
        "child per ACP session or attempt.",
        "Each ACP session or attempt runs exactly one short-lived server "
        "child, terminated when its session context exits.",
        "A Hermes process can run more than one official server child "
        "over its lifetime.",
    ),
)
def test_per_session_attempt_child_statements_are_accepted(
    statement: str,
) -> None:
    assert _singleton_server_child_groups(statement) == set(), statement


@pytest.mark.parametrize("relative", BOUNDARY_DOCS)
def test_public_docs_scope_google_bound_traffic_claims(relative: str) -> None:
    violations = sorted(_unscoped_google_traffic_groups(_collapsed(relative)))
    assert violations == [], (
        f"{relative} asserts a universal, unscoped Google-bound origin "
        f"without scoping runtime model/protocol traffic and naming the "
        f"installer's dl.google.com download: {violations}"
    )


def test_google_traffic_disclosure_names_installer_download() -> None:
    for relative in ("README.md", "docs/data-and-permissions.md"):
        text = _collapsed(relative).lower()
        for fragment in ("model/protocol", "google-distributed", "https",
                         "dl.google.com", "explicit install", "proprietary binary"):
            assert fragment in text, (relative, fragment)


@pytest.mark.parametrize(
    "statement",
    (
        "Data to Google flows exclusively through the official server",
        "All Google-bound network traffic originates from the Google-distributed official binary",
        "all traffic sent onward to Google originates from that Google-distributed binary",
        "**All Google-bound network traffic originates from the Google-distributed official binary.** The plugin does not connect directly to Google's model service.",
    ),
)
def test_unscoped_google_bound_traffic_claim_is_rejected(statement: str) -> None:
    assert _unscoped_google_traffic_groups(statement), statement


@pytest.mark.parametrize(
    "statement",
    (
        "All Google-bound network traffic originates from the "
        "Google-distributed official binary.",
        "Data to Google flows exclusively through the official server.",
        "Everything that flows to Google is handled only by the official "
        "binary.",
    ),
)
def test_universal_google_bound_traffic_statements_are_rejected(
    statement: str,
) -> None:
    violations = _unscoped_google_traffic_groups(statement)
    assert violations, (
        f"universal unscoped Google-bound claim escaped the contract: "
        f"{statement}"
    )


@pytest.mark.parametrize(
    "statement",
    (
        "All runtime model/protocol traffic to Google originates from "
        "the Google-distributed official binary.",
        "The standalone installer fetches the pinned archive from "
        "`dl.google.com` over HTTPS.",
    ),
)
def test_runtime_scoped_google_traffic_statements_are_accepted(
    statement: str,
) -> None:
    assert _unscoped_google_traffic_groups(statement) == set(), statement
