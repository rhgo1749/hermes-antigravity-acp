"""historical reference: the public documentation itself is a delivery contract.

The generalized invariant: every command, availability, support, and terms
claim in the public README/docs must connect to a currently interpretable
artifact and an evidence tier or official-terms source. Concretely this suite
keeps true, in the exact places readers look:

- the README opens with a single-account 5-minute Quick Start built from the
  CURRENTLY reproducible commands (`install_acp.py install/status/verify`) and
  never presents the catalog route as available (that is historical reference);
- credential-free install/initialize is never conflated with auth, model
  discovery, or inference: the live auth/model canary stays
  NOT VALIDATED / NO-GO pending historical reference in README and every new doc;
- `/quota` stays documented as unavailable/unsupported with the
  usage/context-occupancy/billed-token distinction;
- troubleshooting covers the Issue's failure classes; data/permission/process
  and terms/licensing disclosures live in the linked docs;
- NOTICE.md keeps Google non-affiliation, MIT, and Nous Research attribution;
- the public docs pass the repository's own secret-content and personal-ops
  scanners, use sanitized examples only, carry no stale ACP-Registry link, and
  every relative markdown link resolves;
- the README, Quick Start, and data/permissions docs keep the verify/probe
  filesystem boundary stated — harness-observable behavior (no credentials
  required or sent, own code reads no credential stores, probe sends exactly
  one unauthenticated `initialize`) separated from the proprietary server
  child (caller-inherited environment, no filesystem sandbox) whose file
  behavior is attributed as unknown — and docs mutations claiming a
  filesystem sandbox, a vendor-file read-only guarantee, or an independent
  affirmative vendor isolation/sandbox guarantee fail these contracts
  instead of staying green, including affirmative vendor sentences inserted
  beside intact disclosures at period, comma, semicolon, or markdown
  table-cell boundaries
  (reviewer review-record run 521, repeat finding review-record run 524,
  isolation-class repeat review-record run 531, negation-pairing repeat
  review-record run 534, prepositional-negation repeat review-record run 545);
- the README scopes every "no live feed fetch / no real-binary execution"
  CI disclosure to the fake-ACP registry/regression job and keeps the
  dedicated-UID hosted `acp-clean-room` real-binary execution distinct,
  so the disclosure cannot claim CI-wide non-execution and contradict
  the executed clean-room tier (reviewer review-record run 558);
- the three public-disclosure boundaries from maintainer historical reference (historical reference review on head earlier) hold: child-environment
  negatives are scoped to AMBIENT/INHERITED credentials and session env
  variables versus the deliberately synthesized, bounded `ACP_MUX_*`
  routing/session metadata (no implication of Google credentials or full
  environment inheritance); the official server child is disclosed per
  ACP session/attempt with lifecycle cleanup instead of a global
  per-Hermes-process singleton while staying distinct from a daemonized
  service; and Google-bound network claims are scoped to runtime
  model/protocol traffic with the standalone installer's `dl.google.com`
  HTTPS download stated as the distinct repository-side fetch, without
  bounding proprietary vendor-child networking beyond repository evidence.

Credential-free: nothing here downloads, executes, or authenticates.
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


audit = _load("apt_issue83_docs", "scripts/audit_public_tree.py")


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


# ---------------------------------------------------------------------------
# (1) Structure: the Quick Start exists and is built from current commands.
# ---------------------------------------------------------------------------


def test_issue83_public_docs_exist() -> None:
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
    # Hermes selection and the credential-free boundary are stated in place.
    assert "Antigravity ACP (official)" in quick
    assert "current release has not been verified end-to-end" in " ".join(quick.split()) or (
        "current release has not been validated end-to-end" in " ".join(quick.split())
    )
    # The documented clean-room evidence must remain discoverable.
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


def test_quick_start_never_presents_the_catalog_route_as_available() -> None:
    readme = _read("README.md")
    quick = _section(readme, "## 5-minute Quick Start")
    assert "hermes plugins install" not in quick, (
        "the catalog command is not available today and must not appear as a "
        "Quick Start step (publication gate)"
    )
    # The catalog path section states the gate and the re-checked absence.
    install_paths = _section(readme, "## Installation paths")
    assert "NOT available until catalog publication" in install_paths
    assert "hermes plugins install antigravity-acp-provider" in install_paths
    assert "no catalog entry to install from" in install_paths
    assert "does not resolve today" in readme


# ---------------------------------------------------------------------------
# (2) Evidence tiers and availability ledger stay stated everywhere readers
#     look — without weakening the deeper historical reference/historical reference tier contracts elsewhere.
# ---------------------------------------------------------------------------


def test_readme_status_table_states_floor_os_catalog_and_quota() -> None:
    readme = _read("README.md")
    status = _section(readme, "## Status at a glance")
    assert ">=0.21.6" in status
    assert "Ubuntu 24.04 x86_64" in status
    assert "pinned-only" in status
    assert "Not registered yet" in status
    assert "Credential-free CI does not validate authentication or real inference" in status
    assert "current release has not been verified end-to-end" in status
    assert '"/quota"' in status or "`/quota`" in status
    assert "completion.usage=None" in status
    assert "1.4.4" in status
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


def test_catalog_absence_and_registry_link_are_current() -> None:
    readme = _read("README.md")
    terms = _read("docs/terms-and-licensing.md")
    # The registry entry moved out of a nested registry/ directory; the stale
    # 404 path must not survive in any public doc.
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
    # The server-advertised-vs-permitted distinction is explicit.
    assert "does **not** prove" in readme or "does not establish" in readme
    assert "automating account rotation" in terms
    assert "not supported under consumer plans" in terms
    # No rotation/evasion recipe: the docs name the prohibition, never a how-to.
    for text in (readme, terms):
        assert "acp-accounts" not in text
        assert "rotation" in text  # only ever in a prohibition sentence form


# ---------------------------------------------------------------------------
# (3) Troubleshooting and lifecycle coverage (historical reference checklist items).
# ---------------------------------------------------------------------------


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
    assert "Not available until catalog publication" in doc
    assert "Not verified end-to-end on the current release" in doc


# ---------------------------------------------------------------------------
# (4) Attribution, hygiene, and link integrity.
# ---------------------------------------------------------------------------


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
    # Sanitized examples only: no account-looking emails, no personal homes.
    assert re.search(r"[A-Za-z0-9._%+-]*[a-z0-9]{4,}@(?!example\.invalid)[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text) is None, relative


@pytest.mark.parametrize("relative", ("README.md", *PUBLIC_DOCS))
def test_relative_markdown_links_resolve(relative: str) -> None:
    base = (ROOT / relative).parent
    text = _read(relative)
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        assert (base / target.split("#", 1)[0]).is_file(), f"{relative}: broken link {target}"


# ---------------------------------------------------------------------------
# (5) Verify/probe filesystem boundary (reviewer review-record run 521; repeats
#     review-record run 524 and review-record run 531): the public docs must
#     separate what this harness observably does from what the proprietary
#     server child does, and docs edits claiming a filesystem sandbox, an
#     isolation guarantee, or vendor-file behavior must fail here — the
#     mutation class a green suite used to tolerate. Run 524 killed the false
#     negative where an INDEPENDENT affirmative vendor sentence inserted beside
#     an intact disclaimer stayed green because clause segmentation ignored
#     period and comma boundaries; run 531 killed the remaining false
#     negative where the reviewer's exact appended sentence "The vendor
#     binary is fully isolated from user files." stayed green even as its
#     own period-delimited sentence: no `_FILE_ACCESS_PROMISE_TOKENS` word
#     covers isolation wording, and the sandbox scan fires only on the
#     literal "sandbox". The contract now also judges affirmative
#     isolation/segregation wording about a vendor subject inside its own
#     sentence/clause/table cell. Run 534 killed the final false negative:
#     appending the compound sentence "The vendor binary is fully isolated
#     from user files and does not require credentials." stayed green
#     because the clause-wide negation gate let the unrelated credentials
#     `not` excuse the isolation predicate; negation now binds per
#     predicate segment and scopes forward only through `or` coordination.
#     Run 545 (meta review-record run 547 AGREE) killed the remaining false
#     negative: the exact witness re-paired the guarantee with a trailing
#     PREPOSITIONAL adjunct — "The vendor binary is fully isolated from
#     user files without requiring credentials." — and segment-wide
#     negation search let `without` mask the isolation predicate again.
#     Prepositional negators now bind only forward into the phrase they
#     head, so the truthful "…without establishing vendor isolation"
#     stays accepted while an affirmative guarantee with an unrelated
#     `without …`/`no …` adjunct fails.
# ---------------------------------------------------------------------------

BOUNDARY_DOCS = ("README.md", "docs/quick-start.md", "docs/data-and-permissions.md")

# Whitespace-collapsed prose that must stay present in each doc: the
# harness-observable side, the inherited-environment/no-sandbox disclosure,
# and the explicit "vendor file behavior unknown" attribution.
_BOUNDARY_REQUIRED_FRAGMENTS: dict[str, tuple[str, ...]] = {
    "README.md": (
        "Harness behavior (observable, ours)",
        "Vendor behavior (not observed, no claim)",
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

# "sandbox" may only appear negated (no sandbox), as "unsandboxed", or inside
# the explicit disclaimer that the evidence is NOT a sandbox/isolation claim.
_SANDBOX_ALLOWED_CONTEXTS = (
    "no filesystem sandbox",
    "no sandbox",
    "not a sandbox",
    "sandbox or isolation guarantee",
    "unsandboxed",
)

# A clause making a file-access promise about the vendor child without
# scoping it to the harness claims more than the credential-free evidence
# supports (scripts/acp_probe.py starts the child with the inherited
# environment; scripts/install_acp.py applies no filesystem sandbox).
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

# Affirmative isolation/segregation wording predicated on the vendor child
# (reviewer review-record run 531): the exact appended sentence "The vendor
# binary is fully isolated from user files." matched neither the read/write
# promise tokens nor the literal "sandbox" scan, so an independent
# affirmative vendor isolation guarantee stayed green. Word-boundary
# alternation keeps the truthful `Isolation`-note reference and the
# `test_runtime_safety_isolation.py` path out of the pattern's reach, and
# the negation gate below accepts the honest disclosures of isolation's
# ABSENCE ("does not establish a separate OS UID or credential-state
# isolation", "Nothing ... should be read as a sandbox or isolation
# guarantee for that child", "no fixed container").
_ISOLATION_GUARANTEE = re.compile(
    r"\bisolat(?:e|es|ed|ing|ion)\b|\bsandboxed\b|\bquarantin\w*\b"
    r"|\bsegregat\w*\b|\bcontainer(?:s)?\b|\bchroot\b|\bjail\w*\b"
)
# Segment negation vocabulary for the isolation gate. The contraction
# branch REQUIRES the apostrophe: with the bare `n'?t` spelling, the
# trailing letters of ordinary words ("requirement", "environment",
# "amount") matched as negation and masked affirmative isolation
# claims — the same false-negative family as the run 545 prepositional
# adjunct. Real contractions ("isn't", "doesn't") still match, as do
# the per-word `not`/`no`/`never` forms.
_CLAUSE_NEGATION = re.compile(
    r"\b(?:no|not|never|nothing|without|neither)\b|n't\b"
)

# Negation binding (reviewer review-record run 534): the run 531 gate
# searched `_CLAUSE_NEGATION` across the ENTIRE clause, so in the
# compound assertion "The vendor binary is fully isolated from user
# files and does not require credentials." the unrelated credentials
# `not` suppressed the affirmative isolation guarantee and the whole
# suite stayed green. A negation instead binds to its own predicate
# segment: coordinating-conjunction-delimited (`and`/`or`/`but`), and it
# scopes forward only through `or`-joined coordination ("does not A or
# B" negates both disjuncts — keeping the truthful
# "…does not establish a separate OS UID or credential-state isolation"
# and "Nothing … read as a sandbox or isolation guarantee" disclosures
# accepted), never through `and`/`but` ("is A and does not B" keeps A
# affirmative).
_COORDINATING_JOIN = re.compile(r"\s+(and|or|but)\s+")

# Prepositional negation scope (reviewer review-record run 545, meta
# review-record run 547): segment-level binding alone still searched
# `_CLAUSE_NEGATION` across the WHOLE predicate segment, so the witness
# "The vendor binary is fully isolated from user files without
# requiring credentials." stayed green — the trailing adjunct `without`
# modifies the CREDENTIALS yet excused the earlier ISOLATION
# predicate. A prepositional negator (`without`/`no`) therefore counts
# only while it PRECEDES the isolation keyword: it heads the phrase
# that contains it ("runs without establishing vendor isolation") and
# can never negate an affirmative predicate standing before it.
# Adverbial negators (`not`/`never`/`nothing`/`neither`/`n't`) keep
# whole-segment scope, so "Credential-state isolation is not
# established by an environment scrub of that child." stays an accepted
# honest disclosure. `without` is deliberately NOT removed from
# `_CLAUSE_NEGATION` — the truthful without-phrases still need it.
_PREPOSITIONAL_NEGATIONS = frozenset({"without", "no"})


def _boundary_missing_fragments(relative: str, collapsed_text: str) -> list[str]:
    return [
        fragment
        for fragment in _BOUNDARY_REQUIRED_FRAGMENTS[relative]
        if fragment not in collapsed_text
    ]


# Claim segmentation (reviewer review-record run 524 repeating review-record run
# 521, extended for review-record run 531): a standalone affirmative vendor
# promise — "The vendor binary is read-only and never reads credential
# files." or "The vendor binary is fully isolated from user files." —
# inserted beside an intact "not observable from this repository" disclaimer
# used to stay green, because the old splitter only broke on colons,
# semicolons and em-dashes. The whole paragraph stayed one clause, so the
# disclaimer's harness-scope tokens suppressed the promise next to it.
# Boundary-aware segmentation must also break on sentence-ending periods,
# on commas, and on markdown table-cell pipes, so each claim is judged
# inside its OWN sentence/clause/cell: a disclosure cannot launder an
# adjacent guarantee, and a harness-scoped statement stays distinct from an
# unobserved proprietary vendor claim.
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
    """Whether a negation in `clause` legitimately scopes over `clause[pos:]`.

    A negation inside the coordinating-conjunction-delimited predicate
    segment containing `pos` counts. A negation in an EARLIER segment
    counts only while every intervening join is `or` (negative
    coordination: "does not establish X or Y" covers Y too). Joins by
    `and`/`but` cut the scope, so an unrelated trailing negation cannot
    launder an affirmative isolation guarantee in an earlier predicate
    (reviewer review-record run 534). A PREPOSITIONAL negator
    (`without`/`no`, reviewer review-record run 545) additionally counts
    only while it precedes `pos`: it heads the phrase containing the
    keyword and cannot negate an affirmative predicate that stands
    before it ("is fully isolated … without requiring credentials").
    Adverbial negators keep whole-segment scope.
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
                # A prepositional negator at or after the keyword heads
                # a trailing adjunct, not the isolation predicate.
                continue
            return True
        if coord != "or" or idx == 0:
            return False
        idx -= 1


def _boundary_violations(collapsed_text: str) -> list[str]:
    """Boundary-contract violations in whitespace-collapsed doc text."""
    found: list[str] = []
    spans = _clause_spans(collapsed_text)
    # Every sandbox mention must be negated inside its OWN sentence/clause
    # (window-based negation let a neighbouring "no filesystem sandbox"
    # excuse an affirmative sandbox claim inserted directly beside it).
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
    ("relative", "original", "replacement"),
    (
        # Reviewer run 521 mutation class 1: assert a filesystem sandbox
        # where the docs disclose its absence.
        (
            "README.md",
            "environment and no filesystem sandbox",
            "environment and a filesystem sandbox",
        ),
        (
            "docs/data-and-permissions.md",
            "environment and no filesystem sandbox",
            "environment inside a filesystem sandbox",
        ),
        # Mutation class 2: turn the unknown vendor file behavior into a
        # read-only guarantee.
        (
            "docs/quick-start.md",
            "is not observable from this repository — neither claimed nor excluded",
            "is read-only: that process never touches credential files",
        ),
        # Mutation class 3: reintroduce the pre-rework unscoped overclaim.
        (
            "README.md",
            "requires no credentials, its own code reads no credential stores",
            "is read-only and never reads credential files",
        ),
        # Mutation class 4: delete the not-a-guarantee disclaimer.
        (
            "docs/data-and-permissions.md",
            "Nothing in this repository's credential-free evidence should be "
            "read as a sandbox or isolation guarantee for that child.",
            "The credential-free evidence confirms the vendor child stays read-only.",
        ),
        # Mutation class 5 (reviewer review-record run 524, repeating
        # review-record run 521): INSERT an independent affirmative vendor
        # filesystem guarantee as its own sentence or comma-delimited
        # clause while every adjacent harness/vendor-boundary and
        # unobservability disclosure stays intact. These are pure
        # insertions, so `_boundary_missing_fragments` stays empty and the
        # RED must come from `_boundary_violations` segmentation itself.
        #
        # Period-delimited read-only / no-credential-file guarantee
        # (the reviewer's exact sentence) in each public boundary doc:
        (
            "README.md",
            "no prompt, and no credential material.",
            "no prompt, and no credential material. The vendor binary is "
            "read-only and never reads credential files.",
        ),
        (
            "docs/data-and-permissions.md",
            "is not observed here, is not claimed, and is not excluded.",
            "is not observed here, is not claimed, and is not excluded. "
            "The vendor binary is read-only and never reads credential files.",
        ),
        # Period-delimited cannot-write-to-user-directories guarantee:
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor binary "
            "cannot write to user directories.",
        ),
        # Comma-delimited cannot-write-to-user-directories guarantee:
        (
            "README.md",
            "environment and no filesystem sandbox, so what that binary",
            "environment and no filesystem sandbox, the vendor binary "
            "cannot write to user directories, so what that binary",
        ),
        (
            "docs/data-and-permissions.md",
            "no filesystem sandbox — this is not the Hermes runtime path",
            "no filesystem sandbox — this is not the Hermes runtime path, "
            "the vendor binary cannot write to user directories",
        ),
        # Comma-delimited read-only / no-credential-file guarantee:
        (
            "docs/quick-start.md",
            "environment and no filesystem sandbox, so whatever file access that process",
            "environment and no filesystem sandbox, the vendor binary is "
            "read-only and never accesses credential files, so whatever "
            "file access that process",
        ),
        # Period-delimited sandbox/isolation guarantee asserted about the
        # vendor child, inserted beside the intact disclosures:
        (
            "README.md",
            "see the vendor attribution in `docs/data-and-permissions.md`.",
            "see the vendor attribution in `docs/data-and-permissions.md`. "
            "The vendor binary starts Google's proprietary server in a "
            "secure sandbox.",
        ),
        (
            "docs/quick-start.md",
            "It makes no claim about the vendor binary:",
            "The vendor binary starts Google's proprietary server in a "
            "secure sandbox. It makes no claim about the vendor binary:",
        ),
        (
            "docs/data-and-permissions.md",
            "should be read as a sandbox or isolation guarantee for that child.",
            "should be read as a sandbox or isolation guarantee for that "
            "child. The vendor binary starts the official server in a "
            "secure sandbox.",
        ),
        # Mutation class 6 (reviewer review-record run 531): INSERT the
        # reviewer's exact independent affirmative ISOLATION sentence,
        # "The vendor binary is fully isolated from user files.", at
        # period, comma, and markdown table-cell boundaries while every
        # truthful disclosure fragment stays intact. These were the false
        # negatives: no read/write promise token and no literal "sandbox"
        # appears, so only isolation-aware clause judging rejects them.
        #
        # Period-delimited reviewer sentence in each public boundary doc:
        (
            "README.md",
            "no prompt, and no credential material.",
            "no prompt, and no credential material. The vendor binary is "
            "fully isolated from user files.",
        ),
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor binary is "
            "fully isolated from user files.",
        ),
        (
            "docs/data-and-permissions.md",
            "is not observed here, is not claimed, and is not excluded.",
            "is not observed here, is not claimed, and is not excluded. "
            "The vendor binary is fully isolated from user files.",
        ),
        # Comma-delimited reviewer sentence inside the inherited-environment
        # disclosures of README.md and docs/quick-start.md:
        (
            "README.md",
            "environment and no filesystem sandbox, so what that binary",
            "environment and no filesystem sandbox, the vendor binary is "
            "fully isolated from user files, so what that binary",
        ),
        (
            "docs/quick-start.md",
            "environment and no filesystem sandbox, so whatever file access that process",
            "environment and no filesystem sandbox, the vendor binary is "
            "fully isolated from user files, so whatever file access that "
            "process",
        ),
        # Markdown table-cell insertions: a pipe-delimited cell carrying
        # the affirmative isolation sentence (semicolon- and comma-chained)
        # must not launder through the table structure.
        (
            "README.md",
            "No self-update; no redistribution.",
            "No self-update; no redistribution; the vendor binary is fully "
            "isolated from user files.",
        ),
        (
            "docs/data-and-permissions.md",
            "Google's versioned server files as distributed",
            "Google's versioned server files as distributed, the vendor "
            "binary is fully isolated from user files",
        ),
        # Mutation class 7 (reviewer review-record run 534): INSERT the
        # reviewer's affirmative isolation guarantee PAIRED with an
        # unrelated negation inside the same clause — "The vendor binary
        # is fully isolated from user files and does not require
        # credentials." The run 531 negation gate searched the whole
        # clause, so the credentials `not` suppressed the isolation
        # guarantee and all 60 focused tests stayed green. These pure
        # insertions keep every truthful disclosure fragment intact; only
        # predicate-level negation binding rejects them.
        #
        # Period-delimited compound sentence in each public boundary doc:
        (
            "README.md",
            "no prompt, and no credential material.",
            "no prompt, and no credential material. The vendor binary is "
            "fully isolated from user files and does not require "
            "credentials.",
        ),
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor binary is "
            "fully isolated from user files and does not require "
            "credentials.",
        ),
        (
            "docs/data-and-permissions.md",
            "is not observed here, is not claimed, and is not excluded.",
            "is not observed here, is not claimed, and is not excluded. "
            "The vendor binary is fully isolated from user files and does "
            "not require credentials.",
        ),
        # Negated predicate FIRST, affirmative isolation second (same
        # clause, `and`-joined): the negation must not scope forward.
        (
            "README.md",
            "no prompt, and no credential material.",
            "no prompt, and no credential material. The vendor binary "
            "does not require credentials and is fully isolated from user "
            "files.",
        ),
        # Comma-delimited compound clause inside the inherited-environment
        # disclosures:
        (
            "README.md",
            "environment and no filesystem sandbox, so what that binary",
            "environment and no filesystem sandbox, the vendor binary is "
            "fully isolated from user files and does not require "
            "credentials, so what that binary",
        ),
        (
            "docs/quick-start.md",
            "environment and no filesystem sandbox, so whatever file access that process",
            "environment and no filesystem sandbox, the vendor binary is "
            "fully isolated from user files and does not require "
            "credentials, so whatever file access that process",
        ),
        # Semicolon-chained compound claim inside a README table cell:
        (
            "README.md",
            "No self-update; no redistribution.",
            "No self-update; no redistribution; the vendor binary is "
            "fully isolated from user files and does not require "
            "credentials.",
        ),
        # `but`-joined segregation guarantee paired with a credentials
        # negation:
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor binary "
            "is fully segregated from user files but needs no "
            "credentials.",
        ),
        # Quarantine wording paired with a credentials negation at a
        # comma/table-cell boundary:
        (
            "docs/data-and-permissions.md",
            "Google's versioned server files as distributed",
            "Google's versioned server files as distributed, the vendor "
            "binary is quarantined from user files and does not require "
            "credentials",
        ),
        # Mutation class 8 (reviewer review-record run 545, meta
        # review-record run 547): INSERT the affirmative isolation
        # guarantee followed by an UNRELATED PREPOSITIONAL-negation
        # adjunct — "The vendor binary is fully isolated from user
        # files without requiring credentials." Segment-wide negation
        # search inside the predicate segment let the trailing
        # `without` mask the isolation predicate, so every insertion
        # below stayed green at head e9cf4808. Prepositional negators
        # must bind only forward into their own phrase. Pure
        # insertions again — every truthful disclosure fragment stays
        # intact; only negation scoping rejects these.
        #
        # Period-delimited exact witness in each public boundary doc:
        (
            "README.md",
            "no prompt, and no credential material.",
            "no prompt, and no credential material. The vendor binary "
            "is fully isolated from user files without requiring "
            "credentials.",
        ),
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor "
            "binary is fully isolated from user files without "
            "requiring credentials.",
        ),
        (
            "docs/data-and-permissions.md",
            "is not observed here, is not claimed, and is not excluded.",
            "is not observed here, is not claimed, and is not "
            "excluded. The vendor binary is fully isolated from user "
            "files without requiring credentials.",
        ),
        # Comma-delimited exact witness inside the inherited-environment
        # disclosures:
        (
            "README.md",
            "environment and no filesystem sandbox, so what that binary",
            "environment and no filesystem sandbox, the vendor binary "
            "is fully isolated from user files without requiring "
            "credentials, so what that binary",
        ),
        (
            "docs/quick-start.md",
            "environment and no filesystem sandbox, so whatever file access that process",
            "environment and no filesystem sandbox, the vendor binary "
            "is fully isolated from user files without requiring "
            "credentials, so whatever file access that process",
        ),
        # Markdown table-cell insertions (semicolon-chained README
        # cell, comma-chained data/permissions cell):
        (
            "README.md",
            "No self-update; no redistribution.",
            "No self-update; no redistribution; the vendor binary is "
            "fully isolated from user files without requiring "
            "credentials.",
        ),
        (
            "docs/data-and-permissions.md",
            "Google's versioned server files as distributed",
            "Google's versioned server files as distributed, the "
            "vendor binary is fully isolated from user files without "
            "requiring credentials",
        ),
        # Segregation wording with the same `without` adjunct:
        (
            "docs/quick-start.md",
            "its own code reads no credential stores.",
            "its own code reads no credential stores. The vendor "
            "binary is fully segregated from user files without "
            "requiring credentials.",
        ),
        # Quarantine wording with a bare `without` adjunct:
        (
            "docs/data-and-permissions.md",
            "is not observed here, is not claimed, and is not excluded.",
            "is not observed here, is not claimed, and is not "
            "excluded. The vendor binary is quarantined from user "
            "files without any credential requirement.",
        ),
        # Trailing `no` adjunct inside a semicolon-chained table cell:
        (
            "README.md",
            "No self-update; no redistribution.",
            "No self-update; no redistribution; the vendor binary is "
            "fully isolated from user files with no credential "
            "requirements.",
        ),
    ),
)
def test_filesystem_boundary_contracts_reject_mutated_docs(
    relative: str, original: str, replacement: str
) -> None:
    """RED proof: contradictory docs must fail the contract, not stay green."""
    collapsed_text = _collapsed(relative)
    assert original in collapsed_text, (
        f"stale mutation anchor in {relative}: {original!r}; the wording "
        "contract and its mutation proof must move together"
    )
    mutated = collapsed_text.replace(original, replacement)
    violations = _boundary_violations(mutated)
    missing = _boundary_missing_fragments(relative, mutated)
    assert violations or missing, (
        f"{relative} still satisfied the filesystem-boundary contract after "
        f"mutating {original!r} -> {replacement!r}; the tests do not enforce "
        "the harness/vendor boundary (reviewer review-record run 521 and "
        "review-record run 524 findings)"
    )


@pytest.mark.parametrize(
    "statement",
    (
        # Reviewer review-record run 534 direct witness: the exact compound
        # sentence, its predicate-reordered twin, and equivalent
        # isolation/segregation/quarantine guarantees paired with an
        # unrelated negation at every relevant sentence/punctuation
        # boundary. Clause-wide negation used to let all of these stay
        # green; each must produce a vendor-isolation-guarantee violation.
        "The vendor binary is fully isolated from user files and does not require credentials.",
        "The vendor binary does not require credentials and is fully isolated from user files.",
        "The vendor binary is fully isolated from user files, and it does not require credentials.",
        "The vendor binary is fully segregated from user files but needs no credentials.",
        "The vendor binary is quarantined from user files and does not require credentials.",
        "the vendor binary is fully isolated from user files and does not require credentials;",
        "| the vendor binary is fully isolated from user files and does not require credentials |",
        # Prepositional-negation witnesses (reviewer review-record run
        # 545, meta review-record run 547): an affirmative isolation
        # guarantee followed by an unrelated `without …`/`no …`
        # adjunct. Segment-wide negation search let the trailing
        # preposition excuse the isolation predicate at head
        # e9cf4808; each of these must produce a
        # vendor-isolation-guarantee violation.
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
        # The other side of the same invariant: correct harness-scoped
        # statements and honest vendor-unknown statements must stay
        # ACCEPTED even under the boundary-aware segmentation — they
        # describe this harness's own observable behavior or explicitly
        # refuse to claim/exclude vendor behavior.
        "The verify probe requires no credentials; its own code reads no credential stores.",
        "Harness behavior is observable, ours; it never reads credential stores.",
        "Whatever the vendor binary reads or writes is not observable from this repository — neither claimed nor excluded.",
        "What this repository observes of that child is not observed elsewhere, is not claimed, and is not excluded.",
        # Isolation-class accepts (reviewer review-record run 531 boundary):
        # honest absence/negation statements about isolation and unknown
        # vendor file behavior must stay violation-free under the new
        # isolation clause rule.
        "The vendor child is unsandboxed; its file behavior is unknown.",
        "Whatever isolation the vendor binary may have is not observable and not claimed.",
        "Credential-state isolation is not established by an environment scrub of that child.",
        "The official server's file behavior is unknown; nothing here is an isolation guarantee for that child.",
        # Negation-pairing accepts (reviewer review-record run 534 other
        # side): truthful negatives where the negation lives in the SAME
        # predicate as the isolation wording, or scopes forward through
        # `or`-joined disjuncts, must stay violation-free.
        "The vendor binary is not isolated from user files and does not require credentials.",
        "No documentation here claims the vendor binary is isolated from user files or requires credentials.",
        "Nothing here presents the vendor binary as isolated from user files or segregated from credential stores.",
        "The vendor child is unsandboxed and does not run in a container.",
        # Prepositional-negation accepts (reviewer review-record run 545
        # other side): when the prepositional negator PRECEDES the
        # isolation keyword it heads the phrase containing it, so
        # honest disclosures of isolation's ABSENCE stay
        # violation-free — only a trailing adjunct loses the masking
        # power.
        "The vendor binary runs without establishing vendor isolation.",
        "No isolation of the vendor binary from user files is claimed or excluded.",
        "The vendor child operates with no isolation from user files, and its file behavior is unknown.",
    ),
)
def test_harness_scoped_and_vendor_unknown_statements_are_accepted(statement: str) -> None:
    assert _boundary_violations(statement) == [], statement


# ---------------------------------------------------------------------------
# (6) CI real-binary execution disclosure (reviewer review-record run 558):
#     the public docs must not claim that this repository's CI as a whole
#     never executes the official real binary or never fetches from the
#     first-party feed. Per the historical reference venue ruling that IS executed
#     evidence: the dedicated-UID `acp-clean-room` job on a hosted
#     ubuntu-24.04 runner fetches the official 1.4.4 binary under the
#     reviewed publisher pin and executes three unauthenticated
#     `initialize` probes with zero authentication and zero prompt frames
#     (hosted run 42460899585, job 128669769339). A CI-wide non-execution
#     claim contradicts the README's own executed clean-room tier. The
#     truthful non-execution assertions belong to the fake-ACP
#     registry/regression job (no feed fetch, no real binary, credential-
#     free) and to the per-platform pinned-only tiers (OS-scoped).
# ---------------------------------------------------------------------------

# Job or platform scope tokens that keep a CI non-execution/non-fetch
# assertion truthful. Absent all of them, a clause subjecting "CI" as a
# whole to a negated real/official-binary assertion is the run 558
# conflation.
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


# Claim-group boundaries: like `_CLAUSE_BOUNDARY` but WITHOUT the comma,
# so a comma-delimited list under one subject is judged as one claim
# group. Without this pass, mutating only the group's subject (`fake-acp
# registry/regression job` -> `CI as a whole`) while the comma-final item
# still carries the binary noun split subject and object across commas
# and laundered the CI-wide denial back in.
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
    readme = _collapsed("README.md")
    # The non-execution/non-fetch assertion is scoped to the fake-ACP job.
    assert (
        "fake-acp` registry/regression job performs no live feed fetch, "
        "no authentication, and no real-binary execution" in readme
    )
    # The dedicated-UID hosted clean-room job's real-binary execution is
    # stated as the exclusive CI exception, credential-free and prompt-free.
    assert (
        "Real-binary execution in CI belongs exclusively to the "
        "dedicated-UID `acp-clean-room` job" in readme
    )


@pytest.mark.parametrize(
    ("relative", "original", "replacement"),
    (
        # Reverting to the head-3915faaf disclosure (reviewer review-record
        # run 558): re-attaching the old unscoped CI-wide parenthetical
        # in place of the fake-ACP scoping must trip the detector.
        (
            "README.md",
            "that credential-free `fake-acp` registry/regression job "
            "performs no live feed fetch, no authentication, and no "
            "real-binary execution",
            "the CI performs no live feed fetch and never executes the "
            "real binary",
        ),
        # Dropping only the job-scope noun while keeping the rest of the
        # scoped sentence intact must also trip the detector.
        (
            "README.md",
            "that credential-free `fake-acp` registry/regression job "
            "performs",
            "and CI as a whole performs",
        ),
    ),
)
def test_unscoped_ci_real_binary_claim_is_rejected(
    relative: str, original: str, replacement: str
) -> None:
    collapsed_text = _collapsed(relative)
    assert original in collapsed_text, (
        f"stale mutation anchor in {relative}: {original!r}; the wording "
        "contract and its mutation proof must move together"
    )
    mutated = collapsed_text.replace(original, replacement)
    violations = _ci_real_binary_claim_violations(mutated)
    assert violations, (
        f"{relative} still passed the CI real-binary disclosure contract "
        f"after mutating {original!r} -> {replacement!r}; a CI-wide "
        "non-execution claim can again contradict the executed "
        "clean-room tier (reviewer review-record run 558)"
    )


@pytest.mark.parametrize(
    "statement",
    (
        # Direct witnesses of the run 558 conflation class: each asserts
        # CI-wide absence of real-binary execution (or feed fetch) with
        # no fake-ACP job or platform scope. The old README parenthetical
        # is the first witness verbatim.
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
        # The other side of the invariant: truthful job-scoped and
        # platform-scoped disclosures must stay ACCEPTED.
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


# ---------------------------------------------------------------------------
# (7) Three public-disclosure boundaries from maintainer comment
#     the disclosure review (historical reference review on head earlier). Each detector below is
#     boundary-scoped (never a generalized prose-regex framework):
#
#     a. Child-environment disclosure: `hermes-plugin/antigravity-acp/
#        client.py::_spawn()` first narrows the environment to the minimum
#        enumerated allowlist (dropping ambient credentials, ambient session
#        identity variables, and any inherited `ACP_MUX_*` configuration),
#        then DELIBERATELY synthesizes bounded routing/session metadata
#        (`ACP_MUX_SESSION_ID`, `ACP_MUX_AFFINITY`, `ACP_MUX_PAR` when
#        pinned, `ACP_MUX_SESSION_GC`, `ACP_MUX_AFFINITY_PIN`, affinity TTL
#        and entry limits). A claim group that negates passing session
#        identity or mux variables to the child without scoping the negative
#        to the ambient/inherited environment contradicts that code.
#     b. Child-process topology: `AntigravityACPClient._session()` calls
#        `_spawn()` for each session context and `_release_process()`
#        terminates the child when that context exits — one short-lived
#        server child per ACP session/attempt, NOT a global "exactly one
#        child per Hermes process" singleton, while the children remain
#        distinct from a separately daemonized service.
#     c. Google-bound network scope: the repository-visible Google-bound
#        surfaces are runtime model/protocol requests originating from the
#        Google-distributed official binary and the standalone installer's
#        HTTPS download from `dl.google.com` (`scripts/
#        install_official.py`). Universal unscoped origin claims ("all
#        Google-bound traffic", "flows exclusively") overclaim, and no
#        statement may bound proprietary vendor-child networking beyond
#        repository evidence.
# ---------------------------------------------------------------------------

_CHILD_ENV_SUBJECT = re.compile(
    r"\bmux\b|acp_mux|session[- ]identity|session tokens?"
)
_CHILD_ENV_PASSTHROUGH = re.compile(
    r"\bpas{1,2}(?:ed|es|ing)?\b|\bforward\w*|\bcarr\w*|\binherit\w*"
    r"|\bgiven\b|\breceiv\w*"
)
# A never-pass claim is truthful only when the SAME claim group scopes it to
# the ambient/inherited environment or acknowledges the synthesized
# metadata; unscoped negatives are the maintainer's item-1 overclaim.
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
    """Claim groups asserting a universal, unscoped Google-bound origin."""
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
    dp = _collapsed("docs/data-and-permissions.md").lower()
    assert (
        "ambient session identity variables, and inherited operator "
        "`acp_mux_*` environment configuration are **never** passed to "
        "the child" in dp
    )
    assert (
        "what deliberately does cross is a bounded set of "
        "plugin-synthesized routing/session metadata" in dp
    )
    assert "`acp_mux_session_id` and `acp_mux_affinity`" in dp
    assert "not google credentials" in dp
    readme = _collapsed("README.md").lower()
    assert (
        "allowlist carrying no ambient provider api keys, gateway tokens, "
        "or session identity variables, plus a deliberately synthesized "
        "bounded set of `acp_mux_*` routing/session metadata" in readme
    )


@pytest.mark.parametrize(
    ("relative", "original", "replacement"),
    (
        # Reverting the README summary bullet to the earlier
        # "never carries ... session tokens" overclaim must trip.
        (
            "README.md",
            "the ACP child receives a minimum-enumerated environment "
            "allowlist carrying no ambient provider API keys, gateway "
            "tokens, or session identity variables, plus a deliberately "
            "synthesized bounded set of `ACP_MUX_*` routing/session "
            "metadata",
            "the ACP child receives a minimum-enumerated environment "
            "allowlist that never carries provider API keys or session "
            "tokens",
        ),
        # Reverting the data-and-permissions bullet to the earlier
        # unscoped "session identity variables, and operator mux
        # configuration are never passed" must trip.
        (
            "docs/data-and-permissions.md",
            "Ambient provider API keys (`OPENAI_API_KEY`, "
            "`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`), Tier-1 gateway "
            "tokens, ambient session identity variables, and inherited "
            "operator `ACP_MUX_*` environment configuration are **never** "
            "passed to the child",
            "Provider API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, "
            "`GEMINI_API_KEY`), Tier-1 gateway tokens, session identity "
            "variables, and operator mux configuration are **never** "
            "passed to the child",
        ),
    ),
)
def test_overbroad_child_env_never_claim_is_rejected(
    relative: str, original: str, replacement: str
) -> None:
    collapsed_text = _collapsed(relative)
    assert original in collapsed_text, (
        f"stale mutation anchor in {relative}: {original!r}; the wording "
        "contract and its mutation proof must move together"
    )
    violations = _overbroad_child_env_groups(
        collapsed_text.replace(original, replacement)
    )
    assert violations, (
        f"{relative} still passed the child-environment disclosure "
        f"contract after mutating {original!r} -> {replacement!r}; an "
        "unscoped never-pass claim can again contradict the synthesized "
        "ACP_MUX_* metadata (maintainer guidance item 1)"
    )


@pytest.mark.parametrize(
    "statement",
    (
        # Verbatim earlier docs bullet tail and README summary class.
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
        # The other side of the invariant: ambient/inherited-scoped and
        # synthesis-acknowledging disclosures must stay ACCEPTED.
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
    readme = _collapsed("README.md")
    assert (
        "launches one short-lived official server child per ACP session "
        "or attempt" in readme
    )
    assert "more than one child over a Hermes process lifetime" in readme
    assert "each is terminated when its session ends" in readme
    assert "Not daemonized services" in readme
    dp = _collapsed("docs/data-and-permissions.md")
    assert (
        "one short-lived official ACP server child process "
        "**per ACP session or attempt**" in dp
    )
    assert "Each child is terminated when its session context exits" in dp
    assert "not a daemonized service" in dp
    # The global-singleton scope phrase must not survive anywhere in the
    # two disclosure docs; per-session wording carries the guarantee now.
    assert "per Hermes process" not in readme
    assert "per Hermes process" not in dp


@pytest.mark.parametrize(
    ("relative", "original", "replacement"),
    (
        # Reverting the README child-process bullet to the earlier
        # per-Hermes-process singleton promise must trip.
        (
            "README.md",
            "launches one short-lived official server child per ACP "
            "session or attempt",
            "launches exactly one official server child per Hermes process",
        ),
        # Reverting the data-and-permissions topology bullet likewise.
        (
            "docs/data-and-permissions.md",
            "launches one short-lived official ACP server child process "
            "**per ACP session or attempt**",
            "launches **exactly one** official ACP server child process "
            "per Hermes process",
        ),
        # Dropping only the per-session/attempt qualification while
        # restoring the exactly-one count must trip.
        (
            "README.md",
            "and launches a short-lived server child from it for each ACP "
            "session or attempt",
            "and launches exactly one official Antigravity ACP server "
            "child process",
        ),
    ),
)
def test_singleton_server_child_claim_is_rejected(
    relative: str, original: str, replacement: str
) -> None:
    collapsed_text = _collapsed(relative)
    assert original in collapsed_text, (
        f"stale mutation anchor in {relative}: {original!r}; the wording "
        "contract and its mutation proof must move together"
    )
    violations = _singleton_server_child_groups(
        collapsed_text.replace(original, replacement)
    )
    assert violations, (
        f"{relative} still passed the child-process topology contract "
        f"after mutating {original!r} -> {replacement!r}; a global "
        "exactly-one server child claim can again contradict the "
        "per-session/attempt spawning (maintainer guidance "
        "item 2)"
    )


@pytest.mark.parametrize(
    "statement",
    (
        # Verbatim earlier claims: the data-and-permissions topology
        # bullet, the README provider-plugin sentence, and a paraphrase.
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
        # Per-session/attempt qualified lifecycles stay ACCEPTED.
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
    readme = _collapsed("README.md")
    assert (
        "Runtime data to Google flows through the official server" in readme
    )
    assert (
        "every model/protocol request that this runtime sends onward to "
        "Google originates from that Google-distributed binary" in readme
    )
    assert (
        "the standalone installer fetches the pinned server archive over "
        "HTTPS from `dl.google.com` during an explicit install command"
        in readme
    )
    dp = _collapsed("docs/data-and-permissions.md")
    assert (
        "Runtime model/protocol traffic to Google originates from the "
        "Google-distributed official binary" in dp
    )
    assert (
        "retrieves the pinned server archive over HTTPS from "
        "`dl.google.com`" in dp
    )
    assert "installer asset retrieval, not provider model/protocol traffic" in dp


@pytest.mark.parametrize(
    ("relative", "original", "replacement"),
    (
        # Reverting the README summary lead to the earlier universal
        # "flows exclusively" claim must trip.
        (
            "README.md",
            "Runtime data to Google flows through the official server",
            "Data to Google flows exclusively through the official server",
        ),
        # Reverting the data-and-permissions lead to the earlier
        # "All Google-bound network traffic" claim must trip.
        (
            "docs/data-and-permissions.md",
            "Runtime model/protocol traffic to Google originates from "
            "the Google-distributed official binary",
            "All Google-bound network traffic originates from the "
            "Google-distributed official binary",
        ),
        # Dropping the runtime/model/protocol scope nouns from the
        # per-request sentence must also trip.
        (
            "README.md",
            "every model/protocol request that this runtime sends onward "
            "to Google originates from that Google-distributed binary",
            "all traffic sent onward to Google originates from that "
            "Google-distributed binary",
        ),
    ),
)
def test_unscoped_google_bound_traffic_claim_is_rejected(
    relative: str, original: str, replacement: str
) -> None:
    collapsed_text = _collapsed(relative)
    assert original in collapsed_text, (
        f"stale mutation anchor in {relative}: {original!r}; the wording "
        "contract and its mutation proof must move together"
    )
    violations = _unscoped_google_traffic_groups(
        collapsed_text.replace(original, replacement)
    )
    assert violations, (
        f"{relative} still passed the Google-bound traffic disclosure "
        f"contract after mutating {original!r} -> {replacement!r}; an "
        "unscoped universal origin claim can again overstate the "
        "repository-observable surface (maintainer guidance "
        "item 3)"
    )


@pytest.mark.parametrize(
    "statement",
    (
        # Verbatim earlier claims and the universal paraphrase class.
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
        # Runtime-scoped origin claims and the installer-download
        # disclosure stay ACCEPTED.
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
