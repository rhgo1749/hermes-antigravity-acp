#!/usr/bin/env python3
"""Scan tracked and unignored local repository files without echoing secrets.

The scanner reports only rule names and counts. It never prints matched content,
OAuth URLs, or file paths, so its output is safe to copy into public CI logs.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


CONTENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("google_access_token", re.compile(r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{24,}")),
    ("google_client_secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{24,}")),
    (
        "oauth_url",
        re.compile(
            r"(?i)https?://[^\s\"'<>]*(?:oauth|authorize)[^\s\"'<>]*"
            r"[?&](?:client_id|redirect_uri|state|code|access_token|refresh_token)="
            r"[^&\s\"'<>]{16,}"
        ),
    ),
)

SENSITIVE_NAMES = {
    ".env",
    "credentials.json",
    "client_secret.json",
    "token.json",
    "acp-accounts.json",
    "acp-mux-state.json",
    "acp-mux.log",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".log", ".par", ".zip"}
SENSITIVE_DIRS = {
    "logs",
    "plugin-backups",
    "deployment-artifacts",
    ".deploy",
    ".local-deploy",
    "dist",
    "build",
}

# historical reference distribution boundary. The Hermes plugin catalog and the default
# install ship exactly the canonical provider fileset; personal host-deploy,
# mux, and portfolio-ops tooling must never be referenced from the public
# distribution closure. These rules enforce that boundary from the same
# credential-free scanner CI already runs.
PUBLIC_PROVIDER_DIR = "hermes-plugin/antigravity-acp/"
PUBLIC_PROVIDER_FILES = frozenset(
    {
        "plugin.yaml",
        "__init__.py",
        "client.py",
        "bridge.py",
        "conversation_state.py",
        "native_limit_state.py",
        "process_teardown.py",
        "hermes_compat.py",
        "login.py",
    }
)
PUBLIC_CLOSURE_FILES = frozenset(
    {
        "scripts/install_acp.py",
        "scripts/install_official.py",
        "scripts/deploy_hermes_profiles.py",
        "scripts/acp_probe.py",
        "scripts/acp_login.py",
        "README.md",
        "docs/plugin-catalog-entry.draft.yaml",
        ".github/workflows/ci.yml",
        "antigravity_acp/registry.py",
    }
)
# Exact personal-ops tokens (private script paths, container identities,
# account-registry filenames, and the overlay module filename). Rework-r4
# (historical reference): the provider tree lost its token-scan exemption — with the
# public client now carrying a domain-neutral obligation-evidence contract,
# there is no fail-closed naming rationale left, so PERSONAL_OPS_TOKENS are
# findings in the provider tree AND the public distribution closure alike.
PERSONAL_OPS_TOKENS = (
    "acp-accounts.json",
    "acp-mux-state.json",
    "hermes-cloudcli-agent",
    "/home/hermes",
    "antigravity-acp-mux",
    "scripts/acp_mux",
    "deploy_acp_host",
    "deploy_finance_hotfix_host",
    "deploy_portfolio_policy",
    "portfolio_policy",
    "portfolio-manager",
)


@dataclass(frozen=True)
class Finding:
    relative_path: str
    rule: str


def sensitive_path(path: str | Path) -> str | None:
    """Return a safe finding category for secret or deployment artifact paths."""
    parts = Path(path).parts
    lower_parts = tuple(part.lower() for part in parts)
    basename = lower_parts[-1] if lower_parts else ""
    if basename == ".env.example" or basename.endswith(".example.json"):
        return None
    if basename in SENSITIVE_NAMES:
        return "sensitive_filename"
    if basename.startswith(".env."):
        return "sensitive_filename"
    if Path(basename).suffix in SENSITIVE_SUFFIXES:
        return "local_artifact_filename"
    if any(part in SENSITIVE_DIRS for part in lower_parts[:-1]):
        return "local_deployment_artifact"
    return None


def scan_text(text: str) -> list[str]:
    """Return matching rule names only; matched bytes are intentionally omitted."""
    return [name for name, pattern in CONTENT_RULES if pattern.search(text)]


def _repository_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    )
    paths = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [root / value for value in paths if value]


def _public_surface_findings(relative: str, text: str) -> list[str]:
    """historical reference boundary rules over the public distribution surface."""
    rules: list[str] = []
    if relative.startswith(PUBLIC_PROVIDER_DIR):
        # Rework-r2: exact relative path from the provider root, not the
        # basename. A nested file whose basename happens to be canonical
        # (extra/client.py, private_secrets/__init__.py, ...) is NOT part of
        # the public provider contract and is a finding.
        if relative[len(PUBLIC_PROVIDER_DIR) :] not in PUBLIC_PROVIDER_FILES:
            rules.append("public_provider_tree_file")
        # Rework-r4: the provider tree is token-scanned like the rest of the
        # public closure; it carries no personal-ops naming whatsoever.
        if any(token in text for token in PERSONAL_OPS_TOKENS):
            rules.append("personal_ops_reference")
    elif relative in PUBLIC_CLOSURE_FILES:
        if any(token in text for token in PERSONAL_OPS_TOKENS):
            rules.append("personal_ops_reference")
    return rules


def scan_repository(root: Path) -> list[Finding]:
    """Scan tracked and non-ignored worktree files without reading symlink targets."""
    root = root.resolve()
    findings: list[Finding] = []
    for path in _repository_files(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            continue
        if path_rule := sensitive_path(relative):
            findings.append(Finding(relative, path_rule))
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        findings.extend(Finding(relative, rule) for rule in scan_text(text))
        findings.extend(Finding(relative, rule) for rule in _public_surface_findings(relative, text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        findings = scan_repository(args.root)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"repository audit failed ({type(exc).__name__}); details suppressed")
        return 2
    if findings:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.rule] = counts.get(finding.rule, 0) + 1
        summary = ", ".join(f"{rule}={count}" for rule, count in sorted(counts.items()))
        print(f"repository audit found {len(findings)} issue(s): {summary}; paths and values suppressed")
        return 1
    print("repository audit clean; matched values and local paths were not emitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
