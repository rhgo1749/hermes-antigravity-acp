#!/usr/bin/env python3
"""Read-only, sanitized audit of reachable Git history and GitHub assets.

The fast credential-free current-tree check remains scripts/audit_public_tree.py.
This opt-in command reads local Git objects and GitHub REST resources; it never
changes refs, repository contents, Actions, issues, releases, or credentials.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from audit_public_tree import SENSITIVE_DIRS, scan_text, sensitive_path
except ImportError:  # Imported as scripts.audit_exposure by repository tests.
    from scripts.audit_public_tree import SENSITIVE_DIRS, scan_text, sensitive_path


STATUS_CLEAN = "CHECKED_NO_FINDING"
STATUS_FINDING = "FINDING"
STATUS_NOT_VERIFIED = "NOT_VERIFIED"
STATUS_OUTSIDE_VERIFIED_SCOPE = "OUTSIDE_VERIFIED_SCOPE"
API_HOST = "api.github.com"
LOCAL_SURFACE_NAMES: tuple[str, ...] = ("local_git_history", "local_object_store_boundary")
SURFACE_NAMES: tuple[str, ...] = (
    "local_git_history",
    "local_object_store_boundary",
    "github_refs",
    "github_history",
    "github_discussions",
    "github_reviews",
    "github_inline_comments",
    "github_actions",
    "github_action_logs",
    "github_action_artifacts",
    "github_releases",
    "github_release_assets",
    "external_references",
)
ATTACHMENT_PATH_PREFIXES = ("/user-attachments/assets/", "/user-attachments/files/")
JSON_LIMIT = 8 * 1024 * 1024
DOWNLOAD_LIMIT = 32 * 1024 * 1024
GIT_BLOB_LIMIT = 32 * 1024 * 1024
ARCHIVE_MEMBER_LIMIT = 10_000
ARCHIVE_TOTAL_LIMIT = 64 * 1024 * 1024
ARCHIVE_FILE_LIMIT = 8 * 1024 * 1024
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SENSITIVE_PATH_TOKEN_RE = re.compile(
    r"(?<![\w.-])(?:[^\s\"'<>:,;(){}\[\]]+/)*(?:\.env(?:\.[A-Za-z0-9_-]+)?|"
    r"credentials\.json|client_secret\.json|token\.json|acp-accounts\.json|"
    r"acp-mux-state\.json|acp-mux\.log|[^/\s]+\.(?:pem|key|p12|pfx|log|par|zip))"
    r"(?![\w.-])",
    re.IGNORECASE,
)

# Fixed vocabularies for the privacy-preserving per-item class evidence. Only
# these constant tokens may reach a report; the matched path or value itself is
# never retained, only which constant classes it belongs to.
BENIGN_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "demo",
        "demos",
        "example",
        "examples",
        "fake",
        "fakes",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "sample",
        "samples",
        "spec",
        "specs",
        "stub",
        "stubs",
        "synthetic",
        "test",
        "tests",
        "testing",
    }
)
EXAMPLE_NAME_SUFFIXES: tuple[str, ...] = (".example", ".sample", ".template", ".dist", ".default")
CREDENTIAL_JSON_NAMES: frozenset[str] = frozenset({"credentials.json", "client_secret.json", "token.json"})
RUNTIME_STATE_NAMES: frozenset[str] = frozenset({"acp-accounts.json", "acp-mux-state.json", "acp-mux.log"})
KEY_MATERIAL_SUFFIXES: frozenset[str] = frozenset({".pem", ".key", ".p12", ".pfx"})
ORDINARY_ARTIFACT_SUFFIXES: frozenset[str] = frozenset({".log", ".zip", ".par"})
CLASS_TOKEN_RE = re.compile(
    r"^(?:ctx|fam|locator)=[a-z0-9_]{1,63}$|"
    r"^assoc=(?:example_fixture_path|example_naming|general_path)__"
    r"(?:env_name|credential_json_name|runtime_state_name|key_material_suffix|"
    r"ordinary_artifact_suffix|deployment_dir_name|content_rule|unclassified)$"
)


@dataclass
class AuditFailure(Exception):
    """An intentionally non-sensitive, machine-readable failure reason."""

    reason: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"(?:http_[1-5][0-9]{2}|[a-z][a-z0-9_]{1,63})", self.reason):
            self.reason = "transport_error"
        Exception.__init__(self, self.reason)


@dataclass
class AuditSurface:
    name: str
    total: int = 0
    checked_no_finding: int = 0
    finding: int = 0
    not_verified: int = 0
    outside_verified_scope: int = 0
    pages_requested: int = 0
    pages_succeeded: int = 0
    requests_requested: int = 0
    requests_succeeded: int = 0
    collections_requested: int = 0
    collections_completed: int = 0
    collections_incomplete: int = 0
    finding_rules: Counter[str] = field(default_factory=Counter)
    finding_classes: Counter[str] = field(default_factory=Counter)
    reasons: Counter[str] = field(default_factory=Counter)
    outside_scope_reasons: Counter[str] = field(default_factory=Counter)

    def record(
        self,
        rules: Iterator[str] | list[str] | set[str] | tuple[str, ...] = (),
        *,
        classes: Iterable[str] = (),
    ) -> None:
        self.total += 1
        unique = set(rules)
        if unique:
            self.finding += 1
            self.finding_rules.update(unique)
            safe_classes = sorted(token for token in classes if CLASS_TOKEN_RE.fullmatch(str(token)))
            self.finding_classes["|".join(safe_classes) or "unclassified"] += 1
        else:
            self.checked_no_finding += 1

    def record_not_verified(self, reason: str) -> None:
        safe_reason = reason if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[a-z][a-z0-9_]{1,63})", reason) else "unknown_gap"
        self.total += 1
        self.not_verified += 1
        self.reasons[safe_reason] += 1

    def record_outside_verified_scope(self, reason: str) -> None:
        """Record material that verified traversal does not cover at all.

        This is neither clean nor merely unverifiable-this-run: the audit never
        traverses it, so it must never contribute to a clean-coverage claim.
        """
        safe_reason = reason if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[a-z][a-z0-9_]{1,63})", reason) else "unknown_gap"
        self.total += 1
        self.outside_verified_scope += 1
        self.outside_scope_reasons[safe_reason] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "partition": {
                STATUS_CLEAN: self.checked_no_finding,
                STATUS_FINDING: self.finding,
                STATUS_NOT_VERIFIED: self.not_verified,
                STATUS_OUTSIDE_VERIFIED_SCOPE: self.outside_verified_scope,
            },
            "partition_valid": (
                self.total
                == self.checked_no_finding + self.finding + self.not_verified + self.outside_verified_scope
            ),
            "pages": {"requested": self.pages_requested, "succeeded": self.pages_succeeded},
            "requests": {"requested": self.requests_requested, "succeeded": self.requests_succeeded},
            "collections": {
                "requested": self.collections_requested,
                "completed": self.collections_completed,
                "incomplete": self.collections_incomplete,
            },
            "finding_rules": dict(sorted(self.finding_rules.items())),
            "finding_classes": dict(sorted(self.finding_classes.items())),
            "not_verified_reasons": dict(sorted(self.reasons.items())),
            "outside_verified_scope_reasons": dict(sorted(self.outside_scope_reasons.items())),
        }


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class ReadOnlyTransport:
    """HTTPS GET transport with bounded reads and credential-safe redirects."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout
        self.opener = build_opener(_SafeRedirectHandler())

    def get(self, url: str, headers: dict[str, str], limit: int) -> HttpResponse:
        request = Request(url, headers=headers, method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise AuditFailure("response_size_limit")
                return HttpResponse(
                    int(response.status),
                    {key.lower(): value for key, value in response.headers.items()},
                    body,
                )
        except HTTPError as exc:
            raise AuditFailure(f"http_{exc.code}") from None
        except AuditFailure:
            raise
        except (URLError, TimeoutError, OSError):
            raise AuditFailure("transport_error") from None


class _SafeRedirectHandler(HTTPRedirectHandler):
    _allowed_hosts: ClassVar[frozenset[str]] = frozenset(
        {"api.github.com", "github.com", "githubusercontent.com", "githubassets.com"}
    )

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        old = urlsplit(req.full_url)
        new = urlsplit(newurl)
        host = (new.hostname or "").lower()
        try:
            port = new.port
        except ValueError:
            raise AuditFailure("unsafe_redirect") from None
        allowed = host in self._allowed_hosts or host.endswith(
            (".githubusercontent.com", ".githubassets.com")
        )
        if new.scheme != "https" or not allowed or new.username or new.password or port not in (None, 443):
            raise AuditFailure("unsafe_redirect")
        same_host = (old.hostname or "").lower() == host
        copied = {key: value for key, value in req.header_items() if key.lower() != "authorization"}
        if same_host:
            authorization = req.get_header("Authorization")
            if authorization:
                copied["Authorization"] = authorization
        return Request(newurl, headers=copied, method="GET")


class GitHubClient:
    def __init__(
        self,
        repository: str,
        token: str | None = None,
        transport: Any | None = None,
    ) -> None:
        if not REPOSITORY_RE.fullmatch(repository):
            raise AuditFailure("invalid_repository")
        self.repository = repository
        self.repo_path = f"/repos/{repository}"
        self.token = token
        self.transport = transport or ReadOnlyTransport()

    def api_url(self, suffix: str) -> str:
        return f"https://{API_HOST}{self.repo_path}{suffix}"

    def _validated_url(self, url: str, *, allow_attachment: bool = False) -> bool:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            raise AuditFailure("unsafe_url") from None
        if parsed.scheme != "https" or parsed.username or parsed.password or port not in (None, 443):
            raise AuditFailure("unsafe_url")
        if host == API_HOST and parsed.path.startswith(self.repo_path + "/"):
            return True
        if (
            allow_attachment
            and host == "github.com"
            and parsed.path.startswith(ATTACHMENT_PATH_PREFIXES)
        ):
            return False
        raise AuditFailure("unsafe_url")

    def _get(
        self,
        url: str,
        surface: AuditSurface,
        *,
        accept: str,
        limit: int,
        allow_attachment: bool = False,
    ) -> HttpResponse:
        is_api = self._validated_url(url, allow_attachment=allow_attachment)
        headers = {"Accept": accept, "User-Agent": "read-only-exposure-audit"}
        if is_api and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        surface.requests_requested += 1
        try:
            response = self.transport.get(url, headers, limit)
        except AuditFailure:
            raise
        except Exception:  # noqa: BLE001 -- suppress transport detail that may contain secrets.
            raise AuditFailure("transport_error") from None
        if response.status != 200:
            raise AuditFailure(f"http_{response.status}")
        surface.requests_succeeded += 1
        return response

    def get_json(self, url: str, surface: AuditSurface) -> Any:
        response = self._get(
            url,
            surface,
            accept="application/vnd.github+json",
            limit=JSON_LIMIT,
        )
        try:
            return json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise AuditFailure("invalid_json") from None

    def get_download(
        self,
        url: str,
        surface: AuditSurface,
        *,
        allow_attachment: bool = False,
    ) -> HttpResponse:
        return self._get(
            url,
            surface,
            accept="application/octet-stream",
            limit=DOWNLOAD_LIMIT,
            allow_attachment=allow_attachment,
        )

    @staticmethod
    def _header(headers: dict[str, str], name: str) -> str:
        return next((value for key, value in headers.items() if key.lower() == name.lower()), "")

    def _next_link(self, url: str, headers: dict[str, str]) -> str | None:
        link = self._header(headers, "link")
        for match in re.finditer(r"<([^>]+)>\s*;\s*rel=\"?next\"?", link, re.IGNORECASE):
            candidate = urljoin(url, match.group(1))
            self._validated_url(candidate)
            return candidate
        return None

    def pages(
        self,
        url: str,
        surface: AuditSurface,
        *,
        items_key: str | None = None,
    ) -> Iterator[list[Any]]:
        surface.collections_requested += 1
        seen: set[str] = set()
        current = url
        try:
            while current:
                if current in seen:
                    raise AuditFailure("pagination_loop")
                seen.add(current)
                surface.pages_requested += 1
                response = self._get(
                    current,
                    surface,
                    accept="application/vnd.github+json",
                    limit=JSON_LIMIT,
                )
                surface.pages_succeeded += 1
                try:
                    payload = json.loads(response.body)
                except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                    raise AuditFailure("invalid_json") from None
                if isinstance(payload, list):
                    items = payload
                elif items_key and isinstance(payload, dict) and isinstance(payload.get(items_key), list):
                    items = payload[items_key]
                else:
                    raise AuditFailure("invalid_response")
                yield items
                current = self._next_link(current, response.headers)
            surface.collections_completed += 1
        except AuditFailure as exc:
            surface.collections_incomplete += 1
            surface.record_not_verified(exc.reason)


REF_SNAPSHOT_FORMAT = "%(objectname) %(refname)"


def _git_stdout(root: Path, *arguments: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            },
        )
    except Exception:  # noqa: BLE001 -- git diagnostics may contain raw paths.
        return None
    return result.stdout if result.returncode == 0 else None


def snapshot_git_identity(root: Path) -> dict[str, Any]:
    """Deterministic repository-identity snapshot for report/gate binding.

    Only identity digests are produced: the HEAD OID and the sha256 over the
    sorted advertised-ref snapshot. Repository paths are never included. The
    audit embeds this snapshot in the report and the gate recomputes it on
    its own --root so a report from another repository or an older HEAD
    cannot satisfy the current decision.
    """
    head_result = _git_stdout(root, "rev-parse", "HEAD")
    refs_result = _git_stdout(root, "for-each-ref", "--format=" + REF_SNAPSHOT_FORMAT)
    head_oid = head_result.decode("ascii", errors="ignore").strip() if head_result is not None else ""
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head_oid):
        head_oid = ""
    ref_lines: list[str] = []
    refs_available = refs_result is not None
    if refs_available:
        for line in refs_result.decode("utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped:
                ref_lines.append(stripped)
    digest = hashlib.sha256("\n".join(sorted(ref_lines)).encode("utf-8")).hexdigest()
    return {
        "head_oid": head_oid or None,
        "ref_digest_sha256": digest if refs_available else None,
        "ref_count": len(ref_lines) if refs_available else None,
        "binding_status": "bound" if head_oid and refs_available else "unavailable",
    }


def _github_token() -> str | None:
    """Read the active gh credential without ever printing or persisting it."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _path_rules(path: str) -> set[str]:
    category = sensitive_path(path)
    return {category} if category else set()


def _text_rules(text: str) -> set[str]:
    rules = set(scan_text(text))
    for match in SENSITIVE_PATH_TOKEN_RE.finditer(text):
        if category := sensitive_path(match.group(0).rstrip(".,!?")):
            rules.add(category)
    return rules


def _name_segments(value: str) -> list[str]:
    return [segment for segment in value.lower().split("/") if segment]


def _name_suffix(basename: str) -> str:
    dot = basename.rfind(".")
    return basename[dot:] if dot > 0 else ""


def _context_classes(path: str) -> set[str]:
    """Constant context tokens for a path; segments outside the vocabulary are dropped."""
    segments = _name_segments(path)
    if not segments:
        return set()
    classes: set[str] = set()
    if any(segment in BENIGN_PATH_SEGMENTS for segment in segments[:-1]):
        classes.add("ctx=example_fixture_path")
    if segments[-1].endswith(EXAMPLE_NAME_SUFFIXES):
        classes.add("ctx=example_naming")
    if not classes:
        classes.add("ctx=general_path")
    return classes


def _family_classes(name: str) -> set[str]:
    """Coarse name-pattern families from fixed suffix/name vocabularies only."""
    segments = _name_segments(name)
    basename = segments[-1] if segments else ""
    classes: set[str] = set()
    if basename == ".env" or basename.startswith(".env."):
        classes.add("fam=env_name")
    if basename in CREDENTIAL_JSON_NAMES:
        classes.add("fam=credential_json_name")
    if basename in RUNTIME_STATE_NAMES:
        classes.add("fam=runtime_state_name")
    suffix = _name_suffix(basename)
    if suffix in KEY_MATERIAL_SUFFIXES:
        classes.add("fam=key_material_suffix")
    elif suffix in ORDINARY_ARTIFACT_SUFFIXES:
        classes.add("fam=ordinary_artifact_suffix")
    return classes


def _deployment_classes(path: str) -> set[str]:
    segments = _name_segments(path)
    if any(segment in SENSITIVE_DIRS for segment in segments[:-1]):
        return {"fam=deployment_dir_name"}
    return set()


def _association_classes(contexts: Iterable[str], families: Iterable[str]) -> set[str]:
    """Preserve context/family pairs without retaining the matched path or value."""
    associations: set[str] = set()
    for context in contexts:
        if not context.startswith("ctx="):
            continue
        for family in families:
            if not family.startswith("fam="):
                continue
            token = f"assoc={context[4:]}__{family[4:]}"
            if CLASS_TOKEN_RE.fullmatch(token):
                associations.add(token)
    return associations


def _path_classes(path: str, *, context_path: str | None = None) -> set[str]:
    contexts = _context_classes(context_path if context_path is not None and "/" not in path else path)
    families = _family_classes(path) | _deployment_classes(path)
    return contexts | families | _association_classes(contexts, families)


def _text_classes(text: str, *, context_path: str | None = None) -> set[str]:
    """Classify matched tokens, using the source path for bare-name context."""
    classes: set[str] = set()
    if scan_text(text):
        classes.add("fam=content_rule")
    for match in SENSITIVE_PATH_TOKEN_RE.finditer(text):
        token = match.group(0).rstrip(".,!?")
        classes.update(_path_classes(token, context_path=context_path))
    return classes


def _finding_classes(
    locator: str,
    *,
    path: str | None = None,
    text: str | None = None,
    extra: Iterable[str] = (),
) -> set[str]:
    classes: set[str] = {f"locator={locator}"}
    if path is not None:
        classes.update(_path_classes(path))
    if text is not None:
        text_classes = _text_classes(text, context_path=path)
        classes.update(text_classes)
        if path is not None and "fam=content_rule" in text_classes:
            classes.update(_association_classes(_context_classes(path), {"fam=content_rule"}))
    classes.update(extra)
    if not any(token.startswith("fam=") for token in classes):
        classes.add("fam=unclassified")
    return classes


def _extract_urls(text: str) -> set[str]:
    return {
        match.group(0).rstrip(".,;:!?)]")
        for match in URL_RE.finditer(text)
        if match.group(0).rstrip(".,;:!?)]")
    }


def _scan_value(value: Any, key: str = "") -> tuple[set[str], set[str], set[str]]:
    rules: set[str] = set()
    urls: set[str] = set()
    classes: set[str] = set()
    if isinstance(value, str):
        rules.update(_text_rules(value))
        if rules:
            classes.update(_text_classes(value))
        if key.lower() in {"path", "filename", "file_name", "filepath", "file_path"}:
            path_rules = _path_rules(value)
            rules.update(path_rules)
            if path_rules:
                classes.update(_path_classes(value))
        urls.update(_extract_urls(value))
    elif isinstance(value, dict):
        for child_key, child in value.items():
            rules_child, urls_child, classes_child = _scan_value(child, str(child_key))
            rules.update(rules_child)
            urls.update(urls_child)
            classes.update(classes_child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            rules_child, urls_child, classes_child = _scan_value(child, key)
            rules.update(rules_child)
            urls.update(urls_child)
            classes.update(classes_child)
    return rules, urls, classes


class ExternalReferenceTracker:
    def __init__(self, surface: AuditSurface) -> None:
        self.surface = surface
        self.attachment_urls: set[str] = set()
        self._seen_attachment_urls: set[str] = set()
        self._seen_external_hashes: set[str] = set()

    def discover(self, urls: set[str]) -> None:
        for url in urls:
            try:
                parsed = urlsplit(url)
                host = (parsed.hostname or "").lower()
            except ValueError:
                host = ""
                parsed = None
            if (
                parsed is not None
                and parsed.scheme.lower() == "https"
                and host == "github.com"
                and parsed.path.startswith(ATTACHMENT_PATH_PREFIXES)
            ):
                if url not in self._seen_attachment_urls:
                    self._seen_attachment_urls.add(url)
                    self.attachment_urls.add(url)
                continue
            if host in {"github.com", "api.github.com"}:
                continue
            digest = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()
            if digest not in self._seen_external_hashes:
                self._seen_external_hashes.add(digest)
                self.surface.record_not_verified("external_reference_not_fetched")

    def pop_attachment(self) -> str | None:
        if not self.attachment_urls:
            return None
        url = min(self.attachment_urls)
        self.attachment_urls.remove(url)
        return url

    def mark_attachments_not_requested(self) -> None:
        for _ in self.attachment_urls:
            self.surface.record_not_verified("attachment_not_fetched")
        self.attachment_urls.clear()


def _zip_scan(data: bytes) -> tuple[set[str], set[str], set[str], set[str]]:
    rules: set[str] = set()
    reasons: set[str] = set()
    urls: set[str] = set()
    classes: set[str] = set()
    total_size = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001 -- malformed archives must only create a safe gap.
        return rules, {"invalid_archive"}, urls, classes
    with archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if len(members) > ARCHIVE_MEMBER_LIMIT:
            reasons.add("archive_member_limit")
        for item in members[:ARCHIVE_MEMBER_LIMIT]:
            member_path_rules = _path_rules(item.filename)
            rules.update(member_path_rules)
            if member_path_rules:
                classes.update(_path_classes(item.filename))
            if item.file_size > ARCHIVE_FILE_LIMIT:
                reasons.add("archive_member_size_limit")
                continue
            total_size += item.file_size
            if total_size > ARCHIVE_TOTAL_LIMIT:
                reasons.add("archive_total_size_limit")
                break
            try:
                with archive.open(item) as member:
                    content = member.read(ARCHIVE_FILE_LIMIT + 1)
            except Exception:  # noqa: BLE001 -- suppress archive metadata and member names.
                reasons.add("archive_read_failure")
                continue
            if len(content) > ARCHIVE_FILE_LIMIT:
                reasons.add("archive_member_size_limit")
                continue
            decoded = content.decode("utf-8", errors="replace")
            content_rules = _text_rules(decoded)
            rules.update(content_rules)
            if content_rules:
                classes.update(_text_classes(decoded))
            urls.update(_extract_urls(decoded))
            if b"\0" in content and not _text_rules(decoded):
                reasons.add("binary_content")
    return rules, reasons, urls, classes


def _scan_download(data: bytes, content_type: str) -> tuple[set[str], set[str], set[str], set[str]]:
    if data.startswith(b"PK\x03\x04") or "zip" in content_type.lower():
        return _zip_scan(data)
    decoded = data.decode("utf-8", errors="replace")
    rules = _text_rules(decoded)
    classes = _text_classes(decoded) if rules else set()
    urls = _extract_urls(decoded)
    if b"\0" in data and not rules:
        return rules, {"binary_content"}, urls, classes
    if content_type.lower().startswith(("image/", "audio/", "video/")) and not rules:
        return rules, {"unsupported_attachment_media"}, urls, classes
    return rules, set(), urls, classes


class GitHistoryAuditor:
    def __init__(
        self,
        root: Path,
        surface: AuditSurface,
        external_references: ExternalReferenceTracker,
        boundary_surface: AuditSurface | None = None,
    ) -> None:
        self.root = root
        self.surface = surface
        self.external_references = external_references
        self.boundary_surface = boundary_surface
        self.ref_count = 0
        self.commit_count = 0
        self.blob_path_count = 0
        self.dangling_object_count = 0
        self.unreachable_object_count = 0
        self.shallow: bool | None = None

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[bytes] | None:
        try:
            return subprocess.run(
                ["git", "-C", str(self.root), *arguments],
                check=False,
                capture_output=True,
                env={
                    **os.environ,
                    "GIT_NO_LAZY_FETCH": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
            )
        except Exception:  # noqa: BLE001 -- git diagnostics may contain raw paths or object data.
            return None

    def scan(self) -> None:
        self._scan_object_store_boundary()
        shallow_result = self._git("rev-parse", "--is-shallow-repository")
        if shallow_result is None or shallow_result.returncode != 0:
            self.surface.record_not_verified("git_probe_failed")
        else:
            self.shallow = shallow_result.stdout.strip() == b"true"
            if self.shallow:
                self.surface.record_not_verified("shallow_history_boundary")

        refs_result = self._git("for-each-ref", "--format=%(objectname) %(objecttype) %(refname)")
        if refs_result is None or refs_result.returncode != 0:
            self.surface.record_not_verified("git_refs_unavailable")
            return
        refs = [line.split(b" ", 2) for line in refs_result.stdout.splitlines() if line.strip()]
        self.ref_count = len(refs)
        if not refs:
            self.surface.record_not_verified("no_git_refs")

        seen_trees: set[str] = set()
        seen_blob_paths: set[tuple[str, str]] = set()
        blob_sizes: dict[str, int] = {}
        seen_tags: set[str] = set()
        for ref in refs:
            if len(ref) != 3:
                self.surface.record_not_verified("invalid_ref")
                continue
            oid = ref[0].decode("ascii", errors="ignore")
            object_type = ref[1].decode("ascii", errors="ignore")
            ref_name = ref[2].decode("utf-8", errors="surrogateescape")
            if not re.fullmatch(r"[0-9a-fA-F]{40,64}", oid):
                self.surface.record_not_verified("invalid_ref")
                continue
            ref_rules = _text_rules(ref_name)
            self.surface.record(
                ref_rules,
                classes=_finding_classes("git_ref_name", text=ref_name) if ref_rules else (),
            )
            self.external_references.discover(_extract_urls(ref_name))
            if object_type == "tag":
                self._scan_tag(oid, seen_tags, seen_trees, seen_blob_paths, blob_sizes)
            elif object_type == "tree":
                self._scan_tree(oid, seen_trees, seen_blob_paths, blob_sizes)
            elif object_type == "blob":
                self._scan_blob(oid, "", seen_blob_paths, blob_sizes)
            elif object_type != "commit":
                self.surface.record_not_verified("unknown_ref_target")

        commits_result = self._git("rev-list", "--all", "HEAD", "--missing=print")
        if commits_result is None or commits_result.returncode != 0:
            self.surface.record_not_verified("git_history_unavailable")
            return
        commits: list[str] = []
        for line in commits_result.stdout.splitlines():
            oid = line.split(b" ", 1)[0].decode("ascii", errors="ignore")
            if not oid:
                continue
            if oid.startswith("?"):
                self.surface.record_not_verified("missing_git_object")
                continue
            if re.fullmatch(r"[0-9a-fA-F]{40,64}", oid):
                commits.append(oid)
        for commit in commits:
            self._scan_commit(commit, seen_trees, seen_blob_paths, blob_sizes)

    def _scan_object_store_boundary(self) -> None:
        """Type unreachable/dangling local objects as OUTSIDE_VERIFIED_SCOPE.

        Verified traversal follows advertised refs and their reachable commits.
        Objects present in the local object store but not reachable from any
        advertised ref are never inspected; recording them here keeps that
        boundary explicit instead of letting a clean traversal imply a clean
        object store. Object identifiers are counted, never reported.

        A default ``git fsck`` treats reflog entries as reachability roots, so
        a commit discarded by a branch reset would be missing from the
        boundary census. A second ``fsck --unreachable --no-reflogs`` pass
        classifies every object that only the reflog (or nothing at all)
        still references.
        """
        if self.boundary_surface is None:
            return
        result = self._git("fsck", "--dangling", "--no-progress")
        if result is None or result.returncode != 0:
            self.boundary_surface.record_not_verified("git_fsck_failed")
            return
        counted: set[str] = set()
        for line in result.stdout.splitlines():
            match = re.match(rb"^dangling (?:blob|tree|commit|tag) ([0-9a-fA-F]{40,64})$", line.strip())
            if match:
                counted.add(match.group(1).decode("ascii").lower())
                self.dangling_object_count += 1
                self.boundary_surface.record_outside_verified_scope("dangling_object_not_traversed")
        unreachable = self._git("fsck", "--unreachable", "--no-reflogs", "--no-progress")
        if unreachable is None or unreachable.returncode != 0:
            self.boundary_surface.record_not_verified("git_fsck_no_reflogs_failed")
            return
        for line in unreachable.stdout.splitlines():
            match = re.match(rb"^unreachable (?:blob|tree|commit|tag) ([0-9a-fA-F]{40,64})$", line.strip())
            if not match:
                continue
            oid = match.group(1).decode("ascii").lower()
            if oid in counted:
                continue
            counted.add(oid)
            self.unreachable_object_count += 1
            self.boundary_surface.record_outside_verified_scope("unreachable_history_not_traversed")

    def _scan_tag(
        self,
        tag_oid: str,
        seen_tags: set[str],
        seen_trees: set[str],
        seen_blob_paths: set[tuple[str, str]],
        blob_sizes: dict[str, int],
    ) -> None:
        current = tag_oid
        for _ in range(8):
            if current in seen_tags:
                return
            seen_tags.add(current)
            result = self._git("cat-file", "-p", current)
            if result is None or result.returncode != 0:
                self.surface.record_not_verified("missing_git_object")
                return
            tag_text = result.stdout.decode("utf-8", errors="replace")
            tag_rules = _text_rules(tag_text)
            self.surface.record(
                tag_rules,
                classes=_finding_classes("git_object_text", text=tag_text) if tag_rules else (),
            )
            self.external_references.discover(_extract_urls(tag_text))
            object_match = re.search(r"(?m)^object ([0-9a-fA-F]{40,64})$", tag_text)
            type_match = re.search(r"(?m)^type (commit|tree|blob|tag)$", tag_text)
            if not object_match or not type_match:
                self.surface.record_not_verified("invalid_tag_object")
                return
            target = object_match.group(1)
            object_type = type_match.group(1)
            if object_type == "tag":
                current = target
            elif object_type == "tree":
                self._scan_tree(target, seen_trees, seen_blob_paths, blob_sizes)
                return
            elif object_type == "blob":
                self._scan_blob(target, "", seen_blob_paths, blob_sizes)
                return
            else:
                return
        self.surface.record_not_verified("tag_nesting_limit")

    def _scan_commit(
        self,
        commit: str,
        seen_trees: set[str],
        seen_blob_paths: set[tuple[str, str]],
        blob_sizes: dict[str, int],
    ) -> None:
        commit_result = self._git("cat-file", "-p", commit)
        if commit_result is None or commit_result.returncode != 0:
            self.surface.record_not_verified("missing_git_object")
            return
        commit_text = commit_result.stdout.decode("utf-8", errors="replace")
        commit_rules = _text_rules(commit_text)
        self.surface.record(
            commit_rules,
            classes=_finding_classes("git_object_text", text=commit_text) if commit_rules else (),
        )
        self.external_references.discover(_extract_urls(commit_text))
        self.commit_count += 1
        tree_match = re.search(r"(?m)^tree ([0-9a-fA-F]{40,64})$", commit_text)
        if not tree_match:
            self.surface.record_not_verified("invalid_commit_object")
            return
        self._scan_tree(tree_match.group(1), seen_trees, seen_blob_paths, blob_sizes)

    def _scan_tree(
        self,
        tree: str,
        seen_trees: set[str],
        seen_blob_paths: set[tuple[str, str]],
        blob_sizes: dict[str, int],
    ) -> None:
        if tree in seen_trees:
            return
        seen_trees.add(tree)
        tree_result = self._git("ls-tree", "-r", "-z", "--full-tree", tree)
        if tree_result is None or tree_result.returncode != 0:
            self.surface.record_not_verified("missing_git_object")
            return
        for entry in tree_result.stdout.split(b"\0"):
            if not entry:
                continue
            try:
                metadata, raw_path = entry.split(b"\t", 1)
                _mode, object_type, raw_oid = metadata.decode("ascii").split(" ", 2)
                path = raw_path.decode("utf-8", errors="surrogateescape")
            except (ValueError, UnicodeDecodeError):
                self.surface.record_not_verified("invalid_tree_entry")
                continue
            if object_type == "commit":
                if path_rules := _path_rules(path):
                    self.surface.record(path_rules, classes=_finding_classes("git_tree_path", path=path))
                self.surface.record_not_verified("external_submodule_boundary")
                continue
            if object_type != "blob":
                self.surface.record_not_verified("unknown_git_object_type")
                continue
            self._scan_blob(raw_oid, path, seen_blob_paths, blob_sizes)

    def _scan_blob(
        self,
        oid: str,
        path: str,
        seen_blob_paths: set[tuple[str, str]],
        blob_sizes: dict[str, int],
    ) -> None:
        key = (oid, path)
        if key in seen_blob_paths:
            return
        seen_blob_paths.add(key)
        self.blob_path_count += 1
        path_rules = _path_rules(path)
        if oid not in blob_sizes:
            size_result = self._git("cat-file", "-s", oid)
            if size_result is None or size_result.returncode != 0:
                if path_rules:
                    self.surface.record(path_rules, classes=_finding_classes("git_blob_path", path=path))
                self.surface.record_not_verified("missing_git_object")
                return
            try:
                blob_sizes[oid] = int(size_result.stdout.strip())
            except ValueError:
                if path_rules:
                    self.surface.record(path_rules, classes=_finding_classes("git_blob_path", path=path))
                self.surface.record_not_verified("invalid_blob_size")
                return
        if blob_sizes[oid] > GIT_BLOB_LIMIT:
            if path_rules:
                self.surface.record(path_rules, classes=_finding_classes("git_blob_path", path=path))
            self.surface.record_not_verified("git_blob_size_limit")
            return
        blob_result = self._git("cat-file", "blob", oid)
        if blob_result is None or blob_result.returncode != 0:
            if path_rules:
                self.surface.record(path_rules, classes=_finding_classes("git_blob_path", path=path))
            self.surface.record_not_verified("missing_git_object")
            return
        content = blob_result.stdout
        text = content.decode("utf-8", errors="replace")
        self.external_references.discover(_extract_urls(text))
        rules = path_rules | _text_rules(text)
        is_binary = b"\0" in content
        if is_binary:
            self.surface.record_not_verified("binary_content")
        if rules:
            self.surface.record(
                rules,
                classes=_finding_classes("git_blob_content", path=path, text=text),
            )
        elif not is_binary:
            self.surface.record()


def _http_status_reason(failure: AuditFailure) -> str:
    return failure.reason


class GitHubAuditor:
    def __init__(
        self,
        client: GitHubClient,
        surfaces: dict[str, AuditSurface],
        external_references: ExternalReferenceTracker,
    ) -> None:
        self.client = client
        self.surfaces = surfaces
        self.external_references = external_references
        self.remote_ref_count = 0
        self.remote_commit_count = 0
        self._blob_cache: dict[str, bytes] = {}
        self._tree_cache: dict[str, list[dict[str, Any]]] = {}

    def _record_json(self, surface_name: str, payload: Any) -> None:
        rules, urls, classes = _scan_value(payload)
        self.surfaces[surface_name].record(
            rules,
            classes=_finding_classes("github_record", extra=classes) if rules else (),
        )
        self.external_references.discover(urls)

    def _details(self, surface: AuditSurface, url: str) -> Any | None:
        try:
            return self.client.get_json(url, surface)
        except AuditFailure as exc:
            surface.record_not_verified(_http_status_reason(exc))
            return None

    def _collect(self, surface: AuditSurface, url: str, items_key: str | None = None) -> list[Any]:
        items: list[Any] = []
        for page in self.client.pages(url, surface, items_key=items_key):
            items.extend(page)
        return items

    def scan_remote_refs_and_history(self) -> None:
        refs_surface = self.surfaces["github_refs"]
        history_surface = self.surfaces["github_history"]
        ref_records: list[dict[str, Any]] = []
        url = self.client.api_url("/git/matching-refs/?per_page=100")
        records = self._collect(refs_surface, url)
        for record in records:
            if isinstance(record, dict):
                self._record_json("github_refs", record)
                ref_records.append(record)
            else:
                refs_surface.record_not_verified("invalid_item")
        self.remote_ref_count = len(ref_records)
        commit_queue: deque[str] = deque()
        for ref in ref_records:
            obj = ref.get("object") or {}
            sha = obj.get("sha") if isinstance(obj, dict) else None
            object_type = obj.get("type") if isinstance(obj, dict) else None
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
                history_surface.record_not_verified("unresolvable_ref")
            elif object_type == "commit":
                commit_queue.append(sha)
            elif object_type == "tag":
                tag_commit = self._resolve_tag(sha, history_surface)
                if tag_commit:
                    commit_queue.append(tag_commit)
            elif object_type == "tree":
                self._scan_remote_tree(sha, history_surface)
            elif object_type == "blob":
                self._scan_remote_blob(sha, "", history_surface)
            else:
                history_surface.record_not_verified("non_commit_ref")

        seen_commits: set[str] = set()
        while commit_queue:
            sha = commit_queue.popleft()
            if sha in seen_commits:
                continue
            seen_commits.add(sha)
            requests_succeeded = history_surface.requests_succeeded
            commit = self._details(history_surface, self.client.api_url(f"/git/commits/{sha}"))
            if not isinstance(commit, dict):
                if history_surface.requests_succeeded > requests_succeeded:
                    history_surface.record_not_verified("invalid_commit_object")
                continue
            self.remote_commit_count += 1
            self._record_json("github_history", commit)
            tree = commit.get("tree")
            tree_sha = tree.get("sha") if isinstance(tree, dict) else None
            if not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", tree_sha):
                history_surface.record_not_verified("invalid_commit_object")
            else:
                self._scan_remote_tree(tree_sha, history_surface)
            parents = commit.get("parents", [])
            if isinstance(parents, list):
                for parent in parents:
                    parent_sha = parent.get("sha") if isinstance(parent, dict) else None
                    if isinstance(parent_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", parent_sha):
                        commit_queue.append(parent_sha)
                    else:
                        history_surface.record_not_verified("invalid_parent_commit")
            else:
                history_surface.record_not_verified("invalid_parent_commit")

    def _resolve_tag(self, sha: str, surface: AuditSurface) -> str | None:
        current = sha
        for _ in range(8):
            requests_succeeded = surface.requests_succeeded
            tag = self._details(surface, self.client.api_url(f"/git/tags/{current}"))
            if not isinstance(tag, dict):
                if surface.requests_succeeded > requests_succeeded:
                    surface.record_not_verified("invalid_tag_object")
                return None
            self._record_json("github_history", tag)
            obj = tag.get("object") or {}
            next_sha = obj.get("sha") if isinstance(obj, dict) else None
            object_type = obj.get("type") if isinstance(obj, dict) else None
            if object_type == "commit" and isinstance(next_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", next_sha):
                return next_sha
            if object_type == "tree" and isinstance(next_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", next_sha):
                self._scan_remote_tree(next_sha, surface)
                return None
            if object_type == "blob" and isinstance(next_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", next_sha):
                self._scan_remote_blob(next_sha, "", surface)
                return None
            if (
                object_type != "tag"
                or not isinstance(next_sha, str)
                or not re.fullmatch(r"[0-9a-fA-F]{40,64}", next_sha)
            ):
                surface.record_not_verified("unresolvable_tag")
                return None
            current = next_sha
        surface.record_not_verified("tag_nesting_limit")
        return None

    def _scan_remote_tree(self, root_sha: str, surface: AuditSurface) -> None:
        pending: deque[tuple[str, str]] = deque([(root_sha, "")])
        visited: set[tuple[str, str]] = set()
        while pending:
            tree_sha, prefix = pending.popleft()
            key = (tree_sha, prefix)
            if key in visited:
                continue
            visited.add(key)
            entries = self._tree_cache.get(tree_sha)
            if entries is None:
                requests_succeeded = surface.requests_succeeded
                payload = self._details(surface, self.client.api_url(f"/git/trees/{tree_sha}"))
                if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
                    if surface.requests_succeeded > requests_succeeded:
                        surface.record_not_verified("invalid_tree_object")
                    continue
                entries = payload["tree"]
                self._record_json("github_history", payload)
                self._tree_cache[tree_sha] = entries
                if payload.get("truncated") is True:
                    surface.record_not_verified("truncated_tree")
            for entry in entries:
                if not isinstance(entry, dict):
                    surface.record_not_verified("invalid_tree_entry")
                    continue
                name = entry.get("path")
                sha = entry.get("sha")
                kind = entry.get("type")
                if (
                    not isinstance(name, str)
                    or not isinstance(sha, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha)
                ):
                    surface.record_not_verified("invalid_tree_entry")
                    continue
                path = f"{prefix}/{name}" if prefix else name
                if kind == "tree":
                    pending.append((sha, path))
                elif kind == "blob":
                    self._scan_remote_blob(sha, path, surface)
                elif kind == "commit":
                    surface.record_not_verified("external_submodule_boundary")
                else:
                    surface.record_not_verified("unknown_git_object_type")

    def _scan_remote_blob(self, sha: str, path: str, surface: AuditSurface) -> None:
        path_rules = _path_rules(path)
        content = self._blob_cache.get(sha)
        if content is None:
            try:
                payload = self.client.get_json(self.client.api_url(f"/git/blobs/{sha}"), surface)
            except AuditFailure as exc:
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified(exc.reason)
                return
            if (
                not isinstance(payload, dict)
                or payload.get("encoding") != "base64"
                or not isinstance(payload.get("content"), str)
            ):
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified("blob_content_unavailable")
                return
            reported_size = payload.get("size")
            if not isinstance(reported_size, int) or isinstance(reported_size, bool) or reported_size < 0:
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified("blob_size_unavailable")
                return
            if reported_size > GIT_BLOB_LIMIT:
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified("git_blob_size_limit")
                return
            try:
                content = base64.b64decode("".join(payload["content"].split()), validate=True)
            except (ValueError, binascii.Error):
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified("invalid_blob_content")
                return
            if len(content) != reported_size:
                if path_rules:
                    surface.record(path_rules, classes=_finding_classes("remote_blob_path", path=path))
                surface.record_not_verified("invalid_blob_content")
                return
            self._blob_cache[sha] = content
        text = content.decode("utf-8", errors="replace")
        self.external_references.discover(_extract_urls(text))
        rules = path_rules | _text_rules(text)
        is_binary = b"\0" in content
        if is_binary:
            surface.record_not_verified("binary_content")
        if rules:
            surface.record(
                rules,
                classes=_finding_classes("remote_blob_content", path=path, text=text),
            )
        elif not is_binary:
            surface.record()

    def scan_discussions_and_reviews(self) -> None:
        discussions = self.surfaces["github_discussions"]
        reviews = self.surfaces["github_reviews"]
        inline = self.surfaces["github_inline_comments"]
        issues = self._collect(discussions, self.client.api_url("/issues?state=all&per_page=100"))
        for issue in issues:
            if not isinstance(issue, dict):
                discussions.record_not_verified("invalid_item")
                continue
            self._record_json("github_discussions", issue)
            number = issue.get("number")
            if not isinstance(number, int) or number < 1:
                discussions.record_not_verified("invalid_item")
                continue
            comments_url = self.client.api_url(f"/issues/{number}/comments?per_page=100")
            for comment in self._collect(discussions, comments_url):
                if isinstance(comment, dict):
                    self._record_json("github_discussions", comment)
                else:
                    discussions.record_not_verified("invalid_item")
            if isinstance(issue.get("pull_request"), dict):
                review_url = self.client.api_url(f"/pulls/{number}/reviews?per_page=100")
                for review in self._collect(reviews, review_url):
                    if isinstance(review, dict):
                        self._record_json("github_reviews", review)
                    else:
                        reviews.record_not_verified("invalid_item")
                inline_url = self.client.api_url(f"/pulls/{number}/comments?per_page=100")
                for comment in self._collect(inline, inline_url):
                    if isinstance(comment, dict):
                        self._record_json("github_inline_comments", comment)
                    else:
                        inline.record_not_verified("invalid_item")

    def scan_actions(self) -> None:
        actions = self.surfaces["github_actions"]
        logs = self.surfaces["github_action_logs"]
        artifacts = self.surfaces["github_action_artifacts"]
        runs_url = self.client.api_url("/actions/runs?per_page=100")
        runs = self._collect(actions, runs_url, items_key="workflow_runs")
        for run in runs:
            if not isinstance(run, dict):
                actions.record_not_verified("invalid_item")
                continue
            self._record_json("github_actions", run)
            run_id = run.get("id")
            if not isinstance(run_id, int) or run_id < 1:
                actions.record_not_verified("invalid_item")
                continue
            jobs_url = self.client.api_url(f"/actions/runs/{run_id}/jobs?per_page=100")
            for job in self._collect(actions, jobs_url, items_key="jobs"):
                if isinstance(job, dict):
                    self._record_json("github_actions", job)
                else:
                    actions.record_not_verified("invalid_item")
            log_url = self.client.api_url(f"/actions/runs/{run_id}/logs")
            self._scan_download_url(log_url, logs)
            artifact_url = self.client.api_url(f"/actions/runs/{run_id}/artifacts?per_page=100")
            for artifact in self._collect(artifacts, artifact_url, items_key="artifacts"):
                if not isinstance(artifact, dict):
                    artifacts.record_not_verified("invalid_item")
                    continue
                self._record_json("github_action_artifacts", artifact)
                artifact_id = artifact.get("id")
                if not isinstance(artifact_id, int) or artifact_id < 1:
                    artifacts.record_not_verified("invalid_item")
                elif artifact.get("expired") is True:
                    artifacts.record_not_verified("artifact_expired")
                else:
                    self._scan_download_url(
                        self.client.api_url(f"/actions/artifacts/{artifact_id}/zip"),
                        artifacts,
                    )

    def scan_releases(self) -> None:
        releases = self.surfaces["github_releases"]
        assets_surface = self.surfaces["github_release_assets"]
        release_url = self.client.api_url("/releases?per_page=100")
        for release in self._collect(releases, release_url):
            if not isinstance(release, dict):
                releases.record_not_verified("invalid_item")
                continue
            self._record_json("github_releases", release)
            release_id = release.get("id")
            if not isinstance(release_id, int) or release_id < 1:
                assets_surface.record_not_verified("invalid_item")
                continue
            asset_url = self.client.api_url(f"/releases/{release_id}/assets?per_page=100")
            for asset in self._collect(assets_surface, asset_url):
                if not isinstance(asset, dict):
                    assets_surface.record_not_verified("invalid_item")
                    continue
                self._record_json("github_release_assets", asset)
                asset_id = asset.get("id")
                if not isinstance(asset_id, int) or asset_id < 1:
                    assets_surface.record_not_verified("invalid_item")
                else:
                    self._scan_download_url(
                        self.client.api_url(f"/releases/assets/{asset_id}"),
                        assets_surface,
                    )

    def _scan_download_url(self, url: str, surface: AuditSurface) -> None:
        try:
            response = self.client.get_download(url, surface)
        except AuditFailure as exc:
            surface.record_not_verified(exc.reason)
            return
        rules, reasons, urls, classes = _scan_download(response.body, response.headers.get("content-type", ""))
        self.external_references.discover(urls)
        if rules:
            surface.record(rules, classes=_finding_classes("download_content", extra=classes))
        elif not reasons:
            surface.record()
        for reason in sorted(reasons):
            surface.record_not_verified(reason)

    def scan_discovered_attachments(self) -> None:
        surface = self.surfaces["external_references"]
        while url := self.external_references.pop_attachment():
            try:
                response = self.client.get_download(url, surface, allow_attachment=True)
            except AuditFailure as exc:
                surface.record_not_verified(exc.reason)
                continue
            rules, reasons, urls, classes = _scan_download(response.body, response.headers.get("content-type", ""))
            self.external_references.discover(urls)
            if rules:
                surface.record(rules, classes=_finding_classes("attachment_content", extra=classes))
            elif not reasons:
                surface.record()
            for reason in sorted(reasons):
                surface.record_not_verified(reason)


def _new_surfaces() -> dict[str, AuditSurface]:
    return {name: AuditSurface(name) for name in SURFACE_NAMES}


def _report(
    surfaces: dict[str, AuditSurface],
    local: GitHistoryAuditor,
    *,
    repository_requested: bool,
    authenticated: bool,
    remote: GitHubAuditor | None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    partitions = Counter()
    finding_classes: Counter[str] = Counter()
    for surface in surfaces.values():
        partitions[STATUS_CLEAN] += surface.checked_no_finding
        partitions[STATUS_FINDING] += surface.finding
        partitions[STATUS_NOT_VERIFIED] += surface.not_verified
        partitions[STATUS_OUTSIDE_VERIFIED_SCOPE] += surface.outside_verified_scope
        finding_classes.update(surface.finding_classes)
    total = sum(partitions.values())
    if target is None:
        target = {
            "repository": None,
            "head_oid": None,
            "ref_digest_sha256": None,
            "ref_count": None,
            "binding_status": "unavailable",
        }
    return {
        "schema_version": 5,
        "audit_time_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "target": target,
        "scope": [
            "reachable commits and file versions from refs present in the selected local checkout",
            "unreachable/dangling local object-store items are typed OUTSIDE_VERIFIED_SCOPE and never inspected",
            "reflog-only objects are classified via a fsck --unreachable --no-reflogs pass and never inspected",
            "the report is bound to the audited repository slug, HEAD OID, and advertised-ref snapshot digest",
            "GitHub read endpoints for the explicitly selected repository and token-visible resources" if repository_requested else "GitHub surfaces were not requested",
            "arbitrary external links are not fetched; supported GitHub user-attachment links are attempted",
            "the fast current-tree check remains scripts/audit_public_tree.py and is separate",
        ],
        "authentication": "gh credential used (value suppressed)" if authenticated else "unauthenticated or unavailable",
        "reachability": {
            "local_ref_count": local.ref_count,
            "local_reachable_commit_count": local.commit_count,
            "local_blob_path_count": local.blob_path_count,
            "local_dangling_object_count": local.dangling_object_count,
            "local_unreachable_object_count": local.unreachable_object_count,
            "local_shallow": local.shallow,
            "github_ref_count": remote.remote_ref_count if remote else 0,
            "github_reachable_commit_count": remote.remote_commit_count if remote else 0,
        },
        "summary": {
            "total": total,
            "partition": dict(partitions),
            "finding_classes": dict(sorted(finding_classes.items())),
        },
        "sources": {name: surface.to_dict() for name, surface in surfaces.items()},
    }


def _markdown(report: dict[str, Any]) -> str:
    target = report.get("target") or {}
    lines = [
        "# Sanitized read-only exposure audit",
        "",
        f"Audit time (UTC): {report['audit_time_utc']}",
        "Read-only: yes",
        "",
        "## Report binding",
        "",
        f"- Binding status: {target.get('binding_status', 'unavailable')}",
        f"- Target repository: {target.get('repository') or 'unbound (local-only audit)'}",
        f"- Target HEAD: {target.get('head_oid') or 'unbound'}",
        f"- Advertised-ref snapshot digest (sha256): {target.get('ref_digest_sha256') or 'unbound'}",
        f"- Advertised-ref count: {target.get('ref_count') if target.get('ref_count') is not None else 'unbound'}",
        "",
        "Scope:",
    ]
    lines.extend(f"- {scope}" for scope in report["scope"])
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total inventory items: {report['summary']['total']}",
            f"- CHECKED_NO_FINDING: {report['summary']['partition'].get(STATUS_CLEAN, 0)}",
            f"- FINDING: {report['summary']['partition'].get(STATUS_FINDING, 0)}",
            f"- NOT_VERIFIED: {report['summary']['partition'].get(STATUS_NOT_VERIFIED, 0)}",
            f"- OUTSIDE_VERIFIED_SCOPE: {report['summary']['partition'].get(STATUS_OUTSIDE_VERIFIED_SCOPE, 0)}",
            "",
            "## Sources",
            "",
            "| Source | Total | CHECKED_NO_FINDING | FINDING | NOT_VERIFIED | OUTSIDE_VERIFIED_SCOPE | Pages (received/requested) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, source in report["sources"].items():
        partition = source["partition"]
        pages = source["pages"]
        lines.append(
            f"| {name} | {source['total']} | {partition[STATUS_CLEAN]} | "
            f"{partition[STATUS_FINDING]} | {partition[STATUS_NOT_VERIFIED]} | "
            f"{partition.get(STATUS_OUTSIDE_VERIFIED_SCOPE, 0)} | "
            f"{pages['succeeded']}/{pages['requested']} |"
        )
        if source["not_verified_reasons"]:
            reason_text = ", ".join(
                f"{reason}={count}" for reason, count in source["not_verified_reasons"].items()
            )
            lines.append(f"  - Not verified reasons: {reason_text}")
        outside_reasons = source.get("outside_verified_scope_reasons", {})
        if outside_reasons:
            outside_text = ", ".join(f"{reason}={count}" for reason, count in outside_reasons.items())
            lines.append(f"  - Outside verified scope reasons: {outside_text}")
    finding_classes = report["summary"].get("finding_classes", {})
    if finding_classes:
        lines.extend(
            [
                "",
                "## Sanitized finding classes",
                "",
                "Every FINDING item carries a fixed-vocabulary signature with `ctx=` path contexts, "
                "`fam=` coarse name/content families, a `locator=` source, and `assoc=` context/family "
                "pairs for matched path/name evidence. Bare filename matches inherit the containing "
                "source path context. Use `assoc=` pairs rather than combining unrelated `ctx=` and "
                "`fam=` tokens. Signatures contain no matched paths, names, or values.",
                "",
                "| Finding class | Items |",
                "|---|---:|",
            ]
        )
        for signature, count in finding_classes.items():
            escaped = signature.replace("|", "\\|")
            lines.append(f"| `{escaped}` | {count} |")
    lines.extend(
        [
            "",
            "Only rule categories, sanitized class signatures, and counts are included. "
            "Matched values, identities, URLs, and raw paths are suppressed.",
            "NOT_VERIFIED is not a clean result.",
            "OUTSIDE_VERIFIED_SCOPE is never represented as clean.",
            "",
        ]
    )
    return "\n".join(lines)


def run_audit(
    root: Path,
    repository: str | None = None,
    *,
    token: str | None = None,
    transport: Any | None = None,
) -> dict[str, Any]:
    surfaces = _new_surfaces()
    external_references = ExternalReferenceTracker(surfaces["external_references"])
    local = GitHistoryAuditor(
        root,
        surfaces["local_git_history"],
        external_references,
        boundary_surface=surfaces["local_object_store_boundary"],
    )
    local.scan()
    remote: GitHubAuditor | None = None
    if repository:
        client = GitHubClient(repository, token=token, transport=transport)
        remote = GitHubAuditor(client, surfaces, external_references)
        remote.scan_remote_refs_and_history()
        remote.scan_discussions_and_reviews()
        remote.scan_actions()
        remote.scan_releases()
        remote.scan_discovered_attachments()
    else:
        external_references.mark_attachments_not_requested()
        for name, surface in surfaces.items():
            if name not in LOCAL_SURFACE_NAMES:
                surface.record_not_verified("not_requested")
    return _report(
        surfaces,
        local,
        repository_requested=repository is not None,
        authenticated=bool(token),
        remote=remote,
        target={"repository": repository, **snapshot_git_identity(root)},
    )


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        self.exit(2, "audit arguments invalid; details suppressed\n")


def _git_boundary_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _repository_protected_roots(root: Path) -> list[Path]:
    """Repository toplevel, common Git directory, and every linked worktree."""
    repository_result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=_git_boundary_env(),
    )
    if repository_result.returncode != 0:
        return [root.resolve()]
    protected_roots = [Path(item).resolve() for item in repository_result.stdout.splitlines()]
    worktrees_result = subprocess.run(
        ["git", "-C", str(root), "worktree", "list", "--porcelain", "-z"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=_git_boundary_env(),
    )
    if worktrees_result.returncode != 0:
        raise ValueError("linked worktree list unavailable")
    worktree_roots = [
        Path(record.removeprefix("worktree ")).resolve()
        for record in worktrees_result.stdout.split("\0")
        if record.startswith("worktree ")
    ]
    if not worktree_roots:
        raise ValueError("linked worktree list empty")
    protected_roots.extend(worktree_roots)
    return protected_roots


def validate_report_destination(root: Path, destination: Path) -> Path:
    """Resolve an audit/gate report destination outside every protected root.

    Raises AuditFailure('destination_location_unvalidatable') when the
    repository boundary cannot be established and
    AuditFailure('destination_inside_repository') when the destination lies
    inside the repository, its Git directory, or any linked worktree.
    """
    try:
        protected_roots = _repository_protected_roots(root)
        resolved = destination.resolve()
    except (OSError, subprocess.SubprocessError, ValueError):
        raise AuditFailure("destination_location_unvalidatable") from None
    if any(resolved.is_relative_to(repository_root) for repository_root in protected_roots):
        raise AuditFailure("destination_inside_repository")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = _SanitizedArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="local checkout to inspect (read-only)")
    parser.add_argument("--github", metavar="OWNER/REPO", help="opt in to GitHub API GET-only audit")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="write sanitized report to this path")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 if findings are reported")
    args = parser.parse_args(argv)
    if args.github and not REPOSITORY_RE.fullmatch(args.github):
        print("audit configuration invalid; details suppressed", file=sys.stderr)
        return 2
    if args.output:
        try:
            validate_report_destination(args.root, args.output)
        except AuditFailure as exc:
            if exc.reason == "destination_inside_repository":
                print("audit output path must be outside the repository; details suppressed", file=sys.stderr)
            else:
                print("audit output location could not be validated; details suppressed", file=sys.stderr)
            return 2
    try:
        token = _github_token() if args.github else None
        report = run_audit(args.root, args.github, token=token)
        output = _markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
            print("sanitized audit report written; raw values and paths suppressed")
        else:
            sys.stdout.write(output)
        has_findings = report["summary"]["partition"].get(STATUS_FINDING, 0) > 0
        return 1 if args.fail_on_findings and has_findings else 0
    except Exception:  # noqa: BLE001 -- CLI errors must not echo paths, URLs, or response bodies.
        print("audit failed; details suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
