#!/usr/bin/env python3
"""Safely project this repository's Antigravity provider into Hermes profiles.

This installer copies *code only*; it never imports or copies credentials,
profile settings, session state, or model/account registry files.
It can run in a standard user environment against an explicit Hermes home.

Ownership boundary (historical reference): the official Hermes plugin catalog owns every
provider directory installed through ``hermes plugins install``. This standalone
installer never overwrites, upgrades, or deletes a catalog-managed (or any other
installer-managed) provider, and it also refuses directories whose ownership it
cannot verify. Ambiguous ownership fails closed *before* any file is touched.
Directories this installer wrote carry an ``install-provenance.json`` marker;
installs predating the marker are recognized through the canonical managed-file
set byte-matching a verified pre-marker release, or legacy installer artifacts
(``par.txt``/``launch_config.json``) and remain updatable. Catalog installs are
exclusively through ``hermes plugins update``/``hermes plugins remove``.

Ownership boundary (historical reference rework): update propagation never carries
unmanaged files forward, and a run that WOULD strip them now refuses before
any mutation. Before touching a single profile, every target provider tree is
scanned for entries outside the managed fileset and this installer's own
preserved state; if any tree that would be replaced still carries such a
private overlay, the whole run aborts with zero writes. Operators are pointed
to the dedicated private-ops deployment tooling (see ``operator-managed deployment documentation``)
which stages overlays as explicitly managed files, or to the explicit
``--allow-unmanaged-overlays`` operator-approved override.

Migration boundary (historical reference rework-r4): the public provider client's
fail-closed start trusts exactly two pieces of deployment evidence — the
in-tree ``install-provenance.json`` and the per-home policy obligation record.
This installer therefore also refuses (zero writes) while any provider home
still carries a legacy policy-required signature (a constitution
evidence-obligation block, or a profile name declared legacy via
``--legacy-policy-profile``) without having been migrated: run the
private-ops migration tooling to write that home's obligation record, or
waive the profile individually with ``--waive-policy-obligation``.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path

PROVIDER = "antigravity-acp"
PROVIDER_PLUGIN_NAME = "antigravity-acp-provider"
PIN_FILE = "par.txt"
LAUNCH_CONFIG_FILE = "launch_config.json"
# Hermes core's installer-owned provenance record (outside any plugin tree, so
# a plugin repo cannot forge it) and the in-tree catalog sidecar it writes.
INSTALL_METADATA_FILE = ".install-metadata.json"
CATALOG_SIDECAR = ".hermes-catalog.json"
# This installer's own ownership marker, written into every tree it deploys.
INSTALL_PROVENANCE_FILE = "install-provenance.json"
STANDALONE_MANAGED_BY = "antigravity-acp-standalone-installer"
# Files only this installer's provider trees ever carried (pre-marker installs).
# An opt-in private overlay module (see ``private-ops/``) is deliberately NOT
# evidence: a copy of it can appear in any manually assembled tree, so its
# presence proves nothing about ownership.
LEGACY_STANDALONE_EVIDENCE = (PIN_FILE, LAUNCH_CONFIG_FILE)
OFFICIAL_CATALOG_REPO = "rhgo1749/hermes-antigravity-acp"
REQUIRED = (
    "plugin.yaml",
    "__init__.py",
    "client.py",
    "bridge.py",
    "conversation_state.py",
    "native_limit_state.py",
    "hermes_compat.py",
    "login.py",
)
# Provider-tree byte sets this installer verifiably shipped before the
# provenance marker existed (sha256 of each managed file at that release).
# A full managed file set whose bytes match NO release set — and that carries
# neither this installer's marker nor a legacy installer artifact — has
# unknown provenance (a manually copied or foreign-pinned catalog-compatible
# tree) and must never be treated as ours.
PRE_MARKER_LINEAGE_SETS: dict[str, dict[str, str]] = {
    # Git commit 73c8dc7 ("fix(acp): state saves carry usage_drop_counters
    # forward (historical reference)"), the provider bytes deployed to every fleet home on
    # 2026-11-04; verified byte-identical against the deployed trees. The
    # file list is the managed set AS OF that release — later additions to
    # REQUIRED (login.py) must not invalidate this historical fingerprint.
    "73c8dc7 (2026-11-04)": {
        "plugin.yaml": "338dfa83344e4e4ad7686d1ed85db47cdf6f3faf89cfadd0fac532e975ef54f5",
        "__init__.py": "fdb9f7b1255dd9e61d792b98c1ea8f19c520e51f9afd9aae71b5a802ae9e9e8c",
        "client.py": "0a6bc0895a212bcbce7f9bef9f9f5eacd820b898406364547b48afaf50566d44",
        "bridge.py": "69fe92fd5df1a80dd8a7c47ae4c2a204d2d2e6793476fea08abaf894d3e151f0",
        "conversation_state.py": "a94b9680e6fb4fd73650b4f8104e5d7dbab362265dcf73d9997aec0a63eeb6d8",
        "native_limit_state.py": "dfeeb20438439d724f31f8232cdb98079c77789cb2b852d347fe56a18a00c831",
        "hermes_compat.py": "2641fa6be7a84506da38c7178a9d68aaef14a20bab9e70c518b27be880277442",
    },
}
SOURCE = Path(__file__).resolve().parents[1] / "hermes-plugin" / PROVIDER


def _default_hermes_home(platform_name: str, environ: Mapping[str, str], home: Path) -> Path:
    """Match Hermes platform defaults without requiring Hermes in the installer Python."""
    explicit = environ.get("HERMES_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    suffix = environ.get("HERMES_DATA_DIR_SUFFIX", "")
    if platform_name == "win32":
        local_appdata = environ.get("LOCALAPPDATA", "").strip()
        base = Path(local_appdata) if local_appdata else home / "AppData" / "Local"
        return base / ("hermes" + suffix)
    return home / (".hermes" + suffix)


DEFAULT_HERMES_HOME = _default_hermes_home(sys.platform, os.environ, Path.home())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _has_installer_artifact(target: Path, names: tuple[str, ...]) -> bool:
    return any(
        (target / name).is_file() and not (target / name).is_symlink()
        for name in names
    )


def _matches_release_lineage(target: Path, lineage: dict[str, str]) -> bool:
    for name, expected in lineage.items():
        path = target / name
        if not path.is_file() or path.is_symlink():
            return False
        try:
            if digest(path) != expected:
                return False
        except OSError:
            # Unreadable file: ownership cannot be proven, which is a lineage
            # miss (the caller then fails closed as ambiguous), not a crash.
            return False
    return True


def _plugin_name(plugin_yaml: Path) -> str | None:
    try:
        for line in plugin_yaml.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("name:"):
                return stripped.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def homes(home: Path, *, all_profiles: bool = True) -> list[tuple[str, Path]]:
    profiles_dir = home / "profiles"
    if not home.is_dir() or home.is_symlink():
        raise ValueError(f"Missing or unsafe Hermes home: {home}")
    if profiles_dir.is_symlink() or (profiles_dir.exists() and not profiles_dir.is_dir()):
        raise ValueError(f"Missing or unsafe profile directory: {profiles_dir}")
    # Dot-prefixed entries are never profiles: Hermes keeps deleted-profile
    # tombstones under ``profiles/.deleted/`` and valid profile IDs cannot start
    # with a dot. Installing into (or verifying) them would touch archived state.
    profiles = sorted(
        (
            p for p in profiles_dir.iterdir()
            if p.is_dir() and not p.is_symlink() and not p.name.startswith(".")
        ) if profiles_dir.is_dir() else (),
        key=lambda p: p.name,
    )
    targets = [("default", home), *((p.name, p) for p in profiles)]
    return targets if all_profiles else targets[:1]


def _legacy_launch_config(plugin_init: Path) -> dict[str, object] | None:
    """Extract literal launch settings from a pre-generic provider for upgrades."""
    if plugin_init.is_symlink() or not plugin_init.is_file():
        return None
    try:
        tree = ast.parse(plugin_init.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "AntigravityACPProfile":
            continue
        values = {item.arg: item.value for item in node.keywords if item.arg is not None}
        if "process_command" not in values or "process_args" not in values:
            return None
        try:
            command = ast.literal_eval(values["process_command"])
            args = ast.literal_eval(values["process_args"])
        except (TypeError, ValueError):
            return None
        if (
            not isinstance(command, str)
            or not command
            or not isinstance(args, (list, tuple))
            or any(not isinstance(arg, str) for arg in args)
        ):
            return None
        return {"process_command": command, "process_args": list(args)}
    return None


def _preserve_legacy_launch_config(target: Path, candidate: Path) -> None:
    """Persist an old provider's literal launch settings across code replacement."""
    config_path = candidate / LAUNCH_CONFIG_FILE
    if config_path.exists():
        return
    config = _legacy_launch_config(target / "__init__.py")
    if config is not None:
        config_path.write_text(
            json.dumps(config, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _provider_install_record(plugins_dir: Path) -> tuple[str, dict | None]:
    """Look up Hermes core's installer-owned record for this provider.

    ``.install-metadata.json`` lives directly under ``plugins/`` and is written
    only by ``hermes plugins`` tooling, so it — not the repo-controllable
    sidecar — is the authoritative provenance source. States: ``absent``
    (no file), ``corrupt`` (unreadable: ownership cannot be trusted),
    ``found`` (this provider has a record), ``none`` (file exists, no record).
    """
    path = plugins_dir / INSTALL_METADATA_FILE
    if not path.is_file():
        return "absent", None
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return "corrupt", None
    if not isinstance(metadata, dict):
        return "corrupt", None
    for key, record in metadata.items():
        if not isinstance(record, dict):
            continue
        catalog = record.get("catalog")
        catalog_name = catalog.get("name") if isinstance(catalog, dict) else None
        source = str(record.get("source", ""))
        if (
            key == PROVIDER_PLUGIN_NAME
            or catalog_name in {PROVIDER, PROVIDER_PLUGIN_NAME}
            or (OFFICIAL_CATALOG_REPO in source and f"hermes-plugin/{PROVIDER}" in source)
        ):
            return "found", record
    return "none", None


def classify_provider_target(target: Path) -> tuple[str, str]:
    """Decide who owns an existing provider directory before any write.

    Returns ``(kind, reason)`` with kind one of:

    - ``missing``: no provider directory at all (fresh install is allowed).
    - ``catalog``: Hermes core's install metadata records a curated catalog
      install; this installer must never overwrite or implicitly upgrade it.
    - ``installer-managed``: installed through ``hermes plugins install`` from
      a custom source/pin; that tooling owns updates.
    - ``standalone``: this installer's marker, a pre-marker install carrying
      the legacy ``par.txt``/``launch_config.json`` installer artifacts, or a
      pre-marker install whose full canonical managed-file set is byte-identical
      to a verified pre-marker release set (``PRE_MARKER_LINEAGE_SETS``).
    - ``scaffold``: directory holds no provider manifest or managed files
      (never a Hermes registration); deployment may adopt it as today.
    - ``ambiguous``: everything else (forged sidecar without authoritative
      metadata, unreadable marker or metadata, foreign manifest, partial
      registration). Callers must fail closed.
    """
    if not target.is_dir():
        return "missing", "no provider directory"
    plugins_dir = (
        target.parent.parent if target.parent.name == "model-providers" else target.parent
    )
    state, record = _provider_install_record(plugins_dir)
    if state == "corrupt":
        return "ambiguous", (
            f"{INSTALL_METADATA_FILE} under {plugins_dir} is unreadable, so installer "
            "ownership cannot be verified"
        )
    if state == "found" and isinstance(record, dict):
        catalog = record.get("catalog")
        if isinstance(catalog, dict) and catalog:
            revision = str(catalog.get("pin") or catalog.get("sha") or record.get("revision") or "")
            return "catalog", (
                "Hermes plugin catalog install pinned at revision "
                f"{revision[:12] or 'unknown'}"
            )
        return "installer-managed", (
            "installed through 'hermes plugins install' from a custom source or pin"
        )
    if (target / CATALOG_SIDECAR).is_file():
        return "ambiguous", (
            f"{CATALOG_SIDECAR} claims catalog origin but the installer-owned "
            f"{INSTALL_METADATA_FILE} has no matching record (the sidecar alone is "
            "repo-forgeable and cannot be trusted)"
        )
    manifest = target / "plugin.yaml"
    has_manifest = manifest.is_file() and not manifest.is_symlink()
    if has_manifest:
        name = _plugin_name(manifest)
        if name is None:
            return "ambiguous", "plugin.yaml is unreadable or declares no provider name"
        if name != PROVIDER_PLUGIN_NAME:
            return "ambiguous", f"provider directory holds a different plugin manifest ({name!r})"
    marker = target / INSTALL_PROVENANCE_FILE
    if marker.is_file():
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            return "ambiguous", f"{INSTALL_PROVENANCE_FILE} is unreadable or malformed"
        if isinstance(payload, dict) and payload.get("managed_by") == STANDALONE_MANAGED_BY:
            return "standalone", "carries this installer's provenance marker"
        owner = payload.get("managed_by") if isinstance(payload, dict) else "?"
        return "ambiguous", f"{INSTALL_PROVENANCE_FILE} names a different manager ({owner!r})"
    if not has_manifest and all(not (target / name).exists() for name in REQUIRED):
        return "scaffold", "directory holds no provider manifest or managed files"
    if _has_installer_artifact(target, LEGACY_STANDALONE_EVIDENCE):
        return "standalone", "pre-marker standalone install (legacy par/launch-config artifacts)"
    if has_manifest and all((target / name).is_file() for name in REQUIRED):
        for release, lineage in PRE_MARKER_LINEAGE_SETS.items():
            if _matches_release_lineage(target, lineage):
                return "standalone", (
                    f"pre-marker install byte-identical to verified pre-marker "
                    f"release set {release}"
                )
        return "ambiguous", (
            "full managed file set that matches no marker, no legacy installer "
            "artifact, and no verified pre-marker release set — provenance unknown"
        )
    return "ambiguous", "no catalog provenance and no verifiable standalone installer evidence"


def _ownership_refusal(profile: str, target: Path, kind: str, reason: str) -> str:
    """Actionable, credential-free diagnostic for a refused provider mutation."""
    if kind == "catalog":
        what = "the catalog-managed provider"
        recovery = (
            f"update it with 'hermes plugins update {PROVIDER_PLUGIN_NAME}' or remove it "
            f"with 'hermes plugins remove {PROVIDER_PLUGIN_NAME}' — the Hermes plugin "
            "catalog owns its pinned source and manifest bytes; this standalone installer "
            "will never overwrite or implicitly upgrade them. Only after removing it from "
            "catalog management may this installer manage the directory"
        )
    elif kind == "installer-managed":
        what = "a provider installed through Hermes' plugin installer"
        recovery = (
            f"update or remove it with 'hermes plugins update/remove {PROVIDER_PLUGIN_NAME}' "
            "from the same Hermes installation that owns it"
        )
    else:
        what = "a provider directory with unverifiable ownership"
        recovery = (
            "move the directory aside (or delete it only after confirming its origin, "
            "e.g. via 'hermes plugins list'), then re-run this installer to adopt the "
            "profile cleanly"
        )
    return (
        f"{profile}: refusing to overwrite {what} at {target} ({reason}). "
        f"Recovery: {recovery}"
    )


# Pre-mutation private-overlay guard (historical reference rework). Python bytecode
# caches are regenerable artifacts, never user content; everything else in a
# deployed provider tree beyond the managed fileset and this installer's own
# preserved state is unmanaged and must never be replaced silently.
OVERLAY_SCAN_IGNORED_NAMES = frozenset({"__pycache__"})
OVERLAY_SCAN_IGNORED_SUFFIXES = (".pyc", ".pyo")


def _installer_owned_tree_names(managed_files: tuple[str, ...]) -> set[str]:
    """Names this installer may legitimately leave inside a provider tree."""
    return set(managed_files) | {PIN_FILE, LAUNCH_CONFIG_FILE, INSTALL_PROVENANCE_FILE}


def _unmanaged_tree_entries(target: Path, allowed: set[str]) -> list[str]:
    entries = []
    for entry in target.iterdir():
        name = entry.name
        if name in allowed or name in OVERLAY_SCAN_IGNORED_NAMES:
            continue
        if name.endswith(OVERLAY_SCAN_IGNORED_SUFFIXES):
            continue
        entries.append(name)
    return sorted(entries)


def _is_provider_deployment(target: Path, managed_files: tuple[str, ...]) -> bool:
    """True when the tree ever held the provider (manifest or managed file).

    A bare scaffold directory holds no registered provider (see
    ``classify_provider_target``), so it cannot carry a live private overlay;
    adopting one stays the pre-existing documented behavior.
    """
    if (target / "plugin.yaml").exists():
        return True
    return any((target / name).exists() for name in managed_files)


def find_unmanaged_overlay_files(
    home: Path,
    *,
    files: tuple[str, ...] | None = None,
    all_profiles: bool = True,
) -> list[tuple[str, Path, list[str]]]:
    """Read-only preflight: provider trees carrying unmanaged files.

    Returns ``(profile, target, sorted-entry-names)`` for every provider
    deployment tree whose contents extend beyond the managed fileset plus
    this installer's own preserved state. Deployments must run this BEFORE
    any mutation and refuse on a non-empty result; byte-identical trees are
    not deployments in danger here, but are still reported (no decision is
    made here — this scan never writes).
    """
    managed_files = tuple(files or REQUIRED)
    allowed = _installer_owned_tree_names(managed_files)
    findings: list[tuple[str, Path, list[str]]] = []
    for profile, profile_home in homes(home, all_profiles=all_profiles):
        target = profile_home / "plugins" / "model-providers" / PROVIDER
        if target.is_symlink() or not target.is_dir():
            continue
        if not _is_provider_deployment(target, managed_files):
            continue
        entries = _unmanaged_tree_entries(target, allowed)
        if entries:
            findings.append((profile, target, entries))
    return findings


def _overlay_refusal(findings: list[tuple[str, Path, list[str]]]) -> str:
    detail = "; ".join(
        f"{profile}: {target} carries unmanaged file(s) {', '.join(names)}"
        for profile, target, names in findings
    )
    return (
        f"{detail}. This deployment path manages only the canonical provider "
        "fileset plus its own installer state, so continuing would silently "
        "strip those private overlay files and leave the affected profiles' "
        "fail-closed policy declarations broken on next start. Deploy this "
        "host with the dedicated private-ops tooling documented in "
        "operator-managed deployment documentation (which stages overlays as explicitly managed "
        "files), or re-run with --allow-unmanaged-overlays only after "
        "confirming the removal is intended"
    )


# Legacy policy-obligation migration gate (historical reference rework-r4). A
# policy-required deployment keeps its provider-side fail-closed refusal only
# while its home carries an explicit obligation record
# (``policy-obligation.json``, written at deploy time by the private-ops
# tooling). Homes still carrying a legacy obligation signature — a
# constitution with an evidence-hotfix obligation block, or a profile name
# the operator declares legacy-policy-required at run time — must be
# explicitly migrated (the migration writes their obligation record) or
# individually waived BEFORE this installer mutates anything. Same zero-write
# chokepoint as the overlay guard; detection here is deliberately
# signature-based and domain-neutral (this public installer names no personal
# profile itself).
POLICY_OBLIGATION_FILE = "policy-obligation.json"
LEGACY_OBLIGATION_MARKER_RE = re.compile(
    r"<!--\s*[A-Za-z0-9._-]{1,64}-evidence-hotfix:start\s*-->"
)


def _policy_obligation_satisfied(profile_home: Path) -> bool:
    """True only when the home carries a parseable, declaring obligation record."""
    record = profile_home / POLICY_OBLIGATION_FILE
    if record.is_symlink() or not record.is_file():
        return False
    try:
        payload = json.loads(record.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    required = payload.get("required_extensions")
    return isinstance(required, list) and any(
        isinstance(name, str) and name.strip() for name in required
    )


def _legacy_policy_signature(
    profile_home: Path, legacy_profile_names: frozenset[str]
) -> str | None:
    """Return why this never-migrated home looks policy-required, else None."""
    if _policy_obligation_satisfied(profile_home):
        return None
    if profile_home.name in legacy_profile_names:
        return "profile name declared legacy-policy-required by the operator"
    constitution = profile_home / "SOUL.md"
    if constitution.is_symlink():
        return "constitution is a symlink; obligation state cannot be verified"
    if constitution.is_file():
        try:
            text = constitution.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return "constitution is unreadable; obligation state cannot be verified"
        if LEGACY_OBLIGATION_MARKER_RE.search(text):
            return "constitution carries a legacy evidence-obligation block"
    return None


def find_unmigrated_policy_homes(
    home: Path,
    *,
    files: tuple[str, ...] | None = None,
    all_profiles: bool = True,
    legacy_profile_names: tuple[str, ...] = (),
    waived_profiles: tuple[str, ...] = (),
) -> list[tuple[str, Path, str]]:
    """Read-only preflight: provider homes whose obligation was never migrated.

    Returns ``(profile, profile_home, signature)`` for every profile home
    carrying a provider deployment with a legacy policy-required signature
    and no explicit obligation record. Deployments must run this BEFORE any
    mutation and refuse on a non-empty result; this scan never writes.
    """
    managed_files = tuple(files or REQUIRED)
    names = frozenset(legacy_profile_names)
    waived = set(waived_profiles)
    findings: list[tuple[str, Path, str]] = []
    for profile, profile_home in homes(home, all_profiles=all_profiles):
        target = profile_home / "plugins" / "model-providers" / PROVIDER
        if target.is_symlink() or not target.is_dir():
            continue
        if not _is_provider_deployment(target, managed_files):
            continue
        if profile in waived:
            continue
        signature = _legacy_policy_signature(profile_home, names)
        if signature:
            findings.append((profile, profile_home, signature))
    return findings


def _policy_migration_refusal(findings: list[tuple[str, Path, str]]) -> str:
    detail = "; ".join(
        f"{profile}: {location} {signature}" for profile, location, signature in findings
    )
    return (
        f"{detail}. These homes were policy-required deployments whose "
        "provider obligation record has never been migrated, and the public "
        "client's fail-closed start now trusts only that record; a plain "
        "redeploy here would leave them unable to prove their extension "
        "obligation on next provider start. Migrate each home explicitly "
        "with the private-ops migration tooling (it writes the home's "
        f"{POLICY_OBLIGATION_FILE}; see operator-managed deployment documentation), or pass "
        "--waive-policy-obligation for a profile whose policy requirement "
        "has been retired by operator decision"
    )


def install(
    source: Path,
    home: Path,
    *,
    apply: bool,
    files: tuple[str, ...] | None = None,
    all_profiles: bool = True,
    allow_unmanaged_overlays: bool = False,
    legacy_policy_profiles: tuple[str, ...] = (),
    waived_policy_profiles: tuple[str, ...] = (),
) -> list[str]:
    managed_files = tuple(files or REQUIRED)
    if not set(REQUIRED).issubset(managed_files):
        raise ValueError("Managed provider files must include the generic provider contract")
    if any(Path(name).name != name or name.startswith(".") for name in managed_files):
        raise ValueError("Unexpected managed provider filename")
    if not source.is_dir() or any(
        not (source / name).is_file() or (source / name).is_symlink()
        for name in managed_files
    ):
        raise ValueError(f"Provider source incomplete: {source}")
    expected = {name: digest(source / name) for name in managed_files}
    targets = homes(home, all_profiles=all_profiles)

    def is_current(target: Path) -> bool:
        return target.is_dir() and all(
            (target / name).is_file()
            and not (target / name).is_symlink()
            and digest(target / name) == expected[name]
            for name in managed_files
        )

    if apply:
        # Fail closed BEFORE any mutation: a pre-existing duplicate/off-path
        # registration (or leftover artifact) must abort the whole run, not
        # surface after 12 homes were already swapped.
        pre = verify(home, allow_missing=True, all_profiles=all_profiles)
        if pre:
            raise ValueError(
                "pre-deploy verification failed; no files were touched: "
                + "; ".join(pre)
            )
        # Ownership gate (historical reference): catalog-managed, installer-managed, and
        # unverifiable provider directories are refused across every target
        # before a single write happens. A byte-identical "already current"
        # tree is a no-op for any owner, so it needs no ownership claim.
        for profile, profile_home in targets:
            target = profile_home / "plugins" / "model-providers" / PROVIDER
            if target.is_symlink() or not target.is_dir() or is_current(target):
                continue
            kind, reason = classify_provider_target(target)
            if kind not in {"standalone", "scaffold"}:
                raise ValueError(
                    _ownership_refusal(profile, target, kind, reason) + "; no files were touched"
                )
        # Pre-mutation private-overlay guard (historical reference rework): refuse while
        # ANY target this run would replace still carries files outside the
        # managed fileset plus installer-owned state. Zero writes across all
        # profiles; unmanaged overlay bytes stay live and unchanged.
        if not allow_unmanaged_overlays:
            allowed = _installer_owned_tree_names(managed_files)
            overlay_findings: list[tuple[str, Path, list[str]]] = []
            for profile, profile_home in targets:
                target = profile_home / "plugins" / "model-providers" / PROVIDER
                if target.is_symlink() or not target.is_dir() or is_current(target):
                    continue
                if not _is_provider_deployment(target, managed_files):
                    continue
                entries = _unmanaged_tree_entries(target, allowed)
                if entries:
                    overlay_findings.append((profile, target, entries))
            if overlay_findings:
                raise ValueError(
                    _overlay_refusal(overlay_findings) + "; no files were touched"
                )
            # Legacy policy-obligation migration gate (historical reference rework-r4):
            # refuse while ANY provider home still carries a legacy policy
            # signature without its obligation record. Zero writes across all
            # profiles; migrate (private-ops tooling) or waive explicitly.
            migration_findings = find_unmigrated_policy_homes(
                home,
                files=managed_files,
                all_profiles=all_profiles,
                legacy_profile_names=legacy_policy_profiles,
                waived_profiles=waived_policy_profiles,
            )
            if migration_findings:
                raise ValueError(
                    _policy_migration_refusal(migration_findings) + "; no files were touched"
                )
    reports: list[str] = []
    for profile, profile_home in targets:
        parent = profile_home / "plugins" / "model-providers"
        target = parent / PROVIDER
        if target.is_symlink() or (parent.exists() and parent.is_symlink()):
            raise ValueError(f"Refusing symlink target: {target}")
        if target.exists() and not target.is_dir():
            raise ValueError(f"Unexpected provider target: {target}")
        if not apply:
            reports.append(f"dry-run: {profile} -> {target}")
            continue
        if target.is_dir() and all(
            (target / name).is_file()
            and not (target / name).is_symlink()
            and digest(target / name) == expected[name]
            for name in managed_files
        ):
            reports.append(f"already current: {profile} -> {target}")
            continue
        parent.mkdir(parents=True, exist_ok=True)
        unique = uuid.uuid4().hex[:12]
        # Staging and backups live OUTSIDE the plugin discovery tree. Any
        # directory with a plugin.yaml under plugins/ is loaded by Hermes, so
        # `.antigravity-acp.backup-*` inside model-providers resurrects the
        # duplicate-provider discovery bug seen during the 1.3.0 pilot.
        staging_root = home / "plugin-backups" / "staging"
        backups_root = home / "plugin-backups" / f"deploy-{unique}"
        staging_root.mkdir(parents=True, exist_ok=True)
        candidate = staging_root / f"{profile}-{unique}"
        backup = backups_root / profile
        moved_old = False
        try:
            candidate.mkdir(parents=True)
            for name in managed_files:
                shutil.copy2(source / name, candidate / name)
            if target.exists():
                # historical reference boundary: update propagation carries ONLY this
                # installer's own preserved state (legacy launch settings;
                # the par.txt pin is carried below). Unmanaged files in an
                # existing target — opt-in private overlay modules, personal
                # drop-ins, anything not in the managed set — stay in the
                # backup and are never propagated into the new tree. A
                # private deployment re-adds an overlay explicitly by passing
                # it as a managed file (the private finance-hotfix host tool
                # does exactly this).
                carried = target / LAUNCH_CONFIG_FILE
                if carried.is_file() and not carried.is_symlink():
                    shutil.copy2(carried, candidate / LAUNCH_CONFIG_FILE)
                _preserve_legacy_launch_config(target, candidate)
            provenance = {
                "managed_by": STANDALONE_MANAGED_BY,
                "installer": "scripts/deploy_hermes_profiles.py",
                "provider": PROVIDER,
                "managed_files": expected,
            }
            (candidate / INSTALL_PROVENANCE_FILE).write_text(
                json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if any(digest(candidate / name) != expected[name] for name in managed_files):
                raise ValueError(f"Source checksum mismatch before install: {profile}")
            pin_note = ""
            if target.exists():
                pin = target / PIN_FILE
                if pin.is_file():
                    pin_text = pin.read_text(encoding="utf-8", errors="replace").strip()
                    shutil.copy2(pin, candidate / PIN_FILE)
                    if pin_text and Path(pin_text).expanduser().is_file():
                        pin_note = f" (par pin preserved -> {pin_text})"
                    else:
                        pin_note = (
                            f" (par pin preserved but UNRESOLVED: {pin_text or '<empty>'};"
                            " provider will refuse to spawn until re-pinned)"
                        )
                backups_root.mkdir(parents=True, exist_ok=True)
                target.rename(backup)
                moved_old = True
            candidate.rename(target)
            candidate = staging_root / f"{profile}-{unique}-gone"
            if any(digest(target / name) != expected[name] for name in managed_files):
                raise ValueError(f"Installed provider checksum mismatch: {profile}")
            reports.append(
                f"deployed: {profile} -> {target}"
                + (f" (backup: {backup})" if moved_old else "")
                + pin_note
            )
        except Exception:
            if moved_old and backup.exists():
                if target.exists():
                    shutil.rmtree(target)
                backup.rename(target)
            raise
        finally:
            if candidate.exists():
                shutil.rmtree(candidate)
    return reports


def verify(
    home: Path,
    *,
    allow_missing: bool = False,
    all_profiles: bool = True,
) -> list[str]:
    """Post-deploy discovery checks: no deploy artifacts in the plugins tree,
    and the provider is registered exactly once per home at the canonical path.

    ``allow_missing=True`` (pre-deploy gate) tolerates homes that do not carry
    the provider yet, so first installs stay possible while duplicate or
    off-path registrations still block any mutation.

    The registration scan mirrors what Hermes actually imports: direct children
    of ``plugins/model-providers/`` (``is_dir()`` follows symlinked siblings)
    plus flat ``plugins/`` root dirs that declare ``kind: model-provider``.
    Duplicate manifest names matter because provider registration is
    last-writer-wins in sorted order, so a stale sibling like the disabled
    ``antigravity-cli`` copy could override the canonical provider if restored.
    """
    problems: list[str] = []
    for profile, profile_home in homes(home, all_profiles=all_profiles):
        plugins = profile_home / "plugins"
        if not plugins.is_dir():
            continue
        for path in plugins.rglob("*"):
            if path.name.startswith(f".{PROVIDER}."):
                problems.append(f"deploy artifact inside discovery tree: {path}")
        candidates: list[Path] = []
        model_dir = plugins / "model-providers"
        if model_dir.is_dir():
            for child in model_dir.iterdir():
                if not child.name.startswith(("_", ".")) and child.is_dir():
                    candidates.append(child / "plugin.yaml")
        for child in plugins.iterdir():
            if child.name != "model-providers" and not child.name.startswith(("_", ".")) and child.is_dir():
                candidates.append(child / "plugin.yaml")
        candidates.extend(plugins.rglob("plugin.yaml"))
        registrations = []
        seen: set[Path] = set()
        for yaml_path in candidates:
            resolved = yaml_path.resolve()
            if yaml_path in seen or resolved in seen:
                continue
            seen.add(yaml_path)
            if yaml_path.is_file() and _plugin_name(yaml_path) == PROVIDER_PLUGIN_NAME:
                registrations.append(yaml_path)
        if len(registrations) == 0:
            if not allow_missing:
                problems.append(f"{profile}: provider registrations=0")
        elif len(registrations) != 1:
            problems.append(
                f"{profile}: provider registrations={len(registrations)}"
                f" ({', '.join(str(p) for p in registrations)})"
            )
        elif registrations[0].parent != plugins / "model-providers" / PROVIDER:
            problems.append(
                f"{profile}: provider registered outside canonical path: {registrations[0]}"
            )
    return problems


def uninstall(home: Path, *, all_profiles: bool = True) -> list[str]:
    """Remove only provider projections this standalone installer owns.

    Catalog-managed, installer-managed, and unverifiable directories are never
    deleted — removing a catalog install belongs to ``hermes plugins remove``.
    Ownership is classified for every target before the first deletion, so a
    refusal anywhere leaves the whole home untouched. Backups previously kept
    under ``plugin-backups/`` and every other profile state are left alone.
    """
    plans: list[tuple[str, Path]] = []
    reports: list[str] = []
    for profile, profile_home in homes(home, all_profiles=all_profiles):
        parent = profile_home / "plugins" / "model-providers"
        target = parent / PROVIDER
        if target.is_symlink() or (parent.exists() and parent.is_symlink()):
            raise ValueError(f"Refusing symlink target: {target}")
        kind, reason = classify_provider_target(target)
        if kind in {"catalog", "installer-managed", "ambiguous"}:
            raise ValueError(
                _ownership_refusal(profile, target, kind, reason) + "; nothing was deleted"
            )
        if kind == "standalone":
            plans.append((profile, target))
        else:
            reports.append(f"nothing to delete ({kind}): {profile} -> {target}")
    for profile, target in plans:
        shutil.rmtree(target)
        reports.append(
            f"deleted: {profile} -> {target} (a pinned par.txt file, if any, pointed "
            "outside this directory and was not touched)"
        )
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-home", type=Path, default=DEFAULT_HERMES_HOME)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--apply", action="store_true", help="Copy provider code into default and every named profile")
    parser.add_argument("--verify-only", action="store_true", help="Run discovery checks without touching files")
    parser.add_argument(
        "--allow-unmanaged-overlays",
        action="store_true",
        help="Explicit operator-approved override for the pre-mutation private-overlay "
        "guard: provider trees carrying unmanaged private files are replaced anyway "
        "(they stay recoverable in plugin-backups). Prefer the dedicated private-ops "
        "deployment tooling documented in operator-managed deployment documentation",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Delete only provider projections owned by this installer; catalog-managed "
        "and unverifiable directories are refused (use 'hermes plugins remove')",
    )
    parser.add_argument(
        "--legacy-policy-profile",
        action="append",
        default=[],
        metavar="PROFILE",
        help="Declare PROFILE a legacy policy-required home (operator field "
        "knowledge): until it is migrated with the private-ops migration "
        "tooling or waived, this installer refuses before any mutation",
    )
    parser.add_argument(
        "--waive-policy-obligation",
        action="append",
        default=[],
        metavar="PROFILE",
        help="Individually waive the legacy policy-obligation migration gate "
        "for PROFILE (policy requirement retired by operator decision)",
    )
    args = parser.parse_args()
    try:
        if args.verify_only:
            problems = verify(args.hermes_home)
            if problems:
                print("\n".join(problems))
                return 1
            print("discovery check clean: one provider registration per home, no deploy artifacts")
            return 0
        if args.uninstall:
            reports = uninstall(args.hermes_home)
            print("\n".join(reports) if reports else "nothing to delete")
            print("catalog-managed installs are never removed here; no other profile state was touched")
            return 0
        output = install(
            args.source,
            args.hermes_home,
            apply=args.apply,
            allow_unmanaged_overlays=args.allow_unmanaged_overlays,
            legacy_policy_profiles=tuple(args.legacy_policy_profile),
            waived_policy_profiles=tuple(args.waive_policy_obligation),
        )
        problems = verify(args.hermes_home) if args.apply else []
    except (OSError, ValueError) as exc:
        print(f"deployment failed: {exc}", file=sys.stderr)
        return 1
    if problems:
        print("\n".join(output))
        print("DISCOVERY CHECK FAILED:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        return 1
    print("\n".join(output))
    print(f"verified {len(output)} profile homes; runtime processes may need restart to reload provider imports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
