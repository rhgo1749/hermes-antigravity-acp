"""Catalog immutability and standalone server lifecycle separation (historical reference).

Deterministic, credential-free fixtures for four provider-ownership families —
catalog-managed, standalone-managed, ambiguous/unverified, and empty
``HERMES_HOME`` — plus the distinct server-lifecycle diagnostics. Every download
is a fake that materializes fixture bytes; no live credentials, network, or real
ACP/model call happens here.

Regression this suite pins down: previously ``deploy_hermes_profiles.install``
treated any canonical provider directory as its own and silently overwrote a
Hermes catalog-pinned provider (catalog code drift, catalog rule 3). The
ownership gate must now refuse catalog-managed, installer-managed, and
unverifiable directories *before any write*, while supported standalone
install/update/delete flows keep working byte-for-byte.
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import types
import uuid
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

CATALOG_REPO_URL = "https://github.com/rhgo1749/hermes-antigravity-acp"
CATALOG_SHA = "0" * 40


def _load_script(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deploy = _load_script("deploy_hermes_profiles.py", "catalog_imm_deploy")


def _fake_archive_bytes() -> bytes:
    server = b"""#!/usr/bin/env python3
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get('method') == 'initialize':
        print(json.dumps({
            'jsonrpc': '2.0',
            'id': message.get('id'),
            'result': {
                'protocolVersion': 1,
                'agentInfo': {'name': 'fake-official-acp', 'version': 'test'},
                'authMethods': [],
                'agentCapabilities': {},
            },
        }), flush=True)
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("agy_acp_server.par", date_time=(2026, 1, 1, 0, 0, 0))
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, server)
    return buffer.getvalue()


_FAKE_ARCHIVE = _fake_archive_bytes()
_FAKE_ARCHIVE_SHA256 = hashlib.sha256(_FAKE_ARCHIVE).hexdigest()


def _snapshot(root: Path) -> dict[str, str]:
    state: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            state[rel] = "link:" + str(path.readlink())
        elif path.is_file():
            state[rel] = "file:" + hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            state[rel] = "dir"
    return state


def _provider_target(home: Path) -> Path:
    return home / "plugins" / "model-providers" / deploy.PROVIDER


def _catalog_bytes(name: str) -> bytes:
    # the catalog pins an older reviewed commit: every managed byte differs
    return (
        deploy.SOURCE / name
    ).read_bytes() + b"# catalog reviewed commit 0000000000000000000000000000000000000000\n"


def _seed_catalog_provider(home: Path, *, with_metadata: bool = True) -> Path:
    target = _provider_target(home)
    target.mkdir(parents=True)
    for name in deploy.REQUIRED:
        (target / name).write_bytes(_catalog_bytes(name))
    (target / deploy.CATALOG_SIDECAR).write_text(
        json.dumps(
            {
                "name": deploy.PROVIDER_PLUGIN_NAME,
                "repo": CATALOG_REPO_URL,
                "sha": CATALOG_SHA,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    if with_metadata:
        record: dict[str, object] = {
            "pinned": True,
            "revision": CATALOG_SHA,
            "source": f"{CATALOG_REPO_URL}#hermes-plugin/{deploy.PROVIDER}",
            "catalog": {
                "name": deploy.PROVIDER_PLUGIN_NAME,
                "repo": CATALOG_REPO_URL,
                "tier": "community",
                "sha": CATALOG_SHA,
                "pin": CATALOG_SHA,
            },
        }
        (home / "plugins" / deploy.INSTALL_METADATA_FILE).write_text(
            json.dumps({deploy.PROVIDER_PLUGIN_NAME: record}) + "\n", encoding="utf-8"
        )
    return target


def _seed_sentinels(home: Path) -> dict[Path, bytes]:
    sentinels = {
        home / "config.yaml": b"user settings remain untouched\n",
        home / ".env": b"local secret placeholder\n",
        home / "acp-accounts.json": b"private mux registry remains untouched\n",
        home / "sessions.sqlite": b"session state remains untouched\n",
    }
    for path, content in sentinels.items():
        path.write_bytes(content)
    return sentinels


def _prepare_combined_installer(monkeypatch, tmp_path, downloads: list[str]):
    """install_acp with a fake publisher download pinned to fixture bytes."""
    installer = _load_script(
        "install_acp.py", f"catalog_imm_install_acp_{uuid.uuid4().hex[:8]}"
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    launcher = tmp_path / ".local" / "bin" / installer._launcher_name()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(launcher))

    def fake_download(_url: str, filename: str):
        downloads.append(filename)
        Path(filename).write_bytes(_FAKE_ARCHIVE)
        return filename, None

    monkeypatch.setattr(
        installer.official_installer.urllib.request, "urlretrieve", fake_download
    )
    pinned = installer.official_installer.resolve_distribution()
    monkeypatch.setattr(
        installer.official_installer,
        "resolve_distribution",
        lambda *_args, **_kwargs: dataclasses.replace(
            pinned, sha256=_FAKE_ARCHIVE_SHA256
        ),
    )
    return installer, launcher


def _load_official(name: str):
    return _load_script("install_official.py", name)


# ---------------------------------------------------------------------------
# ownership classification
# ---------------------------------------------------------------------------


def test_classify_provider_target_families(tmp_path):
    catalog_home = tmp_path / "catalog"
    target = _seed_catalog_provider(catalog_home)
    assert deploy.classify_provider_target(target)[0] == "catalog"

    custom_home = tmp_path / "custom"
    target = _seed_catalog_provider(custom_home)
    (custom_home / "plugins" / deploy.INSTALL_METADATA_FILE).write_text(
        json.dumps(
            {
                deploy.PROVIDER_PLUGIN_NAME: {
                    "pinned": False,
                    "revision": "1" * 40,
                    "source": "https://example.invalid/fork#hermes-plugin/antigravity-acp",
                }
            }
        ),
        encoding="utf-8",
    )
    assert deploy.classify_provider_target(target)[0] == "installer-managed"

    forged_home = tmp_path / "forged"
    target = _seed_catalog_provider(forged_home, with_metadata=False)
    assert deploy.classify_provider_target(target)[0] == "ambiguous"

    scaffold_home = tmp_path / "scaffold"
    scaffold = _provider_target(scaffold_home)
    scaffold.mkdir(parents=True)
    (scaffold / "legacy.txt").write_text("OLD_PLUGIN", encoding="utf-8")
    assert deploy.classify_provider_target(scaffold)[0] == "scaffold"

    legacy_home = tmp_path / "legacy"
    target = _provider_target(legacy_home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_bytes((deploy.SOURCE / "plugin.yaml").read_bytes())
    (target / "par.txt").write_text("/opt/pin/agy.par", encoding="utf-8")
    assert deploy.classify_provider_target(target)[0] == "standalone"

    fresh_home = tmp_path / "fresh"
    assert deploy.classify_provider_target(_provider_target(fresh_home))[0] == "missing"


# ---------------------------------------------------------------------------
# catalog installs are immutable to provider projection and deletion
# ---------------------------------------------------------------------------


def test_provider_projection_refuses_catalog_managed_provider_before_writes(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    _seed_sentinels(home)
    _seed_catalog_provider(home)
    before = _snapshot(home)

    with pytest.raises(ValueError, match="catalog-managed provider") as caught:
        deploy.install(deploy.SOURCE, home, apply=True)

    assert "hermes plugins remove antigravity-acp-provider" in str(caught.value)
    assert "no files were touched" in str(caught.value)
    assert _snapshot(home) == before
    assert not (home / "plugin-backups").exists()


def test_unverified_upgrade_attempt_is_an_ownership_refusal(tmp_path):
    # an "upgrade" from a different source directory is still an overwrite
    home = tmp_path / "hermes"
    home.mkdir()
    target = _seed_catalog_provider(home)
    other_source = tmp_path / "other-source"
    other_source.mkdir()
    for name in deploy.REQUIRED:
        (other_source / name).write_bytes(f"# newer from elsewhere {name}\n".encode())
    before = _snapshot(home)

    with pytest.raises(ValueError, match="catalog-managed provider"):
        deploy.install(other_source, home, apply=True)

    assert _snapshot(home) == before
    assert target.is_dir()


def test_partial_provider_without_provenance_fails_closed(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _provider_target(home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_bytes((deploy.SOURCE / "plugin.yaml").read_bytes())
    (target / "client.py").write_bytes(b"# hand-placed copy of unknown origin\n")
    before = _snapshot(home)

    with pytest.raises(ValueError, match="unverifiable ownership") as caught:
        deploy.install(deploy.SOURCE, home, apply=True)

    assert "no files were touched" in str(caught.value)
    assert _snapshot(home) == before
    assert not (home / "plugin-backups").exists()


def test_forged_catalog_sidecar_without_install_metadata_fails_closed(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    _seed_catalog_provider(home, with_metadata=False)
    before = _snapshot(home)

    with pytest.raises(ValueError, match="repo-forgeable"):
        deploy.install(deploy.SOURCE, home, apply=True)

    assert _snapshot(home) == before


def test_malformed_provenance_marker_fails_closed(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _provider_target(home)
    target.mkdir(parents=True)
    for name in deploy.REQUIRED:
        body = "name: antigravity-acp-provider\n" if name == "plugin.yaml" else ""
        (target / name).write_bytes(f"{body}# pre-existing provider {name}\n".encode())
    (target / deploy.INSTALL_PROVENANCE_FILE).write_text("not json {{{", encoding="utf-8")
    before = _snapshot(home)

    with pytest.raises(ValueError, match="unreadable or malformed"):
        deploy.install(deploy.SOURCE, home, apply=True)

    assert _snapshot(home) == before


def test_installer_managed_provider_refuses_standalone_adoption(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    _seed_catalog_provider(home)
    (home / "plugins" / deploy.INSTALL_METADATA_FILE).write_text(
        json.dumps(
            {
                deploy.PROVIDER_PLUGIN_NAME: {
                    "pinned": False,
                    "revision": "1" * 40,
                    "source": "https://example.invalid/fork#hermes-plugin/antigravity-acp",
                }
            }
        ),
        encoding="utf-8",
    )
    before = _snapshot(home)

    with pytest.raises(ValueError, match="hermes plugins install") as caught:
        deploy.install(deploy.SOURCE, home, apply=True)

    assert "hermes plugins update/remove antigravity-acp-provider" in str(caught.value)
    assert _snapshot(home) == before


def test_uninstall_refuses_catalog_managed_provider(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    _seed_catalog_provider(home)
    before = _snapshot(home)

    with pytest.raises(ValueError, match="catalog-managed provider") as caught:
        deploy.uninstall(home)

    assert "nothing was deleted" in str(caught.value)
    assert _snapshot(home) == before


# ---------------------------------------------------------------------------
# the official server lifecycle never touches catalog-managed plugin bytes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="fake official archive is a POSIX fixture")
def test_official_server_lifecycle_preserves_catalog_bytes_and_sentinels(tmp_path, monkeypatch):
    official = _load_official(f"catalog_imm_official_{uuid.uuid4().hex[:8]}")
    from antigravity_acp.registry import Distribution

    def fake_distribution(*_args, **_kwargs):
        return Distribution(
            url="https://fake.invalid/catalog-immutable/agy-acp-server.zip",
            executable="agy_acp_server.par",
            sha256=_FAKE_ARCHIVE_SHA256,
            args=("--uid=",),
        )

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_bytes(_FAKE_ARCHIVE)
        return filename, {"Content-Length": str(len(_FAKE_ARCHIVE))}

    monkeypatch.setattr(official, "resolve_distribution", fake_distribution)
    monkeypatch.setattr(official.urllib.request, "urlretrieve", fake_urlretrieve)

    home = tmp_path / "hermes"
    home.mkdir()
    _seed_sentinels(home)
    _seed_catalog_provider(home)
    before = _snapshot(home)
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"

    installed = official.install(prefix, bin_dir)
    assert official.status(prefix, bin_dir) == {
        "server_installed": True,
        "launcher_available": True,
    }
    official.verify(prefix, bin_dir)
    assert installed["version_dir"].is_dir()
    assert _snapshot(home) == before

    removed = official.uninstall(prefix, bin_dir)
    assert Path(installed["launcher"]) in removed
    assert installed["version_dir"] in removed
    assert not installed["version_dir"].exists()
    assert not installed["launcher"].exists()
    assert _snapshot(home) == before


@pytest.mark.skipif(os.name == "nt", reason="fake official archive is a POSIX fixture")
def test_provider_diagnostics_do_not_mutate_catalog_tree(tmp_path, monkeypatch):
    official = _load_official(f"catalog_imm_diag_official_{uuid.uuid4().hex[:8]}")
    from antigravity_acp.registry import Distribution

    def fake_distribution(*_args, **_kwargs):
        return Distribution(
            url="https://fake.invalid/catalog-diag/agy-acp-server.zip",
            executable="agy_acp_server.par",
            sha256=_FAKE_ARCHIVE_SHA256,
            args=("--uid=",),
        )

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_bytes(_FAKE_ARCHIVE)
        return filename, {"Content-Length": str(len(_FAKE_ARCHIVE))}

    monkeypatch.setattr(official, "resolve_distribution", fake_distribution)
    monkeypatch.setattr(official.urllib.request, "urlretrieve", fake_urlretrieve)

    home = tmp_path / "hermes"
    home.mkdir()
    _seed_sentinels(home)
    target = _seed_catalog_provider(home)
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"
    official.install(prefix, bin_dir)
    after_server = _snapshot(home)
    assert official.status(prefix, bin_dir)["server_installed"] is True
    assert official.verify(prefix, bin_dir)["version_dir"].is_dir()
    assert deploy.verify(home) == []
    assert deploy.verify(home, allow_missing=True) == []
    assert _snapshot(home) == after_server
    # the catalog-pinned bytes are still the catalog's, not the repo's
    assert (target / "client.py").read_bytes() == _catalog_bytes("client.py")


@pytest.mark.skipif(os.name == "nt", reason="fake official archive is a POSIX fixture")
def test_combined_install_refuses_catalog_provider_after_server_lifecycle_completes(
    monkeypatch, tmp_path, capsys
):
    downloads: list[str] = []
    installer, _launcher = _prepare_combined_installer(monkeypatch, tmp_path, downloads)
    home = tmp_path / ".hermes"
    home.mkdir()
    _seed_sentinels(home)
    _seed_catalog_provider(home)
    provider_before = _snapshot(home / "plugins")
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"

    exit_code = installer.main(
        [
            "install",
            "--hermes-home",
            str(home),
            "--prefix",
            str(prefix),
            "--bin-dir",
            str(bin_dir),
        ]
    )

    assert exit_code == 2
    assert len(downloads) == 1  # server path B ran to completion first
    assert (prefix / installer.official_installer.VERSION).is_dir()
    assert _snapshot(home / "plugins") == provider_before
    assert not (home / "plugin-backups").exists()
    captured = capsys.readouterr()
    assert "catalog-managed provider" in captured.err
    assert "hermes plugins" in captured.err


# ---------------------------------------------------------------------------
# supported standalone install/update/delete remains intact
# ---------------------------------------------------------------------------


def test_standalone_marker_install_update_delete_lifecycle(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    sentinels = _seed_sentinels(home)

    reports = deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert len(reports) == 1 and reports[0].startswith("deployed:")
    target = _provider_target(home)
    marker = json.loads((target / deploy.INSTALL_PROVENANCE_FILE).read_text(encoding="utf-8"))
    assert marker["managed_by"] == deploy.STANDALONE_MANAGED_BY
    assert marker["managed_files"]["client.py"] == deploy.digest(deploy.SOURCE / "client.py")

    # intentional standalone update after local drift stays supported
    (target / "client.py").write_bytes(b"# drifted standalone copy\n")
    reports = deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert len(reports) == 1 and reports[0].startswith("deployed:")
    assert deploy.digest(target / "client.py") == deploy.digest(deploy.SOURCE / "client.py")

    reports = deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert reports[0].startswith("already current:")

    reports = deploy.uninstall(home, all_profiles=False)
    assert any("deleted:" in row for row in reports)
    assert not target.exists()
    for path, content in sentinels.items():
        assert path.read_bytes() == content
    # prior backups are user-visible state, not deleted by uninstall
    assert (home / "plugin-backups").is_dir()


def test_legacy_pre_marker_install_with_installer_artifacts_remains_updatable(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _provider_target(home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_text(
        "name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n",
        encoding="utf-8",
    )
    for name in deploy.REQUIRED:
        if name != "plugin.yaml":
            (target / name).write_bytes(f"# old provider {name}\n".encode())
    # A legacy installer-exclusive artifact: genuine pre-marker installs from
    # the pinned-server era carried at least one of these. (An opt-in private
    # overlay module copy is repo-portable and therefore NOT evidence.)
    (target / "launch_config.json").write_text(
        json.dumps({"process_command": "agy_acp_server.par", "process_args": ["--stdio"]}) + "\n",
        encoding="utf-8",
    )

    reports = deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert len(reports) == 1 and reports[0].startswith("deployed:")
    assert (target / "client.py").read_bytes() == (deploy.SOURCE / "client.py").read_bytes()
    # the upgraded tree now carries an explicit provenance marker
    marker = json.loads((target / deploy.INSTALL_PROVENANCE_FILE).read_text(encoding="utf-8"))
    assert marker["managed_by"] == deploy.STANDALONE_MANAGED_BY


def test_pre_marker_install_bytes_not_matching_any_verified_release_refused(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _provider_target(home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_text(
        "name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n",
        encoding="utf-8",
    )
    for name in deploy.REQUIRED:
        if name != "plugin.yaml":
            (target / name).write_bytes(f"# old provider {name}\n".encode())
    kind, reason = deploy.classify_provider_target(target)
    assert kind == "ambiguous"
    assert "provenance unknown" in reason


def _catalog_shaped_tree(home: Path) -> Path:
    """Provider directory with the canonical manifest+file set and NO ownership
    evidence at all: no provenance marker, no legacy installer artifact, no
    catalog sidecar, no install metadata. Byte content matches no release this
    installer ever shipped — indistinguishable from a manually copied or
    foreign-pinned catalog-compatible tree."""
    target = _provider_target(home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_bytes(
        b"name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.1\n"
    )
    for name in deploy.REQUIRED:
        if name != "plugin.yaml":
            (target / name).write_bytes(b"# foreign catalog-compatible body " + name.encode() + b"\n")
    return target


def test_catalog_shaped_tree_without_ownership_evidence_is_ambiguous(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _catalog_shaped_tree(home)
    kind, reason = deploy.classify_provider_target(target)
    assert kind == "ambiguous"
    assert target.is_dir()


def test_uninstall_refuses_annihilating_catalog_shaped_tree_without_provenance(tmp_path):
    # classify-as-standalone here means shutil.rmtree with no backup.
    home = tmp_path / "hermes"
    home.mkdir()
    target = _catalog_shaped_tree(home)
    before = _snapshot(target)
    with pytest.raises(ValueError, match="refusing to (overwrite|delete)"):
        deploy.uninstall(home, all_profiles=False)
    assert target.is_dir()
    assert _snapshot(target) == before


def test_install_refuses_overwriting_catalog_shaped_tree_without_provenance(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    target = _catalog_shaped_tree(home)
    before = _snapshot(target)
    with pytest.raises(ValueError, match="refusing to overwrite"):
        deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert _snapshot(target) == before
    assert not (home / "plugin-backups").exists()


def test_catalog_shaped_tree_with_private_overlay_copy_is_still_refused(tmp_path):
    # A manually assembled provider copy may carry a private opt-in overlay
    # module (historical reference moved it out of the public plugin tree). A portable
    # copy is not ownership evidence, so the tree must fail closed anyway.
    home = tmp_path / "hermes"
    home.mkdir()
    target = _catalog_shaped_tree(home)
    (target / "portfolio_policy.py").write_bytes(b"# private overlay copy\n")
    kind, reason = deploy.classify_provider_target(target)
    assert kind == "ambiguous"
    before = _snapshot(target)
    with pytest.raises(ValueError, match="refusing to (overwrite|delete)"):
        deploy.uninstall(home, all_profiles=False)
    assert _snapshot(target) == before


def test_pre_marker_tree_matching_a_verified_release_lineage_stays_updatable(
    tmp_path, monkeypatch
):
    # The compatibility carve-out: a full managed set whose bytes match a
    # release set this installer verifiably shipped before provenance markers.
    home = tmp_path / "hermes"
    home.mkdir()
    target = _provider_target(home)
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_bytes(
        b"name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n"
    )
    lineage: dict[str, str] = {}
    for name in deploy.REQUIRED:
        body = (
            b"name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n"
            if name == "plugin.yaml"
            else b"# verified prior release body " + name.encode() + b"\n"
        )
        (target / name).write_bytes(body)
        lineage[name] = hashlib.sha256(body).hexdigest()
    monkeypatch.setitem(deploy.PRE_MARKER_LINEAGE_SETS, "test-release", lineage)

    reports = deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    assert len(reports) == 1 and reports[0].startswith("deployed:")
    marker = json.loads((target / deploy.INSTALL_PROVENANCE_FILE).read_text(encoding="utf-8"))
    assert marker["managed_by"] == deploy.STANDALONE_MANAGED_BY


def test_official_uninstall_refuses_unmanaged_launcher(tmp_path):
    official = _load_official(f"catalog_imm_uninstall_{uuid.uuid4().hex[:8]}")
    from antigravity_acp.registry import VERSION

    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    version_dir = prefix / VERSION
    version_dir.mkdir(parents=True)
    (version_dir / "agy_acp_server.par").write_bytes(b"managed server body\n")
    bin_dir.mkdir()
    launcher = bin_dir / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n# user-owned wrapper\nexit 0\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        official.uninstall(prefix, bin_dir)

    assert "user-owned wrapper" in launcher.read_text(encoding="utf-8")
    assert version_dir.is_dir()


# ---------------------------------------------------------------------------
# empty HERMES_HOME: install -> status -> verify -> delete -> reinstall
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_empty_hermes_home_install_status_verify_delete_reinstall(monkeypatch, tmp_path):
    downloads: list[str] = []
    installer, launcher = _prepare_combined_installer(monkeypatch, tmp_path, downloads)
    home = tmp_path / ".hermes"
    home.mkdir()
    sentinels = _seed_sentinels(home)
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"
    args = [
        "--hermes-home",
        str(home),
        "--prefix",
        str(prefix),
        "--bin-dir",
        str(bin_dir),
    ]

    assert installer.main(["install", *args]) == 0
    assert len(downloads) == 1
    target = _provider_target(home)
    assert (target / "plugin.yaml").is_file()
    assert (target / deploy.INSTALL_PROVENANCE_FILE).is_file()
    for name in deploy.REQUIRED:
        assert deploy.digest(target / name) == deploy.digest(deploy.SOURCE / name)

    assert installer.main(["status", *args]) == 0
    assert installer.main(["verify", *args]) == 0

    assert installer.main(["delete", *args]) == 0
    assert not target.exists()
    assert not (prefix / installer.official_installer.VERSION).exists()
    assert not launcher.exists()

    assert installer.main(["install", *args]) == 0
    assert len(downloads) == 2  # explicit reinstall re-runs the pinned download
    assert (target / deploy.INSTALL_PROVENANCE_FILE).is_file()
    assert installer.main(["status", *args]) == 0

    for path, content in sentinels.items():
        assert path.read_bytes() == content


# ---------------------------------------------------------------------------
# distinct, security-safe actionable diagnostics
# ---------------------------------------------------------------------------


def test_missing_binary_error_is_actionable(tmp_path):
    official = _load_official(f"catalog_imm_missing_{uuid.uuid4().hex[:8]}")
    with pytest.raises(RuntimeError, match="server binary is missing") as caught:
        official.verify(tmp_path / "empty-prefix", tmp_path / "empty-bin")
    message = str(caught.value)
    assert "install_official.py" in message
    assert "plugin.yaml" in message  # discloses the never-download-at-load policy


def test_version_mismatch_error_is_distinct_from_missing(tmp_path):
    official = _load_official(f"catalog_imm_mismatch_{uuid.uuid4().hex[:8]}")
    from antigravity_acp.registry import VERSION, resolve_distribution

    prefix = tmp_path / "opt" / "antigravity-acp"
    stale = prefix / "1.2.3-ancient"
    stale.mkdir(parents=True)
    (stale / resolve_distribution().executable).write_bytes(b"# stale server\n")

    with pytest.raises(RuntimeError, match="version mismatch") as caught:
        official.verify(prefix, tmp_path / "bin")
    mismatch = str(caught.value)
    assert VERSION in mismatch
    assert "1.2.3-ancient" in mismatch
    assert "install_acp.py update" in mismatch

    with pytest.raises(RuntimeError, match="server binary is missing") as missing:
        official.verify(tmp_path / "nothing-here", tmp_path / "bin")
    assert "version mismatch" not in str(missing.value)
    assert "missing" not in mismatch.lower().replace("version mismatch", "")


@pytest.mark.skipif(os.name == "nt", reason="executable bits are POSIX semantics")
def test_path_launcher_errors_are_distinct(monkeypatch, tmp_path):
    installer = _load_script(
        "install_acp.py", f"catalog_imm_path_errors_{uuid.uuid4().hex[:8]}"
    )
    missing_command = tmp_path / "bin" / "antigravity-acp-official"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(missing_command))
    with pytest.raises(RuntimeError, match="not executable from Hermes") as caught:
        installer._provider_command(tmp_path / "bin", require_existing=True)
    missing_message = str(caught.value)
    assert "PATH" in missing_message

    missing_command.parent.mkdir(parents=True)
    missing_command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    missing_command.chmod(0o644)
    with pytest.raises(RuntimeError) as caught:
        installer._provider_command(tmp_path / "bin", require_existing=True)
    nonexecutable_message = str(caught.value)
    # historical reference: the non-executable diagnostic is actionable (names the
    # launcher and the recovery) while staying distinct from the missing/
    # PATH diagnostic.
    assert nonexecutable_message.startswith("provider launcher ")
    assert "is not executable" in nonexecutable_message
    assert "restore the executable bit" in nonexecutable_message
    assert missing_message != nonexecutable_message


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_acp_initialize_failure_error_is_actionable(monkeypatch, tmp_path):
    downloads: list[str] = []
    installer, _launcher = _prepare_combined_installer(monkeypatch, tmp_path, downloads)
    home = tmp_path / ".hermes"
    home.mkdir()
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"
    args = [
        "install",
        "--hermes-home",
        str(home),
        "--prefix",
        str(prefix),
        "--bin-dir",
        str(bin_dir),
    ]
    assert installer.main(args) == 0

    def failing_probe(*_args, **_kwargs):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(installer.subprocess, "run", failing_probe)
    with pytest.raises(RuntimeError, match="initialize probe failed") as caught:
        installer.verify(home, prefix, bin_dir)
    assert "acp_probe.py" in str(caught.value)


# ---------------------------------------------------------------------------
# never download or self-update the server during plugin loading/import
# ---------------------------------------------------------------------------


def _load_installed_provider(monkeypatch, provider_path: Path):
    registered = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    setattr(providers, "register_provider", registered.append)
    providers_base = types.ModuleType("providers.base")
    setattr(providers_base, "ProviderProfile", FakeProviderProfile)
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    name = f"installed_antigravity_provider_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(
        name,
        provider_path / "__init__.py",
        submodule_search_locations=[str(provider_path)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    assert registered == [module.antigravity_acp]
    return module


def test_plugin_import_never_downloads_or_self_updates(monkeypatch, tmp_path):
    import urllib.request

    home = tmp_path / "hermes"
    home.mkdir()
    deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    plugin = _provider_target(home)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider import performed a download or spawn")

    monkeypatch.setattr(urllib.request, "urlretrieve", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "call", forbidden)
    launcher = tmp_path / "bin" / "antigravity-acp-official"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(launcher))

    provider = _load_installed_provider(monkeypatch, plugin)
    provider.antigravity_acp.create_client()

    # static guard: the shipped provider source has no installer/download hooks
    source_text = "".join(
        (plugin / name).read_text(encoding="utf-8")
        for name in ("__init__.py", "client.py", "bridge.py", "hermes_compat.py")
    )
    for token in ("urlretrieve", "urlopen", "install_official", "install_acp"):
        assert token not in source_text
