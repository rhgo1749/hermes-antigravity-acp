"""Generic installation, vanilla provider registration, and safe repository audit."""
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


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _fake_official_archive_bytes() -> bytes:
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


_FAKE_ARCHIVE_BYTES = _fake_official_archive_bytes()
_FAKE_ARCHIVE_SHA256 = hashlib.sha256(_FAKE_ARCHIVE_BYTES).hexdigest()


def _fake_official_archive(destination: Path) -> None:
    destination.write_bytes(_FAKE_ARCHIVE_BYTES)


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


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_clean_vanilla_install_and_provider_registration(monkeypatch, tmp_path, capsys):
    installer = _load_script(SCRIPTS / "install_acp.py", "generic_install_smoke")
    monkeypatch.setenv("HOME", str(tmp_path))
    if os.name == "nt":
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
    launcher = tmp_path / ".local" / "bin" / installer._launcher_name()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(launcher))
    downloads = []

    def fake_download(_url: str, filename: str):
        downloads.append(filename)
        _fake_official_archive(Path(filename))
        return filename, None

    monkeypatch.setattr(installer.official_installer.urllib.request, "urlretrieve", fake_download)
    pinned = installer.official_installer.resolve_distribution()
    monkeypatch.setattr(
        installer.official_installer,
        "resolve_distribution",
        lambda *_args, **_kwargs: dataclasses.replace(pinned, sha256=_FAKE_ARCHIVE_SHA256),
    )

    home = tmp_path / ".hermes"
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"
    sentinels = {
        home / "config.yaml": b"user settings remain untouched\n",
        home / ".env": b"local secret placeholder\n",
        home / "acp-accounts.json": b"private mux registry remains untouched\n",
        home / "sessions.sqlite": b"session state remains untouched\n",
    }
    home.mkdir()
    for path, content in sentinels.items():
        path.write_bytes(content)
    non_target_home = home / "profiles" / "portfolio-manager"
    non_target_home.mkdir(parents=True)
    non_target_config = non_target_home / "config.yaml"
    non_target_config.write_text("profile settings remain untouched\n", encoding="utf-8")

    install_args = [
        "install", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir)
    ]
    assert installer.main(install_args) == 0
    assert len(downloads) == 1
    assert not (non_target_home / "plugins").exists()
    assert non_target_config.read_text(encoding="utf-8") == "profile settings remain untouched\n"
    assert installer.main([
        "status", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir)
    ]) == 0
    assert installer.main([
        "status", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir),
        "--all-profiles",
    ]) == 1
    assert installer.main(install_args) == 0
    assert len(downloads) == 1
    assert installer.main([
        "verify", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir)
    ]) == 0
    assert "unauthenticated ACP initialize verified" in capsys.readouterr().out

    assert installer.main([*install_args, "--all-profiles"]) == 0
    assert (non_target_home / "plugins" / "model-providers" / "antigravity-acp" / "plugin.yaml").is_file()
    assert non_target_config.read_text(encoding="utf-8") == "profile settings remain untouched\n"
    assert len(downloads) == 1
    assert installer.main([
        "status", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir),
        "--all-profiles",
    ]) == 0

    for path, content in sentinels.items():
        assert path.read_bytes() == content
    plugin = home / "plugins" / "model-providers" / "antigravity-acp"
    assert (plugin / "plugin.yaml").is_file()
    assert (plugin / "hermes_compat.py").is_file()
    assert not (plugin / "portfolio_policy.py").exists()
    assert installer.provider_installer.verify(home) == []

    provider = _load_installed_provider(monkeypatch, plugin)
    client = provider.antigravity_acp.create_client()
    assert client._acp_command == str(bin_dir / installer._launcher_name())
    assert client._acp_args == []
    # R7 (historical reference rework-r4): the generic install is NOT banned — the clean
    # obligation-evidence path loads the provider with zero overlays.
    assert sys.modules[provider.__name__ + ".client"].policy_overlays == ()



def test_windows_launcher_text_round_trips_universal_newlines(monkeypatch, tmp_path):
    official = _load_script(SCRIPTS / "install_official.py", "windows_launcher_newline_test")
    login = _load_script(ROOT / "hermes-plugin" / "antigravity-acp" / "login.py", "windows_login_newline_test")
    target = tmp_path / "server.exe"
    with monkeypatch.context() as scoped:
        scoped.setattr(official.os, "name", "nt")
        current, legacy = official._launcher_variants(target, ())
        login_bodies = login._managed_launcher_bodies(str(target), ())
    assert {current, legacy} == login_bodies
    launcher = tmp_path / "launcher.cmd"
    for content in (current, legacy):
        launcher.write_bytes(content.replace("\n", "\r\n").encode("utf-8"))
        assert launcher.read_text(encoding="utf-8") == content


def test_installer_refuses_to_replace_an_unmanaged_launcher(tmp_path):
    official = _load_script(SCRIPTS / "install_official.py", "official_installer_guard_test")
    launcher = tmp_path / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n# user-owned wrapper\nexit 0\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        official._write_launcher(launcher, tmp_path / "server.par", ())
    assert "user-owned wrapper" in launcher.read_text(encoding="utf-8")


def test_default_home_matches_windows_hermes_and_preserves_override(tmp_path):
    deployer = _load_script(SCRIPTS / "deploy_hermes_profiles.py", "windows_home_resolution_test")
    local = tmp_path / "Local"
    home = tmp_path / "user"
    resolve = deployer._default_hermes_home
    assert resolve("win32", {"LOCALAPPDATA": str(local)}, home) == local / "hermes"
    assert resolve("win32", {}, home) == home / "AppData" / "Local" / "hermes"
    assert resolve("linux", {}, home) == home / ".hermes"
    assert resolve("win32", {"LOCALAPPDATA": str(local), "HERMES_HOME": str(home / "custom")}, home) == home / "custom"
    assert resolve("win32", {"LOCALAPPDATA": str(local), "HERMES_DATA_DIR_SUFFIX": "-test"}, home) == local / "hermes-test"


def test_installer_default_hermes_home_respects_environment(monkeypatch, tmp_path):
    custom_home = tmp_path / "custom-hermes"
    monkeypatch.setenv("HERMES_HOME", str(custom_home))
    installer = _load_script(SCRIPTS / "install_acp.py", "custom_hermes_home_default_test")
    assert installer.DEFAULT_HERMES_HOME == custom_home
    deployer = _load_script(
        SCRIPTS / "deploy_hermes_profiles.py", "custom_deployer_hermes_home_default_test"
    )
    assert deployer.DEFAULT_HERMES_HOME == custom_home


def test_installer_rejects_symlinked_hermes_home(monkeypatch, tmp_path):
    installer = _load_script(SCRIPTS / "install_acp.py", "symlink_hermes_home_test")
    real_home = tmp_path / "real-hermes"
    real_home.mkdir()
    linked_home = tmp_path / "linked-hermes"
    try:
        linked_home.symlink_to(real_home, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {type(exc).__name__}")
    launcher = tmp_path / "custom-bin" / "antigravity-acp-official"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(launcher))
    with pytest.raises(ValueError, match="symlinked Hermes home"):
        installer.install(linked_home, tmp_path / "opt", tmp_path / "custom-bin")


def _seed_outdated_provider_tree(plugin, deployer) -> None:
    plugin.mkdir(parents=True)
    (plugin / "plugin.yaml").write_text(
        "name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n",
        encoding="utf-8",
    )
    for name in deployer.REQUIRED:
        if name != "plugin.yaml":
            (plugin / name).write_text("# old provider " + name + "\n", encoding="utf-8")
    (plugin / deployer.INSTALL_PROVENANCE_FILE).write_text(
        json.dumps({"managed_by": deployer.STANDALONE_MANAGED_BY}) + "\n",
        encoding="utf-8",
    )


def test_generic_install_refuses_before_any_write_when_a_late_profile_carries_an_overlay(
    tmp_path,
):
    """historical reference rework-r2 RED1: pre-mutation refusal across ALL targets.

    The overlay-bearing profile ("zeta") sorts LAST in ``homes()`` iteration
    order. The generic deploy must still refuse before a single write to any
    earlier profile: the default home gets no provider tree, the earlier
    profile's bytes are untouched, and the overlay hash is unchanged.
    """
    deployer = _load_script(
        SCRIPTS / "deploy_hermes_profiles.py", "overlay_guard_multi_profile_test"
    )
    home = tmp_path / "hermes"
    home.mkdir()
    for name in ("alpha", "zeta"):
        (home / "profiles" / name).mkdir(parents=True)
    alpha = home / "profiles" / "alpha" / "plugins" / "model-providers" / deployer.PROVIDER
    zeta = home / "profiles" / "zeta" / "plugins" / "model-providers" / deployer.PROVIDER
    _seed_outdated_provider_tree(alpha, deployer)
    _seed_outdated_provider_tree(zeta, deployer)
    overlay = zeta / "portfolio_policy.py"
    overlay.write_text("# live private opt-in overlay\n", encoding="utf-8")
    overlay_sha_before = hashlib.sha256(overlay.read_bytes()).hexdigest()
    alpha_before = {child.name: child.read_bytes() for child in alpha.iterdir()}
    assert [label for label, _ in deployer.homes(home)] == ["default", "alpha", "zeta"]

    with pytest.raises(ValueError, match="unmanaged file") as excinfo:
        deployer.install(deployer.SOURCE, home, apply=True)
    assert "no files were touched" in str(excinfo.value)

    # Zero writes across ALL profiles: nothing was staged, backed up, or
    # created for any target — including the profile that sorts before the
    # overlay-bearing one and the default home (which had no provider yet).
    assert not (home / "plugins" / "model-providers").exists()
    assert {child.name: child.read_bytes() for child in alpha.iterdir()} == alpha_before
    assert hashlib.sha256(overlay.read_bytes()).hexdigest() == overlay_sha_before
    assert not (home / "plugin-backups").exists()


def test_provider_upgrade_preserves_legacy_launch_config_and_pin(monkeypatch, tmp_path):
    """historical reference rework-r2: an upgrade refuses over overlays, carries state.

    The generic upgrade now refuses while a live opt-in overlay sits in the
    target tree (zero writes). Under the explicit operator-approved override
    the upgrade proceeds and still carries ONLY installer state: the legacy
    par.txt pin and literal launch settings survive; the unmanaged overlay is
    dropped from the live tree (recoverable from the deployment backup) and
    never propagated. The upgraded tree's provenance declares no overlay, so
    loading it under a neutral home runs with no policy.
    """
    deployer = _load_script(
        SCRIPTS / "deploy_hermes_profiles.py", "legacy_launch_config_upgrade_test"
    )
    hermes_home = tmp_path / "profiles" / "portfolio-manager"
    plugin = hermes_home / "plugins" / "model-providers" / "antigravity-acp"
    plugin.mkdir(parents=True)
    (plugin / "plugin.yaml").write_bytes((deployer.SOURCE / "plugin.yaml").read_bytes())
    (plugin / "__init__.py").write_text(
        """from providers import register_provider
from providers.base import ProviderProfile

class AntigravityACPProfile(ProviderProfile):
    pass

antigravity_acp = AntigravityACPProfile(
    process_command="antigravity-acp-mux",
    process_args=("--uid=",),
)
register_provider(antigravity_acp)
""",
        encoding="utf-8",
    )
    pinned_server = tmp_path / "pinned-server.par"
    pinned_server.write_bytes(b"legacy pinned server\n")
    pin_file = plugin / "par.txt"
    pin_file.write_text(str(pinned_server), encoding="utf-8")
    legacy_policy = plugin / "portfolio_policy.py"
    legacy_policy.write_bytes(
        b"# portfolio overlay placeholder (public tree carries no private-ops asset)\n"
    )
    expected_policy = legacy_policy.read_bytes()

    # Rework-r2 pre-mutation guard: the generic upgrade refuses while the
    # overlay is live; the pin and overlay keep their exact bytes.
    with pytest.raises(ValueError, match="unmanaged file"):
        deployer.install(deployer.SOURCE, hermes_home, apply=True, all_profiles=False)
    assert pin_file.read_text(encoding="utf-8") == str(pinned_server)
    assert legacy_policy.read_bytes() == expected_policy
    assert not (hermes_home / "plugin-backups").exists()

    result = deployer.install(
        deployer.SOURCE,
        hermes_home,
        apply=True,
        all_profiles=False,
        allow_unmanaged_overlays=True,
    )

    assert len(result) == 1
    assert pin_file.read_text(encoding="utf-8") == str(pinned_server)
    # The unmanaged overlay is NOT propagated into the upgraded tree, but it
    # remains recoverable in the backup the installer renamed aside.
    assert not legacy_policy.exists()
    backups = list((hermes_home / "plugin-backups").glob("deploy-*/default"))
    assert len(backups) == 1
    assert (backups[0] / "portfolio_policy.py").read_bytes() == expected_policy
    # Loading the upgraded tree under a neutral home works and resolves the
    # preserved pin/launch settings; the public tree simply has no policy.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "neutral-home"))
    provider = _load_installed_provider(monkeypatch, plugin)
    client = provider.antigravity_acp.create_client()
    assert client._acp_command == "antigravity-acp-mux"
    assert client._acp_args == ["--uid="]
    client_module = sys.modules[provider.__name__ + ".client"]
    assert client_module._read_par_pin() == str(pinned_server)
    assert client_module.policy_overlays == ()
    # Rework-r2/r4: the profile-name identity match is gone from client.py,
    # so this operator-overridden tree (whose provenance declares no overlay
    # and whose home carries no obligation record) starts by explicit
    # operator choice instead of via public identity matching. The fail-closed
    # property itself lives in the obligation evidence — asserted in
    # tests/test_portfolio_safety_hotfix.py.
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    overridden = _load_installed_provider(monkeypatch, plugin)
    overridden.antigravity_acp.create_client()
    assert sys.modules[overridden.__name__ + ".client"].policy_overlays == ()


def test_hygiene_scanner_avoids_placeholders_and_flags_sensitive_content_and_paths():
    audit = _load_script(SCRIPTS / "audit_public_tree.py", "repo_hygiene_test")
    benign = "https://github.com/agentclientprotocol/registry plus YOUR_API_KEY and docs."
    assert audit.scan_text(benign) == []
    auth_prefix = "https://accounts.google.com/o/oauth2/v2/auth?client_id="
    assert audit.scan_text(auth_prefix + "abc") == []
    assert audit.scan_text(auth_prefix + ("x" * 40)) == ["oauth_url"]
    synthetic = "Authorization: Bearer " + ("z" * 40)
    assert audit.scan_text(synthetic) == ["bearer_token"]
    assert audit.sensitive_path(".env.example") is None
    assert audit.sensitive_path("examples/acp-accounts.example.json") is None
    assert audit.sensitive_path(".env.local") == "sensitive_filename"
    assert audit.sensitive_path("logs/acp.log") == "local_artifact_filename"
    assert audit.sensitive_path("plugin-backups/deploy-123/provider.par") == "local_artifact_filename"


def test_hygiene_cli_suppresses_matching_values_and_paths(tmp_path, capsys):
    audit = _load_script(SCRIPTS / "audit_public_tree.py", "repo_hygiene_cli_test")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".env.local").write_text("synthetic placeholder\n", encoding="utf-8")
    (tmp_path / "private-probe.txt").write_text(
        "Authorization: Bearer " + ("z" * 40), encoding="utf-8"
    )

    assert audit.main(["--root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "bearer_token=1" in output
    assert "sensitive_filename=1" in output
    assert "private-probe.txt" not in output
    assert ".env.local" not in output
    assert "z" * 24 not in output


def test_gitignore_blocks_local_secrets_logs_and_deployment_artifacts_but_not_examples():
    ignored = (
        ".env", ".env.local", "logs/runtime.log", "plugin-backups/deploy-x/provider.par",
        "deployment-artifacts/archive.zip", "credentials.json", "acp-accounts.json",
    )
    for path in ignored:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", path],
            check=False,
        )
        assert result.returncode == 0, path
    for path in (".env.example", "examples/acp-accounts.example.json"):
        result = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", path],
            check=False,
        )
        assert result.returncode == 1, path
