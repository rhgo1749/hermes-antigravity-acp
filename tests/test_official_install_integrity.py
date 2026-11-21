"""Credential-free download-integrity contract for scripts/install_official.py.

No test here performs a network download or touches real credentials: every
download is a fake that materializes fixture bytes, and the registry pin is
patched to the fixture digest so the verification path itself is exercised.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

SERVER = b"""#!/bin/sh
# fake official agy_acp_server.par body
echo fake
"""


def _load_official_installer(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / "install_official.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _archive_bytes(payload: bytes = SERVER) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("agy_acp_server.par", date_time=(2026, 1, 1, 0, 0, 0))
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, payload)
    return buffer.getvalue()


ARCHIVE = _archive_bytes()
ARCHIVE_SHA256 = hashlib.sha256(ARCHIVE).hexdigest()
TAMPERED = ARCHIVE + b"tamper"


def _patched(monkeypatch, module, *, sha256: str, serve: bytes, name: str):
    from antigravity_acp.registry import Distribution

    calls: list[str] = []

    def fake_distribution(*_args, **_kwargs):
        return Distribution(
            url=f"https://fake.invalid/{name}/agy-acp-server.zip",
            executable="agy_acp_server.par",
            sha256=sha256,
            args=("--uid=",),
        )

    def fake_urlretrieve(url: str, filename: str):
        calls.append(url)
        Path(filename).write_bytes(serve)
        return filename, {"Content-Length": str(len(serve))}

    monkeypatch.setattr(module, "resolve_distribution", fake_distribution)
    monkeypatch.setattr(module.urllib.request, "urlretrieve", fake_urlretrieve)
    return calls


def _paths(prefix: Path, bin_dir: Path, module) -> tuple[Path, Path]:
    version_dir = prefix / module.VERSION
    launcher = bin_dir / (
        "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"
    )
    return version_dir, launcher


def _launcher_text(target: str) -> str:
    quoted = target.replace("'", "'\\''")
    command = f"exec '{quoted}' '--uid=' \"$@\"\n"
    return f"#!/bin/sh\n# managed by hermes-antigravity-acp\n{command}"


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_matching_publisher_digest_installs(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_match")
    calls = _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="match")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"

    result = module.install(prefix, bin_dir)

    version_dir, launcher = _paths(prefix, bin_dir, module)
    assert calls == ["https://fake.invalid/match/agy-acp-server.zip"]
    assert result["version_dir"] == version_dir
    assert result["executable"].name == "agy_acp_server.par"
    assert launcher.is_file()
    assert (version_dir / "agy-acp-server.zip").read_bytes() == ARCHIVE
    assert not [p for p in prefix.iterdir() if p.name.startswith(".antigravity-acp-install-")]


def test_existing_install_acquires_only_pinned_archive(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_existing")
    calls = _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="existing")
    prefix = tmp_path / "opt" / "antigravity-acp"
    version_dir = prefix / module.VERSION
    version_dir.mkdir(parents=True)
    executable = version_dir / "agy_acp_server.par"
    executable.write_bytes(SERVER)
    module.install(prefix, tmp_path / "bin")
    assert (version_dir / "agy-acp-server.zip").read_bytes() == ARCHIVE
    assert executable.read_bytes() == SERVER
    module.install(prefix, tmp_path / "bin")
    assert len(calls) == 1


def test_existing_install_refuses_tampered_archive(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_existing_bad")
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=TAMPERED, name="bad")
    prefix = tmp_path / "opt" / "antigravity-acp"
    version_dir = prefix / module.VERSION
    version_dir.mkdir(parents=True)
    executable = version_dir / "agy_acp_server.par"
    executable.write_bytes(SERVER)
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        module.install(prefix, tmp_path / "bin")
    assert executable.read_bytes() == SERVER
    assert not (version_dir / "agy-acp-server.zip").exists()


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_tampered_archive_fails_before_extraction_and_preserves_existing_install(
    tmp_path, monkeypatch
):
    module = _load_official_installer("integrity_tamper")
    calls = _patched(
        monkeypatch, module, sha256=ARCHIVE_SHA256, serve=TAMPERED, name="tamper"
    )
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    previous = prefix / "0.0.9-previous"
    previous.mkdir(parents=True)
    previous_executable = previous / "agy_acp_server.par"
    previous_executable.write_bytes(b"previous managed server\n")
    launcher = bin_dir / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("user sentinel launcher\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        module.install(prefix, bin_dir)

    assert len(calls) == 1
    version_dir, _ = _paths(prefix, bin_dir, module)
    assert not version_dir.exists()
    assert not any(
        p.name.startswith(".antigravity-acp-install-") for p in prefix.iterdir()
    )
    assert previous_executable.read_bytes() == b"previous managed server\n"
    assert launcher.read_text(encoding="utf-8") == "user sentinel launcher\n"


@pytest.mark.parametrize("bad_pin", ["", "deadbeef", "Z" * 64, ARCHIVE_SHA256 + "f"])
def test_missing_or_malformed_pin_is_rejected(bad_pin: str):
    module = _load_official_installer(f"integrity_bad_pin_{abs(hash(bad_pin)) % 10**8}")
    with pytest.raises(RuntimeError, match="no verifiable SHA-256 pin"):
        module._validate_archive_pin(bad_pin)


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_missing_pin_stops_install_without_network(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_missing_pin_install")
    calls = _patched(monkeypatch, module, sha256="", serve=ARCHIVE, name="stopped")
    with pytest.raises(RuntimeError, match="no verifiable SHA-256 pin"):
        module.install(tmp_path / "opt" / "antigravity-acp", tmp_path / "bin")
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_interrupted_download_fails_closed_without_state_mutation(
    tmp_path, monkeypatch
):
    module = _load_official_installer("integrity_interrupted")
    from antigravity_acp.registry import Distribution

    def fake_distribution(*_args, **_kwargs):
        return Distribution(
            url="https://fake.invalid/interrupted/agy-acp-server.zip",
            executable="agy_acp_server.par",
            sha256=ARCHIVE_SHA256,
            args=("--uid=",),
        )

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_bytes(ARCHIVE[: len(ARCHIVE) // 2])
        raise urllib.error.URLError("synthetic connection reset")

    monkeypatch.setattr(module, "resolve_distribution", fake_distribution)
    monkeypatch.setattr(module.urllib.request, "urlretrieve", fake_urlretrieve)
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"

    # historical reference: an interrupted download surfaces as a safe, actionable
    # download-failure diagnostic (chained from the transport error) instead
    # of a bare transport traceback.
    with pytest.raises(RuntimeError, match="download failed or was interrupted") as excinfo:
        module.install(prefix, bin_dir)
    assert isinstance(excinfo.value.__cause__, urllib.error.URLError)

    version_dir, launcher = _paths(prefix, bin_dir, module)
    assert not version_dir.exists()
    assert not launcher.exists()
    assert not any(
        p.name.startswith(".antigravity-acp-install-") for p in prefix.iterdir()
    )


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_truncated_archive_fails_closed(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_truncated")
    _patched(
        monkeypatch,
        module,
        sha256=ARCHIVE_SHA256,
        serve=ARCHIVE[: len(ARCHIVE) // 2],
        name="truncated",
    )
    prefix = tmp_path / "opt" / "antigravity-acp"
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        module.install(prefix, tmp_path / "bin")
    version_dir, _ = _paths(prefix, tmp_path / "bin", module)
    assert not version_dir.exists()


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_failed_update_then_rollback_preserves_previous_version(tmp_path, monkeypatch):
    module = _load_official_installer("integrity_rollback")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    old_version = "0.0.9-old"
    new_version = "9.9.9-newer"

    monkeypatch.setattr(module, "VERSION", old_version)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="old")
    old_result = module.install(prefix, bin_dir)
    launcher: Path = old_result["launcher"]
    old_target = str(old_result["executable"])
    assert launcher.read_text(encoding="utf-8") == _launcher_text(old_target)

    monkeypatch.setattr(module, "VERSION", new_version)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=TAMPERED, name="bad")
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        module.install(prefix, bin_dir)
    assert not (prefix / new_version).exists()
    assert launcher.read_text(encoding="utf-8") == _launcher_text(old_target)
    assert (prefix / old_version / "agy_acp_server.par").read_bytes() == SERVER

    monkeypatch.setattr(module, "VERSION", old_version)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="old2")
    again = module.install(prefix, bin_dir)
    assert again["executable"] == old_result["executable"]
    assert launcher.read_text(encoding="utf-8") == _launcher_text(old_target)


# ---------------------------------------------------------------------------
# Prior official launcher ownership on version migration (1.4.4 -> 1.5.2).
#
# _write_launcher used to accept only the launcher for the *new* target (or
# its legacy unmarked twin), so an upgrade from a previously installed
# official version refused its own old launcher and deadlocked the update.
# These tests pin the fix: a launcher is adopted only when its bytes are
# byte-exactly what this installer generated for a version directory that
# really exists under the selected prefix (mapped through the selected
# runtime-prefix, with that version's own executable layout). Everything
# else — foreign targets, foreign args, absent/symlinked version dirs,
# unmanaged bytes — stays refused, and the new archive must verify before
# the launcher is ever repointed.
# ---------------------------------------------------------------------------

PRIOR_VERSION = "1.4.4"
NEW_VERSION = "1.5.2"


def _legacy_launcher_text(target: str) -> str:
    quoted = target.replace("'", "'\\''")
    return f"#!/bin/sh\nexec '{quoted}' '--uid=' \"$@\"\n"


def _install_prior_official(tmp_path, monkeypatch, module, *, runtime_prefix=None):
    """Install a fake 1.4.4 official release and return its install result."""
    monkeypatch.setattr(module, "VERSION", PRIOR_VERSION)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="v144")
    return module.install(
        tmp_path / "opt" / "antigravity-acp",
        tmp_path / "bin",
        runtime_prefix=runtime_prefix,
    )


def _promote_to_new_version(module, monkeypatch, *, serve=ARCHIVE):
    monkeypatch.setattr(module, "VERSION", NEW_VERSION)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=serve, name="v152")


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_adopts_exact_prior_official_launcher(tmp_path, monkeypatch):
    module = _load_official_installer("migration_adopt_prior")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    prior_launcher_text = prior["launcher"].read_text(encoding="utf-8")
    assert prior_launcher_text == _launcher_text(str(prior["executable"]))
    prior_archive = (prefix / PRIOR_VERSION / "agy-acp-server.zip").read_bytes()

    _promote_to_new_version(module, monkeypatch)
    result = module.install(prefix, bin_dir)

    launcher = bin_dir / "antigravity-acp-official"
    assert launcher.read_text(encoding="utf-8") == _launcher_text(str(result["executable"]))
    assert os.access(launcher, os.X_OK)
    # The prior install and its retained archive are preserved untouched.
    assert (prefix / PRIOR_VERSION / "agy_acp_server.par").read_bytes() == SERVER
    assert (prefix / PRIOR_VERSION / "agy-acp-server.zip").read_bytes() == prior_archive
    assert result["version_dir"] == prefix / NEW_VERSION


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_adopts_legacy_unmarked_prior_launcher(tmp_path, monkeypatch):
    module = _load_official_installer("migration_adopt_legacy")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    launcher = prior["launcher"]
    launcher.write_text(_legacy_launcher_text(str(prior["executable"])), encoding="utf-8")

    _promote_to_new_version(module, monkeypatch)
    result = module.install(prefix, bin_dir)

    assert launcher.read_text(encoding="utf-8") == _launcher_text(str(result["executable"]))


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_tampered_new_archive_keeps_prior_launcher_untouched(tmp_path, monkeypatch):
    module = _load_official_installer("migration_tampered_new")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    prior_text = prior["launcher"].read_text(encoding="utf-8")

    _promote_to_new_version(module, monkeypatch, serve=TAMPERED)
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        module.install(prefix, bin_dir)

    # The new archive is verified before the launcher is ever repointed.
    assert prior["launcher"].read_text(encoding="utf-8") == prior_text
    assert not (prefix / NEW_VERSION).exists()
    assert (prefix / PRIOR_VERSION / "agy_acp_server.par").read_bytes() == SERVER


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_refuses_unmanaged_launcher(tmp_path, monkeypatch):
    module = _load_official_installer("migration_unmanaged")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    sentinel = "#!/bin/sh\n# hand-written by an operator\nexec /opt/custom/agy \"$@\"\n"
    prior["launcher"].write_text(sentinel, encoding="utf-8")

    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)

    assert prior["launcher"].read_text(encoding="utf-8") == sentinel
    assert (prefix / PRIOR_VERSION / "agy_acp_server.par").read_bytes() == SERVER


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_refuses_prior_shaped_launcher_with_foreign_target(tmp_path, monkeypatch):
    module = _load_official_installer("migration_foreign_target")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    # Byte-exact managed format, plausible prior version name, but the target
    # lives under a different prefix than the one selected for this install.
    foreign = tmp_path / "elsewhere" / "antigravity-acp" / PRIOR_VERSION / "agy_acp_server.par"
    text = _launcher_text(str(foreign))
    prior["launcher"].write_text(text, encoding="utf-8")

    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)

    assert prior["launcher"].read_text(encoding="utf-8") == text


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_refuses_prior_target_with_foreign_args(tmp_path, monkeypatch):
    module = _load_official_installer("migration_foreign_args")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    quoted = str(prior["executable"]).replace("'", "'\\''")
    text = (
        "#!/bin/sh\n# managed by hermes-antigravity-acp\n"
        f"exec '{quoted}' '--evil-flag=' \"$@\"\n"
    )
    prior["launcher"].write_text(text, encoding="utf-8")

    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)

    assert prior["launcher"].read_text(encoding="utf-8") == text


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_refuses_prior_shaped_launcher_without_installed_version(tmp_path, monkeypatch):
    module = _load_official_installer("migration_no_prior_dir")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    prior_text = prior["launcher"].read_text(encoding="utf-8")
    # Ownership is not a marker match: the prior version must actually be
    # installed under the selected prefix for its launcher to be adopted.
    import shutil as _shutil

    _shutil.rmtree(prefix / PRIOR_VERSION)

    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)

    assert prior["launcher"].read_text(encoding="utf-8") == prior_text


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_refuses_prior_launcher_behind_symlinked_version_dir(tmp_path, monkeypatch):
    module = _load_official_installer("migration_symlinked_prior")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    prior_text = prior["launcher"].read_text(encoding="utf-8")
    # Swap the real prior version directory for a symlink with the same name:
    # the reconstructed target is no longer backed by a real directory under
    # the selected prefix, so the launcher is no longer provably ours.
    real = tmp_path / "detached-144"
    (prefix / PRIOR_VERSION).rename(real)
    (prefix / PRIOR_VERSION).symlink_to(real)

    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)

    assert prior["launcher"].read_text(encoding="utf-8") == prior_text
    assert (real / "agy_acp_server.par").read_bytes() == SERVER


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
@pytest.mark.parametrize("shape", ["non-version-directory", "symlinked-executable"])
def test_upgrade_refuses_non_release_prior_target(tmp_path, monkeypatch, shape):
    module = _load_official_installer("migration_invalid_prior")
    prefix, bin_dir = tmp_path / "opt" / "antigravity-acp", tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    target = prior["executable"]
    if shape == "non-version-directory":
        custom = prefix / "custom"
        target.parent.rename(custom)
        target = custom / target.name
    else:
        outside = tmp_path / target.name
        target.rename(outside)
        target.symlink_to(outside)
    launcher_text = _launcher_text(str(target))
    prior["launcher"].write_text(launcher_text, encoding="utf-8")
    _promote_to_new_version(module, monkeypatch)
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir)
    assert prior["launcher"].read_text(encoding="utf-8") == launcher_text


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_upgrade_with_runtime_prefix_adopts_prior_runtime_prefixed_launcher(tmp_path, monkeypatch):
    module = _load_official_installer("migration_runtime_prefix")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    runtime_prefix = tmp_path / "mnt" / "agy-runtime"
    prior = _install_prior_official(tmp_path, monkeypatch, module, runtime_prefix=runtime_prefix)
    prior_target = runtime_prefix / PRIOR_VERSION / "agy_acp_server.par"
    assert prior["launcher"].read_text(encoding="utf-8") == _launcher_text(str(prior_target))

    _promote_to_new_version(module, monkeypatch)
    result = module.install(prefix, bin_dir, runtime_prefix=runtime_prefix)

    new_target = runtime_prefix / NEW_VERSION / "agy_acp_server.par"
    assert result["launcher"].read_text(encoding="utf-8") == _launcher_text(str(new_target))
    # A launcher generated under a different runtime-prefix mapping is not ours.
    old_text = _launcher_text(str(prior_target))
    result["launcher"].write_text(old_text, encoding="utf-8")
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module.install(prefix, bin_dir, runtime_prefix=tmp_path / "mnt" / "other")
    assert result["launcher"].read_text(encoding="utf-8") == old_text


@pytest.mark.skipif(os.name == "nt", reason="fake archive body is a POSIX fixture")
def test_rollback_replays_prior_launcher_after_upgrade(tmp_path, monkeypatch):
    """Reverse direction: re-running the old pin re-adopts the newer launcher.

    This uses the updated installer logic with the old pin, not the old
    released installer. Both version directories remain under the same prefix.
    """
    module = _load_official_installer("migration_rollback")
    prefix = tmp_path / "opt" / "antigravity-acp"
    bin_dir = tmp_path / "bin"
    prior = _install_prior_official(tmp_path, monkeypatch, module)
    _promote_to_new_version(module, monkeypatch)
    upgraded = module.install(prefix, bin_dir)
    assert upgraded["launcher"].read_text(encoding="utf-8") == _launcher_text(
        str(upgraded["executable"])
    )

    monkeypatch.setattr(module, "VERSION", PRIOR_VERSION)
    _patched(monkeypatch, module, sha256=ARCHIVE_SHA256, serve=ARCHIVE, name="v144-again")
    rolled_back = module.install(prefix, bin_dir)

    assert rolled_back["executable"] == prior["executable"]
    assert upgraded["launcher"].read_text(encoding="utf-8") == _launcher_text(
        str(prior["executable"])
    )
    # Rollback preserves both version trees; nothing is deleted.
    assert (prefix / NEW_VERSION / "agy_acp_server.par").read_bytes() == SERVER
    assert (prefix / PRIOR_VERSION / "agy_acp_server.par").read_bytes() == SERVER


def test_windows_prior_launcher_ownership_and_refusals(tmp_path, monkeypatch):
    """Windows .cmd launchers follow the same exact-bytes ownership rule."""
    import types

    module = _load_official_installer("migration_windows_unit")
    fake_os = types.SimpleNamespace(name="nt", replace=os.replace)
    monkeypatch.setattr(module, "os", fake_os)

    launcher = tmp_path / "bin" / "antigravity-acp-official.cmd"
    launcher.parent.mkdir(parents=True)
    prior_target = tmp_path / "opt" / "antigravity-acp" / PRIOR_VERSION / "agy_acp_server.exe"
    new_target = tmp_path / "opt" / "antigravity-acp" / NEW_VERSION / "agy_acp_server.exe"
    prior_content, prior_legacy = module._launcher_variants(prior_target, ("--uid=",))
    new_content = module._launcher_variants(new_target, ("--uid=",))[0]

    launcher.write_text(prior_content, encoding="utf-8")
    module._write_launcher(launcher, new_target, ("--uid=",), prior_targets=(prior_target,))
    assert launcher.read_text(encoding="utf-8") == new_content

    launcher.write_text(prior_legacy, encoding="utf-8")
    module._write_launcher(launcher, new_target, ("--uid=",), prior_targets=(prior_target,))
    assert launcher.read_text(encoding="utf-8") == new_content

    launcher.write_text("@echo off\r\nnot-ours %*\r\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module._write_launcher(launcher, new_target, ("--uid=",), prior_targets=(prior_target,))
    assert launcher.read_bytes() == b"@echo off\r\nnot-ours %*\r\n"

    launcher.write_text(prior_content, encoding="utf-8")
    foreign = tmp_path / "elsewhere" / "agy_acp_server.exe"
    with pytest.raises(RuntimeError, match="unmanaged official ACP launcher"):
        module._write_launcher(launcher, new_target, ("--uid=",), prior_targets=(foreign,))
    assert launcher.read_text(encoding="utf-8") == prior_content


def test_symlinked_launcher_still_refused_with_prior_targets(tmp_path, monkeypatch):
    module = _load_official_installer("migration_symlink_launcher")
    launcher = tmp_path / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.symlink_to(outside)
    with pytest.raises(RuntimeError, match="symlinked official ACP launcher"):
        module._write_launcher(
            launcher,
            tmp_path / "new" / "agy_acp_server.par",
            ("--uid=",),
            prior_targets=(tmp_path / "old" / "agy_acp_server.par",),
        )
    assert launcher.is_symlink()
    assert outside.read_text(encoding="utf-8") == "#!/bin/sh\n"
