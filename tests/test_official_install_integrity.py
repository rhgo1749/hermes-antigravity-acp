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
    assert not [p for p in prefix.iterdir() if p.name.startswith(".antigravity-acp-install-")]


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
