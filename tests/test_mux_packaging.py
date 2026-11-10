"""historical reference packaging guards for the strictly opt-in ACP mux bundle.

These tests cover packaging/install semantics only; engine routing behavior is
covered by test_acp_mux.py / test_acp_mux_guard.py / test_mux_wrapper.py.
Everything here is credential-free and fake-only.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_mux.py"
BUNDLE_FILES = ("acp_mux.py", "antigravity-acp-mux.py", "antigravity-acp-mux")
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

CANARY_SECRET = "CANARY-REGISTRY-SECRET-0d3ad-b3f-n0t-a-real-credential"


def _run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    merged.pop("ACP_MUX_PAR", None)
    merged.pop("HERMES_ANTIGRAVITY_ACP_PAR", None)
    merged.pop("ACP_MUX_ACCOUNTS", None)
    merged.pop("HERMES_ACP_ACCOUNTS", None)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(INSTALLER), *args],
        text=True,
        capture_output=True,
        check=False,
        env=merged,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hashes(base: Path) -> dict[str, str]:
    return {
        str(p.relative_to(base)): _sha256(p)
        for p in sorted(base.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def test_install_writes_exact_bundle_and_manifest(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    result = _run(["--bin-dir", str(bin_dir), "install"])
    assert result.returncode == 0, result.stderr
    manifest = json.loads((bin_dir / ".antigravity-acp-mux-packaging.json").read_text())
    assert manifest["bundle_version"]
    for name in BUNDLE_FILES:
        target = bin_dir / name
        assert target.is_file(), name
        assert target.stat().st_mode & 0o111, name
        assert manifest["files"][name] == _sha256(ROOT / "scripts" / name)
        assert manifest["files"][name] == _sha256(target)


def test_install_refuses_foreign_files_with_zero_writes(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    foreign = bin_dir / "antigravity-acp-mux"
    foreign.write_text("#!/bin/sh\necho not-ours\n")
    before = foreign.read_bytes()
    result = _run(["--bin-dir", str(bin_dir), "install"])
    assert result.returncode == 2
    assert "fail closed" in result.stderr
    assert foreign.read_bytes() == before
    assert not (bin_dir / "acp_mux.py").exists()
    assert not (bin_dir / ".antigravity-acp-mux-packaging.json").exists()


def test_install_is_idempotent(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    first = _run(["--bin-dir", str(bin_dir), "install"])
    assert first.returncode == 0, first.stderr
    hashes = {name: _sha256(bin_dir / name) for name in BUNDLE_FILES}
    second = _run(["--bin-dir", str(bin_dir), "install"])
    assert second.returncode == 0, second.stderr
    assert {name: _sha256(bin_dir / name) for name in BUNDLE_FILES} == hashes


def test_uninstall_preserves_single_and_foreign_files(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    official = bin_dir / "antigravity-acp-official"
    official.write_text("#!/bin/sh\n# official launcher\n")
    personal = bin_dir / "some-other-tool"
    personal.write_text("keep me\n")
    assert _run(["--bin-dir", str(bin_dir), "install"]).returncode == 0
    result = _run(["--bin-dir", str(bin_dir), "uninstall"])
    assert result.returncode == 0, result.stderr
    for name in BUNDLE_FILES:
        assert not (bin_dir / name).exists(), name
    assert not (bin_dir / ".antigravity-acp-mux-packaging.json").exists()
    assert official.read_text().startswith("#!/bin/sh")
    assert personal.read_text() == "keep me\n"


def test_uninstall_refuses_tampered_bytes(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    assert _run(["--bin-dir", str(bin_dir), "install"]).returncode == 0
    (bin_dir / "acp_mux.py").write_text("# tampered\n")
    result = _run(["--bin-dir", str(bin_dir), "uninstall"])
    assert result.returncode == 2
    assert "preserving all files" in result.stderr
    for name in BUNDLE_FILES:
        assert (bin_dir / name).exists(), name
    assert (bin_dir / ".antigravity-acp-mux-packaging.json").exists()


def test_uninstall_without_manifest_refuses(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "acp_mux.py").write_text("# foreign\n")
    result = _run(["--bin-dir", str(bin_dir), "uninstall"])
    assert result.returncode == 2
    assert (bin_dir / "acp_mux.py").exists()


def test_status_reports_paths_and_never_registry_contents(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    assert _run(["--bin-dir", str(bin_dir), "install"]).returncode == 0
    registry = tmp_path / "acp-accounts.json"
    registry.write_text(json.dumps({"accounts": [{"label": "x", "token": CANARY_SECRET}]}))
    home = tmp_path / "home"
    home.mkdir()
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    result = _run(
        ["--bin-dir", str(bin_dir), "status"],
        env={
            "ACP_MUX_ACCOUNTS": str(registry),
            "HOME": str(home),
            "PATH": str(empty_path),  # deterministic: no launcher on PATH
        },
    )
    assert result.returncode == 0, result.stderr
    assert CANARY_SECRET not in result.stdout
    assert CANARY_SECRET not in result.stderr
    report = json.loads(result.stdout)
    assert report["mux_installed"] is True
    assert report["mux_bundle_ok"] is True
    assert report["registry_path"] == str(registry)
    assert report["registry_exists"] is True
    assert report["par_resolved"] is False  # par envs popped; PATH isolated


def test_status_resolves_par_precedence(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    par = tmp_path / "agy_acp_server.par"
    par.write_text("stub")
    result = _run(
        ["--bin-dir", str(bin_dir), "status"],
        env={"ACP_MUX_PAR": str(par)},
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["par_resolved"] is True
    assert report["par_source"] == "ACP_MUX_PAR"
    assert report["par_exists"] is True


def test_single_plugin_surface_byte_untouched_by_install(tmp_path: Path) -> None:
    before = _tree_hashes(PLUGIN_DIR)
    bin_dir = tmp_path / "bin"
    assert _run(["--bin-dir", str(bin_dir), "install"]).returncode == 0
    assert _tree_hashes(PLUGIN_DIR) == before


def test_plugin_sources_never_import_mux() -> None:
    for source in PLUGIN_DIR.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "import acp_mux" not in text, source
        assert "from acp_mux" not in text, source
        assert "antigravity-acp-mux.py" not in text, source


def test_status_without_manifest_flags_foreign_bundle(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    assert _run(["--bin-dir", str(bin_dir), "install"]).returncode == 0
    (bin_dir / ".antigravity-acp-mux-packaging.json").unlink()
    result = _run(["--bin-dir", str(bin_dir), "status"])
    assert result.returncode == 0, result.stderr
    assert "without a manifest" in result.stdout or "without a manifest" in result.stderr
    report = json.loads(result.stdout)
    assert report["mux_installed"] is True
    assert report["mux_bundle_ok"] is False
