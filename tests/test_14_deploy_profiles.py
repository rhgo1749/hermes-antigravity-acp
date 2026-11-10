"""historical reference review: deployer must not leak artifacts into plugin discovery and
must not silently drop the per-home par.txt canary pin."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deploy_hermes_profiles.py"


def _load():
    name = "deploy_hermes_profiles_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The deployer owns the required-file contract; this test follows it so the
# fixture cannot silently drift from production REQUIRED.
REQUIRED = tuple(_load().REQUIRED)


def _plugin_yaml(version: str) -> str:
    return (
        "name: antigravity-acp-provider\n"
        "kind: model-provider\n"
        "version: 0.4.7\n"
    ).replace("0.4.7", version)


def _source(tmp_path: Path) -> Path:
    src = tmp_path / "src" / "antigravity-acp"
    src.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED:
        if name == "plugin.yaml":
            (src / name).write_text(_plugin_yaml("0.4.8"))
        else:
            (src / name).write_text(f"# new {name}\n")
    return src


def _home(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    home = tmp_path / "home"
    (home / "profiles" / "alpha").mkdir(parents=True)
    (home / "profiles" / "beta").mkdir(parents=True)
    targets = {}
    for label, base in (
        ("default", home),
        ("alpha", home / "profiles" / "alpha"),
        ("beta", home / "profiles" / "beta"),
    ):
        target = base / "plugins" / "model-providers" / "antigravity-acp"
        target.mkdir(parents=True)
        (target / "plugin.yaml").write_text(_plugin_yaml("0.4.0"))
        for name in REQUIRED:
            if name != "plugin.yaml":
                (target / name).write_text(f"# old {name}\n")
        # Ownership evidence of a genuine pre-marker installer deploy (the
        # post-historical reference gate refuses canonical trees with no provable provenance).
        (target / "par.txt").write_text("/opt/pin/legacy.par\n")
        targets[label] = target
    return home, targets


def test_deploy_leaves_nothing_in_discovery_tree(tmp_path):
    module = _load()
    home, targets = _home(tmp_path)
    reports = module.install(_source(tmp_path), home, apply=True)
    assert len(reports) == 3
    for base in (home, home / "profiles" / "alpha", home / "profiles" / "beta"):
        plugins = base / "plugins"
        leftovers = [
            p
            for p in plugins.rglob("*")
            if p.name.startswith(".antigravity-acp.")
        ]
        assert leftovers == []
    # old code is retained somewhere outside the discovery tree
    assert (home / "plugin-backups").is_dir()
    assert "# new" in (targets["default"] / "client.py").read_text()
    assert module.verify(home) == []


def test_deploy_preserves_par_pin_and_flags_unresolved(tmp_path):
    module = _load()
    home, targets = _home(tmp_path)
    good = tmp_path / "pin-target.par"
    good.write_bytes(b"par")
    targets["alpha"].joinpath("par.txt").write_text(str(good))
    targets["beta"].joinpath("par.txt").write_text("/does/not/exist.par")
    reports = module.install(_source(tmp_path), home, apply=True)
    joined = "\n".join(reports)
    assert "pin preserved" in joined
    assert (targets["alpha"] / "par.txt").read_text() == str(good)
    assert (targets["beta"] / "par.txt").read_text() == "/does/not/exist.par"
    assert "UNRESOLVED" in joined
    assert "default" in joined  # no pin here; must not error


def test_redeploy_chain_keeps_pin(tmp_path):
    module = _load()
    home, targets = _home(tmp_path)
    pin = tmp_path / "pin2.par"
    pin.write_bytes(b"p")
    targets["alpha"].joinpath("par.txt").write_text(str(pin))
    module.install(_source(tmp_path), home, apply=True)
    module.install(_source(tmp_path), home, apply=True)
    assert (targets["alpha"] / "par.txt").read_text() == str(pin)


def test_verify_flags_leaked_backup_and_duplicate_registration(tmp_path):
    module = _load()
    home, _ = _home(tmp_path)
    module.install(_source(tmp_path), home, apply=True)
    problems = module.verify(home)
    assert problems == []
    leak = home / "plugins" / "model-providers" / ".antigravity-acp.backup-deadbeef"
    leak.mkdir(parents=True)
    (leak / "plugin.yaml").write_text(_plugin_yaml("0.3.0"))
    problems = module.verify(home)
    assert problems
    assert any("backup" in p or "artifact" in p for p in problems)
    assert any("registrations" in p or "registration" in p for p in problems)


def _snapshot(root: Path) -> dict[str, str]:
    state = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            state[rel] = "link:" + str(path.readlink())
        elif path.is_file():
            state[rel] = "file:" + hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            state[rel] = "dir"
    return state


def test_precheck_refuses_duplicate_legacy_sibling_without_touching_anything(tmp_path):
    module = _load()
    home, targets = _home(tmp_path)
    # the exact production hazard: non-dot sibling with the same provider manifest
    legacy = home / "plugins" / "model-providers" / "antigravity-cli"
    legacy.mkdir(parents=True)
    (legacy / "plugin.yaml").write_text(_plugin_yaml("0.4.6"))
    targets["alpha"].joinpath("par.txt").write_text("/opt/pin/agy.par")
    before = _snapshot(home)
    import pytest

    with pytest.raises(ValueError, match="pre-deploy verification failed"):
        module.install(_source(tmp_path), home, apply=True)
    assert _snapshot(home) == before
    problems = module.verify(home, allow_missing=True)
    assert any("antigravity-cli" in p for p in problems)


def test_precheck_allows_missing_but_post_verify_requires_one(tmp_path):
    module = _load()
    home, _ = _home(tmp_path)
    # alpha/beta exist; add a fresh profile whose provider dir is absent yet
    (home / "profiles" / "gamma" / "plugins" / "model-providers").mkdir(parents=True)
    assert module.verify(home, allow_missing=True) == []
    problems = module.verify(home)
    assert len(problems) == 1 and "gamma" in problems[0]
    module.install(_source(tmp_path), home, apply=True)
    assert module.verify(home) == []


def test_mid_install_failure_rolls_back_and_reentry_works(tmp_path, monkeypatch):
    module = _load()
    home, targets = _home(tmp_path)
    original_digest = module.digest
    state = {"boom": True}

    def exploding_digest(path: Path) -> str:
        if (
            state["boom"]
            and "/model-providers/" in str(path)
            and path.name == "client.py"
        ):
            state["boom"] = False
            raise RuntimeError("simulated mid-install failure")
        return original_digest(path)

    monkeypatch.setattr(module, "digest", exploding_digest)
    import pytest

    with pytest.raises(RuntimeError, match="simulated"):
        module.install(_source(tmp_path), home, apply=True)
    # the first mutated home was rolled back to the original bytes
    assert "# old client.py" in (targets["default"] / "client.py").read_text()
    leftovers = [p for p in (home / "plugins").rglob("*") if ".antigravity-acp." in p.name]
    assert leftovers == []
    # re-entry after the crash completes cleanly
    reports = module.install(_source(tmp_path), home, apply=True)
    assert len(reports) == 3
    assert module.verify(home) == []


def test_cli_apply_exits_nonzero_on_duplicate_and_leaves_files(tmp_path):
    module_home = tmp_path / "home"
    (module_home / "profiles" / "alpha").mkdir(parents=True)
    target = module_home / "plugins" / "model-providers" / "antigravity-acp"
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_text(_plugin_yaml("0.4.7"))
    legacy = target.parent / "antigravity-cli"
    legacy.mkdir()
    (legacy / "plugin.yaml").write_text(_plugin_yaml("0.4.6"))
    src = _source(tmp_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--hermes-home", str(module_home), "--source", str(src), "--apply"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "pre-deploy verification failed" in (result.stdout + result.stderr)
    assert (target / "plugin.yaml").read_text() == _plugin_yaml("0.4.7")
