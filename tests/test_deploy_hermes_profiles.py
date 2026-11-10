"""Deployment is code-only, covers all profiles, and is safe to preview."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy_hermes_profiles.py"
spec = importlib.util.spec_from_file_location("_deploy_hermes_profiles_test", SCRIPT)
assert spec is not None and spec.loader is not None
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def _setup(tmp_path: Path) -> Path:
    home = tmp_path / "hermes-home"
    for name in ("alpha", "beta"):
        (home / "profiles" / name).mkdir(parents=True)
        (home / "profiles" / name / ".env").write_text(f"SECRET_{name}", encoding="utf-8")
    (home / "profiles" / "alpha" / "plugins" / "model-providers" / deploy.PROVIDER).mkdir(parents=True)
    (home / "profiles" / "alpha" / "plugins" / "model-providers" / deploy.PROVIDER / "legacy.txt").write_text(
        "OLD_PLUGIN", encoding="utf-8"
    )
    (home / ".env").write_text("SECRET_default", encoding="utf-8")
    return home


def test_dry_run_has_no_side_effects(tmp_path: Path) -> None:
    home = _setup(tmp_path)
    result = deploy.install(deploy.SOURCE, home, apply=False)
    assert len(result) == 3
    assert all(row.startswith("dry-run: ") for row in result)
    assert not (home / "plugins").exists()
    assert (home / "profiles" / "alpha" / "plugins" / "model-providers" / deploy.PROVIDER / "legacy.txt").exists()


def test_deploy_all_profiles_and_keep_runtime_secrets_untouched(tmp_path: Path) -> None:
    home = _setup(tmp_path)
    result = deploy.install(deploy.SOURCE, home, apply=True)
    assert len(result) == 3
    assert all(row.startswith("deployed: ") for row in result)
    for label, target_home in deploy.homes(home):
        destination = target_home / "plugins" / "model-providers" / deploy.PROVIDER
        assert destination.is_dir(), label
        assert all(deploy.digest(destination / item) == deploy.digest(deploy.SOURCE / item) for item in deploy.REQUIRED)
        assert (target_home / ".env").read_text() == f"SECRET_{label}"
    backups = list((home / "plugin-backups").glob("deploy-*/alpha"))
    assert len(backups) == 1
    assert (backups[0] / "legacy.txt").read_text() == "OLD_PLUGIN"
    # the old code must not remain anywhere inside the plugin discovery tree
    assert not list((home / "profiles" / "alpha" / "plugins" / "model-providers").glob(
        f".{deploy.PROVIDER}.*"
    ))
    assert deploy.verify(home) == []


def _tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): (deploy.digest(p) if p.is_file() else "dir")
        for p in sorted(root.rglob("*"))
    }


def test_deleted_profile_tombstones_are_not_targets(tmp_path: Path) -> None:
    """profiles/.deleted holds Hermes deleted-profile tombstones, never a profile."""
    home = _setup(tmp_path)
    deleted = home / "profiles" / ".deleted"
    tomb = deleted / "old" / "plugins" / "model-providers" / deploy.PROVIDER
    tomb.mkdir(parents=True)
    (tomb / "plugin.yaml").write_text(
        "name: antigravity-acp-provider\nkind: model-provider\n", encoding="utf-8"
    )
    before = _tree(deleted)
    assert [name for name, _ in deploy.homes(home)] == ["default", "alpha", "beta"]
    result = deploy.install(deploy.SOURCE, home, apply=True)
    assert len(result) == 3
    assert deploy.verify(home) == []
    assert _tree(deleted) == before
    assert not (deleted / "plugins").exists()


def test_refuses_missing_profiles_and_symlink_target(tmp_path: Path) -> None:
    home = tmp_path / "empty"
    with pytest.raises(ValueError, match="Missing or unsafe Hermes home"):
        deploy.install(deploy.SOURCE, home, apply=True)
    home = _setup(tmp_path)
    target = home / "plugins" / "model-providers" / deploy.PROVIDER
    target.parent.mkdir(parents=True)
    target.symlink_to(deploy.SOURCE, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        deploy.install(deploy.SOURCE, home, apply=True)
