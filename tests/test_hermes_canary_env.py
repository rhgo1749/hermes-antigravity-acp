from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canary_env = _load("hermes_canary_env", ROOT / "scripts" / "hermes_canary_env.py")
acp_mux = _load("canary_env_acp_mux", ROOT / "scripts" / "acp_mux.py")


def test_canary_env_uses_os_home_for_mux_control_paths(tmp_path: Path) -> None:
    os_home = tmp_path / "hermes-user"
    state_home = os_home / ".hermes"
    profile_home = state_home / "profiles" / "eval"

    env = canary_env.build_hermes_canary_env(
        {"HOME": "/old/home", "HERMES_REAL_HOME": "/wrong/state/home", "ACP_MUX_HOME": "/wrong/mux/home", "KEEP": "yes"},
        profile_home=profile_home,
        hermes_state_home=state_home,
    )

    assert env["HOME"] == str(profile_home)
    assert env["HERMES_HOME"] == str(profile_home)
    assert env["HERMES_REAL_HOME"] == str(os_home)
    assert env["ACP_MUX_HOME"] == str(os_home)
    assert env["KEEP"] == "yes"
    assert acp_mux._control_home(env) == str(os_home)
    assert acp_mux._default_control_path("acp-accounts.json", env) == str(
        state_home / "acp-accounts.json"
    )


def test_canary_env_rejects_ambiguous_hermes_state_home(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"\.hermes state directory"):
        canary_env.build_hermes_canary_env(
            {},
            profile_home=tmp_path / "profile",
            hermes_state_home=tmp_path / "not-the-state-home",
        )


def test_canary_env_rejects_profile_outside_state_home(tmp_path: Path) -> None:
    state_home = tmp_path / "hermes-user" / ".hermes"
    with pytest.raises(ValueError, match="inside hermes_state_home"):
        canary_env.build_hermes_canary_env(
            {},
            profile_home=tmp_path / "other-profile",
            hermes_state_home=state_home,
        )
