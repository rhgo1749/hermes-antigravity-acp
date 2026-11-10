from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path


def build_hermes_canary_env(
    base_env: Mapping[str, str],
    *,
    profile_home: str | Path,
    hermes_state_home: str | Path,
) -> dict[str, str]:
    """Build profile env without confusing Hermes state home and OS home.

    ACP MUX treats ``HERMES_REAL_HOME`` as the OS home and appends ``.hermes``
    when resolving shared paths. Pin ``ACP_MUX_HOME`` to that same home so an
    inherited MUX override cannot redirect the canary to another registry.
    """
    state_home = Path(hermes_state_home).expanduser()
    if state_home.name != ".hermes":
        raise ValueError("hermes_state_home must be the Hermes .hermes state directory")

    profile = Path(profile_home).expanduser()
    if profile != state_home and state_home not in profile.parents:
        raise ValueError("profile_home must be inside hermes_state_home")

    env = dict(base_env)
    env["HOME"] = str(profile)
    env["HERMES_HOME"] = str(profile)
    os_home = str(state_home.parent)
    env["HERMES_REAL_HOME"] = os_home
    env["ACP_MUX_HOME"] = os_home
    return env
