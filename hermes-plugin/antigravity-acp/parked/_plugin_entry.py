"""Parked-MCP profile construction and registration (called by the plugin's ``__init__.py``).

Since plugin 0.9.0 the Parked-MCP engine owns the public default surface:
``antigravity-acp`` (with the historical aliases) is the default profile and
``antigravity-acp-mcp`` (alias ``agy-mcp``) remains registered unchanged for
existing opt-in configurations.  The Replay engine is a separate profile
(``antigravity-acp-replay``) registered by the parent package.  Registration is
an explicit call — importing this module has no side effects — so tests can
construct profiles without touching the global registry.
"""

from __future__ import annotations

import os
import time
from typing import Any

from providers import register_provider
from providers.base import ProviderProfile

from .client import _configured_command, _default_official_command

_DISCOVERY_TTL_DEFAULT_SECONDS = 600.0
_DISCOVERY_TTL_MAX_SECONDS = 86400.0


def _discovery_ttl() -> float:
    """Operator TTL override, read per call; garbage/negative/NaN fall back to the default, never crash."""
    raw = os.environ.get("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "")
    try:
        ttl = float(raw) if raw else _DISCOVERY_TTL_DEFAULT_SECONDS
    except ValueError:
        return _DISCOVERY_TTL_DEFAULT_SECONDS
    if not ttl >= 0.0:  # False for negatives AND NaN
        return _DISCOVERY_TTL_DEFAULT_SECONDS
    return min(ttl, _DISCOVERY_TTL_MAX_SECONDS)


class AntigravityAcpMcpProfile(ProviderProfile):
    def create_client(self, **client_kwargs: Any) -> Any:
        from .client import AntigravityAcpMcpClient

        if not client_kwargs.get("command"):
            client_kwargs["command"] = _configured_command() or self.process_command
        if not client_kwargs.get("args"):
            client_kwargs["args"] = list(self.process_args)
        if not client_kwargs.get("base_url"):
            client_kwargs["base_url"] = self.base_url
        return AntigravityAcpMcpClient(**client_kwargs)

    def discover_models(self, **kwargs: Any) -> list[dict[str, Any]] | None:
        """The bound account's live ``models.availableModels`` from one ``session/new`` — no inference.

        Mirrors the standalone antigravity-acp profile's contract: server rows only, ``None`` on any
        failure (the picker then shows ``fallback_models``, which is intentionally empty — an
        unverified model is never offered). A fresh cached listing answers without spawning the server;
        the cache is keyed by the resolved launcher, so repointing the launcher invalidates it.
        """
        launcher = (_configured_command() or self.process_command, tuple(self.process_args))
        cached = getattr(self, "_models_cache", None)
        if cached is not None and cached[2] == launcher and time.monotonic() < cached[0]:
            return list(cached[1])
        try:
            from .acp_connection import AcpConnection

            conn = AcpConnection(launcher[0], list(launcher[1]), os.path.expanduser("~"))
            conn.start()
            try:
                conn.initialize(timeout=60.0)
                sess = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=90.0)
                sid = str(sess.get("sessionId") or "") if isinstance(sess, dict) else ""
                if sid:
                    conn.close_session(sid)  # ACP v1 courtesy before the process teardown
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - discovery failure must fail closed, never fake a picker
            return None
        models = sess.get("models") if isinstance(sess, dict) else None
        entries = models.get("availableModels") if isinstance(models, dict) else None
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            raw_id = entry.get("modelId")
            model_id = raw_id.strip() if isinstance(raw_id, str) else ""
            if not model_id or model_id in seen:
                continue
            seen.add(model_id)
            row: dict[str, Any] = {"id": model_id}
            raw_name = entry.get("name")
            label = raw_name.strip() if isinstance(raw_name, str) else ""
            if label and label != model_id:
                row["label"] = label
            rows.append(row)
        if not rows:
            return None
        self._models_cache = (time.monotonic() + _discovery_ttl(), list(rows), launcher)
        return rows

    def fetch_models(self, *, api_key: str | None = None, base_url: str | None = None,
                     timeout: float = 8.0) -> list[str] | None:
        rows = self.discover_models()
        if not rows:
            return None
        return [str(row["id"]) for row in rows if row.get("id")] or None

    def build_api_kwargs_extras(self, *, reasoning_config: dict | None = None, **_: Any) -> tuple[dict, dict]:
        """Hermes' reasoning effort reaches the client as ``reasoning_effort`` (mapped to agy's thinking level)."""
        if not isinstance(reasoning_config, dict):
            return {}, {}
        effort = "none" if reasoning_config.get("enabled") is False else str(reasoning_config.get("effort") or "")
        return {}, ({"reasoning_effort": effort} if effort else {})


def register_parked_profiles(
    *,
    stored_process_command: str | None = None,
    stored_process_args: tuple[str, ...] = (),
) -> tuple[AntigravityAcpMcpProfile, AntigravityAcpMcpProfile]:
    """Register the default ``antigravity-acp`` and compatibility ``antigravity-acp-mcp`` profiles.

    Both profiles run the same Parked-MCP engine; they differ only in identity
    surface (name/aliases/base_url marker/env-var scope).  ``stored_process_command``/
    ``stored_process_args`` carry the installer-preserved launch config so a
    host pinned by ``deploy_hermes_profiles.py`` keeps its launch target across
    the engine switch.  Returns ``(default, compat)`` for test introspection.
    """
    default = AntigravityAcpMcpProfile(
        name="antigravity-acp",
        aliases=(
            "antigravity-cli",
            "agy",
            "antigravity",
            "agy-acp",
            "antigravity-official-acp",
        ),
        display_name="Antigravity ACP",
        description=(
            "Google Antigravity through Google's official ACP server; Hermes tools over a "
            "parked loopback MCP endpoint (default engine since 0.9.0)"
        ),
        api_mode="chat_completions",
        env_vars=(),
        base_url="acp://antigravity",
        auth_type="external_process",
        supports_vision=True,
        process_command=stored_process_command or _default_official_command(),
        process_args=tuple(stored_process_args),
        process_command_env_vars=(
            "HERMES_ANTIGRAVITY_ACP_MCP_COMMAND",
            "HERMES_ANTIGRAVITY_ACP_COMMAND",
        ),
        process_args_env_var="HERMES_ANTIGRAVITY_ACP_ARGS",
        fallback_models=(),
    )
    compat = AntigravityAcpMcpProfile(
        name="antigravity-acp-mcp",
        aliases=("agy-mcp",),
        display_name="Antigravity ACP (MCP tools)",
        description="Google Antigravity via the official ACP server; Hermes tools over a parked loopback MCP endpoint",
        api_mode="chat_completions",
        env_vars=(),
        base_url="acp://antigravity-mcp",
        auth_type="external_process",
        # Compatibility id for pre-0.9.0 configs: it must keep RESOLVING by
        # name (resolution never consults listing), but a fresh install's
        # picker must not offer a second entry that duplicates the default
        # engine under another name.
        hidden=True,
        supports_vision=True,  # images go to agy as ACP image blocks / MCP image content
        process_command=stored_process_command or _default_official_command(),
        process_args=tuple(stored_process_args),
        process_command_env_vars=("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "HERMES_ANTIGRAVITY_ACP_COMMAND"),
        process_args_env_var="HERMES_ANTIGRAVITY_ACP_MCP_ARGS",
        fallback_models=(),
    )
    register_provider(default)
    register_provider(compat)
    return default, compat
