"""Hermes model-provider registration (imported only by the built plugin's ``__init__.py``, never by tests)."""

from __future__ import annotations

import os
import time
from typing import Any

from providers import register_provider
from providers.base import ProviderProfile

from .client import _configured_command, _default_official_command

_DISCOVERY_TTL_SECONDS = float(os.environ.get("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "600"))


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
        unverified model is never offered). A fresh cached listing answers without spawning the server.
        """
        cached = getattr(self, "_models_cache", None)
        if cached is not None and time.monotonic() < cached[0]:
            return list(cached[1])
        try:
            from .acp_connection import AcpConnection

            conn = AcpConnection(_configured_command() or self.process_command, list(self.process_args),
                                 os.path.expanduser("~"))
            conn.start()
            try:
                conn.initialize(timeout=60.0)
                sess = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=90.0)
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - discovery failure must fail closed, never fake a picker
            return None
        models = sess.get("models") or {}
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in models.get("availableModels") or []:
            model_id = str((entry or {}).get("modelId") or "").strip()
            if not model_id or model_id in seen:
                continue
            seen.add(model_id)
            row: dict[str, Any] = {"id": model_id}
            label = str((entry or {}).get("name") or "").strip()
            if label and label != model_id:
                row["label"] = label
            rows.append(row)
        if not rows:
            return None
        self._models_cache = (time.monotonic() + _DISCOVERY_TTL_SECONDS, list(rows))
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


antigravity_acp_mcp = AntigravityAcpMcpProfile(
    name="antigravity-acp-mcp",
    aliases=("agy-mcp",),
    display_name="Antigravity ACP (MCP tools)",
    description="Google Antigravity via the official ACP server; Hermes tools over a parked loopback MCP endpoint",
    api_mode="chat_completions",
    env_vars=(),
    base_url="acp://antigravity-mcp",
    auth_type="external_process",
    supports_vision=True,  # images go to agy as ACP image blocks / MCP image content
    process_command=_default_official_command(),
    process_args=(),
    process_command_env_vars=("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "HERMES_ANTIGRAVITY_ACP_COMMAND"),
    process_args_env_var="HERMES_ANTIGRAVITY_ACP_MCP_ARGS",
    fallback_models=(),
)

register_provider(antigravity_acp_mcp)
