"""PlanC component 9: the OpenAI-client facade Hermes calls (``chat.completions.create``, ``cancel()``, ``close()``)."""

from __future__ import annotations

import atexit
import json
import os
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ._hermes_seam import _conversation_affinity, _DualModeCompletionCreate, completion_to_stream_chunks
from .acp_connection import AcpConnection
from .conversation import (
    _nonnegative_int,
    Conversation,
    Registry,
)

ACP_MARKER_BASE_URL = "acp://antigravity-mcp"
THINKING_ENV = "HERMES_ANTIGRAVITY_ACP_MCP_THINKING_LEVEL"  # low|medium|high|xhigh; overrides reasoning_effort
_EFFORT_TO_THINKING = {"none": "low", "minimal": "low", "low": "low", "medium": "medium", "high": "high",
                       "xhigh": "xhigh", "max": "xhigh", "ultra": "xhigh"}


def thinking_level(reasoning_effort: Any) -> str | None:
    """agy thinking level for Hermes' effort; None keeps the model id's own level."""
    override = os.environ.get(THINKING_ENV, "").strip().lower()
    return _EFFORT_TO_THINKING.get(override or str(reasoning_effort or "").strip().lower())


def _default_official_command() -> str:
    """Resolve the user-scoped official launcher without assuming a fixed home."""
    launcher_name = (
        "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"
    )
    launcher = Path.home() / ".local" / "bin" / launcher_name
    if launcher.is_file():
        return str(launcher)
    return shutil.which(launcher_name) or launcher_name


def _configured_command() -> str:
    return (
        os.environ.get("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "").strip()
        or os.environ.get("HERMES_ANTIGRAVITY_ACP_COMMAND", "").strip()
    )


def _default_command() -> tuple[str, list[str]]:
    return (_configured_command() or _default_official_command()), []


def _spawn_factory(command: str, args: list[str]):
    def spawn(key: str, cwd: str) -> AcpConnection:
        conn = AcpConnection(command, args, cwd, mux_env={"ACP_MUX_AFFINITY": key} if key else None)
        try:
            conn.start()
            conn.initialize()
        except BaseException:
            conn.close()  # never leak a child whose handshake failed
            raise
        return conn
    return spawn


_registries: dict[tuple[str, tuple[str, ...]], Registry] = {}
_registries_lock = threading.Lock()


def _registry(command: str, args: list[str]) -> Registry:
    key = (command, tuple(args))
    with _registries_lock:
        reg = _registries.get(key)
        if reg is None:
            reg = _registries[key] = Registry(_spawn_factory(command, args))
        return reg


@atexit.register
def _shutdown_all() -> None:
    with _registries_lock:
        regs = list(_registries.values())
    for reg in regs:
        reg.close_all()


def _completion(result: dict, model: str) -> SimpleNamespace:
    tool_calls = [
        SimpleNamespace(id=c.id, type="function",
                        function=SimpleNamespace(name=c.name, arguments=json.dumps(c.arguments, ensure_ascii=False)))
        for c in result["tool_calls"]
    ] or None
    message = SimpleNamespace(content=result["text"], tool_calls=tool_calls,
                              reasoning=result["reasoning"] or None, reasoning_content=result["reasoning"] or None,
                              reasoning_details=None)
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason=result["finish_reason"])],
        usage=_usage(result.get("usage")), model=model)
    # One honest observation channel (never billing): the latest usage_update frame readings, explicitly
    # labelled semantically-unverified per docs/acp-usage-telemetry.md — NOT a verified occupancy claim.
    obs = result.get("usage_observation")
    completion.antigravity_usage_observations = obs
    return completion


def _usage(u: dict | None) -> SimpleNamespace | None:
    """The gated ``session/prompt`` result breakdown as OpenAI-style usage; None when absent or rejected.

    All three totals must be present (the old-engine required-field contract); nothing is invented here
    and there is NO fallback to frame ``used``. None lets Hermes' own estimate stand.
    """
    if not u:
        return None
    prompt, completion, total = u.get("input_tokens"), u.get("output_tokens"), u.get("total_tokens")
    if not all(_nonnegative_int(v) for v in (prompt, completion, total)):
        return None
    ns = SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion, total_tokens=total)
    if _nonnegative_int(u.get("cached_read_tokens")):
        ns.prompt_tokens_details = SimpleNamespace(cached_tokens=u["cached_read_tokens"])
    return ns


class AntigravityAcpMcpClient:
    """OpenAI-client-compatible facade: one ACP prompt per Hermes user turn, tools over a parked MCP endpoint."""

    HERMES_SKIP_TRANSPORT_WRAP = True
    HERMES_SKIP_ASYNC_WRAP = True

    def __init__(self, *, api_key: str | None = None, base_url: str | None = None,
                 command: str | None = None, args: list[str] | None = None,
                 acp_command: str | None = None, acp_args: list[str] | None = None, **_: Any) -> None:
        self.api_key = api_key or "antigravity-acp-mcp"
        self.base_url = base_url or ACP_MARKER_BASE_URL
        default_cmd, default_args = _default_command()
        self._command = acp_command or command or default_cmd
        selected = acp_args if acp_args is not None else args
        self._args = list(selected) if selected else default_args
        self._inflight: tuple[Conversation, threading.Event] | None = None
        self._inflight_lock = threading.Lock()
        self.is_closed = False
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=_DualModeCompletionCreate(self)))

    def _create_chat_completion(self, *, model: str | None = None, messages: list[dict[str, Any]] | None = None,
                                tools: list[dict[str, Any]] | None = None, stream: bool = False,
                                reasoning_effort: Any = None, **_: Any) -> Any:
        messages = list(messages or [])
        registry = _registry(self._command, self._args)
        key = _conversation_affinity(messages, os.getcwd())
        conv = registry.get(key)
        token = threading.Event()  # request-scoped cancel token
        thinking = thinking_level(reasoning_effort)
        with self._inflight_lock:
            self._inflight = (conv, token)
        try:
            result = conv.run(messages, tools, model, token, thinking)
            if result.get("guest"):
                guest = registry.guest()
                with self._inflight_lock:
                    self._inflight = (guest, token)
                try:
                    result = guest.run(messages, tools, model, token, thinking)
                finally:
                    guest.close()
        finally:
            with self._inflight_lock:
                self._inflight = None
            if conv.stateless:
                conv.close()
        completion = _completion(result, model or "antigravity-acp-mcp")
        return completion_to_stream_chunks(completion) if stream else completion

    def cancel(self) -> None:
        """Hermes interrupt path (``client_lifecycle._abort_request_slot_client`` prefers ``cancel``)."""
        with self._inflight_lock:
            inflight = self._inflight
        if inflight is not None:
            conv, token = inflight
            conv.cancel(token)

    def close(self) -> None:
        """Lifecycle only: conversations are process-global and stay warm."""
        self.is_closed = True
