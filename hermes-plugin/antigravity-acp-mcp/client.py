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
    _CONTEXT_OCCUPANCY_SOURCE,
    _USAGE_SCOPE_UNVERIFIED,
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
    # Separate honest channels (never billing): the latest context OCCUPANCY reading from usage_update
    # frames, and the frames' own token fields as raw telemetry. Both are explicitly non-billing.
    occupancy = result.get("context_occupancy")
    completion.antigravity_context_occupancy = ({
        "source": _CONTEXT_OCCUPANCY_SOURCE, "scope": _USAGE_SCOPE_UNVERIFIED,
        "is_billing_usage": False, **occupancy} if occupancy else None)
    completion.antigravity_frame_usage = result.get("frame_usage")
    return completion


def _usage(u: dict | None) -> SimpleNamespace | None:
    """The gated ``session/prompt`` result breakdown as OpenAI-style usage; None when absent or rejected.

    Deliberately has NO fallback to context ``used``: an occupancy snapshot reported as ``prompt_tokens``
    turns every reader into an occupancy integrator (issue #6 class; #194 audit). None lets Hermes' own
    estimate stand.
    """
    if not u:
        return None
    prompt = u.get("input_tokens")
    if not isinstance(prompt, int) or isinstance(prompt, bool):
        return None
    completion = u.get("output_tokens") or 0
    total = u.get("total_tokens")
    ns = SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion,
                         total_tokens=total if isinstance(total, int) else prompt + completion)
    if isinstance(u.get("cached_read_tokens"), int):
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
