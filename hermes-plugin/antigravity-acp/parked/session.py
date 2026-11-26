"""ACP session layer (PlanC component 2): session/new with parked MCP server and native
tools disabled, model selection, prompt with stopReason mapping, cancel."""

from __future__ import annotations

import logging
import queue
from dataclasses import dataclass
from typing import Any

from .acp_connection import AcpConnection, AcpError
from .permission import PermissionGate

logger = logging.getLogger(__name__)

# MEASURED on agy 1.5.2: ``_meta.antigravity.disabledTools`` disables every native tool in the S1 matrix
# (``_meta.agy.disabledTools`` also disables run_command; only the antigravity key was matrix-tested).
THINKING_LEVELS = ("low", "medium", "high", "xhigh")  # agy composite model-id suffixes, ascending
# agy (1.5.2 source, mcp_servers.py) otherwise loads MCP tools lazily: the model sees only names and must read
# brain/<id>/mcp/<server>/<tool>.json through a tool before using one (an extra model step per new tool, seen live).
# It also spills MCP results above its inline limit to a file the model then has to read back.
MCP_MAX_OUTPUT_BYTES = 256 * 1024
EAGER_MCP = True  # module switch, so measurements can compare eager vs lazy loading
NATIVE_TOOLS = [
    # 1.5.2 matrix list + list_resources/read_resource (S1) + the names agy 1.5.15 reports or embeds (PlanRelay R1);
    # with this list the standalone server 1.5.2 passed the 14-probe canary matrix on the gateway host.
    "view_file", "view_file_outline", "view_code_item", "multimodal_view_file", "list_dir", "list_directory",
    "find_by_name", "grep_search", "code_search", "codebase_search", "write_to_file", "write_file",
    "edit_file", "replace_file_content", "multi_edit", "delete_directory", "run_command", "read_terminal",
    "read_url_content", "read_url", "search_web", "read_browser_page", "fetch_media", "generate_image",
    "execute_notebook", "invoke_subagent", "manage_subagents", "manage_task", "run_workflow", "skill_search",
    "trajectory_search", "list_resources", "read_resource", "read_file", "send_message", "schedule",
    "define_subagent", "swarm", "ask_question", "browser_get_dom", "browser_get_network_request",
    "browser_list_network_requests", "capture_browser_console_logs", "capture_browser_screenshot",
    "list_browser_pages", "command_status", "search_in_file", "view_content_chunk", "read_board",
    "manage_inbox", "notify_user", "list_permissions", "list_plugin_accounts", "search_marketplace",
    "swarm_wait",
]  # fmt: skip

# ACP stopReason -> OpenAI-style finish_reason ("cancelled" has no OpenAI equivalent).
STOP_REASON_FINISH = {
    "end_turn": "stop",
    "max_tokens": "length",
    "max_turn_requests": "length",
    "refusal": "content_filter",
    "cancelled": "cancelled",
}


@dataclass(frozen=True)
class PromptResult:
    stop_reason: str
    finish_reason: str
    result: dict[str, Any]


class AcpSession:
    def __init__(self, conn: AcpConnection, session_id: str, gate: PermissionGate) -> None:
        self.conn = conn
        self.session_id = session_id
        self.gate = gate
        self.updates: queue.Queue[dict[str, Any]] = queue.Queue()  # session/update payloads
        self.prompt_active = False
        self.effective_model = ""

    def prompt(self, blocks: str | list[dict[str, Any]], timeout: float | None = None) -> PromptResult:
        if isinstance(blocks, str):
            blocks = [{"type": "text", "text": blocks}]
        if not self.conn.supports_images and any(b.get("type") == "image" for b in blocks):
            logger.warning("acp-mcp: agent did not declare image prompts; images dropped from this prompt")
            blocks = [b for b in blocks if b.get("type") != "image"]

        def end_prompt() -> None:
            self.prompt_active = False

        self.prompt_active = True
        try:
            result = self.conn.request(
                "session/prompt",
                {"sessionId": self.session_id, "prompt": blocks},
                timeout=timeout,
                on_response=end_prompt,
            )
        finally:
            self.prompt_active = False
        result = result if isinstance(result, dict) else {}
        stop = result.get("stopReason")
        if stop not in STOP_REASON_FINISH:
            raise AcpError(f"unknown ACP stopReason {stop!r}")
        return PromptResult(stop, STOP_REASON_FINISH[stop], result)

    def cancel(self) -> None:
        self.conn.cancel_session(self.session_id)

    def close(self) -> None:
        self.conn.close_session(self.session_id)


def _reported_session_model(new_result: dict[str, Any]) -> str:
    for option in new_result.get("configOptions") or []:
        if not isinstance(option, dict) or "model" not in (option.get("category"), option.get("id")):
            continue
        current = str(option.get("currentValue") or "").strip()
        if current:
            return current
    models = new_result.get("models")
    if isinstance(models, dict):
        current = str(models.get("currentModelId") or "").strip()
        if current:
            return current
    return ""


def new_session(
    conn: AcpConnection,
    *,
    mcp_server: dict[str, Any],
    gate: PermissionGate,
    model: str | None = None,
    thinking: str | None = None,
) -> AcpSession:
    # Never log these params: mcp_server carries the bearer (L1).
    result = conn.request(
        "session/new",
        {
            "cwd": conn.cwd,
            "mcpServers": [mcp_server],
            "_meta": {"antigravity": {"disabledTools": NATIVE_TOOLS,
                                      **({"eagerMcpServers": [str(mcp_server.get("name") or "")]} if EAGER_MCP else {}),
                                      "mcpMaxOutputBytes": MCP_MAX_OUTPUT_BYTES}},
        },
        timeout=60.0,
    )
    session = AcpSession(conn, str(result["sessionId"]), gate)

    def on_update(update: dict[str, Any]) -> None:
        gate.observe_update(update)
        if not session.prompt_active and update.get("sessionUpdate") == "usage_update":
            return
        session.updates.put(update)

    conn.attach_session(session.session_id, on_update, gate.decide)
    picked = ""
    if model or thinking:
        while True:
            try:
                session.updates.get_nowait()
            except queue.Empty:
                break
        picked = select_model(conn, session.session_id, result, model or "", thinking)
    session.effective_model = picked or _reported_session_model(result)
    return session


def _nearest(thinking: str, offered: list[str]) -> str | None:
    """The offered level closest to ``thinking`` (ties go to the lower level)."""
    if thinking not in THINKING_LEVELS:
        return None
    want = THINKING_LEVELS.index(thinking)
    ranked = sorted((abs(THINKING_LEVELS.index(o) - want), THINKING_LEVELS.index(o), o)
                    for o in offered if o in THINKING_LEVELS)
    return ranked[0][2] if ranked else None


def _composite(model: str, thinking: str | None, legacy_ids: list[str]) -> str:
    """``<base>-<level>`` nearest to ``thinking`` among the siblings agy offers when ``model`` is a composite id
    (``fake-model-a-medium``), else ``model``."""
    base, _, suffix = model.rpartition("-")
    if not thinking or suffix not in THINKING_LEVELS:
        return model
    level = _nearest(thinking, [i.rpartition("-")[2] for i in legacy_ids if i.rpartition("-")[0] == base])
    return f"{base}-{level}" if level else model


def select_model(conn: AcpConnection, session_id: str, new_result: dict[str, Any], model: str,
                 thinking: str | None = None) -> str:
    """Pick the model, then the thinking level.

    A composite id (``fake-model-a-medium``) carries its level: the requested level swaps the suffix when agy
    offers siblings (nearest offered level; covers ``xhigh``). Otherwise the ``thought_level`` option is set to
    the nearest level it offers.
    """
    legacy = [str(m.get("modelId")) for m in (new_result.get("models") or {}).get("availableModels") or []
              if isinstance(m, dict)]
    picked = _composite(model, thinking, legacy) if model else ""
    if picked:
        _set_model(conn, session_id, new_result, picked)
    if not thinking or picked.rpartition("-")[2] == thinking:
        return picked  # the composite id carries the requested level itself
    for option in new_result.get("configOptions") or []:
        if isinstance(option, dict) and option.get("category") == "thought_level":
            offered = [str(o.get("value")) for o in option.get("options") or [] if isinstance(o, dict)]
            value = _nearest(thinking, offered)
            if value:
                conn.request("session/set_config_option",
                             {"sessionId": session_id, "configId": option.get("id") or "thinking_level",
                              "value": value}, timeout=30.0)
            return picked
    return picked


def _set_model(conn: AcpConnection, session_id: str, new_result: dict[str, Any], model: str) -> None:
    """set_config_option on the ``model`` option when it offers ``model``, else set_model."""
    for option in new_result.get("configOptions") or []:
        if not isinstance(option, dict) or "model" not in (option.get("category"), option.get("id")):
            continue
        if model in [o.get("value") for o in option.get("options") or [] if isinstance(o, dict)]:
            conn.request(
                "session/set_config_option",
                {"sessionId": session_id, "configId": option.get("id") or "model", "value": model},
                timeout=30.0,
            )
            return
    conn.request("session/set_model", {"sessionId": session_id, "modelId": model}, timeout=30.0)
