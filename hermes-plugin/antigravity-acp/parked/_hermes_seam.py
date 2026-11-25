# ruff: noqa: BLE001, B904, UP037, F821  (verbatim upstream code; F821 is a string annotation for the upstream client)
"""Vendored, behaviour-unchanged Hermes seam pieces of the MIT-licensed hermes-antigravity-acp plugin.

Source: rhgo1749/hermes-antigravity-acp, hermes-plugin/antigravity-acp/
        hermes_compat.py (get_runtime_session_env, is_delegated_child_context, get_current_write_origin)
        client.py (_fp_render_message_content, _runtime_conversation_identity, _conversation_affinity,
                   _AsyncCompatibleCompletion, _DualModeCompletionCreate)
        bridge.py (StreamChunks, completion_to_stream_chunks)
Commit: acb68264ea7380082e28ece0bec134028a770622
Upstream: https://github.com/rhgo1749/hermes-antigravity-acp

MIT License. Copyright (c) 2026 rhgo1749
Permission notice: see the upstream LICENSE; it applies to this file unchanged.

Extracted with an AST copy (bodies verbatim); only the imports below were added. Re-vendor, do not edit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any


def get_runtime_session_env() -> tuple[str, str]:
    """Return gateway session identifiers, falling back to explicit process env.

    The os.environ fallback is process-global and may carry a parent's or
    another profile's ids. That is acceptable for foreground/standalone
    surfaces where the ContextVar path is genuinely unavailable. It is NOT
    acceptable for a delegated child (issue #2): a child whose Core lookup
    fails must fail closed rather than silently key its affinity with an
    inherited environment id.
    """
    try:
        from gateway.session_context import get_session_env

        session_id = str(get_session_env("HERMES_SESSION_ID", "") or "").strip()
        session_key = str(get_session_env("HERMES_SESSION_KEY", "") or "").strip()
    except Exception:
        if is_delegated_child_context():
            raise RuntimeError(
                "Hermes session lookup failed during delegated child execution; "
                "refusing to key this child from process-global environment ids."
            )
        session_id = str(os.environ.get("HERMES_SESSION_ID", "") or "").strip()
        session_key = str(os.environ.get("HERMES_SESSION_KEY", "") or "").strip()
    return session_id, session_key


def is_delegated_child_context() -> bool:
    """True only while executing for an in-process delegate_task child.

    This mirrors core's contextvar predicate ``is_delegated_child_context()``
    and NOT core's ``is_delegated_child_process_context()`` (contextvar OR
    descendant env marker). A delegated child intentionally inherits the
    parent's ``HERMES_SESSION_KEY`` contextvar because that key is the
    async-completion routing address, not a conversation identity; callers that
    derive conversation identity must ask this gate so a child never keys
    itself with the parent's routing key.

    A Hermes runtime without the delegation-context module (standalone plugin
    use, or a core older than the shipped ``>=0.21.6`` floor, which carries
    the module) reports no child context: standalone has no delegate runtime
    at all, and pre-module cores keep their pre-issue-#2 keying — documented,
    not silent. A module that is present but fails to import or evaluate
    fails closed rather than guessing.
    """
    try:
        from agent.delegation_context import is_delegated_child_context as resolve_child
    except ImportError as exc:
        try:
            import importlib.util

            spec = importlib.util.find_spec("agent.delegation_context")
        except Exception:
            spec = None
        if spec is None:
            return False
        raise RuntimeError(
            "Hermes delegation context is present but unimportable; refusing to "
            "guess whether this turn may inherit another conversation's session identity."
        ) from exc
    try:
        return bool(resolve_child())
    except Exception as exc:
        raise RuntimeError(
            "Hermes delegation-context lookup failed; refusing to guess whether "
            "this turn may inherit another conversation's session identity."
        ) from exc


def get_current_write_origin() -> str:
    """Return the Hermes lane; unknown origin is unsafe when a session identity exists."""
    try:
        from tools.skill_provenance import get_current_write_origin as resolve_origin
    except ImportError as exc:
        if "tools" not in sys.modules:
            return "foreground"
        raise RuntimeError(
            "Hermes write-origin context is unavailable; refusing to reuse an ACP session across lanes."
        ) from exc
    try:
        origin = str(resolve_origin() or "foreground").strip()
    except Exception as exc:
        raise RuntimeError(
            "Hermes write-origin lookup failed; refusing to reuse an ACP session across lanes."
        ) from exc
    return origin or "foreground"


def _fp_render_message_content(content: Any) -> str:
    """Fingerprint-path renderer. VERBATIM copy of the pre-redaction
    ``_render_message_content``; the persisted ``request_fingerprints`` in the
    conversation checkpoint were built from this exact text, so any drift
    silently forces a full replay and loses native resume for existing
    sessions. Never change this function to "match" the prompt renderers.
    """
    if content is None:
        return ""
    if isinstance(content, dict):
        if "text" in content:
            return str(content.get("text") or "").strip()
        if isinstance(content.get("content"), str):
            return content["content"].strip()
        return json.dumps(content, ensure_ascii=True)
    if isinstance(content, list):
        parts = [
            item if isinstance(item, str) else item["text"].strip()
            for item in content
            if isinstance(item, str)
            or (
                isinstance(item, dict)
                and isinstance(item.get("text"), str)
                and item["text"].strip()
            )
        ]
        return "\n".join(parts).strip()
    return str(content).strip()


def _runtime_conversation_identity() -> str | None:
    """Stable Hermes conversation identity when running inside Hermes.

    ``HERMES_SESSION_KEY`` is the stable gateway conversation identity across
    cached/fresh AIAgent turns. ``HERMES_SESSION_ID`` is a fallback for surfaces
    that do not provide a gateway key. The write-origin ContextVar separates
    detached forks (background review, /btw side questions) that intentionally
    share the parent's physical conversation but must never share its native ACP
    continuation state. Both imports are optional so the standalone plugin and
    tests remain usable outside Hermes.

    A delegate_task child is the one case where the session key is NOT the
    conversation identity: core deliberately propagates the parent's key into the
    child because it is the async-completion routing address
    (``tools/delegate_tool_dispatch.py::_resolve_async_session_key``), while the
    child's own durable session id is bound task-locally around its run
    (``agent/delegation_context.py::delegated_child_context``).  Keying a child
    with the parent's routing key makes every sibling and the parent fight over
    one native ACP continuation (issue #2), so a child keys with its own session
    id.  A child whose own id is absent is AMBIGUOUS: no key can distinguish it
    from its parent or siblings, so it returns ``None`` — the caller must run it
    stateless (empty affinity, fresh native session, resume nothing) rather than
    degrade to the prompt-prefix path, which two same-prompt siblings would
    share.

    Return contract: non-empty string = identity; ``""`` = no Hermes runtime
    identity (standalone fallback path applies); ``None`` = ambiguous delegated
    child (stateless, never resume).
    """
    session_id, session_key = get_runtime_session_env()
    if is_delegated_child_context():
        if not session_id:
            return None
        identity = session_id
    else:
        identity = session_key or session_id
    if not identity:
        return ""
    lane = get_current_write_origin()
    return f"{identity}\0{lane}"


def _conversation_affinity(messages: list[dict[str, Any]], cwd: str) -> str:
    """Stable opaque mux/continuation key for one logical Hermes conversation.

    Prefer Hermes' stable gateway session key over prompt bytes and the more
    transiently-bound durable session id: cached and freshly rebuilt AIAgents must
    resolve to the same native ACP continuation. Outside Hermes, fall back to cwd +
    the immutable opening user prefix so the standalone client still has deterministic
    affinity. An ambiguous delegated child (no own session id) gets the EMPTY
    affinity: the request runs stateless against a fresh native session and resumes
    nothing, because no derivable key can tell it apart from its parent or siblings.
    """
    runtime_identity = _runtime_conversation_identity()
    if runtime_identity is None:
        return ""
    if runtime_identity:
        material = f"hermes-session\0{runtime_identity}"
        return "sha256:" + hashlib.sha256(
            material.encode("utf-8", errors="surrogatepass")
        ).hexdigest()

    opening: list[str] = []
    saw_user = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role in {"assistant", "tool"}:
            break
        if role not in {"system", "context", "user"}:
            continue
        opening.append(f"{role}\0{_fp_render_message_content(message.get('content'))}")
        if role == "user":
            saw_user = True
            break
    if not saw_user:
        return ""
    material = f"{Path(cwd).resolve()}\0" + "\0".join(opening)
    return "sha256:" + hashlib.sha256(
        material.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


class StreamChunks(list):
    """Chunk list that can also carry response-level attributes."""


def completion_to_stream_chunks(completion: SimpleNamespace) -> StreamChunks:
    choice = completion.choices[0]
    message = choice.message
    tool_call_deltas = None
    if message.tool_calls:
        tool_call_deltas = [
            SimpleNamespace(
                index=index,
                id=getattr(tool_call, "id", None),
                type=getattr(tool_call, "type", "function"),
                function=SimpleNamespace(
                    name=getattr(tool_call.function, "name", None),
                    arguments=getattr(tool_call.function, "arguments", None),
                ),
            )
            for index, tool_call in enumerate(message.tool_calls)
        ]
    delta = SimpleNamespace(
        role="assistant",
        content=message.content or None,
        tool_calls=tool_call_deltas,
        reasoning_content=getattr(message, "reasoning_content", None),
        reasoning=getattr(message, "reasoning", None),
        # Hermes consumes ACP through its streaming Chat Completions path. Native
        # ACP tool evidence is carried in reasoning_details; dropping it here made
        # an actually-inspected review indistinguishable from an ungrounded one.
        reasoning_details=getattr(message, "reasoning_details", None),
    )
    data_chunk = SimpleNamespace(
        choices=[SimpleNamespace(index=0, delta=delta, finish_reason=choice.finish_reason)],
        model=completion.model,
        usage=None,
    )
    usage_chunk = SimpleNamespace(choices=[], model=completion.model, usage=completion.usage)
    chunks = StreamChunks([data_chunk, usage_chunk])
    for key, value in vars(completion).items():
        if key not in ("choices", "usage", "model"):
            setattr(chunks, key, value)
    return chunks


class _AsyncCompatibleCompletion:
    """A completion that is awaitable in async code and attribute-compatible in sync code."""

    def __init__(self, call: Callable[[], Any], *, stream: bool) -> None:
        self._call = call
        self._stream = stream
        self._lock = threading.Lock()
        self._resolved = False
        self._result: Any = None
        self._error: BaseException | None = None

    def _resolve(self) -> Any:
        with self._lock:
            if not self._resolved:
                try:
                    self._result = self._call()
                except BaseException as exc:
                    self._error = exc
                self._resolved = True
            if self._error is not None:
                raise self._error
            return self._result

    async def _await_result(self) -> Any:
        result = await asyncio.to_thread(self._resolve)
        if self._stream and isinstance(result, list):
            async def iterate_chunks():
                for chunk in result:
                    yield chunk
            return iterate_chunks()
        return result

    def __await__(self):
        return self._await_result().__await__()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolve(), name)

    def __iter__(self):
        return iter(self._resolve())

    def __getitem__(self, key):
        return self._resolve()[key]

    def __len__(self) -> int:
        return len(self._resolve())

    def __bool__(self) -> bool:
        return bool(self._resolve())

    def __repr__(self) -> str:
        if self._resolved and self._error is None:
            return repr(self._result)
        return "<Antigravity ACP completion pending>"


class _DualModeCompletionCreate:
    """Keep sync calls immediate off-loop; return an awaitable surface on the Gateway loop."""

    def __init__(self, client: "AntigravityACPClient") -> None:
        self._client = client

    def __call__(self, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return self._client._create_chat_completion(**kwargs)
        return _AsyncCompatibleCompletion(
            lambda: self._client._create_chat_completion(**kwargs),
            stream=bool(kwargs.get("stream", False)),
        )
