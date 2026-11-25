"""One ACP child process spoken to over NDJSON JSON-RPC 2.0 on stdio.

Security posture (PlanC components 1, H2, H3, L1):
- the child env is ``_build_subprocess_env()`` plus only the explicit mux control vars;
- stderr is untrusted: always drained, classified at capture time, summarised only by
  ``_acp_stderr_diagnostic`` -- raw stderr bytes never reach an exception or a log;
- request params (``session/new`` carries the MCP bearer) are never logged.
"""

from __future__ import annotations

import collections
import itertools
import json
import logging
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ._upstream import (
    _acp_stderr_diagnostic,
    _acp_stderr_retry_class,
    _build_subprocess_env,
    _redact_acp_error_detail,
)

log = logging.getLogger(__name__)

MUX_ENV_KEYS = frozenset(
    {
        "ACP_MUX_AFFINITY",
        "ACP_MUX_SESSION_ID",
        "ACP_MUX_AFFINITY_PIN",
        "ACP_MUX_AFFINITY_TTL_SECONDS",
        "ACP_MUX_AFFINITY_MAX_ENTRIES",
    }
)
INITIALIZE_PARAMS = {
    "protocolVersion": 1,
    "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False},
    "clientInfo": {
        "name": "hermes-antigravity-acp-mcp",
        "title": "Hermes Antigravity ACP (MCP)",
        "version": "0.1.0",
    },
}
CANCELLED_OUTCOME = {"outcome": {"outcome": "cancelled"}}

_STDERR_KEEP_LINES = 200
_STDERR_LINE_CHARS = 4096
_UPDATE_BUFFER_LIMIT = 10_000

# on_permission(params) -> response result, or None to leave the request pending until
# ``cancel_session`` (or ``respond``) answers it.
PermissionHandler = Callable[[dict[str, Any]], dict[str, Any] | None]


class AcpError(RuntimeError):
    """Base class for ACP connection failures."""


class AcpProcessExit(AcpError):
    """The child exited. ``str()`` is the exit status plus the non-echoing stderr diagnostic."""

    def __init__(self, message: str, *, exit_status: int | None, retry_class: str | None) -> None:
        super().__init__(message)
        self.exit_status = exit_status
        self.retry_class = retry_class  # fixed class name or None, never child text


class AcpRpcError(AcpError):
    def __init__(self, code: Any, message: str) -> None:
        super().__init__(f"ACP error {code}: {message}")
        self.code = code
        self.rpc_message = message


class _Pending:
    __slots__ = ("error", "event", "result")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: Any = None
        self.error: Exception | None = None


_TERMINAL_METHODS = frozenset({
    "terminal/create",
    "terminal/output",
    "terminal/wait_for_exit",
    "terminal/kill",
    "terminal/release",
})
ClientHandler = Callable[[dict[str, Any]], Any]


class AcpConnection:
    def __init__(
        self,
        command: str,
        args: Sequence[str],
        cwd: str,
        *,
        mux_env: Mapping[str, str] | None = None,
        client_info: Mapping[str, str] | None = None,
        client_capabilities: Mapping[str, Any] | None = None,
        client_handlers: Mapping[str, ClientHandler] | None = None,
    ) -> None:
        unknown = set(mux_env or ()) - MUX_ENV_KEYS
        if unknown:
            raise ValueError(f"not a permitted mux control variable: {sorted(unknown)}")
        self._argv = [command, *args]
        self._cwd = cwd
        self._mux_env = dict(mux_env or {})
        self._client_info = dict(client_info) if client_info is not None else dict(INITIALIZE_PARAMS["clientInfo"])
        self._client_capabilities_override = dict(client_capabilities) if client_capabilities is not None else None
        self._client_handlers: dict[str, ClientHandler] = dict(client_handlers or {})
        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.RLock()  # guards the maps below; never held while calling out
        # Serialises session-update callbacks (order of chunks) without holding _lock. Callbacks must not block:
        # the stdout reader runs them, so a callback waiting on another lock would stall every pending response.
        self._dispatch_lock = threading.Lock()
        self._saw_rate_limit = False
        self._write_lock = threading.Lock()  # one NDJSON line at a time on stdin
        self._ids = itertools.count(1)
        self._pending: dict[int, _Pending] = {}
        self._updates: dict[str, collections.deque[dict[str, Any]]] = {}
        self._sessions: dict[str, tuple[Callable[[dict[str, Any]], None], PermissionHandler]] = {}
        self._pending_perms: dict[str, list[Any]] = {}
        self._active_client_reqs: dict[Any, threading.Event] = {}  # agent->client request_id -> cancelled
        self._stderr: collections.deque[str] = collections.deque(maxlen=_STDERR_KEEP_LINES)
        self._stderr_class: str | None = None
        self._exit_error: AcpProcessExit | None = None
        self._exited = threading.Event()
        self._threads: list[threading.Thread] = []
        self.agent_info: dict[str, Any] = {}
        self.agent_capabilities: dict[str, Any] = {}
        self.supports_images = False
        self.supports_load_session = False
        self.supports_session_close = False
        self.supports_session_resume = False
        self.supports_http_mcp = False

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        env = _build_subprocess_env()
        env.update(self._mux_env)
        self._proc = subprocess.Popen(
            self._argv,
            cwd=self._cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._threads = [
            threading.Thread(target=self._read_stdout, name="acp-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, name="acp-stderr", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _build_client_capabilities(self) -> dict[str, Any]:
        # Per ACP v1 spec, only advertise fs/* or terminal when the corresponding client handlers are registered.
        caps: dict[str, Any] = {
            "fs": {
                "readTextFile": "fs/read_text_file" in self._client_handlers,
                "writeTextFile": "fs/write_text_file" in self._client_handlers,
            },
            "terminal": _TERMINAL_METHODS.issubset(self._client_handlers),
        }
        if self._client_capabilities_override is not None:
            caps.update(self._client_capabilities_override)
        return caps

    def initialize(self, timeout: float | None = 30.0) -> dict[str, Any]:
        params = {
            "protocolVersion": INITIALIZE_PARAMS["protocolVersion"],
            "clientCapabilities": self._build_client_capabilities(),
            "clientInfo": self._client_info,
        }
        result = self.request("initialize", params, timeout=timeout)
        res = result if isinstance(result, dict) else {}
        self.agent_info = res.get("agentInfo") if isinstance(res.get("agentInfo"), dict) else {}
        caps = res.get("agentCapabilities") if isinstance(res.get("agentCapabilities"), dict) else {}
        self.agent_capabilities = caps
        pcaps = caps.get("promptCapabilities") if isinstance(caps.get("promptCapabilities"), dict) else {}
        mcaps = caps.get("mcpCapabilities") if isinstance(caps.get("mcpCapabilities"), dict) else {}
        scaps = caps.get("sessionCapabilities") if isinstance(caps.get("sessionCapabilities"), dict) else {}
        self.supports_images = bool(pcaps.get("image"))
        self.supports_load_session = bool(caps.get("loadSession"))
        self.supports_session_close = isinstance(scaps.get("close"), dict) or scaps.get("close") is True
        self.supports_session_resume = isinstance(scaps.get("resume"), dict) or scaps.get("resume") is True
        self.supports_http_mcp = bool(mcaps.get("http"))
        return result

    def close(self) -> None:
        """Reap the child: stdin EOF, then terminate, then kill."""
        proc = self._proc
        if proc is None:
            return
        try:
            with self._write_lock:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
        except (OSError, ValueError):
            pass
        for stop in (None, proc.terminate, proc.kill):
            if stop:
                stop()
            try:
                proc.wait(timeout=2.0)
                break
            except subprocess.TimeoutExpired:
                continue
        for t in self._threads:
            t.join(timeout=2.0)

    @property
    def cwd(self) -> str:
        return self._cwd

    @property
    def stderr_retry_class(self) -> str | None:
        return self._stderr_class

    @property
    def saw_rate_limit(self) -> bool:
        """Sticky per child: any stderr line classified rate-limit (not only the first classified line)."""
        return self._saw_rate_limit

    @property
    def exited(self) -> bool:
        return self._exited.is_set()

    # -- client -> agent -----------------------------------------------------------

    def request(self, method: str, params: dict[str, Any], timeout: float | None = None) -> Any:
        slot = _Pending()
        with self._lock:
            if self._exit_error is not None:
                raise self._exit_error
            rid = next(self._ids)
            self._pending[rid] = slot
        try:
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        except (OSError, ValueError):
            self._exited.wait(5.0)  # the reader builds the typed error
            with self._lock:
                self._pending.pop(rid, None)
            raise self._exit_error or AcpError("ACP child stdin closed") from None
        if not slot.event.wait(timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise TimeoutError(f"ACP request {method} timed out after {timeout}s")
        if slot.error is not None:
            raise slot.error
        return slot.result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        try:
            self._send({"jsonrpc": "2.0", "method": method, "params": params})
        except (OSError, ValueError):
            pass  # child gone: pending requests already fail with the typed exit error

    def respond(self, request_id: Any, result: Any) -> None:
        try:
            self._send({"jsonrpc": "2.0", "id": request_id, "result": result})
        except (OSError, ValueError):
            pass

    def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        line = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            if self._proc.stdin.closed:
                raise OSError("ACP child stdin closed")
            self._proc.stdin.write(line)
            self._proc.stdin.flush()

    # -- sessions ------------------------------------------------------------------

    def attach_session(
        self,
        session_id: str,
        on_update: Callable[[dict[str, Any]], None],
        on_permission: PermissionHandler,
    ) -> None:
        """Route one session's updates and permission requests; flush updates buffered so far.

        ``on_update`` runs on the stdout reader thread (and here for the flush) under the dispatch lock, never
        under the connection lock, so order is preserved: it must not block.
        """
        with self._dispatch_lock:
            with self._lock:
                self._sessions[session_id] = (on_update, on_permission)
                buffered = list(self._updates.pop(session_id, ()))
            for update in buffered:
                self._call_update(on_update, update)

    def detach_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
            self._updates.pop(session_id, None)
            self._pending_perms.pop(session_id, None)

    def close_session(self, session_id: str, timeout: float = 5.0) -> None:
        """Close a session per ACP v1: call ``session/close`` only if advertised; treat -32002 as success."""
        try:
            if self.supports_session_close and not self.exited:
                try:
                    self.request("session/close", {"sessionId": session_id}, timeout=timeout)
                except AcpRpcError as exc:
                    if exc.code != -32002:  # ACP v1: unknown/already-closed session is idempotent success
                        log.debug("session/close returned error %s for %s", exc.code, session_id)
                except (AcpError, TimeoutError, OSError, ValueError):
                    pass
        finally:
            self.detach_session(session_id)

    def cancel_session(self, session_id: str) -> None:
        """Answer every pending permission request ``cancelled``, then send session/cancel."""
        with self._lock:
            pending = self._pending_perms.pop(session_id, [])
        for request_id in pending:
            self.respond(request_id, CANCELLED_OUTCOME)
        self.notify("session/cancel", {"sessionId": session_id})

    # -- reader threads ------------------------------------------------------------

    def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for raw in self._proc.stdout:
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if isinstance(msg, dict):
                self._dispatch(msg)
        self._on_exit()

    def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        # readline(limit) bounds a single huge line; the deque bounds the rest.
        for raw in iter(lambda: self._proc.stderr.readline(_STDERR_LINE_CHARS), b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self._stderr.append(line)
            cls = _acp_stderr_retry_class([line])
            if self._stderr_class is None:
                self._stderr_class = cls
            if cls == "rate-limit":
                self._saw_rate_limit = True

    def _dispatch(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        if method is None:  # response to our request
            with self._lock:
                slot = self._pending.pop(msg.get("id"), None)
            if slot is not None:
                if "error" in msg:
                    err = msg["error"] if isinstance(msg["error"], dict) else {}
                    slot.error = AcpRpcError(
                        err.get("code"),
                        _redact_acp_error_detail(str(err.get("message", ""))),
                    )
                else:
                    slot.result = msg.get("result")
                slot.event.set()
        elif "id" in msg:
            raw_p = msg.get("params")
            self._handle_agent_request(msg["id"], method, raw_p if isinstance(raw_p, dict) else {})
        elif method == "session/update":
            raw_p = msg.get("params")
            self._handle_update(raw_p if isinstance(raw_p, dict) else {})
        elif method == "$/cancel_request":
            raw_p = msg.get("params")
            self._handle_cancel_request(raw_p if isinstance(raw_p, dict) else {})

    def _handle_update(self, params: dict[str, Any]) -> None:
        sid = str(params.get("sessionId") or "")
        update = params.get("update")
        if not sid or not isinstance(update, dict):
            return
        with self._dispatch_lock:
            with self._lock:
                entry = self._sessions.get(sid)
                if entry is None:  # may precede the session/new response
                    buf = self._updates.setdefault(sid, collections.deque(maxlen=_UPDATE_BUFFER_LIMIT))
                    buf.append(update)
                    return
            self._call_update(entry[0], update)

    @staticmethod
    def _call_update(consumer: Callable[[dict[str, Any]], None], update: dict[str, Any]) -> None:
        try:
            consumer(update)
        except Exception:  # noqa: BLE001 - a consumer bug must not kill the reader thread
            log.exception("session update consumer failed")

    def _handle_cancel_request(self, params: dict[str, Any]) -> None:
        """Handle incoming ACP ``$/cancel_request`` notification for pending permissions or client requests."""
        req_id = params.get("requestId") if "requestId" in params else params.get("id")
        if req_id is None:
            return
        cancel_perm = False
        cancel_client = False
        with self._lock:
            for sid, rids in list(self._pending_perms.items()):
                if req_id in rids:
                    rids.remove(req_id)
                    if not rids:
                        self._pending_perms.pop(sid, None)
                    cancel_perm = True
                    break
            ev = self._active_client_reqs.pop(req_id, None)
            if ev is not None:
                ev.set()
                cancel_client = True
        if cancel_perm:
            self.respond(req_id, CANCELLED_OUTCOME)
        if cancel_client:
            self._send_error(req_id, -32800, "Request cancelled")

    def _dispatch_client_handler(self, request_id: Any, method: str, handler: ClientHandler,
                                 params: dict[str, Any]) -> None:
        cancelled = threading.Event()
        with self._lock:
            self._active_client_reqs[request_id] = cancelled

        def run() -> None:
            try:
                res = handler(params)
            except AcpRpcError as exc:
                code = exc.code if isinstance(exc.code, int) and not isinstance(exc.code, bool) else -32603
                err: tuple[int, str] | None = (code, getattr(exc, "rpc_message", str(exc)))
                res = None
            except Exception:  # noqa: BLE001 - never kill worker or leave agent hanging
                log.exception("ACP client handler %s failed", method)
                err = (-32603, f"Internal error in {method}")
                res = None
            else:
                err = None
            with self._lock:
                still_active = self._active_client_reqs.pop(request_id, None) is not None
            if not still_active or cancelled.is_set():
                return  # already answered -32800 by $/cancel_request
            if err is not None:
                self._send_error(request_id, err[0], err[1])
            else:
                self.respond(request_id, res if res is not None else {})

        threading.Thread(target=run, name=f"acp-client-{method}", daemon=True).start()

    def _handle_agent_request(self, request_id: Any, method: str, params: dict[str, Any]) -> None:
        if method != "session/request_permission":
            handler = self._client_handlers.get(method)
            if handler is not None:
                self._dispatch_client_handler(request_id, method, handler, params)
                return
            self._send_error(request_id, -32601, f"Method not found: {method}")
            return
        sid = str(params.get("sessionId") or "")
        with self._lock:
            entry = self._sessions.get(sid)
        result: dict[str, Any] | None = CANCELLED_OUTCOME
        if entry is not None:
            try:
                result = entry[1](params)
            except Exception:  # noqa: BLE001 - a broken gate must fail closed, not hang the child
                log.exception("permission handler failed; answering cancelled")
                result = CANCELLED_OUTCOME
        if result is None:
            with self._lock:
                self._pending_perms.setdefault(sid, []).append(request_id)
        else:
            self.respond(request_id, result)

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        try:
            self._send(
                {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
            )
        except (OSError, ValueError):
            pass

    def _on_exit(self) -> None:
        proc = self._proc
        assert proc is not None
        try:
            status = proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = proc.wait()
        self._threads[1].join(timeout=2.0)  # let stderr finish so the diagnostic is complete
        error = AcpProcessExit(
            f"ACP child exited with status {status}; {_acp_stderr_diagnostic(list(self._stderr))}",
            exit_status=status,
            retry_class=self._stderr_class or _acp_stderr_retry_class(list(self._stderr)),
        )
        with self._lock:
            self._exit_error = error
            pending, self._pending = list(self._pending.values()), {}
        for slot in pending:
            slot.error = error
            slot.event.set()
        self._exited.set()
