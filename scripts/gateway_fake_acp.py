#!/usr/bin/env python3
"""Offline ACP fixture for the disposable real-Core Gateway test; never a vendor server."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve(strict=True)
    events = root / "acp-events.jsonl"
    control = root / "control.json"
    pending: dict | None = None
    permission_prompt: dict | None = None
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)"])

    def record(event: str, **fields) -> None:
        # No protocol payload, prompt, key or raw session identifier is persisted.
        with events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "pid": os.getpid(), **fields}) + "\n")

    def send(value: dict) -> None:
        print(json.dumps(value), flush=True)

    def reply(message: dict, value: dict) -> None:
        send({"jsonrpc": "2.0", "id": message["id"], "result": value})

    def finish(message: dict, text: str, reason: str = "end_turn") -> None:
        send({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": message["params"]["sessionId"], "update": {
                "sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}}}})
        reply(message, {"stopReason": reason})
        record("prompt_completed")

    def stop(_signal=None, _frame=None) -> None:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
        record("server_exited")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    record("server_started", parent_pid=os.getppid(), grandchild_pid=child.pid,
           started=Path(f"/proc/{os.getpid()}/stat").read_text().rsplit(")", 1)[1].split()[22-3],
           grandchild_started=Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[22-3],
           process_group=os.getpgrp())
    try:
        for line in sys.stdin:
            message = json.loads(line)
            method = message.get("method")
            if method == "initialize":
                record("initialize")
                if json.loads(control.read_text())["mode"] == "initialize_failure":
                    send({"jsonrpc": "2.0", "id": message["id"],
                          "error": {"code": -32603, "message": "synthetic_initialize_failure"}})
                else:
                    reply(message, {"protocolVersion": 1, "agentCapabilities": {},
                                    "agentInfo": {"name": "phase-c-fake-acp", "version": "0"}})
            elif method in {"session/new", "session/resume", "session/load"}:
                record("session_opened")
                reply(message, {"sessionId": "synthetic-offline-session", "models": {
                    "currentModelId": "phase-c-model", "availableModels": [
                        {"modelId": "phase-c-model", "name": "Synthetic offline model"}]}})
            elif method in {"session/set_model", "session/set_config_option", "session/set_mode"}:
                reply(message, {})
            elif method == "session/prompt":
                record("prompt_received")
                settings = json.loads(control.read_text())
                if settings["mode"] == "hold":
                    pending = message
                    record("prompt_held")
                elif settings["mode"] == "deny":
                    permission_prompt = message
                    send({"jsonrpc": "2.0", "id": "synthetic-permission", "method": "session/request_permission",
                          "params": {"sessionId": message["params"]["sessionId"],
                                     "toolCall": {"toolCallId": "synthetic-native-command", "kind": "execute",
                                                  "title": "run_command", "rawInput": {"command": "synthetic-forbidden"}},
                                     "options": [{"optionId": "allow", "kind": "allow_once", "name": "Allow"},
                                                 {"optionId": "deny", "kind": "reject_once", "name": "Deny"}]}})
                else:
                    finish(message, settings["text"])
            elif method == "session/cancel":
                record("cancel_received")
                if pending is not None:
                    finish(pending, "", "cancelled")
                    pending = None
            elif message.get("id") == "synthetic-permission" and method is None:
                outcome = message.get("result", {}).get("outcome", {})
                denied = outcome.get("outcome") == "cancelled" or outcome.get("optionId") == "deny"
                record("permission_rejected" if denied else "permission_wrongly_allowed")
                if permission_prompt is not None:
                    finish(permission_prompt, "synthetic-denied", "refusal")
                    permission_prompt = None
            elif "id" in message and method is not None:
                reply(message, {})
    finally:
        stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
