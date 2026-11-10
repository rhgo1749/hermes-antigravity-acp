#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import threading
from typing import Any


def _reader(stream, out: queue.Queue[str]) -> None:
    for line in stream:
        out.put(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe an ACP v1 stdio server without authenticating")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command after --")
    parser.add_argument("--timeout", type=float, default=30.0)
    ns = parser.parse_args()
    command = list(ns.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("provide a server command after --")

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    stdout_q: queue.Queue[str] = queue.Queue()
    stderr_q: queue.Queue[str] = queue.Queue()
    threading.Thread(target=_reader, args=(proc.stdout, stdout_q), daemon=True).start()
    threading.Thread(target=_reader, args=(proc.stderr, stderr_q), daemon=True).start()

    request: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {
                "fs": {"readTextFile": False, "writeTextFile": False},
                "terminal": False,
            },
            "clientInfo": {
                "name": "acp-server-probe",
                "title": "Antigravity ACP Harness Probe",
                "version": "0.1.0",
            },
        },
    }
    proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
    proc.stdin.flush()

    try:
        while True:
            line = stdout_q.get(timeout=ns.timeout)
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") != 1:
                continue
            if "error" in message:
                raise RuntimeError(f"initialize failed: {message['error']}")
            result = message.get("result") or {}
            summary = {
                "protocolVersion": result.get("protocolVersion"),
                "agentInfo": result.get("agentInfo"),
                "authMethods": result.get("authMethods"),
                "agentCapabilities": result.get("agentCapabilities"),
            }
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0
    except queue.Empty as exc:
        stderr_lines: list[str] = []
        while not stderr_q.empty():
            stderr_lines.append(stderr_q.get_nowait().rstrip())
        # Server stderr is untrusted and may carry live credentials; never
        # echo it. Report only a non-reversible fingerprint for correlation.
        import hashlib

        raw = "\n".join(stderr_lines).encode("utf-8", "replace")
        fingerprint = hashlib.sha256(raw).hexdigest()[:16]
        raise TimeoutError(
            "Timed out waiting for ACP initialize. Server stderr suppressed "
            f"(untrusted text is never echoed): {len(stderr_lines)} line(s), "
            f"{len(raw)} byte(s), sha256={fingerprint}"
        ) from exc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
