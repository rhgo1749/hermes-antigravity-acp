"""1.2.1 stabilization regressions: MCP config guard, in-band provider errors, redaction.

All tests use a fake ACP subprocess and isolated homes; no Google binary, no
credentials, no network.  See docs/official-server-1.2.1-contract.md (S1-S4).
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "scripts" / "antigravity-acp-mux.py"

spec = importlib.util.spec_from_file_location("acp_mux_guard_121", GUARD_PATH)
assert spec is not None and spec.loader is not None
acp_mux_guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acp_mux_guard)
base = acp_mux_guard.base

QUOTA_HEAD = (
    "Usage Limit Reached\n\n"
    "You have reached your current quota for this period."
)
CONNECTION_HEAD = (
    "Agent connection was lost and could not be re-established: close(1006)"
)


def _update(text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": text},
            }
        },
    }


# ---------------------------------------------------------------- units


def test_quota_and_connection_signatures_classified_at_turn_head() -> None:
    assert acp_mux_guard._classify_inband_turn_head(QUOTA_HEAD)[0] == "quota"
    assert (
        acp_mux_guard._classify_inband_turn_head(QUOTA_HEAD + " Try again at 5pm.")[0]
        == "quota"
    )
    assert (
        acp_mux_guard._classify_inband_turn_head(CONNECTION_HEAD)[0]
        == "connection-lost"
    )


def test_signatures_are_position_anchored_against_false_positives() -> None:
    # Quoted or mid-turn mentions must never be classified as provider errors.
    assert acp_mux_guard._classify_inband_turn_head(
        "Here is why the error appeared:\n\n" + QUOTA_HEAD
    ) is None
    assert acp_mux_guard._classify_inband_turn_head(
        "```text\n" + QUOTA_HEAD + "\n```"
    ) is None
    assert acp_mux_guard._classify_inband_turn_head("Quota exceeded is a 429.") is None
    assert acp_mux_guard._classify_inband_turn_head("Usage") is None  # partial prefix


def test_mcp_config_guard_reasons() -> None:
    home = str(Path(base.pinned_gemini_home("/tmp/unused")))
    assert base.mcp_config_violation(home) is None


def test_mcp_config_guard_reads_isolated_home(tmp_path) -> None:
    gemini = tmp_path / "gemini"
    config = gemini / "config" / "mcp_config.json"
    assert base.mcp_config_violation(str(gemini)) is None
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    assert base.mcp_config_violation(str(gemini)) is None
    config.write_text('{"mcpServers": {}}', encoding="utf-8")
    assert base.mcp_config_violation(str(gemini)) is None
    config.write_text('{"mcpServers": {"evil": {"command": "x"}}}', encoding="utf-8")
    reason = base.mcp_config_violation(str(gemini))
    assert reason is not None and "evil" in reason
    config.write_text("not-json", encoding="utf-8")
    assert base.mcp_config_violation(str(gemini)) == "malformed-json"


def test_oauth_authentication_urls_are_redacted() -> None:
    line = (
        "Open the following link to authenticate the ACP server: "
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc"
        "&state=topsecretvalue&redirect_uri=http://localhost:1234/callback"
    )
    redacted = base._redact(line)
    assert "topsecretvalue" not in redacted
    assert "accounts.google.com/o/oauth2" not in redacted


# ------------------------------------------------------------- e2e harness


FAKE_ACP = r'''
import json
import os
import sys

mode = os.environ.get("FAKE_MODE", "plain")
log_path = os.environ.get("FAKE_LOG", "")

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(row):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

log({"event": "start", "home": os.environ.get("HOME", ""),
     "gemini_home": os.environ.get("GEMINI_HOME", "")})

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    log({"method": method})
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": 1}})
    elif method == "session/new":
        emit({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": "s-121"}})
    elif method == "session/prompt":
        if mode == "quota-split":
            emit(_u("Usage Limit Reach"))
            emit(_u("ed\n\nYou have reached your current quota for this period."
                    " Try again later."))
        elif mode == "connection-lost":
            emit(_u("Agent connection was lost and could not be"
                    " re-established: (code 429: boom)"))
        elif mode == "ordinary":
            emit(_u("Debug note: "))
            emit(_u("Usage Limit Reached\n\nYou have reached your current"
                    " quota for this period."))
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''

FAKE_ACP_HELPERS = (
    "#!/usr/bin/env python3\n"
    "def _u(text):\n"
    "    return {'jsonrpc': '2.0', 'method': 'session/update', 'params':"
    " {'update': {'sessionUpdate': 'agent_message_chunk',"
    " 'content': {'type': 'text', 'text': text}}}}\n"
)


def _write_fake(tmp_path: Path, mode: str) -> Path:
    fake = tmp_path / "fake-acp.py"
    fake.write_text(FAKE_ACP_HELPERS + FAKE_ACP, encoding="utf-8")
    fake.chmod(0o755)
    return fake


def _registry(tmp_path: Path, home: Path) -> Path:
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps({"accounts": [{"home": str(home), "label": "a", "priority": 0}]}),
        encoding="utf-8",
    )
    return registry


def _run_wrapper(tmp_path: Path, fake: Path, account_home: Path, mode: str,
                 extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_ACCOUNTS": str(_registry(tmp_path, account_home)),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_HOME": str(tmp_path / "default-home"),
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
            "FAKE_MODE": mode,
            "FAKE_LOG": str(tmp_path / "fake.log"),
        }
    )
    env.pop("GEMINI_HOME", None)
    if extra_env:
        env.update(extra_env)
    requests = "\n".join(
        json.dumps(item)
        for item in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "session/new",
             "params": {"cwd": str(tmp_path), "mcpServers": []}},
            {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
             "params": {"sessionId": "s-121",
                        "prompt": [{"type": "text", "text": "hi"}]}},
        ]
    ) + "\n"
    return subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=requests, text=True, capture_output=True, env=env, timeout=15,
        check=False,
    )


def test_quota_digest_split_across_chunks_becomes_error_and_quarantine(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    account_home.mkdir()
    proc = _run_wrapper(tmp_path, _write_fake(tmp_path, "quota-split"), account_home,
                        "quota-split")
    assert proc.returncode == 0, proc.stderr
    messages = [json.loads(raw) for raw in proc.stdout.splitlines() if raw.strip()]
    updates = [m for m in messages if m.get("method") == "session/update"]
    assert updates == []  # digest chunks must never surface as model output
    replies = [m for m in messages if m.get("id") == 3]
    assert len(replies) == 1 and "error" in replies[0]
    message = replies[0]["error"]["message"]
    assert "resource_exhausted" in message and "Usage Limit Reached" in message
    health = json.loads((tmp_path / "state.json").read_text())["accounts"]
    assert health[f"a\t{account_home}"]["reason"] == "quota"


def test_connection_lost_digest_fails_turn_without_retryable_text(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    account_home.mkdir()
    proc = _run_wrapper(tmp_path, _write_fake(tmp_path, "connection-lost"),
                        account_home, "connection-lost")
    messages = [json.loads(raw) for raw in proc.stdout.splitlines() if raw.strip()]
    replies = [m for m in messages if m.get("id") == 3]
    assert len(replies) == 1 and "error" in replies[0]
    message = replies[0]["error"]["message"]
    assert "connection-lost" in message
    # The client must not mistake this for a retryable quota/auth error.
    assert "429" not in message and "quota" not in message
    health = json.loads((tmp_path / "state.json").read_text())["accounts"]
    assert health[f"a\t{account_home}"]["reason"] == "connection-lost"


def test_ordinary_answer_mentioning_quota_passes_through(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    account_home.mkdir()
    proc = _run_wrapper(tmp_path, _write_fake(tmp_path, "ordinary"), account_home,
                        "ordinary")
    messages = [json.loads(raw) for raw in proc.stdout.splitlines() if raw.strip()]
    updates = [m for m in messages if m.get("method") == "session/update"]
    assert len(updates) == 2
    replies = [m for m in messages if m.get("id") == 3]
    assert len(replies) == 1 and "result" in replies[0]
    assert not (tmp_path / "state.json").exists() or json.loads(
        (tmp_path / "state.json").read_text()
    )["accounts"] == {}


def test_mcp_config_guard_blocks_spawn_and_pins_gemini_home(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    config = account_home / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mcpServers": {"evil": {"command": "x"}}}', encoding="utf-8")
    default_home = tmp_path / "default-home"
    (default_home / ".gemini" / "config").mkdir(parents=True)
    (default_home / ".gemini" / "config" / "mcp_config.json").write_text(
        '{"mcpServers": {"also-evil": {}}}', encoding="utf-8"
    )
    proc = _run_wrapper(tmp_path, _write_fake(tmp_path, "plain"), account_home, "plain")
    # historical reference re-pin: the poisoned lane must fail CLOSED at exit 2 instead
    # of the old exit 1 reached through a silent re-bind attempt onto the
    # default home.  The default lane is never even consulted now.
    assert proc.returncode == 2
    assert proc.stdout.strip() == ""
    assert "refusing a silent account fallback" in proc.stderr
    health = json.loads((tmp_path / "state.json").read_text())["accounts"]
    assert health[f"a\t{account_home}"]["reason"] == "mcp-config"


def test_empty_global_config_allows_spawn_with_pinned_gemini_home(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    config = account_home / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    fake = _write_fake(tmp_path, "plain")
    proc = _run_wrapper(tmp_path, fake, account_home, "plain")
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(raw) for raw in (tmp_path / "fake.log").read_text().splitlines()]
    start = rows[0]
    assert start["home"] == str(account_home)
    assert start["gemini_home"] == str(account_home / ".gemini")


def test_toctou_guard_rechecks_mcp_config_before_session_new(tmp_path) -> None:
    account_home = tmp_path / "account-a"
    config = account_home / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    fake = _write_fake(tmp_path, "plain")
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_ACCOUNTS": str(_registry(tmp_path, account_home)),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_HOME": str(tmp_path / "default-home"),
            "FAKE_MODE": "plain",
            "FAKE_LOG": str(tmp_path / "fake.log"),
        }
    )
    env.pop("GEMINI_HOME", None)
    proc = subprocess.Popen(
        [sys.executable, str(GUARD_PATH)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    ) + "\n")
    proc.stdin.flush()
    started = time.monotonic()
    while time.monotonic() - started < 10:
        line = proc.stdout.readline()
        if not line:
            break
        if json.loads(line).get("id") == 1:
            break
    else:
        proc.kill()
        raise AssertionError("no initialize response")
    # TOCTOU: the global MCP config turns hostile after the bind-time check.
    config.write_text('{"mcpServers": {"late": {"command": "x"}}}', encoding="utf-8")
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "session/new",
         "params": {"cwd": str(tmp_path), "mcpServers": []}}
    ) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    proc.stdin.close()
    proc.wait(timeout=10)
    payload = json.loads(line)
    assert payload.get("id") == 2 and "error" in payload
    assert "MCP config guard" in payload["error"]["message"]
    fake_methods = [
        row["method"]
        for row in (
            json.loads(raw) for raw in (tmp_path / "fake.log").read_text().splitlines()
        )
        if row.get("method")
    ]
    assert "session/new" not in fake_methods  # never forwarded upstream


def test_mcp_guard_also_blocks_model_switch_merges(tmp_path) -> None:
    # The official server merges global MCP settings not only on session
    # creation but on every model rebuild (set_model / set_config_option
    # with configId=model), so the TOCTOU guard must cover those too.
    account_home = tmp_path / "account-a"
    config = account_home / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    fake = _write_fake(tmp_path, "plain")
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_ACCOUNTS": str(_registry(tmp_path, account_home)),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_HOME": str(tmp_path / "default-home"),
            "FAKE_MODE": "plain",
            "FAKE_LOG": str(tmp_path / "fake.log"),
        }
    )
    env.pop("GEMINI_HOME", None)
    proc = subprocess.Popen(
        [sys.executable, str(GUARD_PATH)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    ) + "\n")
    proc.stdin.flush()
    started = time.monotonic()
    while time.monotonic() - started < 10:
        line = proc.stdout.readline()
        if not line:
            break
        if json.loads(line).get("id") == 1:
            break
    else:
        proc.kill()
        raise AssertionError("no initialize response")
    # Hostile global MCP config appears after the bind-time validation.
    config.write_text('{"mcpServers": {"late": {"command": "x"}}}', encoding="utf-8")
    for request_id, method, params in (
        (2, "session/set_model", {"sessionId": "s-1", "modelId": "gem"}),
        (3, "session/set_config_option", {"sessionId": "s-1", "configId": "model",
                                          "value": "gem"}),
    ):
        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        ) + "\n")
        proc.stdin.flush()
        payload = json.loads(proc.stdout.readline())
        assert payload.get("id") == request_id and "error" in payload
        assert "MCP config guard" in payload["error"]["message"]
    proc.stdin.close()
    proc.wait(timeout=10)
    fake_methods = [
        row["method"]
        for row in (
            json.loads(raw) for raw in (tmp_path / "fake.log").read_text().splitlines()
        )
        if row.get("method")
    ]
    assert "session/set_model" not in fake_methods
    assert "session/set_config_option" not in fake_methods
