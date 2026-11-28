"""Tests for the resilient scripts/antigravity-acp-mux.py entrypoint."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "scripts" / "antigravity-acp-mux.py"

spec = importlib.util.spec_from_file_location("acp_mux_guard", GUARD_PATH)
assert spec is not None and spec.loader is not None
acp_mux_guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acp_mux_guard)


def _vendor_update(text: str) -> dict:
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


def test_only_exact_vendor_execution_sentinel_is_classified() -> None:
    validation = _vendor_update(
        'Agent execution error: Agent execution terminated due to error. '
        '("request failed (code 403): Verify your account to continue.")'
    )
    assert acp_mux_guard._classify_vendor_execution_error_payload(validation) == (
        "validation",
        validation["params"]["update"]["content"]["text"],
    )

    quota = _vendor_update(
        'Agent execution error: Agent execution terminated due to error. '
        '("request failed (code 429): RESOURCE_EXHAUSTED")'
    )
    assert acp_mux_guard._classify_vendor_execution_error_payload(quota)[0] == "quota"

    ordinary = _vendor_update(
        "A 403 can say Verify your account to continue; here is how to debug it."
    )
    assert acp_mux_guard._classify_vendor_execution_error_payload(ordinary) is None

    wrong_update_kind = validation.copy()
    wrong_update_kind = json.loads(json.dumps(wrong_update_kind))
    wrong_update_kind["params"]["update"]["sessionUpdate"] = "agent_thought_chunk"
    assert acp_mux_guard._classify_vendor_execution_error_payload(wrong_update_kind) is None


def test_validation_uses_long_quarantine() -> None:
    assert acp_mux_guard._cooldown_for("validation") == acp_mux_guard.VALIDATION_COOLDOWN
    assert acp_mux_guard.VALIDATION_COOLDOWN == 86400.0


def test_entrypoint_forwards_resume_pin_to_account_selector(tmp_path) -> None:
    home_a = tmp_path / "account-a"
    home_b = tmp_path / "account-b"
    home_a.mkdir()
    home_b.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps(
            {
                "accounts": [
                    {"home": str(home_a), "label": "a", "priority": 0},
                    {"home": str(home_b), "label": "b", "priority": 1},
                ]
            }
        ),
        encoding="utf-8",
    )
    state = tmp_path / "state.json"
    affinity = "sha256:opaque-affinity"
    digest = acp_mux_guard.base._affinity_digest(affinity)
    account_key = f"b\t{home_b}"
    state.write_text(
        json.dumps(
            {
                "accounts": {},
                "affinities": {
                    digest: {
                        "account_key": account_key,
                        "selected_key": account_key,
                        "last_seen": time.time(),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    fake = tmp_path / "fake-acp"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'protocolVersion': 1}}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    log = tmp_path / "mux.log"
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(state),
            "ACP_MUX_LOG": str(log),
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_AFFINITY": affinity,
            "ACP_MUX_AFFINITY_PIN": "1",
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    proc = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "selected b via affinity" in log.read_text(encoding="utf-8")


def test_lru_strategy_distributes_across_guard_entrypoint_restarts(tmp_path) -> None:
    fake = tmp_path / "fake-acp"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'protocolVersion': 1}}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    accounts = []
    for name in ("a", "b"):
        home = tmp_path / f"account-{name}"
        home.mkdir()
        accounts.append({"home": str(home), "label": name, "priority": 0})
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps({"strategy": "lru", "accounts": accounts}), encoding="utf-8"
    )
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_PAR": str(fake),
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    for _ in range(4):
        proc = subprocess.run(
            [sys.executable, str(GUARD_PATH)],
            input=request,
            text=True,
            capture_output=True,
            env=env,
            timeout=15,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr

    log_text = (tmp_path / "mux.log").read_text(encoding="utf-8")
    labels = re.findall(r"selected (\S+) via lru", log_text)
    assert labels == ["a", "b", "a", "b"]


def test_lru_strategy_preserves_session_owner_routing(tmp_path) -> None:
    fake = tmp_path / "fake-acp"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'protocolVersion': 1}}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    home_a = tmp_path / "account-a"
    home_b = tmp_path / "account-b"
    home_a.mkdir()
    home_b.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps(
            {
                "strategy": "lru",
                "accounts": [
                    {"home": str(home_a), "label": "a", "priority": 0},
                    {"home": str(home_b), "label": "b", "priority": 0},
                ],
            }
        ),
        encoding="utf-8",
    )
    state = tmp_path / "state.json"
    session_id = "11111111-1111-4111-8111-111111111111"
    base = acp_mux_guard.base
    old_registry, old_state = base.REGISTRY_PATH, base.STATE_PATH
    try:
        base.REGISTRY_PATH = str(registry)
        base.STATE_PATH = str(state)
        assert base._record_session_owner(
            session_id, str(home_b), "b", origin="agent", lifecycle="ephemeral"
        )
    finally:
        base.REGISTRY_PATH, base.STATE_PATH = old_registry, old_state

    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(state),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_SESSION_ID": session_id,
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    proc = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "selected b via session-owner" in (tmp_path / "mux.log").read_text(
        encoding="utf-8"
    )


def test_lru_strategy_preserves_resume_pin_on_healthy_lane(tmp_path) -> None:
    home_a = tmp_path / "account-a"
    home_b = tmp_path / "account-b"
    home_a.mkdir()
    home_b.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps(
            {
                "strategy": "lru",
                "accounts": [
                    {"home": str(home_a), "label": "a", "priority": 0},
                    {"home": str(home_b), "label": "b", "priority": 0},
                ],
            }
        ),
        encoding="utf-8",
    )
    state = tmp_path / "state.json"
    affinity = "sha256:opaque-affinity"
    digest = acp_mux_guard.base._affinity_digest(affinity)
    account_key = f"b\t{home_b}"
    state.write_text(
        json.dumps(
            {
                "accounts": {},
                "affinities": {
                    digest: {
                        "account_key": account_key,
                        "selected_key": account_key,
                        "last_seen": time.time(),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    fake = tmp_path / "fake-acp"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'protocolVersion': 1}}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    log = tmp_path / "mux.log"
    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(state),
            "ACP_MUX_LOG": str(log),
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_AFFINITY": affinity,
            "ACP_MUX_AFFINITY_PIN": "1",
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    proc = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "selected b via affinity" in log.read_text(encoding="utf-8")


def test_embedded_validation_becomes_jsonrpc_error_and_quarantines_account(tmp_path) -> None:
    fake = tmp_path / "fake-acp"
    fake.write_text(
        """#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get('method')
    rid = req.get('id')
    if method == 'initialize':
        print(json.dumps({'jsonrpc':'2.0','id':rid,'result':{'protocolVersion':1}}), flush=True)
    elif method == 'session/new':
        print(json.dumps({'jsonrpc':'2.0','id':rid,'result':{'sessionId':'s-test'}}), flush=True)
    elif method == 'session/prompt':
        print(json.dumps({
            'jsonrpc':'2.0',
            'method':'session/update',
            'params':{'update':{
                'sessionUpdate':'agent_message_chunk',
                'content':{'type':'text','text':'Agent execution error: Agent execution terminated due to error. (\\"request failed (code 403): Verify your account to continue.\\")'}
            }}
        }), flush=True)
        print(json.dumps({'jsonrpc':'2.0','id':rid,'result':{'stopReason':'end_turn'}}), flush=True)
"""
    )
    fake.chmod(0o755)

    account_home = tmp_path / "account-a"
    account_home.mkdir()
    registry = tmp_path / "accounts.json"
    state = tmp_path / "state.json"
    log = tmp_path / "mux.log"
    registry.write_text(
        json.dumps(
            {
                "accounts": [
                    {"home": str(account_home), "label": "a", "priority": 0}
                ]
            }
        )
    )

    env = os.environ.copy()
    env.update(
        {
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(state),
            "ACP_MUX_LOG": str(log),
            "ACP_MUX_HOME": str(tmp_path),
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
            "ACP_MUX_VALIDATION_COOLDOWN": "86400",
        }
    )
    requests = "\n".join(
        json.dumps(item)
        for item in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/new",
                "params": {"cwd": str(tmp_path), "mcpServers": []},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {
                    "sessionId": "s-test",
                    "prompt": [{"type": "text", "text": "hello"}],
                },
            },
        ]
    ) + "\n"

    proc = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=requests,
        text=True,
        capture_output=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    messages = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    prompt_responses = [message for message in messages if message.get("id") == 3]
    assert len(prompt_responses) == 1
    assert "error" in prompt_responses[0]
    assert "403" in prompt_responses[0]["error"]["message"]
    assert "Verify your account to continue" in prompt_responses[0]["error"]["message"]
    assert not any(message.get("method") == "session/update" for message in messages)

    health = json.loads(state.read_text())["accounts"]
    record = health[f"a\t{account_home}"]
    assert record["reason"] == "validation"
    assert record["cooldown_until"] > record["last_failure_at"] + 86_000
