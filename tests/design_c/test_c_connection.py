import contextlib
import json
import os
import signal
import types
import sys
import threading

import pytest

from antigravity_acp_mcp.acp_connection import AcpConnection, AcpProcessExit, AcpRpcError
from antigravity_acp_mcp.conversation import Conversation, ProviderError

from ._support import SYS, TOOLS, dump, tree_helpers


def test_early_update_before_session_new_reply_is_buffered_and_flushed(connect):
    conn = connect({"early_update": True})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    got = []
    conn.attach_session(sid, got.append, lambda p: None)
    assert [u["content"]["text"] for u in got] == ["early"]  # delivered in order, on attach


def test_stderr_flood_of_a_megabyte_does_not_block_child(connect):
    conn = connect({"flood_stderr": 1_200_000})  # initialize reply only comes after the flood
    assert conn.request("x/dump", {}, timeout=10)["cwd"] == conn.cwd
    assert len(conn._stderr) == 200  # 12000 lines were flooded; only the bounded tail is kept


def test_child_exit_surfaces_status_and_diagnostic_but_never_stderr_bytes(connect):
    ya29_val = "ya29." + "SECRET1234567"
    bearer_val = "Bea" + "rer SECRET"
    secret_lines = ["boot ok", f"token {ya29_val}", f"Authorization: {bearer_val}"]
    conn = connect({"exit_on": "session/new", "exit_code": 7, "stderr_lines": secret_lines})
    with pytest.raises(AcpProcessExit) as raised:
        conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)
    text = str(raised.value)
    assert "status 7" in text and "server stderr suppressed" in text
    assert "google-access-token-prefix" in text and "bearer-token" in text
    for planted in ("ya29." + "SECRET", bearer_val, "boot ok"):
        assert planted not in text and planted not in repr(raised.value)
    assert raised.value.exit_status == 7
    with pytest.raises(AcpProcessExit):  # later requests fail the same typed way
        conn.request("x/dump", {}, timeout=10)


def test_rate_limit_stderr_sets_fixed_retry_class(connect):
    conn = connect({"exit_on": "session/new", "stderr_lines": ["Error 429, RESOURCE_EXHAUSTED"]})
    with pytest.raises(AcpProcessExit) as raised:
        conn.request("session/new", {}, timeout=10)
    assert raised.value.retry_class == "rate-limit" == conn.stderr_retry_class
    assert "RESOURCE_EXHAUSTED" not in str(raised.value)


def test_child_env_has_no_secrets_but_gets_explicit_mux_vars(connect, planted_secrets):
    conn = connect(mux_env={"ACP_MUX_AFFINITY": "conv-1", "ACP_MUX_AFFINITY_PIN": "1"})
    info = dump(conn)
    for name in planted_secrets:
        assert name not in info["env_names"], name
    assert info["mux"] == {"ACP_MUX_AFFINITY": "conv-1", "ACP_MUX_AFFINITY_PIN": "1"}
    assert info["cwd"] == conn.cwd


def test_unlisted_mux_variable_is_refused(tmp_path):
    with pytest.raises(ValueError):
        AcpConnection("x", [], str(tmp_path), mux_env={"ACP_MUX_PAR": "/evil"})


def test_initialize_is_honest_and_unknown_agent_requests_get_32601(connect):
    conn = connect({"agent_request": "fs/read_text_file", "permission": None})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    conn.attach_session(sid, lambda u: None, lambda p: None)
    meta = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10)["_meta"]
    assert meta["agentRequestResponse"]["error"]["code"] == -32601
    init = dump(conn)["log"][0]["params"]
    assert init["clientInfo"]["name"] == "hermes-antigravity-acp-mcp"
    assert init["clientCapabilities"] == {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}


def test_rpc_error_is_typed(connect):
    conn = connect()
    with pytest.raises(AcpRpcError) as raised:
        conn.request("x/error", {}, timeout=10)
    assert raised.value.code == -32000


def test_rpc_error_message_redacts_secrets_and_truncates_through_conversation(tmp_path):
    oauth_secret = "SYNTH_OAUTH_CODE_999"
    oauth_url = (
        "https://accounts.google.com/o/"
        + "oauth2/v2/auth?client_id="
        + "synthclient1234567890&code="
        + oauth_secret
    )
    bearer_secret = "SYNTH_BEARER_VALUE_12345678901234567890"
    bearer_text = "Bea" + "rer " + bearer_secret
    assign_secret = "SYNTH_ACCESS_ASSIGN_987654321"
    assign_text = "access_" + "token=" + assign_secret
    bare_ya29 = "ya29." + "SYNTH_BARE_TOKEN_1234567890"
    secret_msg = (
        f"login failed at {oauth_url}; header {bearer_text}; "
        f"{assign_text}; raw {bare_ya29}"
    )
    oversized_msg = "oversized-error-" + ("E" * 1200)

    script = tmp_path / "err_acp.py"
    script.write_text(
        "import json, sys\n"
        "cfg = json.loads(sys.argv[1])\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    rid, method = msg.get('id'), msg.get('method')\n"
        "    if rid is None:\n"
        "        continue\n"
        "    if method == 'initialize':\n"
        "        res = {'protocolVersion': 1, 'agentCapabilities': {}}\n"
        "        out = {'jsonrpc': '2.0', 'id': rid, 'result': res}\n"
        "    elif method == 'session/new':\n"
        "        if cfg.get('fail_new'):\n"
        "            out = {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32000, 'message': cfg['fail_new']}}\n"
        "        else:\n"
        "            out = {'jsonrpc': '2.0', 'id': rid, 'result': {'sessionId': 's1'}}\n"
        "    elif method == 'session/prompt':\n"
        "        out = {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32000, 'message': cfg['secret_msg']}}\n"
        "    elif method == 'x/secret_error':\n"
        "        out = {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32000, 'message': cfg['secret_msg']}}\n"
        "    elif method == 'x/long_error':\n"
        "        out = {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32000, 'message': cfg['oversized_msg']}}\n"
        "    else:\n"
        "        out = {'jsonrpc': '2.0', 'id': rid, 'result': {}}\n"
        "    sys.stdout.write(json.dumps(out) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )

    cfg = json.dumps({"secret_msg": secret_msg, "oversized_msg": oversized_msg})
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    conn = AcpConnection(sys.executable, [str(script), cfg], str(cwd))
    conn.start()
    try:
        conn.initialize(timeout=20)
        with pytest.raises(AcpRpcError) as sec_exc:
            conn.request("x/secret_error", {}, timeout=10)
        msg = sec_exc.value.rpc_message
        assert "[REDACTED_OAUTH_URL]" in msg
        assert "Bearer [REDACTED]" in msg
        assert "access_token=[REDACTED]" in msg
        assert "[REDACTED_TOKEN]" in msg
        for planted in (oauth_secret, bearer_secret, assign_secret, bare_ya29):
            assert planted not in msg
            assert planted not in str(sec_exc.value)
            assert planted not in repr(sec_exc.value)

        with pytest.raises(AcpRpcError) as long_exc:
            conn.request("x/long_error", {}, timeout=10)
        assert len(long_exc.value.rpc_message) <= 512
        assert long_exc.value.rpc_message.endswith("…")
    finally:
        conn.close()

    def spawn_for_prompt(_key: str, spawn_cwd: str) -> AcpConnection:
        c = AcpConnection(sys.executable, [str(script), cfg], spawn_cwd)
        c.start()
        c.initialize(timeout=20)
        return c

    conv = Conversation("k-err-prompt", spawn_for_prompt)
    try:
        with pytest.raises(ProviderError) as prov_exc:
            conv.run([SYS, {"role": "user", "content": "hi"}], TOOLS, "m")
        rendered = str(prov_exc.value)
        assert "[REDACTED_OAUTH_URL]" in rendered
        assert "Bearer [REDACTED]" in rendered
        assert "[REDACTED_TOKEN]" in rendered
        for planted in (oauth_secret, bearer_secret, assign_secret, bare_ya29):
            assert planted not in rendered and planted not in repr(prov_exc.value)
    finally:
        conv.close()

    open_cfg = json.dumps({"secret_msg": secret_msg, "oversized_msg": oversized_msg, "fail_new": oversized_msg})

    def spawn_for_open(_key: str, spawn_cwd: str) -> AcpConnection:
        c = AcpConnection(sys.executable, [str(script), open_cfg], spawn_cwd)
        c.start()
        c.initialize(timeout=20)
        return c

    conv_open = Conversation("k-err-open", spawn_for_open)
    try:
        with pytest.raises(ProviderError) as open_exc:
            conv_open.run([SYS, {"role": "user", "content": "hi"}], TOOLS, "m")
        assert len(str(open_exc.value)) < 650
        assert "…" in str(open_exc.value)
    finally:
        conv_open.close()


def test_cancel_answers_pending_permissions_cancelled_then_notifies(connect):
    conn = connect({"permission": {"toolCall": {"toolCallId": "t1"}, "options": []}, "wait_cancel": True})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    seen = threading.Event()
    conn.attach_session(sid, lambda u: None, lambda p: seen.set())  # returns None: stays pending
    result = {}
    t = threading.Thread(target=lambda: result.update(conn.request("session/prompt", {"sessionId": sid, "prompt": []})))
    t.start()
    assert seen.wait(10)
    conn.cancel_session(sid)
    t.join(10)
    assert result["stopReason"] == "cancelled"
    log = dump(conn)["log"]
    answers = [m for m in log if m.get("id") == 900]
    assert answers[0]["result"] == {"outcome": {"outcome": "cancelled"}}
    methods = [m.get("method") for m in log]
    assert methods.index("session/cancel") > log.index(answers[0])


def test_close_reaps_the_child(connect):
    conn = connect()
    conn.close()
    assert conn._proc.poll() is not None


def test_cgroup_containment_hook_dispatches_and_falls_back(tmp_path, monkeypatch):
    import antigravity_acp_mcp.acp_connection as mod

    h = tree_helpers()
    events = []

    class _FakeContainment:
        def __init__(self, ok: bool) -> None:
            self._ok = ok

        def wrap_argv(self, argv):
            events.append(("wrap", list(argv)))
            return list(argv)

        def pass_fds(self):
            return ()

        def confirm(self):
            events.append(("confirm", self._ok))
            return self._ok

        def abort(self):
            events.append(("abort", None))

    orig_td = mod._process_teardown.terminate_process_tree

    def _fake_contained_td(proc, c, graceful_stdin=False):
        events.append(("contained", graceful_stdin))
        res = orig_td(proc, graceful_stdin=graceful_stdin, session_leader=True)
        if res is None and os.name != "nt":
            # Simulate cgroup.kill sweeping survivors even after poll() reaped leader.
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            return True
        return res

    monkeypatch.setattr(mod._process_teardown, "terminate_contained_tree", _fake_contained_td)
    cwd = tmp_path / "cwd"
    cwd.mkdir()

    for name, confirm_ok, cfg in (
        ("cg_ok", True, {}),
        ("cg_waitid_fb", True, {"wrapper_exits_early": True, "wrapper_exit_code": 11, "hang_init": True}),
        ("cg_abort", False, {}),
    ):
        events.clear()
        sdir, _, cmd, args = h._write_fixture(tmp_path, name, cfg)
        fake = _FakeContainment(confirm_ok)
        monkeypatch.setattr(mod._cgroup_containment.Containment, "begin", classmethod(lambda cls, f=fake: f))
        orig_enabled = mod._process_teardown._non_reaping_enabled
        if name == "cg_waitid_fb":
            monkeypatch.setattr(mod._process_teardown, "_non_reaping_enabled", False)
        conn = AcpConnection(cmd, args, str(cwd))
        pids = []
        try:
            conn.start()
            pids = h._tree_pids(sdir)
            if name == "cg_waitid_fb":
                with pytest.raises(AcpProcessExit) as exc_info:
                    conn.initialize(timeout=6.0)
                assert exc_info.value.exit_status == 11
                assert ("contained", False) in events
            else:
                if not confirm_ok:
                    assert ("abort", None) in events and conn._containment is None
                conn.initialize(timeout=15)
                assert conn.close() is True
                assert (("contained", False) in events) is confirm_ok
            assert h._wait_until(lambda: all(not h._pid_alive(p) for p in pids), timeout=5.0)
        finally:
            mod._process_teardown._non_reaping_enabled = orig_enabled
            with contextlib.suppress(Exception):
                conn.close()
            h._cleanup_state(sdir, pids, conn._proc)


@pytest.mark.skipif(os.name == "nt", reason="POSIX stdout-close behavior")
def test_posix_stdout_close_while_alive_terminates_and_unblocks_threads(tmp_path):
    h = tree_helpers()
    sdir, _, cmd, args = h._write_fixture(tmp_path, "close_stdout", {"close_stdout_then_wait": True, "ignore_sigterm": True})
    cwd = tmp_path / "cwd_co"
    cwd.mkdir()
    conn = AcpConnection(cmd, args, str(cwd))
    pids = []
    try:
        conn.start()
        pids = h._tree_pids(sdir)
        conn.close()
        assert h._wait_until(lambda: all(not h._pid_alive(p) for p in pids), timeout=5.0)
        assert all(not t.is_alive() for t in conn._threads)
    finally:
        with contextlib.suppress(Exception):
            conn.close()
        h._cleanup_state(sdir, pids, conn._proc)


def test_windows_spawn_contract_uses_hide_flags_and_no_new_session(tmp_path, monkeypatch):
    import antigravity_acp_mcp.acp_connection as mod

    captured = []

    class _FakeProc:
        pid = 424242
        returncode = None
        stdin = types.SimpleNamespace(closed=True, close=lambda: None)
        stdout = iter(())
        stderr = types.SimpleNamespace(readline=lambda _n=0: b"")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(mod.os, "name", "nt")
    monkeypatch.setattr(mod, "_build_subprocess_env", lambda: {})
    monkeypatch.setattr(mod, "_windows_hide_flags", lambda: 0x08000000)
    monkeypatch.setattr(mod._cgroup_containment.Containment, "begin", classmethod(lambda cls: None))
    monkeypatch.setattr(mod.subprocess, "Popen", lambda argv, **kw: (captured.append(kw), _FakeProc())[-1])
    conn = AcpConnection("fake.exe", ["--acp"], str(tmp_path))
    conn.start()
    try:
        assert captured[0]["start_new_session"] is False
        assert captured[0]["creationflags"] == 0x08000000
    finally:
        conn.close()
