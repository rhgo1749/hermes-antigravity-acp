"""PlanC S3/S4: conversation turns against a fake agy that really calls the parked MCP endpoint."""

import contextlib
import json
import sys
import threading
import time

import pytest

from antigravity_acp_mcp.acp_connection import AcpConnection
from antigravity_acp_mcp.client import AntigravityAcpMcpClient
from antigravity_acp_mcp.conversation import (
    GUARD_TEXT,
    CancelledByUser,
    Conversation,
    RateLimited,
    StepTimeout,
)

from ._support import FAKE_AGY as FAKE, SYS, TOOLS, asst, events, make_conv, tool_rows

U1 = {"role": "user", "content": "check a and b"}
SAMPLE_429 = ("E1123 02:31:21.478230     119 errorreport.go:273] Error 429, Message: Resource has been exhausted "
              "(e.g. check quota)., Status: RESOURCE_EXHAUSTED, Details: []")


def test_two_hop_turn_is_one_prompt_then_continue_sends_only_the_delta(tmp_path):
    conv, log = make_conv(tmp_path, [
        [{"call": {"name": "fetch", "arguments": {"k": "a"}}},
         {"call": {"name": "fetch", "arguments": {"k": "b"}}}, {"text": "both fine"}],
        [{"text": "c fine"}],
    ])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r1["tool_calls"]] == [{"k": "a"}]
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r2["tool_calls"]] == [{"k": "b"}]
        msgs += [asst(r2["tool_calls"]), *tool_rows(r2["tool_calls"], ["B"])]
        r3 = conv.run(msgs, TOOLS, "m")
        assert r3["tool_calls"] == [] and r3["text"] == "both fine"
        ev = events(log)
        assert [e["n"] for e in ev if e["ev"] == "prompt"] == [0]  # one ACP prompt for the whole turn
        assert [e["text"] for e in ev if e["ev"] == "answer"] == ["A", "B"]
        assert "SYS-MARK" in ev[1]["text"]  # system band in the prompt, no append
        meta = ev[0]["meta"]["antigravity"]
        assert set(meta) == {"disabledTools", "eagerMcpServers", "mcpMaxOutputBytes"}  # no systemPrompt append
        assert meta["eagerMcpServers"][0].startswith("hermes-")
        msgs += [{"role": "assistant", "content": "both fine (as stored by Hermes)"},
                 {"role": "user", "content": "now c"}]
        r4 = conv.run(msgs, TOOLS, "m")
        assert r4["text"] == "c fine"
        prompts = [e for e in events(log) if e["ev"] == "prompt"]
        assert prompts[1]["sid"] == prompts[0]["sid"] and prompts[1]["text"] == "now c"
    finally:
        conv.close()


def test_deadline_retires_and_replay_guard_blocks_reissue(tmp_path):
    conv, log = make_conv(tmp_path, [
        [{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"text": "never"}],
        [{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"echo_last": True}],
    ], call_deadline=0.5)
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        time.sleep(1.5)  # Hermes approval takes longer than the call deadline
        assert any(e["ev"] == "cancel" for e in events(log))
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A-late"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert r2["tool_calls"] == []  # the re-issued call was not handed to Hermes again
        assert GUARD_TEXT in r2["text"]
        ev = events(log)
        prompts = [e for e in ev if e["ev"] == "prompt"]
        assert prompts[1]["sid"] != prompts[0]["sid"]  # fresh session after the cancel
        assert "A-late" in prompts[1]["text"] and "already executed" in prompts[1]["text"]
    finally:
        conv.close()


def test_new_user_row_while_parked_supersedes(tmp_path):
    conv, log = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}], [{"text": "redo"}]])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A"]),
                 {"role": "user", "content": "also c"}]
        r2 = conv.run(msgs, TOOLS, "m")
        assert r2["text"] == "redo"
        ev = events(log)
        assert any(e["ev"] == "cancel" for e in ev)
        assert len({e["sid"] for e in ev if e["ev"] == "prompt"}) == 2
    finally:
        conv.close()


def test_cancel_while_in_flight_returns_fast(tmp_path):
    conv, log = make_conv(tmp_path, [[{"silent": 20}]])
    try:
        err = {}
        token = threading.Event()

        def go():
            try:
                conv.run([SYS, U1], TOOLS, "m", token)
            except Exception as exc:  # noqa: BLE001
                err["e"] = exc

        th = threading.Thread(target=go)
        th.start()
        time.sleep(1.0)
        t = time.monotonic()
        conv.cancel(token)
        th.join(5)
        assert not th.is_alive() and time.monotonic() - t < 5
        assert isinstance(err.get("e"), CancelledByUser)
        assert any(e["ev"] == "cancel" for e in events(log))
    finally:
        conv.close()


def test_silent_model_step_times_out(tmp_path):
    conv, _ = make_conv(tmp_path, [[{"silent": 10}]], step_deadline=0.8)
    try:
        t = time.monotonic()
        with pytest.raises(StepTimeout):
            conv.run([SYS, U1], TOOLS, "m")
        assert time.monotonic() - t < 5
    finally:
        conv.close()


def test_silence_after_resume_also_times_out(tmp_path):
    conv, _ = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"silent": 10}]],
                        step_deadline=0.8)
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        time.sleep(1.5)  # waiting on Hermes does not count as model inactivity
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A"])]
        with pytest.raises(StepTimeout):
            conv.run(msgs, TOOLS, "m")
    finally:
        conv.close()


def test_real_429_line_raises_rate_limited_fast(tmp_path):
    conv, _ = make_conv(tmp_path, [[{"stderr": SAMPLE_429}, {"silent": 10}]])
    try:
        t = time.monotonic()
        with pytest.raises(RateLimited) as info:
            conv.run([SYS, U1], TOOLS, "m")
        assert time.monotonic() - t < 5
        assert "Resource has been exhausted" not in str(info.value) or "429" in str(info.value)
    finally:
        conv.close()


def test_facade_tool_calls_stream_and_cancel(tmp_path, monkeypatch):
    log = tmp_path / "agy.log"
    behaviour = json.dumps({"script": [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"text": "done"}]],
                            "log": str(log)})
    client = AntigravityAcpMcpClient(acp_command=sys.executable, acp_args=[FAKE, behaviour])
    msgs = [SYS, {"role": "user", "content": "facade turn " + tmp_path.name}]
    c1 = client.chat.completions.create(model="m", messages=msgs, tools=TOOLS)
    tc = c1.choices[0].message.tool_calls
    assert c1.choices[0].finish_reason == "tool_calls" and json.loads(tc[0].function.arguments) == {"k": "a"}
    msgs += [{"role": "assistant", "content": "", "tool_calls": [
        {"id": tc[0].id, "type": "function", "function": {"name": "fetch", "arguments": tc[0].function.arguments}}]},
        {"role": "tool", "tool_call_id": tc[0].id, "content": "A"}]
    chunks = client.chat.completions.create(model="m", messages=msgs, tools=TOOLS, stream=True)
    assert chunks[0].choices[0].delta.content == "done"
    assert [e["n"] for e in events(log) if e["ev"] == "prompt"] == [0]
    client.cancel()  # nothing in flight: no-op
    client.close()


def test_cancel_before_run_starts(tmp_path):
    conv, log = make_conv(tmp_path, [[{"text": "never"}]])
    try:
        token = threading.Event()
        token.set()
        with pytest.raises(CancelledByUser):
            conv.run([SYS, U1], TOOLS, "m", token)
        assert not [e for e in events(log) if e["ev"] == "prompt"]
    finally:
        conv.close()


def test_rate_limit_is_not_sticky_next_request_uses_a_fresh_child(tmp_path):
    conv, _ = make_conv(tmp_path, [[{"stderr": SAMPLE_429}, {"silent": 10}], [{"text": "back"}]])
    try:
        with pytest.raises(RateLimited):
            conv.run([SYS, U1], TOOLS, "m")
        r = conv.run([SYS, U1, {"role": "user", "content": "again"}], TOOLS, "m")
        assert r["text"] == "back"
    finally:
        conv.close()


def test_straggler_from_retired_generation_is_refused():
    from antigravity_acp_mcp.parked_mcp import ParkedCall
    conv = Conversation("k", lambda key, cwd: None)
    try:
        conv.gen = 3
        call = ParkedCall("fetch", {"k": "a"})
        conv._on_call(2, call)
        assert call.state != "parked" and call.is_error and conv.events.empty()
    finally:
        conv.close()


def test_guest_while_in_flight_does_not_touch_the_owned_turn(tmp_path):
    from antigravity_acp_mcp.matcher import BTW_FORK_MARKER
    conv, log = make_conv(tmp_path, [[{"silent": 2}, {"text": "main done"}]])
    try:
        out = {}
        th = threading.Thread(target=lambda: out.update(r=conv.run([SYS, U1], TOOLS, "m")))
        th.start()
        time.sleep(0.8)
        fork = [SYS, U1, {"role": "user", "content": BTW_FORK_MARKER + " ... what is a?"}]
        assert conv.run(fork, [], "m") == {"guest": True}
        th.join(10)
        assert out["r"]["text"] == "main done"
        assert not any(e["ev"] == "cancel" for e in events(log))
    finally:
        conv.close()


def test_native_tool_update_trips_and_cancels(tmp_path):
    from antigravity_acp_mcp.conversation import ProviderError
    conv, log = make_conv(tmp_path, [[{"foreign": True}, {"silent": 10}]])
    try:
        with pytest.raises(ProviderError, match="native tool"):
            conv.run([SYS, U1], TOOLS, "m")
        assert any(e["ev"] == "cancel" for e in events(log))
    finally:
        conv.close()


def test_model_change_forces_a_fresh_session(tmp_path):
    conv, log = make_conv(tmp_path, [[{"text": "one"}], [{"text": "two"}]])
    try:
        msgs = [SYS, U1]
        conv.run(msgs, TOOLS, "m1")
        msgs += [{"role": "assistant", "content": "one"}, {"role": "user", "content": "next"}]
        conv.run(msgs, TOOLS, "m2")
        assert len({e["sid"] for e in events(log) if e["ev"] == "prompt"}) == 2
    finally:
        conv.close()


def test_guard_loop_stops_with_a_visible_message_and_guard_clears_after_end(tmp_path):
    from antigravity_acp_mcp.conversation import GUARD_LOOP_TEXT
    a = {"call": {"name": "fetch", "arguments": {"k": "a"}}}
    conv, _ = make_conv(tmp_path, [[a], [a, a, {"silent": 5}]], call_deadline=0.5)
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        time.sleep(1.2)  # deadline -> retired
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert r2["text"] == GUARD_LOOP_TEXT and r2["tool_calls"] == []
    finally:
        conv.close()


def test_cancel_while_the_session_is_opening_returns_within_5s(tmp_path):
    conv, _ = make_conv(tmp_path, [[{"text": "late"}]], new_delay=12)
    try:
        err, token = {}, threading.Event()

        def go():
            try:
                conv.run([SYS, U1], TOOLS, "m", token)
            except Exception as exc:  # noqa: BLE001
                err["e"] = exc

        th = threading.Thread(target=go)
        th.start()
        time.sleep(1.0)
        t = time.monotonic()
        conv.cancel(token)
        th.join(6)
        assert not th.is_alive() and time.monotonic() - t < 5
        assert isinstance(err.get("e"), CancelledByUser)
    finally:
        conv.close()


def test_btw_guest_while_the_owner_is_opening_is_a_guest(tmp_path):
    from antigravity_acp_mcp.matcher import BTW_FORK_MARKER
    conv, log = make_conv(tmp_path, [[{"text": "main done"}]], new_delay=2)
    try:
        out = {}
        th = threading.Thread(target=lambda: out.update(r=conv.run([SYS, U1], TOOLS, "m")))
        th.start()
        time.sleep(0.8)
        fork = [SYS, U1, {"role": "user", "content": BTW_FORK_MARKER + " ... what is a?"}]
        assert conv.run(fork, [], "m") == {"guest": True}
        th.join(10)
        assert out["r"]["text"] == "main done"
        assert not any(e["ev"] == "cancel" for e in events(log))
    finally:
        conv.close()


def test_failed_open_is_a_provider_error_and_not_live(tmp_path):
    from antigravity_acp_mcp.conversation import ProviderError

    def spawn(key, cwd):
        raise FileNotFoundError("no such launcher")

    conv = Conversation("k1", spawn)
    try:
        with pytest.raises(ProviderError, match="could not open"):
            conv.run([SYS, U1], TOOLS, "m")
        assert conv.live is False
    finally:
        conv.close()


def test_child_spawned_after_close_is_reaped(tmp_path):
    started, gate = [], threading.Event()
    log = tmp_path / "agy.log"
    behaviour = json.dumps({"script": [[{"text": "x"}]], "log": str(log)})

    def spawn(key, cwd):
        gate.wait(5)  # still spawning when the conversation is closed (close() removes its cwd)
        conn = AcpConnection(sys.executable, [FAKE, behaviour], str(tmp_path))
        conn.start()
        started.append(conn)
        return conn

    conv = Conversation("", spawn, stateless=True)
    token = threading.Event()
    def go():
        with contextlib.suppress(Exception):
            conv.run([SYS, U1], TOOLS, "m", token)

    th = threading.Thread(target=go)
    th.start()
    time.sleep(0.5)
    conv.cancel(token)
    conv.close()
    gate.set()
    th.join(10)
    deadline = time.monotonic() + 10
    while started and not started[0].exited and time.monotonic() < deadline:
        time.sleep(0.1)
    assert started and started[0].exited


def test_refused_native_attempt_does_not_cancel_the_turn(tmp_path):
    conv, log = make_conv(tmp_path, [[{"refused_native": True}, {"text": "fine"}]])
    try:
        assert conv.run([SYS, U1], TOOLS, "m")["text"] == "fine"
        assert not any(e["ev"] == "cancel" for e in events(log))
    finally:
        conv.close()


_M3_FAKE_AGY = r'''
import json, os, sys, threading, time, urllib.request

B = json.loads(sys.argv[1])
LOG = B["log"]
lock = threading.Lock()
state = {"sessions": {}, "inflight": None, "next_sid": 0, "pending": {}}


def log(**kw):
    with lock, open(LOG, "a") as fh:
        fh.write(json.dumps(kw) + "\n")


def emit(obj):
    with lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def update(sid, payload):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": payload}})


def request_permission(sid, tcid, server_name, tool_name, raw_input=None):
    rid = f"perm-{time.monotonic_ns()}"
    ev = threading.Event()
    slot = {"event": ev, "resp": None}
    with lock:
        state["pending"][rid] = slot
    tool_call = {
        "toolCallId": tcid,
        "title": f"{server_name}_{tool_name}",
        "_meta": {"is_mcp_tool_call": True, "mcp": {"server": server_name, "tool": tool_name}},
    }
    if raw_input is not None:
        tool_call["rawInput"] = raw_input
    emit({
        "jsonrpc": "2.0",
        "id": rid,
        "method": "session/request_permission",
        "params": {
            "sessionId": sid,
            "toolCall": tool_call,
            "options": [{"optionId": "allow", "name": "allow_once", "kind": "allow_once"}],
        },
    })
    ev.wait(10.0)
    with lock:
        state["pending"].pop(rid, None)


def mcp_call(server, name, arguments):
    headers = {h["name"]: h["value"] for h in server.get("headers", [])}
    headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }).encode()
    req = urllib.request.Request(server["url"], data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read() or b"{}")
    except Exception as exc:
        return {"error": type(exc).__name__}
    res = data.get("result") or {}
    text = "".join(c.get("text", "") for c in res.get("content", []))
    return {"text": text, "isError": bool(res.get("isError"))}


def do_call(sid, server, call_spec, *, sync_perm=False, skip_completed=False):
    tcid = f"tc{time.monotonic_ns()}"
    name, args = call_spec["name"], call_spec.get("arguments", {})
    if sync_perm:
        request_permission(sid, tcid, server["name"], name)
    update(sid, {
        "sessionUpdate": "tool_call",
        "toolCallId": tcid,
        "status": "in_progress",
        "title": server["name"] + "_" + name,
        "_meta": {"is_mcp_tool_call": True, "mcp": {"server": server["name"], "tool": name}},
    })
    ans = mcp_call(server, name, args)
    log(ev="answer", sid=sid, name=name, args=args, **ans)
    failed = bool(ans.get("isError") or ans.get("error"))
    if failed:
        update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tcid, "status": "failed"})
    elif not skip_completed:
        update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tcid, "status": "completed"})
    return ans, failed


def run_prompt(rid, sid, steps, token):
    server = state["sessions"][sid]
    last = ""
    for step in steps:
        if token["cancelled"]:
            return
        if "call" in step:
            ans, failed = do_call(
                sid, server, step["call"],
                sync_perm=bool(step.get("sync_perm")),
                skip_completed=bool(step.get("skip_completed")),
            )
            if failed and step.get("retry_on_error"):
                ans, _ = do_call(sid, server, step["call"], skip_completed=bool(step.get("skip_completed")))
            last = ans.get("text", "")
        elif "concurrent_rhgo" in step:
            spec = step["concurrent_rhgo"]
            name = spec["name"]
            args_a = spec["args_a"]
            args_b = spec["args_b"]
            with_raw = bool(spec.get("agy152_raw_input"))
            tc_a = f"tcA-{time.monotonic_ns()}"
            tc_b = f"tcB-{time.monotonic_ns()}"
            raw_a = {"arguments": args_a, **args_a} if with_raw else None
            raw_b = {"arguments": args_b, **args_b} if with_raw else None

            def emit_call_start(tcid, raw_input):
                if with_raw:
                    update(sid, {
                        "sessionUpdate": "tool_call", "toolCallId": tcid, "status": "pending",
                        "title": server["name"] + "_" + name,
                        "_meta": {"is_mcp_tool_call": True, "mcp": {"server": server["name"], "tool": name}},
                        "rawInput": raw_input,
                    })
                request_permission(sid, tcid, server["name"], name, raw_input=raw_input)
                in_prog = {
                    "sessionUpdate": "tool_call_update", "toolCallId": tcid, "status": "in_progress",
                    "title": server["name"] + "_" + name,
                    "_meta": {"is_mcp_tool_call": True, "mcp": {"server": server["name"], "tool": name}},
                }
                if raw_input is not None:
                    in_prog["rawInput"] = raw_input
                update(sid, in_prog)

            emit_call_start(tc_a, raw_a)
            emit_call_start(tc_b, raw_b)

            a_sent = threading.Event()
            b_completed = threading.Event()
            res_holder = {}

            def run_a():
                a_sent.set()
                lost = mcp_call(server, name, args_a)
                log(ev="answer", sid=sid, name=name, args=args_a, phase="lost_after_200", **lost)
                b_completed.wait(10.0)
                retried = mcp_call(server, name, args_a)
                log(ev="answer", sid=sid, name=name, args=args_a, phase="retry", **retried)
                res_holder["a"] = retried.get("text", "")
                update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tc_a, "status": "completed"})

            def run_b():
                a_sent.wait(5.0)
                time.sleep(0.02)
                ans_b = mcp_call(server, name, args_b)
                log(ev="answer", sid=sid, name=name, args=args_b, phase="sibling", **ans_b)
                res_holder["b"] = ans_b.get("text", "")
                update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tc_b, "status": "completed"})
                request_permission(sid, tc_a, server["name"], name, raw_input=raw_a)
                b_completed.set()

            ta = threading.Thread(target=run_a, daemon=True)
            tb = threading.Thread(target=run_b, daemon=True)
            ta.start()
            tb.start()
            ta.join(15.0)
            tb.join(15.0)

            tc_a2 = f"tcA2-{time.monotonic_ns()}"
            request_permission(sid, tc_a2, server["name"], name, raw_input=raw_a)
            in_prog2 = {
                "sessionUpdate": "tool_call", "toolCallId": tc_a2, "status": "in_progress",
                "title": server["name"] + "_" + name,
                "_meta": {"is_mcp_tool_call": True, "mcp": {"server": server["name"], "tool": name}},
            }
            if raw_a is not None:
                in_prog2["rawInput"] = raw_a
            update(sid, in_prog2)
            fresh_a = mcp_call(server, name, args_a)
            log(ev="answer", sid=sid, name=name, args=args_a, phase="post_batch_repeat", **fresh_a)
            update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tc_a2, "status": "completed"})
            last = f"{res_holder.get('a', '')}|{res_holder.get('b', '')}|{fresh_a.get('text', '')}"
        elif "text" in step:
            update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": step["text"]}})
        elif step.get("echo_last"):
            update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": last}})
    with lock:
        if token["done"]:
            return
        token["done"] = True
    emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})


for line in sys.stdin:
    msg = json.loads(line)
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method is None and rid is not None:
        with lock:
            slot = state["pending"].get(rid)
        if slot is not None:
            slot["resp"] = msg
            slot["event"].set()
        continue
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "antigravity-acp", "version": "1.5.2"},
            "agentCapabilities": {"mcpCapabilities": {"http": True}, "promptCapabilities": {"image": True}},
        }})
    elif method == "session/new":
        state["next_sid"] += 1
        sid = f"s{state['next_sid']}"
        state["sessions"][sid] = params["mcpServers"][0]
        log(ev="new", sid=sid)
        emit({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": sid}})
    elif method in ("session/set_model", "session/set_config_option", "session/close"):
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "session/prompt":
        sid = params["sessionId"]
        n = sum(1 for ln in open(LOG) if '"ev": "prompt"' in ln) if os.path.exists(LOG) else 0
        log(ev="prompt", sid=sid, n=n)
        steps = B["script"][n] if n < len(B["script"]) else [{"text": "ok"}]
        token = {"cancelled": False, "done": False, "rid": rid}
        state["inflight"] = token
        threading.Thread(target=run_prompt, args=(rid, sid, steps, token), daemon=True).start()
    elif method == "session/cancel":
        token = state["inflight"]
        log(ev="cancel", sid=params.get("sessionId"))
        if token and not token["done"]:
            token["cancelled"] = True
            token["done"] = True
            emit({"jsonrpc": "2.0", "id": token["rid"], "result": {"stopReason": "cancelled"}})
    elif rid is not None and method:
        emit({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nf"}})
'''


def _make_m3_conv(tmp_path, script, **kw):
    fake = tmp_path / "m3_fake_agy.py"
    fake.write_text(_M3_FAKE_AGY)
    log = tmp_path / "m3_agy.log"
    behaviour = json.dumps({"script": script, "log": str(log)})

    def spawn(key, cwd):
        conn = AcpConnection(sys.executable, [str(fake), behaviour], cwd)
        conn.start()
        conn.initialize()
        return conn

    return Conversation("k-m3", spawn, **kw), log


def _inject_drop_on_sends(server, drop_indices):
    handler_cls = server._httpd.RequestHandlerClass
    orig_send = handler_cls._send
    counter = {"n": 0}

    def wrapped_send(self, status, payload=None):
        if (
            status == 200
            and isinstance(payload, dict)
            and isinstance(payload.get("result"), dict)
            and "content" in payload["result"]
        ):
            counter["n"] += 1
            if counter["n"] in drop_indices:
                raise ConnectionResetError(f"simulated drop #{counter['n']}")
        return orig_send(self, status, payload)

    handler_cls._send = wrapped_send


def test_probe1_dropped_http_200_retry_hits_completed_cache_single_handoff(tmp_path):
    conv, log = _make_m3_conv(tmp_path, [[
        {"call": {"name": "fetch", "arguments": {"k": "a"}}, "retry_on_error": True},
        {"echo_last": True},
    ]])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r1["tool_calls"]] == [{"k": "a"}]
        _inject_drop_on_sends(conv.server, {1})
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["A-cached"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert r2["tool_calls"] == [] and r2["text"] == "A-cached"
        ev = events(log)
        answers = [e for e in ev if e["ev"] == "answer"]
        assert len(answers) == 2
        assert "error" in answers[0]
        assert answers[1]["text"] == "A-cached"
        assert [e["n"] for e in ev if e["ev"] == "prompt"] == [0]
    finally:
        conv.close()


def test_probe2_intentional_repeat_after_completed_hands_out_twice(tmp_path):
    conv, log = _make_m3_conv(tmp_path, [[
        {"call": {"name": "fetch", "arguments": {"k": "a"}}},
        {"call": {"name": "fetch", "arguments": {"k": "a"}}, "sync_perm": True},
        {"echo_last": True},
    ]])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r1["tool_calls"]] == [{"k": "a"}]
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["FIRST"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r2["tool_calls"]] == [{"k": "a"}]
        assert r2["tool_calls"][0].id != r1["tool_calls"][0].id
        msgs += [asst(r2["tool_calls"]), *tool_rows(r2["tool_calls"], ["SECOND"])]
        r3 = conv.run(msgs, TOOLS, "m")
        assert r3["tool_calls"] == [] and r3["text"] == "SECOND"
        ev = events(log)
        assert [e["text"] for e in ev if e["ev"] == "answer"] == ["FIRST", "SECOND"]
        assert [e["n"] for e in ev if e["ev"] == "prompt"] == [0]
    finally:
        conv.close()


def test_degenerate_nudge_clears_completed_cache_before_reissue(tmp_path):
    conv, log = _make_m3_conv(tmp_path, [
        [{"call": {"name": "fetch", "arguments": {"k": "a"}}, "skip_completed": True}, {"text": "}"}],
        [{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"echo_last": True}],
    ])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r1["tool_calls"]] == [{"k": "a"}]
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["BEFORE-NUDGE"])]
        r2 = conv.run(msgs, TOOLS, "m")
        # Degenerate "}" triggered nudge + clear_completed(); re-issued call parks freshly.
        assert [c.arguments for c in r2["tool_calls"]] == [{"k": "a"}]
        assert r2["tool_calls"][0].id != r1["tool_calls"][0].id
        msgs += [asst(r2["tool_calls"]), *tool_rows(r2["tool_calls"], ["AFTER-NUDGE"])]
        r3 = conv.run(msgs, TOOLS, "m")
        assert r3["tool_calls"] == [] and r3["text"] == "AFTER-NUDGE"
        ev = events(log)
        prompts = [e for e in ev if e["ev"] == "prompt"]
        assert len(prompts) == 2 and prompts[0]["sid"] == prompts[1]["sid"]
        assert [e["text"] for e in ev if e["ev"] == "answer"] == ["BEFORE-NUDGE", "AFTER-NUDGE"]
    finally:
        conv.close()


def test_resume_held_clears_prior_round_cache_while_preserving_handed_round(tmp_path):
    conv, log = _make_m3_conv(tmp_path, [[
        {"call": {"name": "fetch", "arguments": {"k": "r1"}}, "retry_on_error": False},
        {"call": {"name": "fetch", "arguments": {"k": "r2"}}, "retry_on_error": True},
        {"call": {"name": "fetch", "arguments": {"k": "r1"}}},
        {"echo_last": True},
    ]])
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r1["tool_calls"]] == [{"k": "r1"}]
        # Drop HTTP 200 for both round 1 (r1) and round 2's first send (r2).
        _inject_drop_on_sends(conv.server, {1, 2})
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], ["R1-DROPPED"])]
        r2 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r2["tool_calls"]] == [{"k": "r2"}]
        # Round 1's un-retried dropped entry is still cached until round 2 enters resume_held.
        assert len(conv.server._completed) == 1

        msgs += [asst(r2["tool_calls"]), *tool_rows(r2["tool_calls"], ["R2-CACHED"])]
        r3 = conv.run(msgs, TOOLS, "m")
        # Round 2's retry of r2 hit _completed (preserved by preserve_parked=True), while r1 was cleared
        # on round 2 resume_held and therefore parks freshly for Hermes.
        assert [c.arguments for c in r3["tool_calls"]] == [{"k": "r1"}]
        assert r3["tool_calls"][0].id != r1["tool_calls"][0].id

        msgs += [asst(r3["tool_calls"]), *tool_rows(r3["tool_calls"], ["R1-FRESH"])]
        r4 = conv.run(msgs, TOOLS, "m")
        assert r4["tool_calls"] == [] and r4["text"] == "R1-FRESH"

        answers = [e for e in events(log) if e["ev"] == "answer"]
        assert len(answers) == 4
        assert answers[0]["args"] == {"k": "r1"} and "error" in answers[0]
        assert answers[1]["args"] == {"k": "r2"} and "error" in answers[1]
        assert answers[2]["args"] == {"k": "r2"} and answers[2]["text"] == "R2-CACHED"
        assert answers[3]["args"] == {"k": "r1"} and answers[3]["text"] == "R1-FRESH"
    finally:
        conv.close()


@pytest.mark.parametrize("agy152_raw_input", [True, False], ids=["layer1-rawInput", "layer2-no-rawInput"])
def test_rhgo1749_concurrent_same_name_sibling_completion_does_not_evict_retry(tmp_path, agy152_raw_input):
    """Regression for PR #83 concurrent same-name different-arg M3 edge case.

    Call A (k="alpha") and Call B (k="beta") run concurrently on the same tool name:
    - Call A writes HTTP 200 locally (delivery_ok=True) then response is lost in transit.
    - Sibling Call B completes first and ACP emits tool_call_update(completed).
    - Call A retries and MUST hit the completed cache (tool executes ONCE, not twice).
    - After both A and B complete, a post-batch intentional repeat of A executes fresh.
    """
    conv, log = _make_m3_conv(
        tmp_path,
        [[
            {
                "concurrent_rhgo": {
                    "name": "fetch",
                    "args_a": {"k": "alpha"},
                    "args_b": {"k": "beta"},
                    "agy152_raw_input": agy152_raw_input,
                },
            },
            {"echo_last": True},
        ]],
        collect_window=0.5,
    )
    try:
        msgs = [SYS, U1]
        r1 = conv.run(msgs, TOOLS, "m")
        assert len(r1["tool_calls"]) == 2
        by_k = {c.arguments["k"]: c for c in r1["tool_calls"]}
        assert set(by_k) == {"alpha", "beta"}
        answers_r1 = [
            "ALPHA-1" if c.arguments["k"] == "alpha" else "BETA-1"
            for c in r1["tool_calls"]
        ]
        msgs += [asst(r1["tool_calls"]), *tool_rows(r1["tool_calls"], answers_r1)]

        # Call A's retry hits cache (zero extra handoff); next handoff is the post-batch intentional repeat.
        r2 = conv.run(msgs, TOOLS, "m")
        assert [c.arguments for c in r2["tool_calls"]] == [{"k": "alpha"}]
        assert r2["tool_calls"][0].id != by_k["alpha"].id

        msgs += [asst(r2["tool_calls"]), *tool_rows(r2["tool_calls"], ["ALPHA-FRESH"])]
        r3 = conv.run(msgs, TOOLS, "m")
        assert r3["tool_calls"] == []
        assert r3["text"] == "ALPHA-1|BETA-1|ALPHA-FRESH"

        ev = events(log)
        answers = [e for e in ev if e["ev"] == "answer"]
        by_phase = {e["phase"]: e for e in answers}
        assert by_phase["lost_after_200"]["text"] == "ALPHA-1"
        assert by_phase["sibling"]["text"] == "BETA-1"
        assert by_phase["retry"]["text"] == "ALPHA-1"
        assert by_phase["post_batch_repeat"]["text"] == "ALPHA-FRESH"
        assert [e["n"] for e in ev if e["ev"] == "prompt"] == [0]
    finally:
        conv.close()
