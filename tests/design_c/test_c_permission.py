import threading
from collections import Counter

from antigravity_acp_mcp.parked_mcp import ParkedMcpServer, signature_key
from antigravity_acp_mcp.permission import (
    _MAX_TRACKED_SIG_KEYS,
    PermissionGate,
    _bounded_equal,
    _extract_sig_keys,
)

SERVER = "hermes-deadbeef"
CANCELLED = {"outcome": {"outcome": "cancelled"}}


def meta(server=SERVER, tool="terminal", is_mcp=True):
    return {"is_mcp_tool_call": is_mcp, "mcp": {"server": server, "tool": tool}}


def request(tool_meta, kinds=("allow_always", "allow_once", "reject_once"), title="terminal",
            call_id="t1", raw_input=None):
    tool_call = {"toolCallId": call_id, "title": title, "_meta": tool_meta}
    if raw_input is not None:
        tool_call["rawInput"] = raw_input
    return {
        "toolCall": tool_call,
        "options": [{"optionId": f"opt-{k}", "name": k, "kind": k} for k in kinds],
    }


def selected(option_id):
    return {"outcome": {"outcome": "selected", "optionId": option_id}}


def gate(**kw):
    return PermissionGate(SERVER, {"terminal", "read_file"}, **kw)


def test_allows_our_mcp_call_with_allow_once_only():
    assert gate().decide(request(meta())) == selected("opt-allow_once")


def test_title_only_match_is_rejected():
    assert gate().decide(request(None, title=f"{SERVER}: terminal")) == selected("opt-reject_once")
    assert gate().decide(request({"mcp": {"server": SERVER, "tool": "terminal"}})) == selected("opt-reject_once")
    assert gate().decide(request(meta(is_mcp="true"))) == selected("opt-reject_once")


def test_foreign_server_and_unknown_tool_are_rejected():
    assert gate().decide(request(meta(server="hermes-00000000"))) == selected("opt-reject_once")
    assert gate().decide(request(meta(tool="run_command"))) == selected("opt-reject_once")


def test_never_picks_allow_always():
    assert gate().decide(request(meta(), kinds=("allow_always", "reject_once"))) == selected("opt-reject_once")
    assert gate().decide(request(meta(), kinds=("allow_always",))) == CANCELLED
    assert gate().decide(request(meta(server="x"), kinds=("allow_always", "allow_once"))) == CANCELLED


def test_tripwire_fires_only_when_a_foreign_call_actually_runs():
    seen = []
    g = gate(on_foreign_tool_call=seen.append)
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "mine", "status": "in_progress", "_meta": meta()})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "mine", "status": "completed"})
    g.observe_update({"sessionUpdate": "agent_message_chunk"})
    assert seen == []
    # a disabled native tool the model only tries: pending -> failed, never runs (live 2026-11-23)
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "n0", "status": "pending", "title": "write_to_file"})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "n0", "status": "failed"})
    assert seen == []
    native = {"sessionUpdate": "tool_call", "toolCallId": "n1", "status": "in_progress", "title": "view_file"}
    g.observe_update(native)
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "n2", "status": "completed",
                      "_meta": meta(server="other")})
    assert seen[0] == native and len(seen) == 2


def test_permission_request_registers_the_call_as_ours():
    seen = []
    g = gate(on_foreign_tool_call=seen.append)
    g.decide(request(meta()))
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "t1", "status": "in_progress"})
    assert seen == []


def test_our_tool_completed_callback_on_followup_and_single_frame():
    completed, foreign = [], []
    g = gate(on_foreign_tool_call=foreign.append,
             on_our_tool_completed=lambda tool, sigs: completed.append((tool, sigs)))
    # 1) _our_meta on tool_call, followed by tool_call_update(completed) without _meta.
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "c1", "status": "in_progress",
                      "_meta": meta(tool="terminal")})
    assert completed == []
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed"})
    assert completed == [("terminal", ())] and foreign == []

    # 2) Registered via decide() then completed via tool_call_update without _meta.
    g.decide(request(meta(tool="read_file")))
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed"})
    assert completed == [("terminal", ()), ("read_file", ())] and foreign == []

    # 3) Single-frame _our_meta + completed.
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "s1", "status": "completed",
                      "_meta": meta(tool="read_file")})
    assert completed == [("terminal", ()), ("read_file", ()), ("read_file", ())] and foreign == []


def test_duplicate_completed_is_idempotent_and_failed_does_not_fire():
    completed, foreign = [], []
    g = gate(on_foreign_tool_call=foreign.append,
             on_our_tool_completed=lambda tool, sigs: completed.append((tool, sigs)))
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "c1", "status": "in_progress", "_meta": meta()})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed"})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed"})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed", "_meta": meta()})
    assert completed == [("terminal", ())] and foreign == []

    # status="failed" never fires on_our_tool_completed.
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "f1", "status": "in_progress", "_meta": meta()})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "f1", "status": "failed"})
    assert completed == [("terminal", ())] and foreign == []


def test_empty_call_id_does_not_disable_h1_or_fire_completion():
    completed, foreign = [], []
    g = gate(on_foreign_tool_call=foreign.append,
             on_our_tool_completed=lambda tool, sigs: completed.append((tool, sigs)))
    # Empty/missing toolCallId with our _meta must not register "" in _ours or fire completion (SEC-M3-6).
    g.decide({
        "toolCall": {"toolCallId": "", "title": "terminal", "_meta": meta()},
        "options": [{"optionId": "opt-allow_once", "name": "allow_once", "kind": "allow_once"}],
    })
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "", "status": "completed", "_meta": meta()})
    g.observe_update({"sessionUpdate": "tool_call", "status": "completed", "_meta": meta()})
    assert completed == [] and foreign == []

    # Foreign tool with empty/missing toolCallId still trips H1.
    f1 = {"sessionUpdate": "tool_call", "toolCallId": "", "status": "in_progress", "title": "view_file"}
    f2 = {"sessionUpdate": "tool_call_update", "status": "completed", "title": "run_command"}
    g.observe_update(f1)
    g.observe_update(f2)
    assert foreign == [f1, f2] and completed == []


def test_concurrent_decide_and_observe_update_thread_safety():
    completed, foreign = [], []
    cb_lock = threading.Lock()

    def on_done(tool_name, sig_keys):
        with cb_lock:
            completed.append((tool_name, sig_keys))

    g = gate(on_foreign_tool_call=foreign.append, on_our_tool_completed=on_done)
    n_ids = 120
    barrier = threading.Barrier(4)
    errors = []

    def worker(offset, tool_name):
        try:
            barrier.wait(5)
            for i in range(n_ids):
                cid = f"cid-{offset}-{i}"
                args = {"offset": offset, "i": i}
                raw_input = {"arguments": args, **args}
                g.decide({
                    "toolCall": {"toolCallId": cid, "title": tool_name, "_meta": meta(tool=tool_name),
                                 "rawInput": raw_input},
                    "options": [{"optionId": "opt-allow_once", "name": "allow_once", "kind": "allow_once"}],
                })
                g.observe_update({"sessionUpdate": "tool_call", "toolCallId": cid, "status": "in_progress",
                                  "_meta": meta(tool=tool_name), "rawInput": raw_input})
                g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": cid, "status": "completed"})
                g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": cid, "status": "completed"})
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(0, "terminal")),
        threading.Thread(target=worker, args=(1, "read_file")),
        threading.Thread(target=worker, args=(2, "terminal")),
        threading.Thread(target=worker, args=(3, "read_file")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert errors == []
    assert foreign == []
    assert Counter(t for t, _ in completed) == {"terminal": 2 * n_ids, "read_file": 2 * n_ids}
    assert all(len(sigs) == 2 for _, sigs in completed)
    assert g._our_sig_keys == {}


def test_bounded_equal_bool_int_depth_nodes_and_cycles():
    assert _bounded_equal({"a": [1, True, None]}, {"a": [1, True, None]}) is True
    assert _bounded_equal(True, 1) is False
    assert _bounded_equal(False, 0) is False
    assert _bounded_equal({"x": True}, {"x": 1}) is False
    assert _bounded_equal([0], [False]) is False

    # Depth bound (iterative, never raises RecursionError).
    deep_a: dict = {}
    deep_b: dict = {}
    cur_a, cur_b = deep_a, deep_b
    for _ in range(70):
        cur_a["n"] = {}
        cur_b["n"] = {}
        cur_a, cur_b = cur_a["n"], cur_b["n"]
    assert _bounded_equal(deep_a, deep_b) is False

    # Node budget bound.
    wide_a = list(range(100))
    wide_b = list(range(100))
    assert _bounded_equal(wide_a, wide_b, max_nodes=50) is False
    assert _bounded_equal(wide_a, wide_b, max_nodes=101) is True

    # Cyclic structure terminates via depth bound without RecursionError.
    cyc_a: dict = {}
    cyc_a["self"] = cyc_a
    cyc_b: dict = {}
    cyc_b["self"] = cyc_b
    assert _bounded_equal(cyc_a, cyc_b) is False
    assert _bounded_equal(cyc_a, cyc_a) is False


def test_sec_m3c_4_extract_sig_keys_shapes_and_unwrapped_isolation():
    # Empty or non-dict rawInput yields ().
    assert _extract_sig_keys("terminal", {}) == ()
    assert _extract_sig_keys("terminal", None) == ()
    assert _extract_sig_keys("terminal", ["a"]) == ()
    assert _extract_sig_keys("terminal", "raw") == ()

    # {"arguments": {}} and {"arguments": None} both include sig(tool, {}) first.
    sig_empty = signature_key("terminal", {})
    assert sig_empty is not None
    assert _extract_sig_keys("terminal", {"arguments": {}}) == (
        sig_empty,
        signature_key("terminal", {"arguments": {}}),
    )
    assert _extract_sig_keys("terminal", {"arguments": None}) == (
        sig_empty,
        signature_key("terminal", {"arguments": None}),
    )

    # agy 1.5.2 wrapped + flattened shape.
    wrapped = {"arguments": {"tag": "alpha"}, "tag": "alpha"}
    assert _extract_sig_keys("terminal", wrapped) == (
        signature_key("terminal", {"tag": "alpha"}),
        signature_key("terminal", wrapped),
    )

    # Tool args legitimately containing an "arguments" key match wrapper branch.
    nested_args_flat = {"arguments": {"arguments": "foo", "k": 1}, "k": 1}
    assert _extract_sig_keys("terminal", nested_args_flat) == (
        signature_key("terminal", {"arguments": "foo", "k": 1}),
        signature_key("terminal", nested_args_flat),
    )
    nested_args_only = {"arguments": {"arguments": "foo"}}
    assert _extract_sig_keys("terminal", nested_args_only) == (
        signature_key("terminal", {"arguments": "foo"}),
        signature_key("terminal", nested_args_only),
    )

    # Unwrapped {"cmd": "noop", "arguments": {"cmd": "deploy"}} must NOT extract {"cmd": "deploy"}.
    unwrapped = {"cmd": "noop", "arguments": {"cmd": "deploy"}}
    sig_deploy = signature_key("terminal", {"cmd": "deploy"})
    sigs = _extract_sig_keys("terminal", unwrapped)
    assert sigs == (signature_key("terminal", unwrapped),)
    assert sig_deploy not in sigs

    # Unrelated extra key or bool/int mismatch also stay unwrapped.
    extra = {"arguments": {"cmd": "deploy"}, "extra": 1}
    assert _extract_sig_keys("terminal", extra) == (signature_key("terminal", extra),)
    bool_int_mismatch = {"arguments": {"flag": True}, "flag": 1}
    assert _extract_sig_keys("terminal", bool_int_mismatch) == (
        signature_key("terminal", bool_int_mismatch),
    )

    # End-to-end with ParkedMcpServer: unwrapped call never evicts {"cmd": "deploy"}.
    server = ParkedMcpServer([{"name": "terminal"}], lambda _c: None)
    assert sig_deploy is not None
    from antigravity_acp_mcp.parked_mcp import _CompletedCall
    server._completed[sig_deploy] = _CompletedCall(
        name="terminal", text="ok", is_error=False, images=[], seq=1, size_bytes=2, delivery_ok=True
    )
    server._completed_bytes = 2
    assert server.mark_completed("terminal", sigs) is False
    assert sig_deploy in server._completed


def test_sec_m3c_2_adversarial_raw_input_never_blocks_decide_or_raises():
    completed = []
    g = gate(on_our_tool_completed=lambda tool, sigs: completed.append((tool, sigs)))

    deep: dict = {}
    cur = deep
    for _ in range(1200):
        cur["d"] = {}
        cur = cur["d"]
    cyclic: dict = {}
    cyclic["self"] = cyclic

    adversarial_cases = [
        ("oversized", {"blob": "a" * (16 * 1024 * 1024 + 64)}),
        ("deep", deep),
        ("cyclic", cyclic),
        ("surrogate", {"bad": "\ud800"}),
        ("non_json", {"obj": object()}),
    ]
    for cid, bad_input in adversarial_cases:
        assert g.decide(request(meta(), call_id=cid, raw_input=bad_input)) == selected("opt-allow_once")
        g.observe_update({
            "sessionUpdate": "tool_call", "toolCallId": cid, "status": "in_progress",
            "_meta": meta(), "rawInput": bad_input,
        })
        g.observe_update({
            "sessionUpdate": "tool_call_update", "toolCallId": cid, "status": "completed",
            "rawInput": bad_input,
        })

    assert completed == [("terminal", ()) for _ in adversarial_cases]
    assert g._our_sig_keys == {}


def test_sec_m3c_2_foreign_calls_never_hash_raw_input(monkeypatch):
    from antigravity_acp_mcp import permission as perm_mod

    def fail_if_called(*_a, **_kw):
        raise AssertionError("_extract_sig_keys must not run for foreign calls")

    monkeypatch.setattr(perm_mod, "_extract_sig_keys", fail_if_called)
    foreign = []
    g = gate(on_foreign_tool_call=foreign.append)
    assert g.decide(request(meta(server="other"), call_id="f1", raw_input={"k": "v"})) == selected("opt-reject_once")
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "f2", "status": "in_progress",
                      "rawInput": {"k": "v"}})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "f2", "status": "completed",
                      "rawInput": {"k": "v"}})
    assert len(foreign) == 2


def test_sec_m3c_5_sig_keys_lifecycle_precedence_tool_change_and_cap():
    completed, foreign = [], []
    g = gate(on_foreign_tool_call=foreign.append,
             on_our_tool_completed=lambda tool, sigs: completed.append((tool, sigs)))

    # 1) pending partial -> decide full -> completed empty keeps decide's sig_keys.
    partial = {"arguments": {"k": "partial"}, "k": "partial"}
    full = {"arguments": {"k": "full"}, "k": "full"}
    expected_full = _extract_sig_keys("terminal", full)
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "p1", "status": "pending",
                      "_meta": meta(tool="terminal"), "rawInput": partial})
    assert g.decide(request(meta(tool="terminal"), call_id="p1", raw_input=full)) == selected("opt-allow_once")
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "p1", "status": "completed",
                      "rawInput": {}})
    assert completed[-1] == ("terminal", expected_full)
    assert "p1" not in g._our_sig_keys

    # 2) pending partial -> decide full -> completed with different rawInput STILL keeps decide's sig_keys.
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "p2", "status": "pending",
                      "_meta": meta(tool="terminal"), "rawInput": partial})
    g.decide(request(meta(tool="terminal"), call_id="p2", raw_input=full))
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "p2", "status": "completed",
                      "rawInput": {"arguments": {"k": "different"}, "k": "different"}})
    assert completed[-1] == ("terminal", expected_full)
    assert "p2" not in g._our_sig_keys

    # 3) _meta-less update rawInput populates sig_keys after decide() without rawInput.
    g.decide(request(meta(tool="read_file"), call_id="m1"))
    meta_less_input = {"arguments": {"path": "a.py"}, "path": "a.py"}
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "m1", "status": "in_progress",
                      "rawInput": meta_less_input})
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "m1", "status": "completed"})
    assert completed[-1] == ("read_file", _extract_sig_keys("read_file", meta_less_input))

    # 4) tool_name change without rawInput clears stale sig_keys.
    g.observe_update({"sessionUpdate": "tool_call", "toolCallId": "tc1", "status": "pending",
                      "_meta": meta(tool="terminal"), "rawInput": full})
    assert "tc1" in g._our_sig_keys
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "tc1", "status": "completed",
                      "_meta": meta(tool="read_file")})
    assert completed[-1] == ("read_file", ())
    assert "tc1" not in g._our_sig_keys

    # 5) Late decide/observe_update for already-completed call_id never re-inserts into _our_sig_keys.
    g.decide(request(meta(tool="terminal"), call_id="p1", raw_input=full))
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "p1", "status": "in_progress",
                      "_meta": meta(tool="terminal"), "rawInput": full})
    assert "p1" not in g._our_sig_keys
    assert g._our_sig_keys == {}

    # 6) Cap <= 1024 under 1,500+ uncompleted pending frames without touching _ours.
    for i in range(1500):
        g.observe_update({"sessionUpdate": "tool_call", "toolCallId": f"pend-{i}", "status": "pending",
                          "_meta": meta(tool="terminal"), "rawInput": {"i": i}})
    assert len(g._our_sig_keys) <= _MAX_TRACKED_SIG_KEYS
    assert len(g._our_sig_keys) == _MAX_TRACKED_SIG_KEYS
    assert "pend-0" not in g._our_sig_keys and "pend-1499" in g._our_sig_keys
    # Oldest call_id is still in _ours -> completing it fires our callback with (), NOT foreign tripwire!
    g.observe_update({"sessionUpdate": "tool_call_update", "toolCallId": "pend-0", "status": "completed"})
    assert completed[-1] == ("terminal", ())
    assert foreign == []
