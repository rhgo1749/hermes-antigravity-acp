import hashlib
import http.client
import json
import queue
import re
import socket
import struct
import threading
import time
from urllib.parse import urlparse

import pytest

from antigravity_acp_mcp.parked_mcp import (
    _MAX_COMPLETED_BYTES,
    _MAX_COMPLETED_CACHE,
    _MAX_SIGNATURE_BYTES,
    ParkedCall,
    ParkedMcpServer,
    signature_key,
)

TOOLS = [{"name": "terminal", "description": "run", "inputSchema": {"type": "object"}},
         {"name": "read_file"}]


class Client:
    def __init__(self, server, token=None, path=None, headers=None):
        cfg = server.acp_mcp_server_config()
        self.url = urlparse(cfg["url"])
        self.path = path or self.url.path
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        auth = cfg["headers"][0]["value"] if token is None else token
        if auth:
            self.headers["Authorization"] = auth

    def post(self, payload, timeout=10):
        conn = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=timeout)
        conn.request("POST", self.path, json.dumps(payload), self.headers)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, (json.loads(body) if body else None)

    def call(self, rid, name="terminal", args=None, timeout=10):
        return self.post({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                          "params": {"name": name, "arguments": args or {}}}, timeout)


@pytest.fixture
def make():
    servers = []

    def factory(**kw):
        parked = queue.Queue()
        server = ParkedMcpServer(TOOLS, parked.put, **kw).start()
        servers.append(server)
        return server, parked

    yield factory
    for s in servers:
        s.close()


def in_thread(fn, *a, **kw):
    out = []
    t = threading.Thread(target=lambda: out.append(fn(*a, **kw)))
    t.start()
    return t, out


def test_transport_invariants(make):
    server, _ = make()
    cfg = server.acp_mcp_server_config()
    assert re.fullmatch(r"hermes-[0-9a-f]{8}", server.server_name) and cfg["name"] == server.server_name
    assert urlparse(cfg["url"]).hostname == "127.0.0.1" and urlparse(cfg["url"]).path != "/mcp"
    listing = Client(server).post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[1]
    assert [t["name"] for t in listing["result"]["tools"]] == ["terminal", "read_file"]
    assert Client(server, token="Bearer wrong").post({"id": 1})[0] == 401
    assert Client(server, token="").post({"id": 1})[0] == 401
    assert Client(server, headers={"Origin": "http://evil.example"}).post({"id": 1})[0] == 403
    assert Client(server, headers={"Host": "evil.example"}).post({"id": 1})[0] == 403
    assert Client(server, path="/mcp").post({"id": 1})[0] == 404
    status, body = Client(server).call(2, name="rm_rf")
    assert status == 200 and body["error"]["code"] == -32602


def test_parked_call_blocks_then_returns_the_answered_text(make):
    server, parked = make()
    t, out = in_thread(Client(server).call, 42, "terminal", {"cmd": "ls"})
    call = parked.get(timeout=5)  # handed to the caller; nothing executes
    assert (call.name, call.arguments) == ("terminal", {"cmd": "ls"})
    assert re.fullmatch(r"call_[0-9a-f]{32}", call.id)  # plugin-minted, not the JSON-RPC id
    time.sleep(0.2)
    assert t.is_alive() and out == []  # still blocked
    assert call.answer("file1\nfile2") is True
    t.join(5)
    assert out[0][1] == {"jsonrpc": "2.0", "id": 42, "result": {
        "content": [{"type": "text", "text": "file1\nfile2"}], "isError": False}}
    assert call.answer("late") is False  # first answer wins


def test_answer_with_is_error_is_forwarded(make):
    server, parked = make()
    t, out = in_thread(Client(server).call, 1)
    parked.get(timeout=5).answer("denied", is_error=True)
    t.join(5)
    assert out[0][1]["result"] == {"content": [{"type": "text", "text": "denied"}], "isError": True}


def test_retired_endpoint_refuses_immediately_and_never_parks(make):
    server, parked = make()
    server.retire()
    started = time.monotonic()
    status, body = Client(server).call(1)
    assert time.monotonic() - started < 1.0
    assert body["result"]["isError"] is True and "retired" in body["result"]["content"][0]["text"]
    assert parked.empty()


def test_retire_does_not_release_a_call_already_parked(make):
    server, parked = make()
    t, out = in_thread(Client(server).call, 1)
    call = parked.get(timeout=5)
    server.retire()
    time.sleep(0.2)
    assert t.is_alive()  # M4: nothing is released until the caller says so
    call.answer("ok")
    t.join(5)
    assert out[0][1]["result"]["isError"] is False


def test_release_parked_drops_the_connection_without_a_result(make):
    server, parked = make()
    t, out = in_thread(lambda: _expect_disconnect(Client(server)))
    parked.get(timeout=5)
    server.retire()
    server.release_parked(drop_connection=True)
    t.join(5)
    assert out == ["disconnected"]


def _expect_disconnect(client):
    try:
        client.call(1)
    except (http.client.RemoteDisconnected, ConnectionError, http.client.BadStatusLine):
        return "disconnected"
    return "got a response"


def test_release_parked_can_answer_is_error_instead(make):
    server, parked = make()
    t, out = in_thread(Client(server).call, 1)
    parked.get(timeout=5)
    server.release_parked("superseded", drop_connection=False)
    t.join(5)
    assert out[0][1]["result"] == {"content": [{"type": "text", "text": "superseded"}], "isError": True}


def test_duplicate_signature_shares_one_parked_call(make):
    server, parked = make()
    first, out1 = in_thread(Client(server).call, 1, "terminal", {"a": 1, "b": [2, 3]})
    call = parked.get(timeout=5)
    second, out2 = in_thread(Client(server).call, 99, "terminal", {"b": [2, 3], "a": 1})  # same, reordered
    time.sleep(0.3)
    assert parked.empty()  # no second ParkedCall
    other, out3 = in_thread(Client(server).call, 3, "terminal", {"a": 2})  # different args: new call
    other_call = parked.get(timeout=5)
    assert other_call is not call
    call.answer("shared")
    first.join(5)
    second.join(5)
    other_call.answer("other")
    other.join(5)
    assert out1[0][1]["result"]["content"][0]["text"] == "shared" == out2[0][1]["result"]["content"][0]["text"]
    assert out2[0][1]["id"] == 99 and out3[0][1]["result"]["content"][0]["text"] == "other"
    # Before mark_completed, a repeat returns the cached answer without parking a new call.
    status, cached_body = Client(server).call(4, "terminal", {"a": 1, "b": [2, 3]})
    assert status == 200 and cached_body["id"] == 4
    assert cached_body["result"]["content"][0]["text"] == "shared"
    assert parked.empty()
    # Two terminal calls are cached: Layer 2 defers until both complete, while Layer 1 evicts precisely.
    assert server.mark_completed("terminal", (signature_key("terminal", {"a": 1, "b": [2, 3]}),)) is True
    # Unrelated sibling {"a": 2} stays cached.
    status_other, other_cached = Client(server).call(40, "terminal", {"a": 2})
    assert status_other == 200 and other_cached["result"]["content"][0]["text"] == "other"
    assert parked.empty()
    # The evicted signature parks freshly.
    again, _ = in_thread(Client(server).call, 5, "terminal", {"a": 1, "b": [2, 3]})
    assert parked.get(timeout=5) is not call
    server.release_parked(drop_connection=False)
    again.join(5)


def test_deadline_returns_is_error_and_notifies(make):
    expired = []
    server, parked = make(deadline=0.3, on_deadline=expired.append)
    started = time.monotonic()
    status, body = Client(server).call(1)
    assert 0.25 < time.monotonic() - started < 3
    assert body["result"]["isError"] is True and "deadline" in body["result"]["content"][0]["text"]
    assert expired == [parked.get_nowait()] and expired[0].state == "deadline"


def test_failed_handoff_does_not_leave_the_request_parked():
    def boom(call):
        raise RuntimeError("callback bug")

    server = ParkedMcpServer(TOOLS, boom, deadline=30).start()
    try:
        started = time.monotonic()
        _, body = Client(server).call(1)
        assert time.monotonic() - started < 5 and body["result"]["isError"] is True
    finally:
        server.close()


def _call_and_answer(server, parked, rid, name, args, answer_text, *, images=None, is_error=False):
    t, out = in_thread(Client(server).call, rid, name, args)
    call = parked.get(timeout=5)
    call.answer(answer_text, images=images, is_error=is_error)
    t.join(5)
    assert not t.is_alive() and len(out) == 1
    return out[0]


def test_completed_cache_bounds_bytes_oversized_and_hashed_keys(make):
    server, parked = make()
    chunk_3m = "x" * (3 * 1024 * 1024)
    # Two 3 MiB entries fit within the 8 MiB cap.
    _call_and_answer(server, parked, 1, "terminal", {"i": 1}, chunk_3m)
    _call_and_answer(server, parked, 2, "terminal", {"i": 2}, chunk_3m)
    assert len(server._completed) == 2
    assert server._completed_bytes == 6 * 1024 * 1024

    # Third 3 MiB entry evicts the oldest (i=1) to stay <= _MAX_COMPLETED_BYTES.
    _call_and_answer(server, parked, 3, "terminal", {"i": 3}, chunk_3m)
    assert len(server._completed) == 2
    assert server._completed_bytes == 6 * 1024 * 1024
    # Newer entries still hit cache.
    _, b2 = Client(server).call(20, "terminal", {"i": 2})
    _, b3 = Client(server).call(30, "terminal", {"i": 3})
    assert len(b2["result"]["content"][0]["text"]) == len(chunk_3m)
    assert len(b3["result"]["content"][0]["text"]) == len(chunk_3m)
    assert parked.empty()

    # Single entry > _MAX_COMPLETED_BYTES is skipped without evicting existing cached entries.
    oversized = "y" * (_MAX_COMPLETED_BYTES + 64)
    _, b_over = _call_and_answer(server, parked, 4, "terminal", {"i": "big"}, oversized)
    assert len(b_over["result"]["content"][0]["text"]) == len(oversized)
    assert len(server._completed) == 2
    assert server._completed_bytes == 6 * 1024 * 1024
    # Repeating the oversized call parks freshly.
    t_over, _ = in_thread(Client(server).call, 5, "terminal", {"i": "big"})
    c_over = parked.get(timeout=5)
    c_over.answer("small")
    t_over.join(5)
    assert server.mark_completed("terminal", (signature_key("terminal", {"i": 2}),)) is True  # evicts i=2

    # Large-argument calls use fixed 32-byte SHA-256 keys and respect _MAX_COMPLETED_CACHE.
    server.clear_completed()
    large_arg = "z" * (256 * 1024)
    for idx in range(_MAX_COMPLETED_CACHE + 4):
        _call_and_answer(server, parked, 100 + idx, "read_file", {"blob": large_arg, "n": idx}, f"ok-{idx}")
    assert len(server._completed) == _MAX_COMPLETED_CACHE
    assert all(isinstance(k, bytes) and len(k) == 32 for k in server._completed)
    assert server._completed_bytes == sum(e.size_bytes for e in server._completed.values())
    assert server._completed_bytes < 1024


def test_toctou_answered_call_sharing_and_no_zombie_secondary(make):
    # (a) Duplicate call arrives after call.answer() sets state="answered" and before first handler acquires _lock.
    parked = queue.Queue()
    on_call_count = 0
    first_woke = threading.Event()
    release_first = threading.Event()

    def on_call_a(call):
        nonlocal on_call_count
        on_call_count += 1
        orig_wait = call.wait
        first_seen = False

        def wrapped_wait(timeout):
            nonlocal first_seen
            res = orig_wait(timeout)
            if not first_seen:
                first_seen = True
                first_woke.set()
                release_first.wait(5)
            return res

        call.wait = wrapped_wait
        parked.put(call)

    server = ParkedMcpServer(TOOLS, on_call_a).start()
    try:
        t1, out1 = in_thread(Client(server).call, 1, "terminal", {"k": "toctou"})
        call = parked.get(timeout=5)
        call.answer("toctou-ok")
        assert first_woke.wait(5)
        # call.state is "answered", still in _live, not yet in _completed.
        status2, body2 = Client(server).call(2, "terminal", {"k": "toctou"})
        assert status2 == 200 and body2["result"]["content"][0]["text"] == "toctou-ok"
        release_first.set()
        t1.join(5)
        assert out1[0][1]["result"]["content"][0]["text"] == "toctou-ok"
        assert on_call_count == 1
        assert len(server._completed) == 1
        entry = next(iter(server._completed.values()))
        assert entry.delivery_ok is True and entry.inflight_sends == 0
    finally:
        server.close()

    # (b) Secondary waiter paused past mark_completed() never re-inserts a zombie entry.
    server2, parked2 = make()
    second_woke = threading.Event()
    release_second = threading.Event()
    t1, out1 = in_thread(Client(server2).call, 10, "terminal", {"k": "zombie"})
    call2 = parked2.get(timeout=5)
    orig_wait2 = call2.wait
    waiter_count = 0
    waiter_lock = threading.Lock()

    def wrapped_wait2(timeout):
        nonlocal waiter_count
        with waiter_lock:
            waiter_count += 1
            is_second = waiter_count == 2
        res = orig_wait2(timeout)
        if is_second:
            second_woke.set()
            release_second.wait(5)
        return res

    call2.wait = wrapped_wait2
    # Wait briefly until first waiter is blocked in orig_wait2 (it already entered wait before we wrapped,
    # so only the second waiter goes through wrapped_wait2).
    waiter_count = 1
    t2, out2 = in_thread(Client(server2).call, 11, "terminal", {"k": "zombie"})
    time.sleep(0.1)
    assert parked2.empty()
    call2.answer("no-zombie")
    t1.join(5)
    assert out1[0][1]["result"]["content"][0]["text"] == "no-zombie"
    assert second_woke.wait(5)
    assert server2.mark_completed("terminal") is True
    assert server2._completed == {} and server2._completed_bytes == 0
    release_second.set()
    t2.join(5)
    assert out2[0][1]["result"]["content"][0]["text"] == "no-zombie"
    assert server2._completed == {} and server2._completed_bytes == 0


def test_clear_completed_and_preserve_parked_block_stragglers():
    parked = queue.Queue()
    woke = {}
    release = {}

    def on_call(call):
        tag = call.arguments["id"]
        if tag in ("stale", "r1"):
            woke[tag] = threading.Event()
            release[tag] = threading.Event()
            orig_wait = call.wait

            def paused_wait(timeout):
                res = orig_wait(timeout)
                woke[tag].set()
                release[tag].wait(5)
                return res

            call.wait = paused_wait
        parked.put(call)

    server = ParkedMcpServer(TOOLS, on_call).start()
    try:
        # SEC-M3-3: clear_completed() blocks a delayed answered straggler from inserting into _completed.
        t_stale, out_stale = in_thread(Client(server).call, 1, "terminal", {"id": "stale"})
        c_stale = parked.get(timeout=5)
        c_stale.answer("stale-ans")
        assert woke["stale"].wait(5)
        server.clear_completed()
        release["stale"].set()
        t_stale.join(5)
        assert out_stale[0][1]["result"]["content"][0]["text"] == "stale-ans"
        assert server._completed == {} and server._completed_bytes == 0

        # SEC-M3-7: clear_completed(preserve_parked=True) blocks prior-round answered straggler while
        # preserving a currently parked call's epoch so it enters _completed when answered.
        t_r1, out_r1 = in_thread(Client(server).call, 2, "terminal", {"id": "r1"})
        c_r1 = parked.get(timeout=5)
        c_r1.answer("r1-ans")
        assert woke["r1"].wait(5)

        t_r2, out_r2 = in_thread(Client(server).call, 3, "terminal", {"id": "r2"})
        c_r2 = parked.get(timeout=5)
        server.clear_completed(preserve_parked=True)

        release["r1"].set()
        t_r1.join(5)
        assert out_r1[0][1]["result"]["content"][0]["text"] == "r1-ans"
        assert server._completed == {}

        c_r2.answer("r2-ans")
        t_r2.join(5)
        assert out_r2[0][1]["result"]["content"][0]["text"] == "r2-ans"
        assert len(server._completed) == 1
        # Repeating r2 hits cache; repeating r1 parks freshly.
        _, body_r2 = Client(server).call(4, "terminal", {"id": "r2"})
        assert body_r2["result"]["content"][0]["text"] == "r2-ans"
        assert parked.empty()
        t_r1_again, _ = in_thread(Client(server).call, 5, "terminal", {"id": "r1"})
        assert parked.get(timeout=5).arguments == {"id": "r1"}
        server.release_parked(drop_connection=False)
        t_r1_again.join(5)
    finally:
        server.close()


def test_delivery_failure_inflight_sends_images_and_error_skip(make):
    # 1) Initial OSError -> retry OSError -> retry succeeds -> mark_completed evicts.
    server, parked = make()
    handler_cls = server._httpd.RequestHandlerClass
    orig_send = handler_cls._send
    send_calls = 0

    def fail_first_two(self, status, payload=None):
        nonlocal send_calls
        if status == 200 and isinstance(payload, dict) and "result" in payload:
            send_calls += 1
            if send_calls <= 2:
                raise BrokenPipeError("simulated drop")
        return orig_send(self, status, payload)

    handler_cls._send = fail_first_two
    t1, out1 = in_thread(lambda: _expect_disconnect(Client(server)))
    call = parked.get(timeout=5)
    call.answer("recovered")
    t1.join(5)
    assert out1 == ["disconnected"]
    assert len(server._completed) == 1
    entry = next(iter(server._completed.values()))
    assert entry.delivery_failed is True and entry.delivery_ok is False and entry.inflight_sends == 0
    # mark_completed NEVER evicts a delivery_failed entry.
    assert server.mark_completed("terminal") is False
    assert len(server._completed) == 1

    # Second attempt (first retry) also raises OSError -> stays cached for another retry.
    assert _expect_disconnect(Client(server)) == "disconnected"
    assert parked.empty()
    assert entry.delivery_failed is True and entry.inflight_sends == 0
    assert server.mark_completed("terminal") is False

    # Third attempt (second retry) succeeds -> delivery_ok=True, mark_completed evicts it.
    status, body = Client(server).call(3)
    assert status == 200 and body["result"]["content"][0]["text"] == "recovered"
    assert parked.empty()
    assert entry.delivery_ok is True and entry.delivery_failed is False and entry.inflight_sends == 0
    assert server.mark_completed("terminal") is True
    assert server._completed == {} and server._completed_bytes == 0

    # 2) Slow-RST OSError while retry is in flight (inflight_sends > 0) does NOT set delivery_failed.
    send1_entered = threading.Event()
    send1_fail = threading.Event()
    send2_entered = threading.Event()
    send2_finish = threading.Event()
    inflight_mode = {"n": 0}

    def slow_rst_inflight(self, status, payload=None):
        if status == 200 and isinstance(payload, dict) and "result" in payload:
            inflight_mode["n"] += 1
            n = inflight_mode["n"]
            if n == 1:
                send1_entered.set()
                send1_fail.wait(5)
                raise ConnectionResetError("slow rst")
            if n == 2:
                send2_entered.set()
                send2_finish.wait(5)
        return orig_send(self, status, payload)

    handler_cls._send = slow_rst_inflight
    ta, outa = in_thread(lambda: _expect_disconnect(Client(server)))
    ca = parked.get(timeout=5)
    ca.answer("slow-rst-1")
    assert send1_entered.wait(5)
    tb, outb = in_thread(Client(server).call, 22)
    assert send2_entered.wait(5)
    entry2 = next(iter(server._completed.values()))
    assert entry2.inflight_sends == 2
    send1_fail.set()
    ta.join(5)
    assert outa == ["disconnected"]
    # Wait until send1's finally ran.
    deadline = time.monotonic() + 5
    while entry2.inflight_sends != 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert entry2.inflight_sends == 1 and entry2.delivery_failed is False
    send2_finish.set()
    tb.join(5)
    assert outb[0][1]["result"]["content"][0]["text"] == "slow-rst-1"
    assert entry2.delivery_ok is True and entry2.delivery_failed is False and entry2.inflight_sends == 0
    assert server.mark_completed("terminal") is True

    # 3) Slow-RST OSError AFTER retry already succeeded (delivery_ok=True) does NOT set delivery_failed.
    send3_entered = threading.Event()
    send3_fail = threading.Event()
    after_ok_mode = {"n": 0}

    def slow_rst_after_ok(self, status, payload=None):
        if status == 200 and isinstance(payload, dict) and "result" in payload:
            after_ok_mode["n"] += 1
            if after_ok_mode["n"] == 1:
                send3_entered.set()
                send3_fail.wait(5)
                raise ConnectionResetError("late rst after ok")
        return orig_send(self, status, payload)

    handler_cls._send = slow_rst_after_ok
    tc, outc = in_thread(lambda: _expect_disconnect(Client(server)))
    cc = parked.get(timeout=5)
    cc.answer("slow-rst-2")
    assert send3_entered.wait(5)
    status_d, body_d = Client(server).call(33)
    assert status_d == 200 and body_d["result"]["content"][0]["text"] == "slow-rst-2"
    entry3 = next(iter(server._completed.values()))
    assert entry3.delivery_ok is True and entry3.inflight_sends == 1
    send3_fail.set()
    tc.join(5)
    assert outc == ["disconnected"]
    deadline = time.monotonic() + 5
    while entry3.inflight_sends != 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert entry3.delivery_ok is True and entry3.delivery_failed is False
    assert server.mark_completed("terminal") is True

    # 4) Images preserved on cache hit; is_error=True never cached.
    handler_cls._send = orig_send
    _, img_first = _call_and_answer(
        server, parked, 40, "terminal", {"img": True}, "pic", images=[("image/png", "QUFB")]
    )
    _, img_cached = Client(server).call(41, "terminal", {"img": True})
    assert parked.empty()
    assert img_first["result"]["content"] == img_cached["result"]["content"] == [
        {"type": "text", "text": "pic"},
        {"type": "image", "mimeType": "image/png", "data": "QUFB"},
    ]
    assert server.mark_completed("terminal") is True

    _, err_first = _call_and_answer(server, parked, 50, "terminal", {"err": True}, "denied", is_error=True)
    assert err_first["result"]["isError"] is True
    assert server._completed == {}
    t_err, _ = in_thread(Client(server).call, 51, "terminal", {"err": True})
    assert parked.get(timeout=5).arguments == {"err": True}
    server.release_parked(drop_connection=False)
    t_err.join(5)


def test_sec_m3c_2_signature_key_identity_bounds_and_fail_closed(make):
    # Byte-for-byte identity with reference canonical JSON SHA-256 across normal inputs.
    samples = [
        ("terminal", {}),
        ("terminal", {"b": [2, 3], "a": 1, "u": "日本語🚀", "flag": True, "nil": None, "f": 1.5}),
        ("read_file", {"nested": {"z": 0, "a": [{"k": "v"}]}}),
    ]
    for name, args in samples:
        expected = hashlib.sha256(
            (name + "\0" + json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode("utf-8")
        ).digest()
        assert signature_key(name, args) == expected

    # Reordered keys yield identical digests.
    assert signature_key("terminal", {"a": 1, "b": 2}) == signature_key("terminal", {"b": 2, "a": 1})

    # Bounds and invalid inputs return None without raising.
    assert signature_key("terminal", {"blob": "a" * (_MAX_SIGNATURE_BYTES + 64)}) is None
    assert signature_key("terminal", {"k": "1234567890"}, max_bytes=16) is None
    assert signature_key("terminal", {"bad": "\ud800"}) is None
    assert signature_key("terminal", {"obj": object()}) is None
    assert signature_key("terminal", {1: "a", "b": 2}) is None
    cyclic: dict = {}
    cyclic["self"] = cyclic
    assert signature_key("terminal", cyclic) is None
    deep: dict = {}
    cur = deep
    for _ in range(1200):
        cur["d"] = {}
        cur = cur["d"]
    assert signature_key("terminal", deep) is None

    # ParkedCall handles unhashable arguments defensively without raising.
    bad_call = ParkedCall("terminal", {"bad": "\ud800"})
    assert bad_call.sig_key == b""

    # ParkedMcpServer fails closed with -32602 when signature_key returns None.
    server, parked = make()
    for bad_args in (cyclic, deep, {"bad": "\ud800"}, {"obj": object()}, {"blob": "a" * (_MAX_SIGNATURE_BYTES + 64)}):
        resp, sig, entry, rb = server._dispatch_rpc(7, "tools/call", {"name": "terminal", "arguments": bad_args})
        assert resp == {"jsonrpc": "2.0", "id": 7, "error": {"code": -32602, "message": "Invalid tool arguments"}}
        assert sig is None and entry is None and rb is None
    assert server._live == {} and server._completed == {} and parked.empty()


def test_sec_m3c_1_uncached_answered_and_oserror_rollback(make):
    # (a) Call A cached + Call B is_error=True: first Layer 2 completion must NOT evict Call A.
    server, parked = make()
    _call_and_answer(server, parked, 1, "terminal", {"tag": "A"}, "ans-A")
    _call_and_answer(server, parked, 2, "terminal", {"tag": "B"}, "err-B", is_error=True)
    assert server._uncached_answered == {"terminal": 1}
    assert server.mark_completed("terminal") is False
    assert len(server._completed) == 1
    # Call A retry still hits cache.
    _, retry_a = Client(server).call(3, "terminal", {"tag": "A"})
    assert retry_a["result"]["content"][0]["text"] == "ans-A" and parked.empty()
    # Second Layer 2 completion evicts Call A and clears counters.
    assert server.mark_completed("terminal") is True
    assert server._completed == {} and server._uncached_answered == {} and server._uncorrelated_completions == {}

    # (b) Call A cached + Call B > 8 MiB oversized: same preservation and batch eviction.
    _call_and_answer(server, parked, 10, "terminal", {"tag": "A2"}, "ans-A2")
    _call_and_answer(server, parked, 11, "terminal", {"tag": "B2"}, "x" * (_MAX_COMPLETED_BYTES + 64))
    assert server._uncached_answered == {"terminal": 1}
    assert server.mark_completed("terminal") is False
    _, retry_a2 = Client(server).call(12, "terminal", {"tag": "A2"})
    assert retry_a2["result"]["content"][0]["text"] == "ans-A2" and parked.empty()
    assert server.mark_completed("terminal") is True
    assert server._completed == {} and server._uncached_answered == {} and server._uncorrelated_completions == {}

    # (c) OSError on uncached answer (entry is None) rolls back _uncached_answered (is_error and >8 MiB).
    handler_cls = server._httpd.RequestHandlerClass
    orig_send = handler_cls._send

    def fail_tool_results(self, status, payload=None):
        if status == 200 and isinstance(payload, dict) and "result" in payload:
            raise BrokenPipeError("uncached drop")
        return orig_send(self, status, payload)

    _call_and_answer(server, parked, 20, "terminal", {"tag": "A3"}, "ans-A3")
    handler_cls._send = fail_tool_results
    try:
        # is_error=True send fails -> rolled back.
        t_err, out_err = in_thread(lambda: _expect_disconnect(Client(server)))
        c_err = parked.get(timeout=5)
        c_err.answer("boom", is_error=True)
        t_err.join(5)
        assert out_err == ["disconnected"]
        deadline = time.monotonic() + 5
        while server._uncached_answered and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server._uncached_answered == {}

        # >8 MiB send fails -> rolled back.
        t_big, out_big = in_thread(lambda: _expect_disconnect(Client(server)))
        c_big = parked.get(timeout=5)
        c_big.answer("y" * (_MAX_COMPLETED_BYTES + 64))
        t_big.join(5)
        assert out_big == ["disconnected"]
        deadline = time.monotonic() + 5
        while server._uncached_answered and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server._uncached_answered == {}
    finally:
        handler_cls._send = orig_send

    # Because both uncached sends rolled back, lone cached A3 evicts on a single Layer 2 completion.
    assert server.mark_completed("terminal") is True
    assert server._completed == {}

    # (d) Coalesced retry on parked is_error=True call increments _uncached_answered ONCE, not twice.
    t1, out1 = in_thread(Client(server).call, 30, "terminal", {"tag": "coalesce-err"})
    c1 = parked.get(timeout=5)
    t2, out2 = in_thread(Client(server).call, 31, "terminal", {"tag": "coalesce-err"})
    time.sleep(0.15)
    assert parked.empty()
    c1.answer("shared-err", is_error=True)
    t1.join(5)
    t2.join(5)
    assert out1[0][1]["result"]["isError"] is True and out2[0][1]["result"]["isError"] is True
    assert server._uncached_answered == {"terminal": 1}
    assert server.mark_completed("terminal") is False
    assert server._uncached_answered == {}


def test_sec_m3c_3_capacity_eviction_mixed_reconciliation_and_no_prebank(make):
    server, parked = make()

    # 1) Empty mark_completed never pre-banks.
    assert server.mark_completed("terminal") is False
    assert server._uncorrelated_completions == {}

    # 2) Capacity eviction decrements _uncorrelated_completions so remaining entries aren't evicted early.
    chunk_3m = "x" * (3 * 1024 * 1024)
    _call_and_answer(server, parked, 1, "terminal", {"i": 1}, chunk_3m)
    _call_and_answer(server, parked, 2, "terminal", {"i": 2}, chunk_3m)
    assert server.mark_completed("terminal") is False
    assert server._uncorrelated_completions == {"terminal": 1}
    # Adding i=3 evicts i=1 due to _MAX_COMPLETED_BYTES -> decrements _uncorrelated_completions to 0.
    _call_and_answer(server, parked, 3, "terminal", {"i": 3}, chunk_3m)
    assert server._uncorrelated_completions == {}
    assert len(server._completed) == 2
    # Now 2 remaining entries require 2 Layer 2 completions (first defers, second evicts both).
    assert server.mark_completed("terminal") is False
    assert len(server._completed) == 2
    assert server.mark_completed("terminal") is True
    assert server._completed == {} and server._uncorrelated_completions == {}

    # 3) Mixed Layer 2 -> Layer 1 reconciliation (two cached entries A, B).
    _call_and_answer(server, parked, 10, "terminal", {"k": "A"}, "A")
    _call_and_answer(server, parked, 11, "terminal", {"k": "B"}, "B")
    assert server.mark_completed("terminal") is False  # Layer 2 defers: uncorr=1
    assert server._uncorrelated_completions == {"terminal": 1}
    # Layer 1 evicts A -> remaining=[B], uncorr=1 >= 1 -> reconciles & evicts B too!
    assert server.mark_completed("terminal", (signature_key("terminal", {"k": "A"}),)) is True
    assert server._completed == {} and server._uncorrelated_completions == {}

    # 4) Mixed Layer 2 -> Layer 1 reconciliation with uncached error B.
    _call_and_answer(server, parked, 20, "terminal", {"k": "C"}, "C")
    _call_and_answer(server, parked, 21, "terminal", {"k": "D"}, "err-D", is_error=True)
    assert server.mark_completed("terminal") is False  # Layer 2 defers: uncorr=1, uncached=1
    assert server.mark_completed("terminal", (signature_key("terminal", {"k": "C"}),)) is True
    assert server._completed == {} and server._uncached_answered == {} and server._uncorrelated_completions == {}

    # 5) Layer 1 miss NEVER falls back to evicting an unrelated sibling.
    _call_and_answer(server, parked, 30, "terminal", {"k": "keep"}, "KEEP")
    assert server.mark_completed("terminal", (signature_key("terminal", {"k": "other"}),)) is False
    assert len(server._completed) == 1

    # 6) Retired server never evicts or pre-banks.
    server.retire()
    assert server.mark_completed("terminal") is False
    assert server.mark_completed("terminal", (signature_key("terminal", {"k": "keep"}),)) is False
    assert server._uncorrelated_completions == {} and server._uncached_answered == {}


def test_sec_m3c_6_layer1_strict_sig_key_priority_order(make):
    server, parked = make()
    _call_and_answer(server, parked, 1, "terminal", {"tag": "inner"}, "INNER")
    _call_and_answer(server, parked, 2, "terminal", {"arguments": {"tag": "inner"}, "tag": "inner"}, "OUTER")
    k1 = signature_key("terminal", {"tag": "inner"})
    k2 = signature_key("terminal", {"arguments": {"tag": "inner"}, "tag": "inner"})
    assert k1 is not None and k2 is not None
    # k1 has delivery_ok=False, delivery_failed=False while k2 has delivery_ok=True.
    server._completed[k1].delivery_ok = False
    server._completed[k1].delivery_failed = False
    server._completed[k2].delivery_ok = True
    server._completed[k2].delivery_failed = False
    # Strict priority order (k1, k2) MUST evict k1 and retain k2.
    assert server.mark_completed("terminal", (k1, k2)) is True
    assert k1 not in server._completed
    assert k2 in server._completed


def _open_raw_call_socket(server, rid, name="terminal", args=None):
    cfg = server.acp_mcp_server_config()
    url = urlparse(cfg["url"])
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": args or {}},
        }
    ).encode("utf-8")
    req = (
        f"POST {url.path} HTTP/1.1\r\n"
        f"Host: {url.hostname}:{url.port}\r\n"
        f"Authorization: {cfg['headers'][0]['value']}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"\r\n"
    ).encode("ascii") + payload
    sock = socket.create_connection((url.hostname, url.port), timeout=5)
    sock.sendall(req)
    return sock


def test_sec_m3c_1_uncached_coalesced_retry_after_primary_rst(make):
    # (1) Real raw TCP SO_LINGER=(1, 0) RST mid-park while coalesced retry delivers HTTP 200.
    # Run multiple iterations to cover real OS socket scheduling.
    server, parked = make()
    for i in range(5):
        _call_and_answer(server, parked, 10 + i, "terminal", {"tag": f"A-{i}"}, f"ans-A-{i}")
        raw_sock = _open_raw_call_socket(server, 100 + i, "terminal", {"tag": f"B-{i}"})
        try:
            call_b = parked.get(timeout=5)
            t_retry, out_retry = in_thread(
                Client(server).call, 200 + i, "terminal", {"tag": f"B-{i}"}
            )
            time.sleep(0.05)
            assert parked.empty()
            # Drop primary socket with TCP RST mid-park.
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            raw_sock.close()
            raw_sock = None
            time.sleep(0.02)
            assert call_b.answer(f"err-B-{i}", is_error=True) is True
            t_retry.join(5)
            assert not t_retry.is_alive() and len(out_retry) == 1
            assert out_retry[0][0] == 200
            assert out_retry[0][1]["result"] == {
                "content": [{"type": "text", "text": f"err-B-{i}"}],
                "isError": True,
            }
            u_entry = call_b._uncached_entry
            assert u_entry is not None
            deadline = time.monotonic() + 5
            while u_entry.inflight_sends != 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert u_entry.inflight_sends == 0
            assert u_entry.delivery_ok is True
            assert u_entry.rolled_back is False
            assert server._uncached_answered == {"terminal": 1}
            # First Layer 2 completion must NOT evict Call A.
            assert server.mark_completed("terminal") is False
            _, retry_a = Client(server).call(300 + i, "terminal", {"tag": f"A-{i}"})
            assert retry_a["result"]["content"][0]["text"] == f"ans-A-{i}" and parked.empty()
            # Second Layer 2 completion evicts Call A and clears counters.
            assert server.mark_completed("terminal") is True
            assert server._completed == {} and server._uncached_answered == {}
        finally:
            if raw_sock is not None:
                raw_sock.close()

    # (2) Deterministic interleaving A: coalesced joins before primary fails with OSError.
    parked_a = queue.Queue()
    coalesced_parked_a = threading.Event()
    primary_in_send_a = threading.Event()
    coalesced_in_send_a = threading.Event()
    allow_coalesced_send_a = threading.Event()

    def on_call_interleave_a(call):
        if call.arguments.get("tag") in ("B-interleave-A", "B-all-fail-conc"):
            orig_wait = call.wait
            wait_count = 0
            wait_lock = threading.Lock()

            def wrapped_wait(timeout):
                nonlocal wait_count
                with wait_lock:
                    wait_count += 1
                    is_coalesced = wait_count == 2
                if is_coalesced:
                    coalesced_parked_a.set()
                res = orig_wait(timeout)
                if is_coalesced:
                    # Ensure primary wins _live before coalesced acquires _lock.
                    primary_in_send_a.wait(5)
                return res

            call.wait = wrapped_wait
        parked_a.put(call)

    srv_a = ParkedMcpServer(TOOLS, on_call_interleave_a).start()
    try:
        _call_and_answer(srv_a, parked_a, 1, "terminal", {"tag": "A-interleave-A"}, "ans-A")
        handler_cls = srv_a._httpd.RequestHandlerClass
        orig_send = handler_cls._send
        fail_coalesced_a = False

        def send_interleave_a(self, status, payload=None):
            if status == 200 and isinstance(payload, dict) and payload.get("id") in (101, 111):
                primary_in_send_a.set()
                coalesced_in_send_a.wait(5)
                raise ConnectionResetError("primary rst while coalesced inflight")
            if status == 200 and isinstance(payload, dict) and payload.get("id") in (102, 112):
                coalesced_in_send_a.set()
                allow_coalesced_send_a.wait(5)
                if fail_coalesced_a:
                    raise BrokenPipeError("coalesced also fails")
            return orig_send(self, status, payload)

        handler_cls._send = send_interleave_a
        t1, out1 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_a).call(101, "terminal", {"tag": "B-interleave-A"})})()
            )
        )
        call_ba = parked_a.get(timeout=5)
        t2, out2 = in_thread(Client(srv_a).call, 102, "terminal", {"tag": "B-interleave-A"})
        assert coalesced_parked_a.wait(5)
        assert parked_a.empty()
        call_ba.answer("err-A", is_error=True)
        t1.join(5)
        assert out1 == ["disconnected"]
        u_a = call_ba._uncached_entry
        assert u_a is not None
        deadline = time.monotonic() + 5
        while u_a.inflight_sends != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        # Primary failed while coalesced is still inflight -> must NOT roll back.
        assert u_a.inflight_sends == 1 and u_a.rolled_back is False
        assert srv_a._uncached_answered == {"terminal": 1}
        allow_coalesced_send_a.set()
        t2.join(5)
        assert out2[0][0] == 200 and out2[0][1]["result"]["isError"] is True
        deadline = time.monotonic() + 5
        while u_a.inflight_sends != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_a.delivery_ok is True and u_a.rolled_back is False
        assert srv_a._uncached_answered == {"terminal": 1}
        assert srv_a.mark_completed("terminal") is False
        _, retry_aa = Client(srv_a).call(103, "terminal", {"tag": "A-interleave-A"})
        assert retry_aa["result"]["content"][0]["text"] == "ans-A" and parked_a.empty()
        assert srv_a.mark_completed("terminal") is True
        assert srv_a._completed == {} and srv_a._uncached_answered == {}

        # (2b) Concurrent all-fail: inflight_sends 2 -> 1 (no rollback) -> 0 (rollback to 0).
        _call_and_answer(srv_a, parked_a, 110, "terminal", {"tag": "A-all-fail-conc"}, "ans-conc")
        coalesced_parked_a.clear()
        primary_in_send_a.clear()
        coalesced_in_send_a.clear()
        allow_coalesced_send_a.clear()
        fail_coalesced_a = True
        tc1, outc1 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_a).call(111, "terminal", {"tag": "B-all-fail-conc"})})()
            )
        )
        call_bc = parked_a.get(timeout=5)
        tc2, outc2 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_a).call(112, "terminal", {"tag": "B-all-fail-conc"})})()
            )
        )
        assert coalesced_parked_a.wait(5)
        call_bc.answer("err-conc", is_error=True)
        tc1.join(5)
        assert outc1 == ["disconnected"]
        u_c = call_bc._uncached_entry
        assert u_c is not None
        deadline = time.monotonic() + 5
        while u_c.inflight_sends != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_c.inflight_sends == 1 and u_c.rolled_back is False
        assert srv_a._uncached_answered == {"terminal": 1}
        allow_coalesced_send_a.set()
        tc2.join(5)
        assert outc2 == ["disconnected"]
        deadline = time.monotonic() + 5
        while (not u_c.rolled_back or u_c.inflight_sends != 0) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_c.delivery_ok is False and u_c.rolled_back is True and u_c.inflight_sends == 0
        assert srv_a._uncached_answered == {}
        assert srv_a.mark_completed("terminal") is True
        assert srv_a._completed == {}
    finally:
        srv_a.close()

    # (3) Deterministic interleaving B: primary fails and rolls back BEFORE coalesced enters _lock.
    parked_b = queue.Queue()
    coalesced_parked_b = threading.Event()
    coalesced_woke_b = threading.Event()
    release_coalesced_b = threading.Event()

    def on_call_interleave_b(call):
        if call.arguments.get("tag") in ("B-interleave-B", "B-all-fail-seq"):
            orig_wait = call.wait
            wait_count = 0
            wait_lock = threading.Lock()

            def wrapped_wait(timeout):
                nonlocal wait_count
                with wait_lock:
                    wait_count += 1
                    is_coalesced = wait_count == 2
                if is_coalesced:
                    coalesced_parked_b.set()
                res = orig_wait(timeout)
                if is_coalesced:
                    coalesced_woke_b.set()
                    release_coalesced_b.wait(5)
                return res

            call.wait = wrapped_wait
        parked_b.put(call)

    srv_b = ParkedMcpServer(TOOLS, on_call_interleave_b).start()
    try:
        _call_and_answer(srv_b, parked_b, 1, "terminal", {"tag": "A-interleave-B"}, "ans-B")
        handler_cls_b = srv_b._httpd.RequestHandlerClass
        orig_send_b = handler_cls_b._send
        fail_ids = {201}

        def send_interleave_b(self, status, payload=None):
            if status == 200 and isinstance(payload, dict) and payload.get("id") in fail_ids:
                raise BrokenPipeError("simulated primary drop before coalesced")
            return orig_send_b(self, status, payload)

        handler_cls_b._send = send_interleave_b
        t1, out1 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_b).call(201, "terminal", {"tag": "B-interleave-B"})})()
            )
        )
        call_bb = parked_b.get(timeout=5)
        t2, out2 = in_thread(Client(srv_b).call, 202, "terminal", {"tag": "B-interleave-B"})
        assert coalesced_parked_b.wait(5)
        assert parked_b.empty()
        call_bb.answer("err-B", is_error=True)
        t1.join(5)
        assert out1 == ["disconnected"]
        assert coalesced_woke_b.wait(5)
        u_b = call_bb._uncached_entry
        assert u_b is not None
        deadline = time.monotonic() + 5
        while (not u_b.rolled_back or u_b.inflight_sends != 0) and time.monotonic() < deadline:
            time.sleep(0.01)
        # Primary rolled back before coalesced entered _lock.
        assert u_b.rolled_back is True and u_b.inflight_sends == 0
        assert srv_b._uncached_answered == {}
        # Now release coalesced: it must re-increment _uncached_answered and deliver HTTP 200.
        release_coalesced_b.set()
        t2.join(5)
        assert out2[0][0] == 200 and out2[0][1]["result"]["isError"] is True
        deadline = time.monotonic() + 5
        while u_b.inflight_sends != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_b.delivery_ok is True and u_b.rolled_back is False
        assert srv_b._uncached_answered == {"terminal": 1}
        assert srv_b.mark_completed("terminal") is False
        _, retry_ab = Client(srv_b).call(203, "terminal", {"tag": "A-interleave-B"})
        assert retry_ab["result"]["content"][0]["text"] == "ans-B" and parked_b.empty()
        assert srv_b.mark_completed("terminal") is True
        assert srv_b._completed == {} and srv_b._uncached_answered == {}

        # (4) Rollback still reaches 0 when ALL coalesced sends fail (sequential rollback -> re-inc -> rollback).
        _call_and_answer(srv_b, parked_b, 204, "terminal", {"tag": "A-all-fail"}, "ans-all-fail")
        coalesced_parked_b.clear()
        coalesced_woke_b.clear()
        release_coalesced_b.clear()
        fail_ids.update({211, 212})
        tf1, outf1 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_b).call(211, "terminal", {"tag": "B-all-fail-seq"})})()
            )
        )
        call_bf = parked_b.get(timeout=5)
        tf2, outf2 = in_thread(
            lambda: _expect_disconnect(
                type("C", (), {"call": lambda _self, _rid: Client(srv_b).call(212, "terminal", {"tag": "B-all-fail-seq"})})()
            )
        )
        assert coalesced_parked_b.wait(5)
        call_bf.answer("err-all-fail", is_error=True)
        tf1.join(5)
        assert outf1 == ["disconnected"]
        assert coalesced_woke_b.wait(5)
        u_f = call_bf._uncached_entry
        assert u_f is not None
        deadline = time.monotonic() + 5
        while (not u_f.rolled_back or u_f.inflight_sends != 0) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_f.rolled_back is True and srv_b._uncached_answered == {}
        release_coalesced_b.set()
        tf2.join(5)
        assert outf2 == ["disconnected"]
        deadline = time.monotonic() + 5
        while (not u_f.rolled_back or u_f.inflight_sends != 0) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert u_f.delivery_ok is False and u_f.rolled_back is True and u_f.inflight_sends == 0
        assert srv_b._uncached_answered == {}
        # Because both sends failed, lone cached Call A evicts on a single Layer 2 completion.
        assert srv_b.mark_completed("terminal") is True
        assert srv_b._completed == {}
    finally:
        srv_b.close()
