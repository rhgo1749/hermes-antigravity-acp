"""Images (ACP image blocks, MCP image content) and thinking level (reasoning_effort -> agy) end to end."""

import os

import pytest

from antigravity_acp_mcp.client import thinking_level
from antigravity_acp_mcp.conversation import MAX_PROMPT_IMAGES, degenerate, render_delta, render_replay
from antigravity_acp_mcp.matcher import classify, explain_mismatch, view_after
from antigravity_acp_mcp.permission import PermissionGate
from antigravity_acp_mcp.session import new_session

from ._support import SYS, TOOLS, asst, dump, events, make_conv

PNG_A, PNG_B = "QUFBQQ==", "QkJCQg=="
SERVER = {"type": "http", "name": "hermes-deadbeef", "url": "http://127.0.0.1:1/mcp/p", "headers": []}


def img(data, mime="image/png"):
    return {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{data}"}}


def user_with(*parts):
    return {"role": "user", "content": [{"type": "text", "text": "look"}, *parts]}


def image_blocks(blocks):
    return [(b["mimeType"], b["data"]) for b in blocks if b["type"] == "image"]


def test_replay_attaches_inline_images_numbered_and_deduped():
    msgs = [SYS, user_with(img(PNG_A)), {"role": "assistant", "content": "seen"},
            user_with(img(PNG_B, "image/jpeg"), img(PNG_A), {"type": "image_url", "image_url": {"url": "https://x/y.png"}})]
    blocks = render_replay(msgs)
    text = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert "User: look\n[image #1]" in text  # history row
    assert "[image #2]\n[image #1]\n[image at https://x/y.png (not attached; use a vision tool" in text  # active row, same bytes = same number
    assert image_blocks(blocks) == [("image/png", PNG_A), ("image/jpeg", PNG_B)]
    # each image sits right after its first marker; the closing instruction stays the last block
    assert [b["type"] for b in blocks] == ["text", "image", "text", "image", "text"]
    assert blocks[0]["text"].endswith("[image #1]") and blocks[2]["text"].endswith("[image #2]")
    assert blocks[-1]["text"].rstrip().endswith("respond to ACTIVE_REQUEST.")


def test_replay_caps_attached_images_to_the_newest():
    datas = [f"SU1H{i:04d}" for i in range(MAX_PROMPT_IMAGES + 2)]
    blocks = render_replay([SYS, user_with(*[img(d) for d in datas])])
    assert [d for _, d in image_blocks(blocks)] == datas[2:]
    assert blocks[0]["text"].startswith("(image #1-#2 not attached: only the newest 8 are)")
    assert blocks[-1]["text"].rstrip().endswith("respond to ACTIVE_REQUEST.")


def test_delta_carries_its_images_and_text_only_stays_one_block():
    assert image_blocks(render_delta([user_with(img(PNG_A))])) == [("image/png", PNG_A)]
    assert render_delta([{"role": "user", "content": "hi"}]) == [{"type": "text", "text": "hi"}]


def test_image_change_is_a_prefix_mismatch_reported_without_content():
    base = [SYS, user_with(img(PNG_A))]
    view = view_after(base)
    swapped = [SYS, user_with(img(PNG_B)), {"role": "assistant", "content": "x"}, {"role": "user", "content": "n"}]
    assert classify(swapped, view).kind == "replay"
    why = explain_mismatch(swapped, list(view.seen))
    assert why == "index 1: user images differ (1 -> 1)" and PNG_B not in why


def test_images_reach_agy_in_the_prompt_and_in_tool_results(tmp_path):
    conv, log = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "shot"}}}, {"text": "done"}]])
    try:
        msgs = [SYS, user_with(img(PNG_A))]
        r1 = conv.run(msgs, TOOLS, "m")
        msgs += [asst(r1["tool_calls"]),
                 {"role": "tool", "tool_call_id": r1["tool_calls"][0].id,
                  "content": [{"type": "text", "text": "screenshot"}, img(PNG_B, "image/webp")]}]
        assert conv.run(msgs, TOOLS, "m")["text"] == "done"
        ev = events(log)
        assert [e["images"] for e in ev if e["ev"] == "prompt"] == [["image/png"]]
        (answer,) = [e for e in ev if e["ev"] == "answer"]
        assert answer["text"] == "screenshot\n[image]" and answer["images"] == ["image/webp"]
    finally:
        conv.close()


@pytest.mark.parametrize(("effort", "level"), [
    ("none", "low"), ("minimal", "low"), ("medium", "medium"), ("high", "high"), ("xhigh", "xhigh"),
    ("max", "xhigh"), ("ultra", "xhigh"), ("", None), (None, None), ("weird", None),
])
def test_effort_maps_to_thinking_level(monkeypatch, effort, level):
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_MCP_THINKING_LEVEL", raising=False)
    assert thinking_level(effort) == level


def test_env_overrides_effort(monkeypatch):
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_THINKING_LEVEL", "low")
    assert thinking_level("high") == "low"


LEGACY = ["fake-model-a-low", "fake-model-a-medium", "fake-model-a-high", "fake-model-a-xhigh",
          "fake-model-b-high"]
THOUGHT = [{"id": "thinking_level", "category": "thought_level",
            "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}]}]


def calls(conn):
    return [(m["method"], m["params"]) for m in dump(conn)["log"]
            if m.get("method") in ("session/set_model", "session/set_config_option")]


@pytest.mark.parametrize(("model", "thinking", "expected"), [
    # composite id with an offered sibling: the suffix is swapped, no extra option call
    ("fake-model-a-medium", "xhigh", [("session/set_model", "fake-model-a-xhigh")]),
    ("fake-model-a-medium", "medium", [("session/set_model", "fake-model-a-medium")]),
    # no exact sibling: nearest sibling, then thought_level set to the nearest level it offers
    ("fake-model-b-high", "xhigh", [("session/set_model", "fake-model-b-high"),
                                    ("session/set_config_option", "high")]),
    ("fake-model-b-high", "low", [("session/set_model", "fake-model-b-high"),
                                  ("session/set_config_option", "low")]),
    # not a composite id: the model as requested, then the option
    ("m", "medium", [("session/set_model", "m"), ("session/set_config_option", "medium")]),
    # no effort: the model id alone decides
    ("fake-model-a-high", None, [("session/set_model", "fake-model-a-high")]),
])
def test_thinking_selection(connect, model, thinking, expected):
    conn = connect({"legacy_models": LEGACY, "config_options": THOUGHT})
    new_session(conn, mcp_server=SERVER, gate=PermissionGate("hermes-deadbeef", set()), model=model, thinking=thinking)
    got = [(m, p.get("modelId") or p.get("value")) for m, p in calls(conn)]
    assert got == expected


def test_thinking_change_mid_conversation_opens_a_fresh_session(tmp_path):
    conv, log = make_conv(tmp_path, [[{"text": "one"}], [{"text": "two"}], [{"text": "three"}]])
    try:
        msgs = [SYS, {"role": "user", "content": "q"}]
        conv.run(msgs, TOOLS, "m", thinking="medium")
        msgs += [{"role": "assistant", "content": "one"}, {"role": "user", "content": "next"}]
        conv.run(msgs, TOOLS, "m", thinking="medium")  # same level: continue on the same session
        msgs += [{"role": "assistant", "content": "two"}, {"role": "user", "content": "more"}]
        conv.run(msgs, TOOLS, "m", thinking="high")
        sids = [e["sid"] for e in events(log) if e["ev"] == "prompt"]
        assert sids[0] == sids[1] != sids[2]
    finally:
        conv.close()


def test_prompt_drops_images_when_the_agent_lacks_the_capability(connect):
    conn = connect({})
    session = new_session(conn, mcp_server=SERVER, gate=PermissionGate("hermes-deadbeef", set()))
    session.prompt(render_delta([user_with(img(PNG_A))]), timeout=10)
    (params,) = [m["params"] for m in dump(conn)["log"] if m.get("method") == "session/prompt"]
    assert all(b["type"] == "text" for b in params["prompt"])


def test_prompt_keeps_images_when_the_agent_declares_them(connect):
    conn = connect({"prompt_images": True})
    session = new_session(conn, mcp_server=SERVER, gate=PermissionGate("hermes-deadbeef", set()))
    session.prompt(render_delta([user_with(img(PNG_A))]), timeout=10)
    (params,) = [m["params"] for m in dump(conn)["log"] if m.get("method") == "session/prompt"]
    assert [b["type"] for b in params["prompt"]] == ["text", "image"]


def test_nearest_level_both_directions(connect):
    only_high = [{"id": "thinking_level", "category": "thought_level", "options": [{"value": "medium"}, {"value": "high"}]}]
    conn = connect({"config_options": only_high})
    new_session(conn, mcp_server=SERVER, gate=PermissionGate("hermes-deadbeef", set()), model="m", thinking="low")
    assert calls(conn)[-1] == ("session/set_config_option",
                               {"sessionId": "sess-1", "configId": "thinking_level", "value": "medium"})


def test_numbering_continues_across_prompts_on_one_session(tmp_path):
    conv, log = make_conv(tmp_path, [[{"text": "one"}], [{"text": "two"}]])
    try:
        msgs = [SYS, user_with(img(PNG_A))]
        conv.run(msgs, TOOLS, "m")
        msgs += [{"role": "assistant", "content": "one"}, user_with(img(PNG_B), img(PNG_A))]
        conv.run(msgs, TOOLS, "m")
        prompts = [e for e in events(log) if e["ev"] == "prompt"]
        assert prompts[1]["sid"] == prompts[0]["sid"]
        assert prompts[1]["text"] == "look\n[image #2]\n[image #1]"  # A keeps #1 and is not attached again
        assert prompts[1]["images"] == ["image/png"]
    finally:
        conv.close()


def test_data_url_with_parameters_is_inline():
    part = {"type": "image_url", "image_url": {"url": f"data:image/png;name=x.png;base64,{PNG_A}"}}
    assert image_blocks(render_delta([user_with(part)])) == [("image/png", PNG_A)]


def test_one_skipped_image_note_names_a_single_number():
    datas = [f"SU1H{i:04d}" for i in range(MAX_PROMPT_IMAGES + 1)]
    assert "(image #1 not attached: only the newest 8 are)" in render_replay([SYS, user_with(*[img(d) for d in datas])])[0]["text"]


@pytest.mark.parametrize(("text", "bad"), [("}", True), (" ]} ", True), ("...", True), ("", False), ("OK", False),
                                           ("\U0001F44D", False), ("好", False), ("}" * 9, False)])
def test_degenerate_reply_detection(text, bad):
    assert degenerate(text) is bad


def test_degenerate_final_reply_is_re_asked_once_on_the_same_session(tmp_path):
    conv, log = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"text": "}"}],
                                     [{"text": "the full answer"}]])
    try:
        msgs = [SYS, {"role": "user", "content": "q"}]
        r1 = conv.run(msgs, TOOLS, "m")
        msgs += [asst(r1["tool_calls"]), {"role": "tool", "tool_call_id": r1["tool_calls"][0].id, "content": "A"}]
        r2 = conv.run(msgs, TOOLS, "m")
        assert r2["text"] == "the full answer" and r2["finish_reason"] == "stop"
        prompts = [e for e in events(log) if e["ev"] == "prompt"]
        assert len(prompts) == 2 and prompts[1]["sid"] == prompts[0]["sid"] and "'}'" in prompts[1]["text"]
    finally:
        conv.close()


def test_second_degenerate_reply_is_returned_as_is(tmp_path):
    conv, log = make_conv(tmp_path, [[{"text": "}"}], [{"text": "}"}]])
    try:
        assert conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")["text"] == "}"
        assert len([e for e in events(log) if e["ev"] == "prompt"]) == 2
    finally:
        conv.close()


def test_replays_of_one_conversation_share_a_byte_identical_prefix(tmp_path):
    conv, log = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}], [{"text": "x"}],
                                     [{"text": "y"}]])
    try:
        msgs = [SYS, {"role": "user", "content": "q"}]
        r1 = conv.run(msgs, TOOLS, "m")
        msgs += [asst(r1["tool_calls"]), {"role": "tool", "tool_call_id": r1["tool_calls"][0].id, "content": "A"}]
        conv.cancel()  # retire: each next request replays on a fresh session
        conv.run(msgs, TOOLS, "m")
        conv.cancel()
        conv.run(msgs, TOOLS, "m")
        prompts = [e["text"] for e in events(log) if e["ev"] == "prompt"]
        assert len(prompts) == 3 and prompts[1].count(conv.fence) == 2
        # identical through the end of the fenced tool output, not just the system band
        end = prompts[1].rindex(conv.fence) + len(conv.fence)
        assert prompts[2][:end] == prompts[1][:end]
    finally:
        conv.close()


@pytest.mark.parametrize("literal_row", [
    {"role": "user", "content": "what is [image #1]?"},
    {"role": "assistant", "content": "In [image #1] I see a cat"},
])
def test_typed_marker_text_never_decides_where_an_image_lands(literal_row):
    msgs = [SYS, literal_row, {"role": "user", "content": "ok"}, user_with(img(PNG_A))]
    blocks = render_replay(msgs)
    idx = next(i for i, b in enumerate(blocks) if b["type"] == "image")
    before = blocks[idx - 1]["text"]
    assert "<ACTIVE_REQUEST>" in before and before.endswith("[image #1]")  # placed in the active request
    assert "\x1e" not in "".join(b.get("text", "") for b in blocks)  # no sentinel leaks into the prompt


def test_marker_text_in_tool_output_does_not_move_the_image():
    msgs = [SYS, user_with(img(PNG_A)), {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "fetch", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "page says [image #1]"}]
    blocks = render_replay(msgs)
    idx = next(i for i, b in enumerate(blocks) if b["type"] == "image")
    assert "<ACTIVE_REQUEST>" in blocks[idx - 1]["text"] and "page says" not in blocks[idx - 1]["text"]



def test_replay_keeps_the_active_copy_of_a_repeated_system_message_full():
    big = "<system-message>\n" + "rule " * 60 + "\n</system-message>"
    msgs = [SYS, {"role": "user", "content": "first\n" + big}, {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "second\n" + big}]
    text = "".join(b["text"] for b in render_replay(msgs, seen_sys=set()) if b["type"] == "text")
    active = text.split("<ACTIVE_REQUEST>")[1].split("</ACTIVE_REQUEST>")[0]
    history = text.split("<HISTORICAL_CONTEXT>")[1].split("</HISTORICAL_CONTEXT>")[0]
    assert "rule rule" in active and "rule rule" not in history
    assert "repeated in full later in this prompt" in history


def test_usage_update_frames_are_never_billing_usage(tmp_path):
    """Semantics split (issue #6 class): frames feed occupancy/telemetry channels, never ``completion.usage``."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[{"usage": {"used": 1200, "size": 1000000, "inputTokens": 900,
                                               "outputTokens": 40}}, {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        c = _completion(r, "m")
        assert c.usage is None  # no prompt-result breakdown -> Hermes' own estimate stands
        occ = c.antigravity_context_occupancy
        assert occ["used"] == 1200 and occ["size"] == 1000000
        assert occ["is_billing_usage"] is False
        assert occ["source"] == "acp.session/update:usage_update"
        assert c.antigravity_frame_usage == {"input_tokens": 900, "output_tokens": 40}
    finally:
        conv.close()


def test_caller_cwd_is_never_deleted(tmp_path):
    keep = tmp_path / "workspace"
    keep.mkdir()
    conv, _ = make_conv(tmp_path, [[{"text": "x"}]], cwd=str(keep))
    conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
    conv.close()
    assert keep.is_dir()
    handed = tmp_path / "pool-temp"
    handed.mkdir()
    conv, _ = make_conv(tmp_path, [[{"text": "x"}]], cwd=str(handed), owns_cwd=True)
    conv.close()
    assert not handed.exists()  # ownership handed over explicitly
    own, _ = make_conv(tmp_path, [[{"text": "x"}]])
    own_dir = own.cwd
    own.close()
    assert not os.path.exists(own_dir)


def test_duplicate_tool_result_request_is_refused_and_the_running_step_survives(tmp_path):
    import threading
    import time

    from antigravity_acp_mcp.conversation import ProviderError
    conv, _ = make_conv(tmp_path, [[{"call": {"name": "fetch", "arguments": {"k": "a"}}}, {"silent": 1.0},
                                    {"text": "done"}]])
    try:
        msgs = [SYS, {"role": "user", "content": "q"}]
        r1 = conv.run(msgs, TOOLS, "m")
        msgs += [asst(r1["tool_calls"]), {"role": "tool", "tool_call_id": r1["tool_calls"][0].id, "content": "A"}]
        out = []
        t = threading.Thread(target=lambda: out.append(conv.run(msgs, TOOLS, "m")))
        t.start()
        time.sleep(0.3)
        with pytest.raises(ProviderError, match="duplicate"):
            conv.run(msgs, TOOLS, "m")
        t.join(20)
        assert out and out[0]["text"] == "done"
    finally:
        conv.close()


def test_replay_budget_preserves_active_request_and_drops_old_history_and_images():
    from antigravity_acp_mcp.conversation import MAX_REPLAY_BYTES
    sys_msg = {"role": "system", "content": "sys " * 2000}
    msgs = [sys_msg, user_with(img(PNG_A)), {"role": "assistant", "content": "old screenshot reply"}]
    for i in range(40):
        msgs.append({"role": "user", "content": f"old turn {i} " + ("漢" * 1000)})
        msgs.append({"role": "assistant", "content": "", "tool_calls": [
            {"id": f"c{i}", "type": "function", "function": {"name": "fetch", "arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": f"tool-{i}-" + ("X" * 10000)})
        msgs.append({"role": "assistant", "content": f"done {i}"})
    msgs.append(user_with(img(PNG_B)))
    msgs.append({"role": "assistant", "content": "recent turn reply"})
    msgs.append({"role": "user", "content": "最新的實際問題：每日提醒每次都是真的對話嗎？"})
    blocks = render_replay(msgs)
    full_text = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert len(full_text.encode("utf-8")) <= MAX_REPLAY_BYTES
    assert "<ACTIVE_REQUEST>\n最新的實際問題：每日提醒每次都是真的對話嗎？\n</ACTIVE_REQUEST>" in full_text
    assert full_text.endswith("Use the provided tools when you need them; respond to ACTIVE_REQUEST.")
    assert "recent turn reply" in full_text
    assert "earlier historical messages omitted" in full_text
    # Dropped old screenshot PNG_A must NOT be attached; surviving recent PNG_B MUST be attached as #1.
    assert image_blocks(blocks) == [("image/png", PNG_B)]
    assert "[image #1]" in full_text and "[image #2]" not in full_text


def test_replay_budget_shrinks_historical_tool_outputs_before_dropping_turns():
    msgs = [
        SYS,
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "fetch", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "HEAD-" + ("Z" * 20_000) + "-TAIL"},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "second question"},
    ]
    blocks = render_replay(msgs, max_bytes=12_000)
    full_text = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert len(full_text.encode("utf-8")) <= 12_000
    assert "first question" in full_text and "first answer" in full_text
    assert "HEAD-" in full_text and "-TAIL" in full_text
    assert "truncated" in full_text and "earlier historical messages omitted" not in full_text
    assert "<ACTIVE_REQUEST>\nsecond question\n</ACTIVE_REQUEST>" in full_text


def test_replay_budget_handles_oversized_system_and_cjk_safely():
    msgs = [
        {"role": "system", "content": "系統規則：" + ("繁體中文測試" * 1000)},
        {"role": "user", "content": "歷史訊息" * 500},
        {"role": "assistant", "content": "歷史回覆" * 500},
        {"role": "user", "content": "最後一個真正的問題"},
    ]
    blocks = render_replay(msgs, max_bytes=4_000)
    full_text = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert len(full_text.encode("utf-8")) <= 4_000
    assert "<ACTIVE_REQUEST>\n最後一個真正的問題\n</ACTIVE_REQUEST>" in full_text


@pytest.mark.parametrize("limit", [200, 1_024, 4_000, 180_000])
def test_replay_budget_enforces_limit_on_oversized_progress_and_assistant_calls(limit):
    msgs_tool = [
        {"role": "system", "content": "sys " * 500},
        {"role": "user", "content": "active question 🚀 " + ("漢" * 1000)},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "write_file",
                                                          "arguments": '{"body":"' + ("W" * 200_000) + '"}'}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "T" * 200_000},
    ]
    msgs_asst = [
        {"role": "system", "content": "sys " * 500},
        {"role": "user", "content": "active question 🎉 " + ("字" * 1000)},
        {"role": "assistant", "content": "A" * 200_000},
    ]
    msgs_no_user = [{"role": "assistant", "content": "N" * 200_000}]
    for msgs in (msgs_tool, msgs_asst, msgs_no_user):
        blocks = render_replay(msgs, max_bytes=limit)
        full_text = "".join(b["text"] for b in blocks if b["type"] == "text")
        assert len(full_text.encode("utf-8")) <= limit


def test_replay_budget_oversized_active_with_image_has_no_orphan_registration():
    from antigravity_acp_mcp.conversation import MAX_REPLAY_BYTES, _Images
    msgs = [
        SYS,
        {"role": "user", "content": [
            {"type": "text", "text": "LONG-" + ("漢" * 70_000) + "-END"},
            img(PNG_B),
        ]},
    ]
    sink = _Images()
    blocks = render_replay(msgs, imgs=sink, max_bytes=MAX_REPLAY_BYTES)
    full_text = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert len(full_text.encode("utf-8")) <= MAX_REPLAY_BYTES
    assert image_blocks(blocks) == [("image/png", PNG_B)]
    assert len(sink.items) == 1 and "[image #1]" in full_text

    tiny_sink = _Images()
    tiny_blocks = render_replay(msgs, imgs=tiny_sink, max_bytes=200)
    tiny_text = "".join(b["text"] for b in tiny_blocks if b["type"] == "text")
    assert len(tiny_text.encode("utf-8")) <= 200
    assert len(image_blocks(tiny_blocks)) == len(tiny_sink.items)
    if tiny_sink.items:
        assert "[image #1]" in tiny_text

    clamp_sink = _Images()
    clamp_blocks = render_replay(msgs, imgs=clamp_sink, max_bytes=80)
    clamp_text = "".join(b["text"] for b in clamp_blocks if b["type"] == "text")
    assert len(clamp_text.encode("utf-8")) <= 80
    assert image_blocks(clamp_blocks) == [] and len(clamp_sink.items) == 0
