"""Native image input must reach the ACP server as ImageContent blocks.

Hermes Core routes a turn's image attachments to the adapter as OpenAI-style
``image_url`` parts (inline ``data:<mime>;base64`` URLs) on the last user
message.  The adapter must convert them to ACP v1 ``{"type":"image",
"data":...,"mimeType":...}`` prompt blocks instead of silently dropping them.
Fake subprocess only: no credentials, no Google binary.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

PNG_B64 = "iVBORw0KGgoAAAANSUhEUg=="
JPEG_B64 = "/9j/4AAQSkZJRg=="


def _load_client(monkeypatch, *, args: list[str], cwd: str, retries: int = 0):
    client, _ = _load_client_and_module(monkeypatch, args=args, cwd=cwd, retries=retries)
    return client


def _load_client_and_module(monkeypatch, *, args: list[str], cwd: str, retries: int = 0):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(Path(cwd) / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(Path(cwd) / "acp-limits.json")
    )
    registered: list = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)

    module_name = "antigravity_acp_vision"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name, PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    client = module.antigravity_acp.create_client(
        command=sys.executable, args=args, acp_cwd=cwd, rate_limit_retries=retries
    )
    return client, sys.modules[type(client).__module__]


# Records every session/prompt request and answers with a canned text turn.
FAKE = r'''
import json
import sys

REC = REC

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "antigravity-acp", "title": "Google Antigravity",
                          "version": "1.4.0"},
            "agentCapabilities": {
                "loadSession": True,
                "sessionCapabilities": {"list": {}, "resume": {}},
                "promptCapabilities": {"image": True, "audio": True,
                                       "embeddedContext": True},
                "mcpCapabilities": {},
                "auth": {"logout": {}}},
            "authMethods": []}})
    elif method in ("session/new", "session/resume"):
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": "s-vision",
            "models": {"currentModelId": "gemini-3.8-flash-high",
                       "availableModels": [
                           {"modelId": "gemini-3.8-flash-high",
                            "name": "Gemini 3.8 Flash (High)"}]}}})
    elif method == "session/prompt":
        if REC:
            with open(REC, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(msg.get("params")) + "\n")
        emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "ok-vision"}}}})
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''


def _fake_server(tmp_path: Path, record_path: Path) -> list[str]:
    script = tmp_path / "fake_acp_vision.py"
    script.write_text(
        f"REC = {str(record_path)!r}\n" + FAKE, encoding="utf-8"
    )
    return [str(script)]


def _prompts(record_path: Path) -> list[list[dict]]:
    return [
        json.loads(line)["prompt"]
        for line in record_path.read_text(encoding="utf-8").splitlines()
    ]


def test_data_url_images_become_acp_image_blocks(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    reply = client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What colour is the shape?"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
                ],
            }
        ],
        timeout=10,
    )
    assert reply.choices[0].message.content == "ok-vision"
    (prompt,) = _prompts(rec)
    assert [block["type"] for block in prompt] == ["image", "text"]
    image = prompt[0]
    assert image["mimeType"] == "image/png"
    assert image["data"] == PNG_B64
    assert "What colour is the shape?" in prompt[1]["text"]


def test_multiple_images_keep_order_and_mime(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
                    {"type": "image_url", "image_url": f"data:image/jpeg;base64,{JPEG_B64}"},
                    {"type": "text", "text": "compare them"},
                ],
            }
        ],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    assert [block["type"] for block in prompt] == ["image", "image", "text"]
    assert prompt[0]["mimeType"] == "image/png"
    assert prompt[1]["mimeType"] == "image/jpeg"
    assert prompt[1]["data"] == JPEG_B64


def test_text_only_turns_keep_single_text_block(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": "plain text only"}],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    assert [block["type"] for block in prompt] == ["text"]


def test_non_data_image_urls_are_skipped(monkeypatch, tmp_path) -> None:
    # ACP ImageContent requires inline base64 data; a remote URL is Core's job
    # to fetch, so the transport must not forward a bogus image block.
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "look at this"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
                ],
            }
        ],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    assert [block["type"] for block in prompt] == ["text"]


def test_images_in_history_not_resent(monkeypatch, tmp_path) -> None:
    # Core normalizes older turns to plain text and attaches images only to the
    # active turn; the adapter scans just the latest user message.
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "first turn had an image"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
                ],
            },
            {"role": "assistant", "content": "noted"},
            {"role": "user", "content": "and now a text-only follow-up"},
        ],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    assert [block["type"] for block in prompt] == ["text"]


def test_continuation_turn_carries_new_active_image(monkeypatch, tmp_path) -> None:
    # Second turn resumes the same session via a continuation delta; the new
    # turn's image must ride the delta, not be lost to the resume path.
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is in the first image"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
                ],
            }
        ],
        timeout=10,
    )
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is in the first image"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
                ],
            },
            {"role": "assistant", "content": "ok-vision"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "and this second one"},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{JPEG_B64}"}},
                ],
            },
        ],
        timeout=10,
    )
    first, second = _prompts(rec)
    assert first[0]["type"] == "image" and first[0]["data"] == PNG_B64
    assert [block["type"] for block in second] == ["image", "text"]
    assert second[0]["data"] == JPEG_B64 and second[0]["mimeType"] == "image/jpeg"


def _tool_call_message() -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": "call-vision-1",
            "type": "function",
            "function": {"name": "vision_analyze", "arguments": "{}"},
        }],
    }


def _tool_image_result(image_data: str = JPEG_B64, mime: str = "image/jpeg") -> dict:
    return {
        "role": "tool",
        "tool_call_id": "call-vision-1",
        "name": "vision_analyze",
        "content": {
            "_multimodal": True,
            "content": [
                {"type": "text", "text": "Image loaded; answer from the pixels."},
                {"type": "image_url", "image_url": {
                    "url": f"data:{mime};base64,{image_data}"
                }},
            ],
            "text_summary": "Image attached natively.",
        },
    }


def _assert_image_block(prompt: list[dict], expected_data: str, expected_mime: str) -> None:
    images = [block for block in prompt if block.get("type") == "image"]
    assert images == [{"type": "image", "data": expected_data, "mimeType": expected_mime}]
    text = "\n".join(block.get("text", "") for block in prompt if block.get("type") == "text")
    assert expected_data not in text
    assert "data:" not in text


def test_tool_role_content_list_image_becomes_acp_image_block(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    tool_result = _tool_image_result()
    tool_result["content"] = tool_result["content"]["content"]
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": "What is in this image?"}, _tool_call_message(), tool_result],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    _assert_image_block(prompt, JPEG_B64, "image/jpeg")
    assert "Image loaded; answer from the pixels." in prompt[-1]["text"]


def test_tool_role_multimodal_envelope_does_not_put_base64_in_prompt_text(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": "Describe the attached image."}, _tool_call_message(), _tool_image_result()],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    _assert_image_block(prompt, JPEG_B64, "image/jpeg")
    assert "Image loaded; answer from the pixels." in prompt[-1]["text"]
    assert "Image attached natively." in prompt[-1]["text"]


def test_user_multimodal_envelope_becomes_acp_image_block(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    result = _tool_image_result()
    client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": result["content"]}],
        timeout=10,
    )
    (prompt,) = _prompts(rec)
    _assert_image_block(prompt, JPEG_B64, "image/jpeg")
    assert "Image loaded; answer from the pixels." in prompt[-1]["text"]


def test_resume_sends_only_new_tool_image_and_never_replays_it_again(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    original_user = {
        "role": "user",
        "content": [
            {"type": "text", "text": "Compare this original with the later result."},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
        ],
    }
    client.chat.completions.create(
        model="antigravity-acp", messages=[original_user], timeout=10,
    )
    tool_result = _tool_image_result()
    continued = [original_user, {"role": "assistant", "content": "ok-vision"}, _tool_call_message(), tool_result]
    client.chat.completions.create(model="antigravity-acp", messages=continued, timeout=10)
    followup = [*continued, {"role": "assistant", "content": "ok-vision"},
                {"role": "user", "content": "Now summarize the comparison."}]
    client.chat.completions.create(model="antigravity-acp", messages=followup, timeout=10)

    first, resumed, resumed_again = _prompts(rec)
    _assert_image_block(first, PNG_B64, "image/png")
    _assert_image_block(resumed, JPEG_B64, "image/jpeg")
    assert [block["type"] for block in resumed_again] == ["text"]
    assert PNG_B64 not in json.dumps(resumed)
    assert JPEG_B64 not in json.dumps(resumed_again)


@pytest.mark.asyncio
async def test_async_completion_awaits_and_runs_transport_off_loop(monkeypatch, tmp_path) -> None:
    import threading

    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    loop_thread = threading.get_ident()
    transport_threads: list[int] = []
    original_create = client._create_chat_completion

    def tracked_create(**kwargs):
        transport_threads.append(threading.get_ident())
        return original_create(**kwargs)

    monkeypatch.setattr(client, "_create_chat_completion", tracked_create)
    response = await client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": [
            {"type": "text", "text": "What is shown?"},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
        ]}],
        timeout=10,
    )
    assert response.choices[0].message.content == "ok-vision"
    assert transport_threads and transport_threads[0] != loop_thread
    (prompt,) = _prompts(rec)
    _assert_image_block(prompt, PNG_B64, "image/png")


@pytest.mark.asyncio
async def test_sync_completion_called_inside_running_loop_stays_sync_usable(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    # A synchronous caller can exist inside an async Gateway/plugin callback; merely
    # detecting a running loop and returning a coroutine breaks this established API.
    response = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "sync in loop"}], timeout=10,
    )
    assert response.choices[0].message.content == "ok-vision"
    assert _prompts(rec)


@pytest.mark.asyncio
async def test_async_stream_result_is_async_iterable(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    chunks = await client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "stream me"}],
        stream=True, timeout=10,
    )
    collected = [chunk async for chunk in chunks]
    assert collected and collected[0].choices[0].delta.content == "ok-vision"


# --- continuation frontier compatibility -------------------------------------
# The conversation checkpoint persists request_fingerprints computed from the
# pre-redaction renderers. Prompt rendering may redact Base64, but the
# fingerprint path must stay byte-identical to the pinned legacy renderers
# below, or every stored multimodal session silently loses native resume.
# These copies are verbatim from git HEAD (d98612e) client.py lines 432-496.

def _legacy_render_message_content(content) -> str:
    if content is None:
        return ""
    if isinstance(content, dict):
        if "text" in content:
            return str(content.get("text") or "").strip()
        if isinstance(content.get("content"), str):
            return content["content"].strip()
        return json.dumps(content, ensure_ascii=True)
    if isinstance(content, list):
        parts = [
            item if isinstance(item, str) else item["text"].strip()
            for item in content
            if isinstance(item, str)
            or (
                isinstance(item, dict)
                and isinstance(item.get("text"), str)
                and item["text"].strip()
            )
        ]
        return "\n".join(parts).strip()
    return str(content).strip()


def _legacy_render_prompt_message(message: dict, role: str) -> str:
    content = _legacy_render_message_content(message.get("content"))
    if role == "assistant":
        parts = [content] if content else []
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict) or not str(function.get("name") or "").strip():
                continue
            payload = {
                "id": str(tool_call.get("id") or ""),
                "type": str(tool_call.get("type") or "function"),
                "function": {
                    "name": str(function.get("name") or ""),
                    "arguments": function.get("arguments", "{}"),
                },
            }
            parts.append(
                f"<tool_call>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n</tool_call>"
            )
        return "\n".join(parts).strip()
    if role == "tool" and message.get("tool_call_id"):
        result = content
        if content.lstrip().startswith(("{", "[")):
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                pass
        payload = {
            "tool_call_id": str(message["tool_call_id"]),
            "content": result,
        }
        if message.get("name"):
            payload["name"] = str(message["name"])
        return (
            f"<tool_response>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n"
            "</tool_response>"
        )
    return content


def _legacy_message_fingerprint(message: dict, client_mod) -> str:
    role = str(message.get("role") or "unknown").strip().lower()
    if role != "assistant":
        rendered = _legacy_render_prompt_message(message, role)
    else:
        content = _legacy_render_message_content(message.get("content"))
        parts = [content] if content else []
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict) or not str(function.get("name") or "").strip():
                continue
            payload = {
                "id": str(tool_call.get("id") or ""),
                "type": str(tool_call.get("type") or "function"),
                "function": {
                    "name": str(function.get("name") or ""),
                    "arguments": client_mod._normalized_tool_arguments(
                        function.get("arguments", "{}")
                    ),
                },
            }
            parts.append(
                json.dumps(
                    payload, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), default=str,
                )
            )
        rendered = "\n".join(parts).strip()
    import hashlib
    return hashlib.sha256(
        f"{role}\0{rendered}".encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _assistant_tool_call_message(call_id: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": "vision_analyze", "arguments": "{}"},
        }],
    }


def _tool_image_result_for(call_id: str, image_data: str, mime: str) -> dict:
    return {
        "role": "tool",
        "tool_call_id": call_id,
        "name": "vision_analyze",
        "content": {
            "_multimodal": True,
            "content": [
                {"type": "text", "text": "Image loaded; answer from the pixels."},
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_data}"}},
            ],
            "text_summary": "Image attached natively.",
        },
    }


def _continuation_prefix_messages() -> list[dict]:
    return [
        {"role": "user", "content": "Run vision on the earlier image."},
        _assistant_tool_call_message("call-vision-1"),
        _tool_image_result_for("call-vision-1", JPEG_B64, "image/jpeg"),
    ]


def test_legacy_multimodal_checkpoint_still_continues_and_sends_new_image(
    monkeypatch, tmp_path
) -> None:
    """A checkpoint written by the pre-fix renderer must keep native resume.

    Simulates the on-disk frontier of an already-upgraded deployment: the
    request_fingerprints come from the legacy renderers (base64 included in
    the hashed payload), so the current fingerprint path must reproduce them
    exactly. The follow-up turn then continues (not bootstraps) and carries
    only the new PNG image block.
    """
    rec = tmp_path / "prompts.jsonl"
    client, client_mod = _load_client_and_module(
        monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path)
    )
    prefix = _continuation_prefix_messages()
    legacy_fingerprints = tuple(
        _legacy_message_fingerprint(message, client_mod) for message in prefix
    )
    affinity_key = client_mod._conversation_affinity(prefix, str(tmp_path))
    assert affinity_key
    client_mod.conversation_registry.put(
        affinity_key,
        client_mod.ACPConversationState(
            session_id="s-vision",
            context_fingerprint=client_mod._context_fingerprint(
                "antigravity-acp", None, None, execution_mode="trusted-coding"
            ),
            request_fingerprints=legacy_fingerprints,
            response_fingerprint=client_mod._response_fingerprint("ok-vision", []),
            updated_at=__import__("time").time(),
            native_tokens=100,
            effective_model="gemini-3.8-flash-high",
        ),
    )

    followup = [
        *prefix,
        {"role": "assistant", "content": "ok-vision"},
        _assistant_tool_call_message("call-vision-2"),
        _tool_image_result_for("call-vision-2", PNG_B64, "image/png"),
    ]
    client.chat.completions.create(
        model="antigravity-acp", messages=followup, timeout=10,
    )
    (continuation,) = _prompts(rec)
    continuation_text = "\n".join(
        block.get("text", "") for block in continuation if block.get("type") == "text"
    )
    assert "Hermes continuation delta" in continuation_text
    images = [block for block in continuation if block.get("type") == "image"]
    assert images == [{"type": "image", "data": PNG_B64, "mimeType": "image/png"}]
    assert JPEG_B64 not in json.dumps(continuation)
    assert PNG_B64 not in continuation_text


def test_multiple_tool_images_in_one_continuation_all_delivered_once(
    monkeypatch, tmp_path
) -> None:
    rec = tmp_path / "prompts.jsonl"
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, rec), cwd=str(tmp_path))
    user = {"role": "user", "content": "Run two vision passes."}
    client.chat.completions.create(
        model="antigravity-acp", messages=[user], timeout=10,
    )
    two_pass = [
        user,
        {"role": "assistant", "content": "ok-vision"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-vision-a",
                    "type": "function",
                    "function": {"name": "vision_analyze", "arguments": "{}"},
                },
                {
                    "id": "call-vision-b",
                    "type": "function",
                    "function": {"name": "vision_analyze", "arguments": "{}"},
                },
            ],
        },
        _tool_image_result_for("call-vision-a", JPEG_B64, "image/jpeg"),
        _tool_image_result_for("call-vision-b", PNG_B64, "image/png"),
    ]
    client.chat.completions.create(
        model="antigravity-acp", messages=two_pass, timeout=10,
    )
    followup = [
        *two_pass,
        {"role": "assistant", "content": "ok-vision"},
        {"role": "user", "content": "Now compare the two."},
    ]
    client.chat.completions.create(
        model="antigravity-acp", messages=followup, timeout=10,
    )
    first, second, third = _prompts(rec)
    assert [block["type"] for block in first] == ["text"]
    images = [block for block in second if block.get("type") == "image"]
    assert [block["data"] for block in images] == [JPEG_B64, PNG_B64]
    assert [block["mimeType"] for block in images] == ["image/jpeg", "image/png"]
    assert [block["type"] for block in third] == ["text"]
    assert JPEG_B64 not in json.dumps(first)
    assert JPEG_B64 not in json.dumps(third)
    assert PNG_B64 not in json.dumps(third)


# Fake that answers session/new normally but reports the resumed session gone.
FAKE_RESUME_MISS = FAKE.replace(
    '''    elif method in ("session/new", "session/resume"):
        emit({"jsonrpc": "2.0", "id": rid, "result": {''',
    '''    elif method == "session/resume":
        emit({"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32603, "message": "session not found"}})
    elif method == "session/new":
        emit({"jsonrpc": "2.0", "id": rid, "result": {''',
)


def test_resume_miss_replays_active_turn_images(monkeypatch, tmp_path) -> None:
    rec = tmp_path / "prompts.jsonl"
    script = tmp_path / "fake_acp_resume_miss.py"
    script.write_text(
        f"REC = {str(rec)!r}\n" + FAKE_RESUME_MISS, encoding="utf-8"
    )
    client = _load_client(
        monkeypatch, args=[str(script)], cwd=str(tmp_path), retries=0
    )
    user = {"role": "user", "content": "Inspect the screenshot."}
    client.chat.completions.create(
        model="antigravity-acp", messages=[user], timeout=10,
    )
    with_image = [
        user,
        {"role": "assistant", "content": "ok-vision"},
        _assistant_tool_call_message("call-vision-1"),
        _tool_image_result_for("call-vision-1", JPEG_B64, "image/jpeg"),
    ]
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=with_image, timeout=10,
    )
    assert reply.choices[0].message.content == "ok-vision"
    first, replay = _prompts(rec)
    replay_text = "\n".join(
        block.get("text", "") for block in replay if block.get("type") == "text"
    )
    assert "Hermes continuation delta" not in replay_text
    images = [block for block in replay if block.get("type") == "image"]
    assert images == [{"type": "image", "data": JPEG_B64, "mimeType": "image/jpeg"}]
    assert JPEG_B64 not in replay_text
