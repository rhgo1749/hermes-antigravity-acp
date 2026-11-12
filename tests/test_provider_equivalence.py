"""Provider permission-policy and capability equivalence checks.

Pre-merge review follow-up for the catalog fail-closed work (PR #11).
Invariants under test:

- The final allow/deny of commands and file operations is Hermes core
  policy: the adapter never executes tools itself, never filters the
  advertised tool surface per provider, and hands tool calls back to
  Hermes in the standard OpenAI tool-call shape so core dispatch and
  approval treat them identically to native-provider calls.
- Tool capability and the fail-closed permission policy survive
  tool-list changes (context fingerprint invalidation forces a full
  re-prompt that re-includes the bridge contract).
- Failure causes stay separable: adapter parse failures raise
  MalformedToolCallError and execute nothing; a model that simply does
  not select tools degrades to plain content instead of an adapter error.

Credential-free by construction: no ACP server process is launched.
"""

from __future__ import annotations

import json

import pytest

from test_native_permission_policy import _load_plugin


def _openai_tool(name: str, *, description: str = "", parameters: dict | None = None):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description or f"desc-{name}",
            "parameters": parameters if parameters is not None else {"type": "object", "properties": {}},
        },
    }


# --- tool surface is identical to what the Hermes caller supplied -----------


def test_bridge_renders_every_supplied_tool_without_provider_filtering(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    tools = [
        _openai_tool("terminal"),
        _openai_tool("read_file"),
        _openai_tool("write_file"),
        _openai_tool("my_custom_tool", parameters={"type": "object", "properties": {"q": {"type": "string"}}}),
    ]
    sections = module.render_tool_bridge_sections(tools, None)
    rendered = "\n".join(sections)
    expected_specs = [
        {
            "name": tool["function"]["name"],
            "description": tool["function"]["description"],
            "parameters": tool["function"]["parameters"],
        }
        for tool in tools
    ]
    # exact schema pass-through: same names, descriptions, and parameter
    # schemas Hermes would serialize for any native provider
    assert json.dumps(expected_specs, ensure_ascii=False) in rendered
    assert module.advertised_tool_names(tools) == [
        "terminal", "read_file", "write_file", "my_custom_tool",
    ]


def test_tool_choice_hint_is_forwarded_like_native_providers(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    sections = module.render_tool_bridge_sections([_openai_tool("terminal")], "required")
    assert any('"required"' in section for section in sections)


# --- adapter output shape is indistinguishable from native providers -------


def test_parsed_tool_call_uses_openai_tool_call_shape(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    text = (
        '<tool_call>{"id":"call_1","type":"function","function":'
        '{"name":"terminal","arguments":"{\\"command\\": \\"ls -la\\"}"}}</tool_call>'
        " working on it"
    )
    calls, rest = module.extract_tool_calls_from_text(text)
    assert len(calls) == 1
    call = calls[0]
    assert call.id == "call_1"
    assert call.type == "function"
    assert call.function.name == "terminal"
    assert json.loads(call.function.arguments) == {"command": "ls -la"}
    assert "working on it" in rest


# --- failure-cause separation: adapter parse failure -----------------------


def test_malformed_envelope_is_classified_as_adapter_parse_failure(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    with pytest.raises(module.MalformedToolCallError):
        module.extract_tool_calls_from_text("<tool_call>{not-json}")


def test_invalid_arguments_json_is_classified_as_adapter_parse_failure(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    text = (
        '<tool_call>{"id":"c","type":"function","function":'
        '{"name":"terminal","arguments":"{broken"}}</tool_call>'
    )
    with pytest.raises(module.MalformedToolCallError) as excinfo:
        module.extract_tool_calls_from_text(text)
    assert getattr(excinfo.value, "tool_name", None) == "terminal"


# --- model selection failure degrades to content, not adapter error --------


def test_model_without_tool_selection_returns_plain_content(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    calls, rest = module.extract_tool_calls_from_text("The tests pass; no further action needed.")
    assert calls == []
    assert rest.strip() == "The tests pass; no further action needed."


# --- tool capability survives tool-list changes (resume/continuation) ------


def test_tool_list_change_invalidates_delta_and_forces_full_reprompt(monkeypatch):
    _, _, module = _load_plugin(monkeypatch)
    base = [_openai_tool("terminal"), _openai_tool("read_file")]
    changed = [_openai_tool("terminal"), _openai_tool("read_file"), _openai_tool("write_file")]
    same_a = module._context_fingerprint("model-x", base, None)
    same_b = module._context_fingerprint("model-x", [dict(t) for t in base], None)
    different = module._context_fingerprint("model-x", changed, None)
    # identical surfaces keep the fingerprint stable (delta continuations
    # stay cheap)...
    assert same_a == same_b
    # ...but any capability change changes the fingerprint, which makes
    # _continuation_delta return None and the client re-send the full
    # prompt including the tool bridge contract.
    assert same_a != different
