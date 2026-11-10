"""Small OpenAI-shape bridge for the standalone Antigravity ACP provider.

The ACP wire has no OpenAI-style ``tools`` / ``tool_calls`` channel. Hermes tool
schemas are therefore rendered into prompt text and ACP responses are parsed back
into the object shape Hermes expects from a Chat Completions client.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any, Iterable

TOOL_CALL_BLOCK_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)
TOOL_CALL_JSON_RE = re.compile(
    r"\{\s*\"id\"\s*:\s*\"[^\"]+\"\s*,\s*\"type\"\s*:\s*\"function\"\s*,\s*\"function\"\s*:\s*\{.*?\}\s*\}",
    re.DOTALL,
)
TOOL_RESPONSE_BLOCK_RE = re.compile(
    r"<tool_response>\s*(.*?)\s*</tool_response>",
    re.DOTALL | re.IGNORECASE,
)
_TOOL_LABEL_SUFFIX_RE = re.compile(r"(?:^|\n)[ \t]*Tool:[ \t]*\n[ \t]*$", re.IGNORECASE)
# A damaged XML-like delimiter can evade the normal extractor and leak a
# previous tool result into the assistant's final answer. Detect protocol-like
# leftovers without rejecting harmless prose examples of the tag names.
_ORPHAN_CALL_RE = re.compile(r"<\s*/?\s*tool_call\b", re.IGNORECASE)
_ORPHAN_RESULT_RE = re.compile(
    r'(?:<tool_response\b[^>]*>\s*\{[\s\S]{0,500}?"tool_call_id"|'
    r'(?:^|\n)\s*Tool:\s*\n\s*<tool_response\b)',
    re.IGNORECASE,
)

TOOL_CALL_CONTRACT = (
    "Available tools (OpenAI function schema). "
    "When using a tool, emit ONLY <tool_call>{...}</tool_call> with one JSON object "
    "containing id/type/function{name,arguments}. arguments must be a JSON string."
)

WEB_RESEARCH_BRIDGE_GUIDANCE = (
    "Research: Only tools advertised through this Hermes tool bridge are callable; do not infer native ACP web tools. "
    "If current web research is requested, web_search absent means NOT AVAILABLE; present but unused means "
    "NOT ATTEMPTED. Report DENIED, CANCELLED, or FAILED only from explicit tool/ACP outcomes. Preserve the user's "
    "research objective. Never fabricate citations or claim live-source verification; cite only actual returned tool "
    "results. Do not bypass or replay denied native actions."
)


class MalformedToolCallError(ValueError):
    """Model emitted a tool-call envelope or arguments that are not valid JSON."""

    def __init__(
        self,
        message: str,
        *,
        tool_name: str = "",
        unrecoverable: bool = False,
        reason: str = "malformed_tool_call",
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.unrecoverable = unrecoverable
        self.reason = reason


class StreamChunks(list):
    """Chunk list that can also carry response-level attributes."""


def completion_to_stream_chunks(completion: SimpleNamespace) -> StreamChunks:
    choice = completion.choices[0]
    message = choice.message
    tool_call_deltas = None
    if message.tool_calls:
        tool_call_deltas = [
            SimpleNamespace(
                index=index,
                id=getattr(tool_call, "id", None),
                type=getattr(tool_call, "type", "function"),
                function=SimpleNamespace(
                    name=getattr(tool_call.function, "name", None),
                    arguments=getattr(tool_call.function, "arguments", None),
                ),
            )
            for index, tool_call in enumerate(message.tool_calls)
        ]
    delta = SimpleNamespace(
        role="assistant",
        content=message.content or None,
        tool_calls=tool_call_deltas,
        reasoning_content=getattr(message, "reasoning_content", None),
        reasoning=getattr(message, "reasoning", None),
        # Hermes consumes ACP through its streaming Chat Completions path. Native
        # ACP tool evidence is carried in reasoning_details; dropping it here made
        # an actually-inspected review indistinguishable from an ungrounded one.
        reasoning_details=getattr(message, "reasoning_details", None),
    )
    data_chunk = SimpleNamespace(
        choices=[SimpleNamespace(index=0, delta=delta, finish_reason=choice.finish_reason)],
        model=completion.model,
        usage=None,
    )
    usage_chunk = SimpleNamespace(choices=[], model=completion.model, usage=completion.usage)
    chunks = StreamChunks([data_chunk, usage_chunk])
    for key, value in vars(completion).items():
        if key not in ("choices", "usage", "model"):
            setattr(chunks, key, value)
    return chunks


def build_openai_tool_call(*, call_id: str, name: str, arguments: str) -> SimpleNamespace:
    """Return the minimal OpenAI-compatible tool-call shape Hermes consumes."""
    return SimpleNamespace(
        id=call_id,
        call_id=call_id,
        response_item_id=None,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _named_function(container: Any) -> tuple[dict[str, Any], str] | None:
    fn = container.get("function") if isinstance(container, dict) else None
    name = fn.get("name") if isinstance(fn, dict) else None
    return (fn, name.strip()) if isinstance(name, str) and name.strip() else None


def tool_specs_from_openai_tools(
    tools: list[dict[str, Any]] | None,
    *,
    allowlist: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    allowed = {str(name).strip() for name in allowlist} if allowlist is not None else None
    specs: list[dict[str, Any]] = []
    for tool in tools or []:
        named = _named_function(tool)
        if named is None or (allowed is not None and named[1] not in allowed):
            continue
        fn, name = named
        specs.append(
            {
                "name": name,
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters", {}),
            }
        )
    return specs


def advertised_tool_names(tools: list[dict[str, Any]] | None) -> list[str]:
    """Return unique function names actually supplied by the Hermes caller."""
    names: list[str] = []
    seen: set[str] = set()
    for spec in tool_specs_from_openai_tools(tools):
        name = str(spec.get("name") or "").strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def render_tool_bridge_sections(
    tools: list[dict[str, Any]] | None,
    tool_choice: Any = None,
    *,
    allowlist: Iterable[str] | None = None,
) -> list[str]:
    specs = tool_specs_from_openai_tools(tools, allowlist=allowlist)
    sections: list[str] = []
    if specs:
        sections.append(TOOL_CALL_CONTRACT + "\n" + json.dumps(specs, ensure_ascii=False))
    if tool_choice is not None:
        sections.append(f"Tool choice hint: {json.dumps(tool_choice, ensure_ascii=False)}")
    sections.append(WEB_RESEARCH_BRIDGE_GUIDANCE)
    return sections


def _parse_tool_call(raw_json: str, ordinal: int) -> SimpleNamespace | None:
    try:
        obj = json.loads(raw_json)
    except Exception as exc:
        raise MalformedToolCallError("Antigravity emitted malformed tool-call envelope JSON.") from exc
    named = _named_function(obj)
    if named is None:
        return None
    fn, fn_name = named
    fn_args = fn.get("arguments", "{}")
    if not isinstance(fn_args, str):
        fn_args = json.dumps(fn_args, ensure_ascii=False)
    else:
        fn_args = fn_args.strip() or "{}"
        try:
            json.loads(fn_args)
        except Exception as exc:
            raise MalformedToolCallError(
                f"Antigravity emitted invalid JSON in function.arguments for tool {fn_name!r}.",
                tool_name=fn_name,
            ) from exc
    call_id = obj.get("id")
    if not isinstance(call_id, str) or not call_id.strip():
        call_id = f"acp_call_{ordinal}"
    return build_openai_tool_call(call_id=call_id, name=fn_name, arguments=fn_args)


def _strip_replayed_tool_responses(text: str) -> str:
    """Remove ACP-internal tool-result envelopes accidentally replayed as assistant text.

    Only well-formed Hermes envelopes with both ``tool_call_id`` and ``content`` are
    treated as protocol material.  Unparseable/example XML is left alone so ordinary
    prose is not silently discarded.  A standalone ``Tool:`` label immediately before
    a removed envelope is protocol decoration and is removed with it.
    """
    if not isinstance(text, str) or "<tool_response>" not in text.lower():
        return text.strip() if isinstance(text, str) else ""

    spans: list[tuple[int, int]] = []
    for match in TOOL_RESPONSE_BLOCK_RE.finditer(text):
        try:
            payload = json.loads(match.group(1))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not (
            isinstance(payload, dict)
            and bool(str(payload.get("tool_call_id") or "").strip())
            and "content" in payload
        ):
            continue
        start = match.start()
        prefix_match = _TOOL_LABEL_SUFFIX_RE.search(text[:start])
        if prefix_match and prefix_match.end() == start:
            start = prefix_match.start()
        spans.append((start, match.end()))

    if not spans:
        return text.strip()

    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        if cursor < start:
            parts.append(text[cursor:start])
        cursor = end
    if cursor < len(text):
        parts.append(text[cursor:])
    return "\n".join(part.strip() for part in parts if part and part.strip()).strip()


def _reject_orphan_protocol_fragments(text: str) -> str:
    """Fail closed on unparsed action/result payloads, not on tag examples."""
    if _ORPHAN_RESULT_RE.search(text):
        # The result might belong to an already executed side-effecting action.
        # Never ask the model to recreate it: surface an explicit unknown outcome.
        raise MalformedToolCallError(
            "Antigravity leaked an incomplete Hermes tool-result envelope.",
            unrecoverable=True,
        )
    if _ORPHAN_CALL_RE.search(text):
        raise MalformedToolCallError(
            "Antigravity emitted an incomplete Hermes tool-call envelope."
        )
    return text


def extract_tool_calls_from_text(text: str) -> tuple[list[SimpleNamespace], str]:
    if not isinstance(text, str) or not text.strip():
        return [], ""
    extracted: list[SimpleNamespace] = []
    consumed_spans: list[tuple[int, int]] = []
    for pattern, group in ((TOOL_CALL_BLOCK_RE, 1), (TOOL_CALL_JSON_RE, 0)):
        for match in pattern.finditer(text):
            call = _parse_tool_call(match.group(group), len(extracted) + 1)
            if call is not None:
                extracted.append(call)
            consumed_spans.append((match.start(), match.end()))
        if extracted:
            break
    if not consumed_spans:
        return extracted, _reject_orphan_protocol_fragments(_strip_replayed_tool_responses(text))

    consumed_spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in consumed_spans:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        if cursor < start:
            parts.append(text[cursor:start])
        cursor = max(cursor, end)
    if cursor < len(text):
        parts.append(text[cursor:])
    cleaned = "\n".join(part.strip() for part in parts if part and part.strip()).strip()
    return extracted, _reject_orphan_protocol_fragments(_strip_replayed_tool_responses(cleaned))
