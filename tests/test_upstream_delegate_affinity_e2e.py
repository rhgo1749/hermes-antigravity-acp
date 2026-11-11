"""Issue #2 E2E: real Hermes delegation context -> provider client -> mux -> fake ACP.

Runs only under a real Hermes checkout/venv (same skip convention as
``test_vanilla_hermes_seam.py``): the delegation identity is produced by the
GENUINE ``agent.delegation_context.delegated_child_context`` and
``gateway.session_context`` contextvars — the exact seam
``tools/delegate_tool_child_run.py`` binds around each child run — never by a
substituted ContextVar. The ACP server side is a credential-free fake.

Substitution boundary (honest scope): the full AIAgent dispatch loop of
``delegate_task`` (child agent construction, tool loops) is NOT run; a parent
and two siblings drive real client requests while the real core context
managers scope each identity. The dispatch loop is upstream-owned and
orthogonal to affinity keying: its only contact with this plugin is the
context this file reproduces verbatim.

Invariants proven here:
  * parent, child A, and child B land on three distinct affinities;
  * child A resumes only the native session child A created;
  * child B likewise; the parent resumes only its own;
  * a child with no durable id is stateless: fresh native session, no pin,
    and it resumes nothing;
  * no session/resume ever references a session id created under another
    affinity.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"

try:
    from agent.delegation_context import delegated_child_context
    from gateway.session_context import clear_session_vars, set_session_vars

    _CORE_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment gate
    delegated_child_context = None
    clear_session_vars = set_session_vars = None
    _CORE_IMPORT_ERROR = exc

pytestmark = pytest.mark.skipif(
    delegated_child_context is None
    and os.environ.get("HERMES_STRICT_SEAM_TEST") != "1",
    reason="requires a real Hermes checkout/venv for genuine delegation context",
)


def _require_real_core() -> None:
    if delegated_child_context is None:
        pytest.fail(
            "strict mode requires the real delegation context; import failed: "
            f"{_CORE_IMPORT_ERROR!r}",
            pytrace=False,
        )
    # Provenance: the identity seam must be a real file inside the Hermes
    # package tree, never a hand-built module.
    import agent.delegation_context as delegation_module
    import gateway.session_context as session_module

    for module in (delegation_module, session_module):
        module_file = getattr(module, "__file__", None)
        assert isinstance(module_file, str) and module_file.endswith(".py"), (
            f"{module.__name__} is not a genuine core module file"
        )


def _write_unique_session_fake_server(tmp_path: Path) -> tuple[Path, Path]:
    """Fake ACP server handing out a UNIQUE session id per session/new.

    Logs every request with the ACP_MUX_AFFINITY it was served under, so
    cross-affinity resume is directly observable.
    """
    script = tmp_path / "fake_acp_unique.py"
    log_path = tmp_path / "fake_acp_unique_log.jsonl"
    script.write_text(
        r'''
import itertools
import json
import os
import sys

log_path = sys.argv[1]
_sessions = itertools.count(1)

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(payload):
    row = {
        "affinity": os.environ.get("ACP_MUX_AFFINITY", ""),
        **payload,
    }
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    log({
        "id": msg.get("id"),
        "method": method,
        "sessionId": params.get("sessionId", ""),
    })
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/new":
        issued = f"session-{os.getpid()}-{next(_sessions)}"
        log({"id": msg.get("id"), "method": "session/new", "sessionId": issued})
        emit({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "sessionId": issued,
                "configOptions": [{
                    "id": "model",
                    "category": "model",
                    "currentValue": "gemini-3.8-flash-high",
                    "options": [
                        {"value": "gemini-3.1-pro"},
                        {"value": "gemini-3.8-flash-high"},
                    ],
                }],
            },
        })
    elif method == "session/resume":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method in ("session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/prompt":
        text = ((params.get("prompt") or [{}])[0].get("text") or "")
        emit({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {"update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": f"reply[{text[:24]}]"},
            }},
        })
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
'''.lstrip(),
        encoding="utf-8",
    )
    return script, log_path


def _load_client(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "acp-conversation-state.json"),
    )
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_NATIVE_GC", raising=False)
    registered = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    # Registration surface only; delegation identity stays genuine core.
    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    module_name = "antigravity_acp_delegate_e2e"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _turn(client, messages, label):
    response = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=messages,
    )
    content = response.choices[0].message.content
    assert isinstance(content, str) and content, label
    return messages + [{"role": "assistant", "content": content}]


def test_parent_and_sibling_children_keep_disjoint_native_continuations(
    monkeypatch, tmp_path
) -> None:
    _require_real_core()
    script, log_path = _write_unique_session_fake_server(tmp_path)
    par = tmp_path / "par.py"
    par.write_text(
        "#!/usr/bin/env python3\n"
        f"import sys\n"
        f"sys.argv = [{str(script)!r}, {str(log_path)!r}]\n"
        f"exec(compile(open({str(script)!r}).read(), {str(script)!r}, 'exec'))\n"
    )
    par.chmod(0o755)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_REAL_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    for pin in (
        "ACP_MUX_SESSION_ID",
        "ACP_MUX_AFFINITY",
        "ACP_MUX_ACCOUNTS",
        "ACP_MUX_STATE",
        "ACP_MUX_LOG",
        "ACP_MUX_PAR",
    ):
        monkeypatch.delenv(pin, raising=False)

    accounts = []
    for name in ("lane-a", "lane-b"):
        home = tmp_path / name
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
        accounts.append({"home": str(home), "label": name})
    registry = tmp_path / ".hermes" / "acp-accounts.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps({"accounts": accounts}))

    module = _load_client(monkeypatch, tmp_path)
    client_mod = importlib.import_module(f"{module.__name__}.client")
    monkeypatch.setattr(client_mod, "_read_par_pin", lambda: str(par))
    client = module.antigravity_acp.create_client(
        command=sys.executable,
        args=[str(PLUGIN_DIR.parents[1] / "scripts" / "antigravity-acp-mux.py")],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )

    tokens = set_session_vars(
        platform="telegram",
        source="telegram",
        chat_id="1",
        session_key="agent:main:telegram:dm:1:2",
        session_id="parent-durable-1",
    )
    try:
        parent_messages = _turn(client, [{"role": "user", "content": "parent task"}], "parent-1")
        with delegated_child_context("child-a-1"):
            child_a_messages = _turn(client, [{"role": "user", "content": "child A task"}], "a-1")
        with delegated_child_context("child-b-1"):
            child_b_messages = _turn(client, [{"role": "user", "content": "child B task"}], "b-1")
        with delegated_child_context("child-a-1"):
            child_a_messages = _turn(
                client,
                child_a_messages + [{"role": "user", "content": "child A follow-up"}],
                "a-2",
            )
        with delegated_child_context("child-b-1"):
            _turn(
                client,
                child_b_messages + [{"role": "user", "content": "child B follow-up"}],
                "b-2",
            )
        # Ambiguous child: core enters the scope without a durable id.
        with delegated_child_context(""):
            ambiguous_messages = _turn(
                client, [{"role": "user", "content": "ambiguous child task"}], "amb-1"
            )
            _turn(
                client,
                ambiguous_messages + [{"role": "user", "content": "ambiguous follow-up"}],
                "amb-2",
            )
        _turn(client, parent_messages + [{"role": "user", "content": "parent follow-up"}], "parent-2")
    finally:
        clear_session_vars(tokens)

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    created = [
        row["sessionId"]
        for row in rows
        if row["method"] == "session/new" and row["sessionId"]
    ]
    resumed = [row["sessionId"] for row in rows if row["method"] == "session/resume"]

    # Affinity attribution: the mux strips ACP_MUX_AFFINITY from the server
    # child, so the client-side conversation state file is the affinity->
    # native-session ledger; the fake-server log is the resume ledger.
    state = json.loads(
        (tmp_path / "acp-conversation-state.json").read_text(encoding="utf-8")
    )
    states = state["states"]
    keyed_sessions = {entry["session_id"] for entry in states.values()}
    affinities = set(states)

    # Parent, child A, and child B hold three DISTINCT affinity entries, each
    # bound to its own native session. The ambiguous child is absent: it never
    # gets state, never gets a pin, and resumes nothing.
    assert len(affinities) == 3, affinities
    assert len(keyed_sessions) == 3, keyed_sessions

    # Five native sessions were created: three keyed conversations plus two
    # fresh stateless sessions for the ambiguous child's two turns.
    assert len(created) == 5, created
    unkeyed = [sid for sid in created if sid not in keyed_sessions]
    assert len(unkeyed) == 2, unkeyed

    # Exactly three resumes (parent, A, B follow-ups), and every resume
    # targets a session owned by a keyed affinity — never the ambiguous
    # child's sessions, never a session id that was never created.
    assert len(resumed) == 3, resumed
    assert set(resumed) == keyed_sessions, (resumed, keyed_sessions)
    assert not set(resumed) & set(unkeyed)

    # Each keyed affinity resumed exactly its own session: the resume ledger
    # consumed each keyed session id exactly once and no affinity moved.
    assert sorted(resumed) == sorted(keyed_sessions)


def _captured_child_context(child_id: str):
    """Snapshot the REAL core context a delegate child runs in.

    Mirrors how core scopes each child (``delegated_child_context`` around the
    child run) and how the parent dispatches it (``contextvars.copy_context``),
    so threads execute with exactly the child's ContextVars — parent session
    key inherited, own durable id bound.
    """
    import contextvars

    with delegated_child_context(child_id):
        return contextvars.copy_context()


def test_concurrent_same_prompt_siblings_never_share_affinity_or_frontier(
    monkeypatch, tmp_path
) -> None:
    """Issue #2's core repro condition, executed concurrently.

    Three siblings share cwd, prompt bytes, and the parent session key — the
    exact collision shape measured in production — and run their requests in
    overlapping windows forced by barriers. A fourth ambiguous child (no
    durable id) runs concurrently and must stay stateless. Follow-ups then
    complete in reverse order with a freshly regenerated client per request:
    every conversation must still resume only its own native session.
    """
    _require_real_core()
    script, log_path = _write_unique_session_fake_server(tmp_path)
    par = tmp_path / "par.py"
    par.write_text(
        "#!/usr/bin/env python3\n"
        f"import sys\n"
        f"sys.argv = [{str(script)!r}, {str(log_path)!r}]\n"
        f"exec(compile(open({str(script)!r}).read(), {str(script)!r}, 'exec'))\n"
    )
    par.chmod(0o755)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_REAL_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    for pin in (
        "ACP_MUX_SESSION_ID",
        "ACP_MUX_AFFINITY",
        "ACP_MUX_ACCOUNTS",
        "ACP_MUX_STATE",
        "ACP_MUX_LOG",
        "ACP_MUX_PAR",
    ):
        monkeypatch.delenv(pin, raising=False)

    accounts = []
    for name in ("lane-a", "lane-b"):
        home = tmp_path / name
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
        accounts.append({"home": str(home), "label": name})
    registry = tmp_path / ".hermes" / "acp-accounts.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps({"accounts": accounts}))

    module = _load_client(monkeypatch, tmp_path)
    client_mod = importlib.import_module(f"{module.__name__}.client")
    monkeypatch.setattr(client_mod, "_read_par_pin", lambda: str(par))

    def fresh_client():
        return module.antigravity_acp.create_client(
            command=sys.executable,
            args=[str(PLUGIN_DIR.parents[1] / "scripts" / "antigravity-acp-mux.py")],
            acp_cwd=str(tmp_path),
            rate_limit_retries=0,
        )

    # One shared client for the concurrent phase, exactly as the gateway
    # serves concurrent sessions through one registered provider client.
    client = fresh_client()
    lane = client_mod.get_current_write_origin()

    keyed_ids = ["child-a-1", "child-b-1", "child-c-1"]
    contexts = {cid: _captured_child_context(cid) for cid in keyed_ids + [""]}
    identical_prompt = [{"role": "user", "content": "identical sibling task"}]
    histories: dict[str, list] = {cid: list(identical_prompt) for cid in contexts}
    failures: list[BaseException] = []

    def run_turn(cid: str, extra: str | None, actor) -> None:
        messages = histories[cid] + (
            [{"role": "user", "content": extra}] if extra else []
        )
        response = actor.chat.completions.create(
            model="gemini-3.1-pro", messages=messages
        )
        content = response.choices[0].message.content
        assert isinstance(content, str) and content, cid
        histories[cid] = messages + [{"role": "assistant", "content": content}]

    def guarded(cid: str, extra: str | None, actor) -> None:
        try:
            run_turn(cid, extra, actor)
        except BaseException as exc:  # noqa: BLE001 - surfaced via failures
            failures.append(exc)

    tokens = set_session_vars(
        platform="telegram",
        source="telegram",
        chat_id="1",
        session_key="agent:main:telegram:dm:1:2",
        session_id="parent-durable-1",
    )
    try:
        import threading

        # Phase 1: all four children enter create() simultaneously with the
        # SAME prompt bytes and cwd; keyed children differ only by durable id.
        barrier = threading.Barrier(len(contexts), timeout=120)

        def phase1(cid: str) -> None:
            barrier.wait()
            guarded(cid, None, client)

        threads = [
            threading.Thread(target=contexts[cid].run, args=(phase1, cid), name=cid)
            for cid in contexts
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=180)
        assert not failures, failures

        # Phase 2: concurrent follow-ups — each conversation must resume only
        # its own session while siblings are mid-request.
        def phase2(cid: str) -> None:
            barrier.wait()
            guarded(cid, f"follow-up {cid}", client)

        threads = [
            threading.Thread(target=contexts[cid].run, args=(phase2, cid), name=cid)
            for cid in contexts
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=180)
        assert not failures, failures

        # Phase 3: reverse-order completion with a freshly regenerated client
        # per request — affinity must survive client lifetime entirely.
        for cid in reversed(keyed_ids):
            contexts[cid].run(guarded, cid, f"late turn {cid}", fresh_client())
        assert not failures, failures
    finally:
        clear_session_vars(tokens)

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    created = [
        row["sessionId"]
        for row in rows
        if row["method"] == "session/new" and row["sessionId"]
    ]
    resumed = [row["sessionId"] for row in rows if row["method"] == "session/resume"]

    state = json.loads(
        (tmp_path / "acp-conversation-state.json").read_text(encoding="utf-8")
    )
    states = state["states"]

    # Exact attribution: each keyed child's affinity is the hash of its OWN
    # durable id + lane — not the shared parent key, not the identical prompt.
    import hashlib

    expected_affinities = {
        "sha256:"
        + hashlib.sha256(
            f"hermes-session\0{cid}\0{lane}".encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        for cid in keyed_ids
    }
    assert set(states) == expected_affinities, set(states)

    keyed_sessions = {entry["session_id"] for entry in states.values()}
    assert len(keyed_sessions) == 3, keyed_sessions

    # Ambiguous child: two stateless turns, two fresh sessions, zero state.
    unkeyed = [sid for sid in created if sid not in keyed_sessions]
    assert len(unkeyed) == 2, unkeyed

    # Resume ledger: 3 keyed conversations x 2 follow-up phases = 6 resumes,
    # every one targeting its own keyed session; the ambiguous child's fresh
    # sessions were never resumed, and no frontier was ever overwritten by a
    # sibling (each keyed session id is stable across all three phases).
    assert len(resumed) == 6, resumed
    assert set(resumed) == keyed_sessions, (resumed, keyed_sessions)
    assert not set(resumed) & set(unkeyed)
