"""Issue #2: delegated children must own distinct ACP continuation affinities.

Root cause (deployed Core, verified 2026-11-11): ``delegate_task`` children run
under ``agent.delegation_context.delegated_child_context(child_session_id)``,
which scopes ``HERMES_SESSION_ID`` to the child but leaves ``HERMES_SESSION_KEY``
as the parent's route key.  The plugin used ``key or id`` for its ACP affinity,
so every sibling in a fan-out shared one native continuation.

Fix contract under test:
  * inside a delegated-child execution the affinity is namespaced onto the
    child's own Core-scoped session id (sibling-unique, same-child-stable);
  * a delegated execution whose id is missing or provably inherited from the
    process (ContextVar id == os.environ HERMES_SESSION_ID, which Core never
    overwrites for children) is ambiguous and fails closed to the empty
    affinity: fresh native session, never a parent/sibling resume;
  * foreground, standalone, lane-fork and legacy (pre-delegation Core) routes
    keep their exact previous behaviour.

The fakes below are faithful ContextVar mirrors of the deployed modules
(``gateway.session_context.get_session_env`` / ``scoped_current_session_id``
and ``agent.delegation_context.delegated_child_context``); the real-Core
contract is pinned separately in test_upstream_hermes_runtime_contracts.py.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import importlib.util
import os
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

_UNSET = object()


class SessionFakes:
    """Faithful mirrors of the two deployed Hermes context modules."""

    def __init__(self) -> None:
        self.session_id_var: contextvars.ContextVar = contextvars.ContextVar(
            "HERMES_SESSION_ID", default=_UNSET
        )
        self.session_key_var: contextvars.ContextVar = contextvars.ContextVar(
            "HERMES_SESSION_KEY", default=_UNSET
        )
        self.delegated_var: contextvars.ContextVar = contextvars.ContextVar(
            "hermes_delegated_child_context", default=False
        )

    def get_session_env(self, name: str, default: str = "") -> str:
        var = {
            "HERMES_SESSION_ID": self.session_id_var,
            "HERMES_SESSION_KEY": self.session_key_var,
        }.get(name)
        if var is not None and (value := var.get()) is not _UNSET:
            return value
        return os.getenv(name, default)

    @contextlib.contextmanager
    def scoped_current_session_id(self, session_id: str | None = None):
        previous = self.session_id_var.get()
        if session_id is not None:
            self.session_id_var.set(session_id)
        try:
            yield
        finally:
            self.session_id_var.set(previous)

    @contextlib.contextmanager
    def bind_parent(self, session_id: str, session_key: str):
        token_id = self.session_id_var.set(session_id)
        token_key = self.session_key_var.set(session_key)
        try:
            yield
        finally:
            self.session_key_var.reset(token_key)
            self.session_id_var.reset(token_id)

    @contextlib.contextmanager
    def delegated_child_context(self, session_id: str | None = None):
        token = self.delegated_var.set(True)
        try:
            with self.scoped_current_session_id(session_id):
                yield
        finally:
            self.delegated_var.reset(token)

    def is_delegated_child_context(self) -> bool:
        return bool(self.delegated_var.get())


def install_hermes_session_fakes(monkeypatch) -> SessionFakes:
    fakes = SessionFakes()
    gateway_pkg = types.ModuleType("gateway")
    gateway_pkg.__path__ = []
    session_context = types.ModuleType("gateway.session_context")
    session_context.get_session_env = fakes.get_session_env
    session_context.scoped_current_session_id = fakes.scoped_current_session_id
    agent_pkg = types.ModuleType("agent")
    agent_pkg.__path__ = []
    delegation = types.ModuleType("agent.delegation_context")
    delegation.delegated_child_context = fakes.delegated_child_context
    delegation.is_delegated_child_context = fakes.is_delegated_child_context
    monkeypatch.setitem(sys.modules, "gateway", gateway_pkg)
    monkeypatch.setitem(sys.modules, "gateway.session_context", session_context)
    monkeypatch.setitem(sys.modules, "agent", agent_pkg)
    monkeypatch.setitem(sys.modules, "agent.delegation_context", delegation)
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    return fakes


def _load_plugin(monkeypatch, tmp_path: Path, module_name: str):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "acp-limits.json"),
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
    import importlib as _importlib

    client_module = _importlib.import_module(module_name + ".client")
    return module, client_module


def _client(module, tmp_path: Path):
    return module.antigravity_acp.create_client(
        command=sys.executable,
        args=["-c", "pass"],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )


MESSAGES = [{"role": "user", "content": "shared fan-out goal"}]


def _affinity(client_module, tmp_path: Path) -> str:
    return client_module._conversation_affinity(MESSAGES, str(tmp_path))


def test_client_instances_share_one_registry_so_instance_identity_is_unusable(
    monkeypatch, tmp_path
) -> None:
    """The user's first candidate — one client instance per child — is dead.

    The provider registers ONE profile per process and every client it builds
    shares the module-level ``conversation_registry`` singleton, so native
    continuation state is process-scoped, never instance-scoped.  Identity must
    therefore be resolved per call from the request context.
    """
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_instances")
    module_state = sys.modules["acp_issue2_instances" + ".conversation_state"]
    first = _client(sys.modules["acp_issue2_instances"], tmp_path)
    second = _client(sys.modules["acp_issue2_instances"], tmp_path)
    assert first is not second
    assert client_module.conversation_registry is module_state.conversation_registry


def test_one_shared_resolution_point_gives_parent_and_siblings_own_affinities(
    monkeypatch, tmp_path
) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_distinct")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        parent_first = _affinity(client_module, tmp_path)
        parent_second = _affinity(client_module, tmp_path)
        with fakes.delegated_child_context("child-row-a"):
            child_a = _affinity(client_module, tmp_path)
        with fakes.delegated_child_context("child-row-b"):
            child_b = _affinity(client_module, tmp_path)

    assert parent_first == parent_second, "foreground continuation must not split"
    assert len({parent_first, child_a, child_b}) == 3


def test_threaded_fanout_with_copy_context_keeps_every_sibling_distinct(
    monkeypatch, tmp_path
) -> None:
    """Mirrors delegate_tool_child_run: copy_context().run on a worker thread."""
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_fanout")

    results: dict[str, str] = {}
    barrier = threading.Barrier(3)

    def child(child_id: str) -> None:
        with fakes.delegated_child_context(child_id):
            barrier.wait()  # force genuine overlap
            results[child_id] = _affinity(client_module, tmp_path)

    with fakes.bind_parent("parent-row", "parent-route-key"):
        parent_affinity = _affinity(client_module, tmp_path)
        threads = [
            threading.Thread(
                target=contextvars.copy_context().run, args=(child, child_id)
            )
            for child_id in ("child-row-a", "child-row-b", "child-row-c")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert set(results) == {"child-row-a", "child-row-b", "child-row-c"}
    assert len(set(results.values()) | {parent_affinity}) == 4


def test_nested_grandchild_gets_its_own_affinity(monkeypatch, tmp_path) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_nested")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        parent_affinity = _affinity(client_module, tmp_path)
        with fakes.delegated_child_context("child-row-a"):
            child_affinity = _affinity(client_module, tmp_path)
            with fakes.delegated_child_context("grandchild-a1"):
                grandchild_affinity = _affinity(client_module, tmp_path)
            child_after = _affinity(client_module, tmp_path)

    assert child_after == child_affinity
    assert len({parent_affinity, child_affinity, grandchild_affinity}) == 3


def test_child_without_scoped_id_fails_closed_to_fresh_session(
    monkeypatch, tmp_path
) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_noid")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        parent_affinity = _affinity(client_module, tmp_path)
        with fakes.delegated_child_context(), fakes.scoped_current_session_id(""):
            assert _affinity(client_module, tmp_path) == ""
        assert _affinity(client_module, tmp_path) == parent_affinity


def test_child_inheriting_process_id_fails_closed_to_fresh_session(
    monkeypatch, tmp_path
) -> None:
    """Core never writes os.environ for children, so a ContextVar id equal to
    the process-pinned HERMES_SESSION_ID was never scoped: inherited."""
    fakes = install_hermes_session_fakes(monkeypatch)
    monkeypatch.setenv("HERMES_SESSION_ID", "parent-row")
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_inherit")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        parent_affinity = _affinity(client_module, tmp_path)
        with fakes.delegated_child_context():  # enters WITHOUT scoping an id
            assert _affinity(client_module, tmp_path) == ""
        assert _affinity(client_module, tmp_path) == parent_affinity


def test_foreground_affinity_formula_is_pinned(monkeypatch, tmp_path) -> None:
    """Foreground continuation must keep the exact v0.7.7 key material."""
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_foreground")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        affinity = _affinity(client_module, tmp_path)
    material = "hermes-session\0parent-route-key\0foreground"
    assert affinity == "sha256:" + hashlib.sha256(
        material.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def test_core_without_delegation_module_keeps_legacy_route(
    monkeypatch, tmp_path
) -> None:
    """Declared-floor compatibility: no agent.delegation_context -> v0.7.7 key."""
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_legacy")
    monkeypatch.delitem(sys.modules, "agent.delegation_context")

    with fakes.bind_parent("parent-row", "parent-route-key"):
        with fakes.delegated_child_context("child-row-a"):
            # marker module is gone; the plugin cannot know it is a child and
            # must keep the legacy route-key behaviour, not crash.
            assert _affinity(client_module, tmp_path) != ""


def test_broken_delegation_marker_raises_instead_of_guessing(
    monkeypatch, tmp_path
) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    _, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_broken")

    def broken() -> bool:
        raise RuntimeError("simulated marker lookup failure")

    sys.modules["agent.delegation_context"].is_delegated_child_context = broken
    with fakes.bind_parent("parent-row", "parent-route-key"):
        with pytest.raises(RuntimeError, match="delegated-child context"):
            _affinity(client_module, tmp_path)


# ---------------------------------------------------------------------------
# Client-level continuation behaviour with the prompt transport faked.
# ---------------------------------------------------------------------------


def _fake_run(client, calls: list) -> None:
    def run(prompt_text, **kwargs):
        child = ""
        marker = sys.modules.get("agent.delegation_context")
        if marker is not None and marker.is_delegated_child_context():
            child = str(getattr(run, "current_child", "") or "")
        resume = kwargs.get("resume_session_id") or ""
        calls.append((child, resume))
        session_id = resume or f"native-{child or 'foreground'}"
        kwargs["session_result"].update(
            session_id=session_id, resumed=bool(resume)
        )
        return f"answer-{child or 'foreground'}", ""

    client._run_prompt = run


def test_sibling_children_resume_their_own_native_sessions(
    monkeypatch, tmp_path
) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    module, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_resume")
    client = _client(module, tmp_path)
    calls: list[tuple[str, str]] = []
    _fake_run(client, calls)

    def child_turn(child_id: str, second: bool = False):
        run_fake = client._run_prompt
        run_fake.current_child = child_id
        with fakes.delegated_child_context(child_id):
            if not second:
                client.chat.completions.create(
                    model="gemini-test",
                    messages=[{"role": "user", "content": "shared fan-out goal"}],
                )
                return ""
            answer = f"answer-{child_id}"
            client.chat.completions.create(
                model="gemini-test",
                messages=[
                    {"role": "user", "content": "shared fan-out goal"},
                    {"role": "assistant", "content": answer},
                    {"role": "user", "content": "second request"},
                ],
            )
            return answer

    with fakes.bind_parent("parent-row", "parent-route-key"):
        child_turn("child-row-a")
        child_turn("child-row-b")
        # foreground parent turn must not collide with either child
        client.chat.completions.create(
            model="gemini-test",
            messages=[{"role": "user", "content": "shared fan-out goal"}],
        )
        child_turn("child-row-a", second=True)
        child_turn("child-row-b", second=True)

    assert calls == [
        ("child-row-a", ""),
        ("child-row-b", ""),
        ("", ""),
        ("child-row-a", "native-child-row-a"),
        ("child-row-b", "native-child-row-b"),
    ], "each child resumes only its own native session; parent stays separate"


def test_ambiguous_child_never_resumes_the_parents_session(
    monkeypatch, tmp_path
) -> None:
    fakes = install_hermes_session_fakes(monkeypatch)
    module, client_module = _load_plugin(monkeypatch, tmp_path, "acp_issue2_ambig")
    client = _client(module, tmp_path)
    calls: list[tuple[str, str]] = []
    _fake_run(client, calls)

    with fakes.bind_parent("parent-row", "parent-route-key"):
        # Parent establishes a native continuation.
        client.chat.completions.create(
            model="gemini-test",
            messages=[{"role": "user", "content": "shared fan-out goal"}],
        )
        parent_affinity = client_module._conversation_affinity(
            [{"role": "user", "content": "shared fan-out goal"}], str(tmp_path)
        )
        parent_state = client_module.conversation_registry.get(parent_affinity)
        assert parent_state is not None
        parent_session = parent_state.session_id

        # A delegated child with no trustworthy id gets a fresh native session.
        run_fake = client._run_prompt
        run_fake.current_child = ""
        with fakes.delegated_child_context(), fakes.scoped_current_session_id(""):
            client.chat.completions.create(
                model="gemini-test",
                messages=[{"role": "user", "content": "shared fan-out goal"}],
            )

        assert calls[-1] == ("", "")
        ambiguous_state = client_module.conversation_registry.get("")
        assert ambiguous_state is None, "ambiguous child must not checkpoint"
        assert (
            client_module.conversation_registry.get(parent_affinity).session_id
            == parent_session
        ), "the parent's continuation must be untouched"
