"""Compatibility test against the real, unmodified Hermes provider registry.

Hermes itself owns and tests the generic ``ProviderProfile.create_client()`` ->
``create_openai_client()`` dispatch path.  This file proves the Antigravity
plugin can register against vanilla Hermes and construct its standalone client
without importing the patched/forked Copilot ACP implementation.  The positive
dispatch is exercised with zero ``sys.modules`` substitution: the Core modules
the dispatch depends on must resolve to tracked files of the tested official
checkout (``_assert_genuine_core_provenance``).  Module substitution is
reserved for the negative oracle in this file and for the fault-injection
contracts in ``test_upstream_hermes_runtime_contracts.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from scripts.provider_origin import ProviderOrigin

PLUGIN_DIR = (
    Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
)

try:
    import providers
except Exception as exc:
    providers = None
    _PROVIDERS_IMPORT_ERROR = exc
else:
    _PROVIDERS_IMPORT_ERROR = None

pytestmark = pytest.mark.skipif(
    providers is None and os.environ.get("HERMES_STRICT_SEAM_TEST") != "1",
    reason="run under a Hermes checkout/test environment to exercise the real provider registry",
)


def _load_real_plugin(monkeypatch, tmp_path, provider_name: str = "antigravity-acp-replay"):
    if providers is None:
        pytest.fail(
            "strict Hermes seam validation requires importing the real providers package; "
            f"import failed: {_PROVIDERS_IMPORT_ERROR!r}",
            pytrace=False,
        )
    assert providers is not None
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    deploy_script = PLUGIN_DIR.parents[1] / "scripts" / "deploy_hermes_profiles.py"
    spec = importlib.util.spec_from_file_location("vanilla_seam_deployer", deploy_script)
    assert spec is not None and spec.loader is not None
    deployer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deployer)
    deployer.install(deployer.SOURCE, hermes_home, apply=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    installed = hermes_home / "plugins/model-providers/antigravity-acp"
    # Replay is created only under an explicit install-time declaration
    # (launch_config.json extra_providers); declare it when the test asks for
    # that provider, mirroring what an opt-in installer writes.
    if provider_name == "antigravity-acp-replay":
        (installed / "launch_config.json").write_text(
            json.dumps({"extra_providers": ["antigravity-acp-replay"]}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    core = Path(providers.__file__).resolve().parent.parent
    origin = ProviderOrigin(installed, hermes_home, core)
    with origin.observing():
        profile = providers.get_provider_profile(provider_name)
    module = sys.modules.get(profile.__class__.__module__)
    assert module is not None
    module_path = getattr(module, "__file__", None)
    assert isinstance(module_path, str)
    # The profile's defining module must be a tracked file of the installed
    # tree itself (or of a Core-staged frozen snapshot bound by the observer):
    # the Replay profile lives in the package ``__init__.py``, the Parked-MCP
    # profiles live under ``parked/``.  Core may serve the plugin from a
    # runtime snapshot root, so the in-tree relative path is derived from the
    # last occurrence of the installed directory name — never assumed, and
    # ``accepts`` re-verifies payload bytes against the installed tree.
    resolved_module = Path(module_path).resolve()
    parts = resolved_module.parts
    tree_name = installed.name
    if tree_name not in parts:
        pytest.fail(f"module path {resolved_module} is outside any {tree_name} tree")
    tree_index = len(parts) - 1 - parts[::-1].index(tree_name)
    relative = Path(*parts[tree_index + 1 :]).as_posix()
    assert relative, f"module path {resolved_module} is the tree root itself"
    assert origin.accepts(module_path, relative), "candidate/home/runtime provenance unverified"
    if "providers.plugin_reload" in sys.modules:
        _assert_genuine_core_provenance("providers.plugin_reload", core)
    return module, profile


def _assert_genuine_core_provenance(symbol: str, upstream_path: Path | None) -> None:
    """Assert ``sys.modules[symbol]`` is the tested official checkout's module.

    Provenance is resolved-file identity inside the official checkout, proven
    tracked at the tested commit by ``git ls-files`` — never module *type*:
    every real imported module is also a ``types.ModuleType`` instance, so
    type checks neither admit fakes nor reject genuine modules.  A hand-built
    module has no ``__file__`` and fails here.
    """
    core_module = sys.modules.get(symbol)
    assert core_module is not None, (
        f"{symbol!r} is absent from sys.modules: genuine dispatch never imported it"
    )
    module_file = getattr(core_module, "__file__", None)
    assert isinstance(module_file, str) and module_file, (
        f"sys.modules[{symbol!r}] has no __file__; it is a hand-built module "
        "object, not the official checkout's module"
    )
    resolved = Path(module_file).resolve()
    assert resolved.is_file(), f"sys.modules[{symbol!r}] __file__ {resolved} is not a real file"
    if upstream_path is not None:
        assert resolved.is_relative_to(upstream_path), (
            f"sys.modules[{symbol!r}] resolves to {resolved}, outside the tested "
            f"official checkout {upstream_path}: a substituted or overlay module is in play"
        )
        relative = resolved.relative_to(upstream_path)
        tracked = subprocess.run(
            ["git", "-C", str(upstream_path), "ls-files", "--error-unmatch", str(relative)],
            capture_output=True,
        )
        assert tracked.returncode == 0, (
            f"{relative} is not a tracked file at the tested official commit: "
            f"{tracked.stderr.decode(errors='replace').strip()}"
        )


def _state_provenance_symbol(upstream_path: Path | None) -> str:
    """Pick the Core-era name of the state module the compression import
    chain pulls in during genuine dispatch.

    ``hermes_state_pidns`` shipped through v0.23.1 (and the v0.21.6 floor);
    the v0.23.3 storage reorganisation replaced it with ``process_identity``
    (imported at module top level by ``agent.conversation_compression``).
    Require exactly one candidate to be unambiguous — tracked in the tested
    checkout, or (without a checkout binding) present in ``sys.modules`` —
    then let the caller's provenance assertion prove genuine import from
    the tested checkout.  Zero candidates names a stale pin; two candidates
    (a transitional checkout carrying both eras, or both modules in memory)
    is ambiguous and fails closed.  A fixed preference order is forbidden:
    tracked presence alone does not prove which module the dispatch
    imported, and validating the wrong witness would be a false pass.
    """
    candidates = ("process_identity", "hermes_state_pidns")
    if upstream_path is not None:
        unambiguous = [
            name for name in candidates
            if subprocess.run(
                ["git", "-C", str(upstream_path), "ls-files",
                 "--error-unmatch", f"{name}.py"],
                capture_output=True,
            ).returncode == 0
        ]
        scope = f"tracked in the tested Core checkout {upstream_path}"
    else:
        unambiguous = [name for name in candidates if name in sys.modules]
        scope = "present in sys.modules without a checkout binding"
    if len(unambiguous) != 1:
        pytest.fail(
            "provenance pin stale or ambiguous: expected exactly one of "
            + " / ".join(candidates)
            + f" to be {scope}, found {unambiguous or 'none'}",
            pytrace=False,
        )
    return unambiguous[0]


def test_vanilla_upstream_create_client_seam_builds_standalone_client(monkeypatch, tmp_path) -> None:
    # The Replay engine stays seam-proven under its explicit id: selecting it
    # must keep working byte-for-byte after 0.9.0 made Parked MCP the default.
    module, profile = _load_real_plugin(monkeypatch, tmp_path, "antigravity-acp-replay")
    assert providers is not None
    assert callable(providers.register_provider)

    upstream_dir = os.environ.get("UPSTREAM_HERMES_DIR")
    upstream_path = Path(upstream_dir).resolve() if upstream_dir else None
    if upstream_path is not None:
        remote = subprocess.check_output(
            ["git", "-C", str(upstream_path), "remote", "get-url", "origin"],
            text=True,
        ).strip()
        commit = subprocess.check_output(
            ["git", "-C", str(upstream_path), "rev-parse", "HEAD"], text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "-C", str(upstream_path), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        assert remote.rstrip("/").removesuffix(".git").lower() == (
            "https://github.com/nousresearch/hermes-agent"
        )
        assert os.environ.get("HERMES_TESTED_COMMIT") == commit
        assert os.environ.get("HERMES_TESTED_TREE") == tree
        assert Path(providers.__file__).resolve().is_relative_to(upstream_path)

    assert profile is module.antigravity_acp_replay
    assert isinstance(profile, module.ProviderProfile)
    direct_client = profile.create_client(
        api_key="antigravity-acp",
        base_url="acp://antigravity",
        command="antigravity-acp-official",
        args=[],
    )
    assert direct_client.__class__.__name__ == "AntigravityACPClient"
    assert callable(direct_client.chat.completions.create)
    assert not any(base.__name__ == "CopilotACPClient" for base in direct_client.__class__.__mro__)

    # Genuine Core dispatch with zero ``sys.modules`` substitution.  On this
    # path ``agent.agent_runtime_helpers`` reaches the shared logger through a
    # lazy ``run_agent`` import inside ``create_openai_client`` itself, and
    # its compression import pulls in the era's Core state module
    # (``hermes_state_pidns`` through v0.23.1, ``process_identity`` from
    # v0.23.3; see ``_state_provenance_symbol``).  Both are tracked files of
    # the tested official checkout, and their file provenance is asserted
    # immediately after dispatch — before anything else can touch
    # ``sys.modules`` — never by module type.
    from agent.agent_runtime_helpers import create_openai_client

    run_agent_before = sys.modules.get("run_agent")
    agent = SimpleNamespace(
        provider="antigravity-acp-replay",
        _client_log_context=lambda: "",
        _build_keepalive_http_client=lambda *args, **kwargs: None,
    )
    client = create_openai_client(
        agent,
        {
            "api_key": "antigravity-acp",
            "base_url": "acp://antigravity",
            "command": "antigravity-acp-official",
            "args": [],
        },
        reason="standalone-antigravity-test",
        shared=False,
    )
    if run_agent_before is None:
        assert sys.modules.get("run_agent") is not None, (
            "run_agent was absent from sys.modules before dispatch and is still "
            "absent after: create_openai_client never genuinely imported it"
        )
    _assert_genuine_core_provenance("run_agent", upstream_path)
    _assert_genuine_core_provenance(_state_provenance_symbol(upstream_path), upstream_path)

    assert client.__class__.__name__ == "AntigravityACPClient"
    assert client.__class__.__module__.endswith(".client")
    assert callable(client.chat.completions.create)
    assert client.HERMES_SKIP_TRANSPORT_WRAP is True
    assert client.HERMES_SKIP_ASYNC_WRAP is True
    assert not any(base.__name__ == "CopilotACPClient" for base in client.__class__.__mro__)


def test_vanilla_upstream_default_profile_seam_builds_parked_client(monkeypatch, tmp_path) -> None:
    """The DEFAULT public identity (``antigravity-acp``) resolves to the Parked-MCP
    engine and survives the same genuine Core dispatch as the Replay engine."""
    module, profile = _load_real_plugin(monkeypatch, tmp_path, "antigravity-acp")
    assert providers is not None
    assert profile is not None
    assert profile.name == "antigravity-acp"
    assert profile.__class__.__module__.endswith("parked._plugin_entry")
    assert isinstance(profile, module.ProviderProfile)
    # The compatibility id is an alias: it resolves to the same profile
    # instance, not to a separately-created provider.
    compat = providers.get_provider_profile("antigravity-acp-mcp")
    assert compat is profile

    direct_client = profile.create_client(
        api_key="antigravity-acp",
        base_url="acp://antigravity",
        command="antigravity-acp-official",
        args=[],
    )
    assert direct_client.__class__.__name__ == "AntigravityAcpMcpClient"
    assert callable(direct_client.chat.completions.create)
    assert not any(base.__name__ == "CopilotACPClient" for base in direct_client.__class__.__mro__)

    from agent.agent_runtime_helpers import create_openai_client

    agent = SimpleNamespace(
        provider="antigravity-acp",
        _client_log_context=lambda: "",
        _build_keepalive_http_client=lambda *args, **kwargs: None,
    )
    client = create_openai_client(
        agent,
        {
            "api_key": "antigravity-acp",
            "base_url": "acp://antigravity",
            "command": "antigravity-acp-official",
            "args": [],
        },
        reason="default-parked-mcp-test",
        shared=False,
    )
    assert client.__class__.__name__ == "AntigravityAcpMcpClient"
    assert client.__class__.__module__.endswith("parked.client")
    assert callable(client.chat.completions.create)
    assert client.HERMES_SKIP_TRANSPORT_WRAP is True
    assert client.HERMES_SKIP_ASYNC_WRAP is True


def test_core_provenance_oracle_rejects_substituted_core_modules(monkeypatch) -> None:
    """Negative contract, deliberately separate from the positive proof above:
    the provenance oracle must reject hand-built Core substitutes.

    ``types.ModuleType`` instantiation is exactly how the pre-rework seam
    substituted ``run_agent`` and ``hermes_state_pidns``.  Type identity
    proves nothing — every genuine imported module is also a
    ``types.ModuleType`` instance — so only resolved-file provenance
    separates a checkout module from a stand-in.  The substitutes below are
    injected on purpose and restored by ``monkeypatch``.
    """
    for symbol in ("run_agent", "hermes_state_pidns"):
        substitute = ModuleType(symbol)
        assert isinstance(substitute, ModuleType)  # type identity proves nothing
        monkeypatch.setitem(sys.modules, symbol, substitute)
        with pytest.raises(AssertionError, match="hand-built"):
            _assert_genuine_core_provenance(symbol, None)


@pytest.mark.parametrize(
    "tracked",
    [(), ("process_identity",), ("hermes_state_pidns",),
     ("process_identity", "hermes_state_pidns")],
)
def test_state_provenance_symbol_requires_exactly_one_tracked(tmp_path, tracked) -> None:
    """Zero tracked candidates is a stale pin; two (a transitional checkout
    carrying both eras) is ambiguous.  Both must fail closed — never a
    preference-ordered pick that could validate the wrong witness."""
    repo = tmp_path / "core"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for name in tracked:
        (repo / f"{name}.py").write_text("", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", f"{name}.py"], check=True)
    if len(tracked) == 1:
        assert _state_provenance_symbol(repo) == tracked[0]
    else:
        with pytest.raises(pytest.fail.Exception, match="exactly one"):
            _state_provenance_symbol(repo)


@pytest.mark.parametrize(
    "present",
    [(), ("process_identity",), ("hermes_state_pidns",),
     ("process_identity", "hermes_state_pidns")],
)
def test_state_provenance_symbol_requires_exactly_one_in_modules(monkeypatch, present) -> None:
    """Same unambiguous-witness rule for the no-checkout-binding fallback."""
    for name in ("process_identity", "hermes_state_pidns"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    for name in present:
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    if len(present) == 1:
        assert _state_provenance_symbol(None) == present[0]
    else:
        with pytest.raises(pytest.fail.Exception, match="exactly one"):
            _state_provenance_symbol(None)
