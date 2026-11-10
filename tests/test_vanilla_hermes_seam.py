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
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

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


def _load_real_plugin(monkeypatch, tmp_path):
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
    profile = providers.get_provider_profile("antigravity-acp")
    module = sys.modules.get(profile.__class__.__module__)
    assert module is not None
    module_path = getattr(module, "__file__", None)
    assert isinstance(module_path, str)
    assert Path(module_path).resolve() == (
        hermes_home / "plugins" / "model-providers" / "antigravity-acp" / "__init__.py"
    ).resolve()
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


def test_vanilla_upstream_create_client_seam_builds_standalone_client(monkeypatch, tmp_path) -> None:
    module, profile = _load_real_plugin(monkeypatch, tmp_path)
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

    assert profile is module.antigravity_acp
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
    # its compression import pulls in ``hermes_state_pidns``.  Both are
    # tracked files of the tested official checkout, and their file
    # provenance is asserted immediately after dispatch — before anything
    # else can touch ``sys.modules`` — never by module type.
    from agent.agent_runtime_helpers import create_openai_client

    run_agent_before = sys.modules.get("run_agent")
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
        reason="standalone-antigravity-test",
        shared=False,
    )
    if run_agent_before is None:
        assert sys.modules.get("run_agent") is not None, (
            "run_agent was absent from sys.modules before dispatch and is still "
            "absent after: create_openai_client never genuinely imported it"
        )
    _assert_genuine_core_provenance("run_agent", upstream_path)
    _assert_genuine_core_provenance("hermes_state_pidns", upstream_path)

    assert client.__class__.__name__ == "AntigravityACPClient"
    assert client.__class__.__module__.endswith(".client")
    assert callable(client.chat.completions.create)
    assert client.HERMES_SKIP_TRANSPORT_WRAP is True
    assert client.HERMES_SKIP_ASYNC_WRAP is True
    assert not any(base.__name__ == "CopilotACPClient" for base in client.__class__.__mro__)


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
