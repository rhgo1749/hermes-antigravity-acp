"""historical reference (Lane A): credential, approval, and unattended-execution isolation.

Every scenario below is credential-free: synthetic tmp homes, injected FAKE
environment values that are structurally secret-shaped but carry no meaning,
and hand-built ACP frames (no real ACP/model calls). The generalized invariant
under test: every ACP child-process launch, file-bridge operation, and
permission decision fail closed against credential inheritance, unapproved
mutation, and unattended blocking, regardless of runtime host.

Coverage map (historical reference criteria 2/4/5/7 boundary tests):
- child env: injected API_KEY/TOKEN/auth-class entries never reach the ACP
  child, and the locale/XDG admission is an explicit enumeration (no
  wildcard ``LC_``/``XDG_`` prefix) with XDG bases verified against the
  child's own profile home; the compat policy layer fails closed when the
  Hermes subprocess policy call fails while a Hermes runtime is loaded;
- fs/read_text_file: content returns only through Hermes redaction; read-block,
  NT-namespace, and vendor-credential denials raise before any content access;
  a missing or broken policy fails closed;
- fs/write_text_file: the bridge never writes without Hermes write approval and
  fails closed when the approval policy is unavailable;
- unattended (gateway/cron) permission requests: answered synchronously with a
  deny/cancel — never an allow, never a wait for a human;
- trusted coding mode: default-disabled; exact opt-in only; even when opted in,
  commands and paths outside the session cwd are refused.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import types
from pathlib import Path

import pytest
from test_standalone_client import _load

# Synthetic markers: secret-shaped for policy purposes, meaningless values.
# They intentionally never match audit_public_tree's credential patterns.
# The ``XDG_*``/``LC_*`` entries are the maintainer-P2 (historical reference)
# regression class: names the old wildcard prefix filter silently authorized.
FAKE_SECRET_MARKERS = {
    "OPENAI_API_KEY": "synthetic-openai-value-not-a-key",
    "ANTHROPIC_API_KEY": "synthetic-anthropic-value-not-a-key",
    "GEMINI_API_KEY": "synthetic-gemini-value-not-a-key",
    "GOOGLE_CLIENT_SECRET": "synthetic-google-client-value",
    "GOOGLE_OAUTH_TOKEN": "synthetic-google-oauth-value",
    "HERMES_AUTH_TOKEN": "synthetic-hermes-auth-value",
    "GH_TOKEN": "synthetic-forge-token-value",
    "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret-value",
    "UNLISTED_ACP_SECRET": "synthetic-unlisted-value",
    "XDG_ACCESS_TOKEN": "synthetic-xdg-access-value",
    "XDG_PRIVATE_KEY": "synthetic-xdg-private-value",
    "XDG_TOKEN": "synthetic-xdg-token-value",
    "LC_API_TOKEN": "synthetic-lc-api-value",
    "LC_SECRET": "synthetic-lc-secret-value",
}

# Credential-shaped names plus lower/mixed-case spellings (the Windows env
# block is case-insensitive, so casing must never be an admission path).
XDG_LC_CASE_VARIANTS = {
    "xdg_private_key": "synthetic-xdg-lowercase-value",
    "Lc_Api_Token": "synthetic-lc-mixedcase-value",
}

# The explicit enumeration the ACP child minimum contract must settle for.
ALLOWED_LOCALE_NAMES = (
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
)
ALLOWED_XDG_HOME_VARS = (
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
)
ALLOWED_WINDOWS_OS_VARS = (
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
)


def _assert_no_lc_xdg_wildcards(env):
    """Oracle: no LC_*/XDG_* key outside the explicit enumeration reaches the child."""
    admitted = set(ALLOWED_LOCALE_NAMES) | set(ALLOWED_XDG_HOME_VARS)
    return sorted(
        key
        for key in env
        if key.upper().startswith(("LC_", "XDG_")) and key.upper() not in admitted
    )


def _poison_parent_environment(monkeypatch, tmp_path):
    for key, value in FAKE_SECRET_MARKERS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HERMES_SESSION_ID", "synthetic-session-id")
    monkeypatch.setenv("HERMES_SESSION_KEY", "synthetic-session-key")
    monkeypatch.setenv("PATH", "/bin")
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))


def _clear_ambient_lc_xdg(monkeypatch):
    """Remove the developer host's own locale/XDG state so assertions are exact."""
    for key in list(os.environ):
        if key.upper().startswith(("LC_", "XDG_")):
            monkeypatch.delenv(key, raising=False)


def _stub_hermes_constants(monkeypatch, home: Path):
    constants = types.ModuleType("hermes_constants")
    setattr(constants, "get_hermes_home", lambda: home)
    setattr(constants, "apply_subprocess_home_env", lambda env: None)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)


def _stub_file_safety(
    monkeypatch,
    *,
    read_block=None,
    write_denied=None,
    needs_approval=None,
    redact=None,
    nt_error=None,
):
    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", nt_error or (lambda path, verb=None: None))
    setattr(file_safety, "get_read_block_error", read_block or (lambda path: None))
    setattr(
        file_safety,
        "get_write_denied_error",
        write_denied or (lambda path, **_kwargs: None),
    )
    setattr(
        file_safety,
        "is_write_approval_required",
        needs_approval or (lambda path: False),
    )
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact_module = types.ModuleType("agent.redact")
    setattr(redact_module, "redact_sensitive_text", redact or (lambda text, force=True: text))
    monkeypatch.setitem(sys.modules, "agent.redact", redact_module)


def _isolation(monkeypatch, tmp_path):
    """Load a fresh provider client with host policy pinned to synthetic tmp state."""
    _, client, module = _load(monkeypatch)
    compat = sys.modules[module.__package__ + ".hermes_compat"]
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    _stub_hermes_constants(monkeypatch, fake_home)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return client, module, compat, workspace


class FakeProcess:
    def __init__(self):
        self.stdin = io.StringIO()

    def responses(self):
        text = self.stdin.getvalue().strip()
        return [json.loads(line) for line in text.splitlines() if line]


def _permission_params(name, kind, raw_input, options, tool_call_id="call-1"):
    return {
        "toolCall": {
            "toolCallId": tool_call_id,
            "name": name,
            "kind": kind,
            "title": f"Running {name}",
            "rawInput": raw_input,
        },
        "options": options,
    }


_ALLOW_REJECT = [
    {"optionId": "always", "kind": "allow_always"},
    {"optionId": "once", "kind": "allow_once"},
    {"optionId": "deny", "kind": "reject_once"},
]


def _ask(client, params, cwd):
    process = FakeProcess()
    started = time.monotonic()
    handled = client._handle_server_message(
        {"jsonrpc": "2.0", "id": 7, "method": "session/request_permission", "params": params},
        process=process,
        cwd=cwd,
        text_parts=None,
        reasoning_parts=None,
    )
    elapsed = time.monotonic() - started
    assert handled
    return process.responses(), elapsed


# ---------------------------------------------------------------------------
# (1) Child-process environment isolation
# ---------------------------------------------------------------------------

def test_child_environment_purges_injected_secret_class_entries(monkeypatch, tmp_path):
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _poison_parent_environment(monkeypatch, tmp_path)
    # Select the documented local allowlist fallback (no Hermes host policy).
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: None)

    env = module._build_subprocess_env()

    leaked = sorted(
        key for key in FAKE_SECRET_MARKERS if key in env or env.get(key) == FAKE_SECRET_MARKERS[key]
    )
    assert leaked == []
    # Session identity is gateway-scoped parent state; the ACP child has no need
    # for it and the allowlist must not carry it across the process boundary.
    assert "HERMES_SESSION_ID" not in env
    assert "HERMES_SESSION_KEY" not in env
    # The allowlist still carries what a child legitimately needs.
    assert env["PATH"] == "/bin"
    assert env["HOME"]


# Real upstream ``hermes_subprocess_env(inherit_credentials=True)`` documents
# and (at the declared v0.21.6 compatibility floor through current upstream)
# empirically retains Tier-2 provider credentials for children that need them
# while Tier-1 bot/GitHub tokens are always stripped. This fixture models that
# REALISTIC successful policy output — deliberately NOT a pre-scrubbed mapping.
# The real unmodified upstream proof runs in tests/test_upstream_hermes_runtime_contracts.py
# inside both hosted upstream Hermes lanes (main and floor v0.21.6).
REALISTIC_UPSTREAM_POLICY_RESULT = {
    "PATH": "/policy/bin",
    "HOME": "/synthetic/policy-home",
    "USER": "synthetic-user",
    "SHELL": "/bin/sh",
    "LANG": "C.UTF-8",
    "TERM": "xterm-256color",
    "TMPDIR": "/synthetic/scratch",
    "GEMINI_HOME": "/synthetic/policy-home/.gemini",
    "SAFE_PROFILE_VALUE": "not-an-acp-child-need",
    "ACP_MUX_ACCOUNTS": "/synthetic/acp-accounts.json",
    "ACP_MUX_PAR": "/synthetic/agy_acp_server.par",
    "HERMES_SESSION_ID": "synthetic-session-id",
    "HERMES_SESSION_KEY": "synthetic-session-key",
}
REALISTIC_UPSTREAM_POLICY_RESULT.update(FAKE_SECRET_MARKERS)


def test_host_policy_success_is_narrowed_to_acp_child_minimum_contract(monkeypatch, tmp_path):
    """A successful host policy is the BASE, never the contract.

    Upstream ``hermes_subprocess_env(inherit_credentials=True)`` intentionally
    retains Tier-2 provider credentials; the ACP child must still receive zero
    provider/gateway secrets, zero ``ACP_MUX_*`` configuration, and zero session
    identity, while the legitimate runtime variables it actually needs survive.
    """
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _poison_parent_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("PATH", "/parent/bin")
    monkeypatch.setenv("ACP_MUX_TOKEN", "synthetic-mux-value")
    calls = []

    def host_policy(*, inherit_credentials):
        calls.append(inherit_credentials)
        return dict(REALISTIC_UPSTREAM_POLICY_RESULT)

    monkeypatch.setattr(
        module,
        "build_hermes_subprocess_env",
        lambda: host_policy(inherit_credentials=True),
    )
    env = module._build_subprocess_env()
    assert calls == [True], "the Hermes credential-aware policy must still be consulted"
    leaked = sorted(key for key in FAKE_SECRET_MARKERS if key in env)
    assert leaked == []
    assert not any(value in env.values() for value in FAKE_SECRET_MARKERS.values())
    assert not [key for key in env if key.startswith("ACP_MUX_")]
    assert "HERMES_SESSION_ID" not in env
    assert "HERMES_SESSION_KEY" not in env
    assert "SAFE_PROFILE_VALUE" not in env, (
        "the ACP child env is a minimum contract, not an arbitrary passthrough"
    )
    # The policy result remains the base for legitimate runtime keys (policy PATH
    # wins over the parent PATH), and the ACP-relevant homes/scratch survive.
    assert env["PATH"] == "/policy/bin"
    assert env["USER"] == "synthetic-user"
    assert env["SHELL"] == "/bin/sh"
    assert env["LANG"] == "C.UTF-8"
    assert env["TERM"] == "xterm-256color"
    assert env["TMPDIR"] == "/synthetic/scratch"
    assert env["GEMINI_HOME"] == "/synthetic/policy-home/.gemini"
    assert env["HOME"]
    assert env["HERMES_HOME"]


def _seed_lc_xdg_boundary_state(monkeypatch, tmp_path):
    """Seed the maintainer-P2 class: credential-shaped LC_*/XDG_* names, case
    variants, a current-profile XDG base (must survive), and a sibling-profile
    XDG base (must not cross into this child)."""
    fake_home = tmp_path / "home"
    current_profile_base = fake_home / ".config"
    sibling_profile_base = tmp_path / "sibling-profile" / ".cache"
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("LC_CTYPE", "C.UTF-8")
    monkeypatch.setenv("LC_ALL_BUT_UNLISTED", "unused")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(current_profile_base))
    monkeypatch.setenv("XDG_CACHE_HOME", str(sibling_profile_base))
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setenv("XDG_DATA_DIRS", "/etc/xdg")
    for name, value in XDG_LC_CASE_VARIANTS.items():
        monkeypatch.setenv(name, value)
    return current_profile_base, sibling_profile_base


def test_offline_fallback_rejects_arbitrary_lc_xdg_and_sibling_paths(monkeypatch, tmp_path):
    """No wildcard ``LC_``/``XDG_`` admission on the offline fallback base."""
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _clear_ambient_lc_xdg(monkeypatch)
    _poison_parent_environment(monkeypatch, tmp_path)
    current_base, sibling_base = _seed_lc_xdg_boundary_state(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: None)

    env = module._build_subprocess_env()

    assert _assert_no_lc_xdg_wildcards(env) == []
    leaked = sorted(key for key in FAKE_SECRET_MARKERS if key in env)
    assert leaked == []
    for name, value in XDG_LC_CASE_VARIANTS.items():
        assert name not in env
        assert value not in env.values()
    # The legitimate current-profile runtime survives untouched.
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["LC_CTYPE"] == "C.UTF-8"
    assert env["XDG_CONFIG_HOME"] == str(current_base)
    # A sibling profile's cache directory and non-permitted XDG state never cross.
    assert "XDG_CACHE_HOME" not in env
    assert str(sibling_base) not in env.values()
    assert "XDG_RUNTIME_DIR" not in env
    assert "XDG_DATA_DIRS" not in env


def test_host_policy_success_rejects_arbitrary_lc_xdg_and_sibling_paths(monkeypatch, tmp_path):
    """A successful host policy is a base: its LC/XDG entries face the same gate."""
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _clear_ambient_lc_xdg(monkeypatch)
    _poison_parent_environment(monkeypatch, tmp_path)
    current_base, sibling_base = _seed_lc_xdg_boundary_state(monkeypatch, tmp_path)
    policy_result = dict(REALISTIC_UPSTREAM_POLICY_RESULT)
    policy_result.update(
        {
            "LC_ALL": "C.UTF-8",
            "LC_PAPER": "de_DE",
            "XDG_CONFIG_HOME": str(current_base),
            "XDG_CACHE_HOME": str(sibling_base),
            "XDG_STATE_HOME": str(tmp_path / "sibling-profile" / ".local" / "state"),
        }
    )
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: policy_result)

    env = module._build_subprocess_env()

    assert _assert_no_lc_xdg_wildcards(env) == []
    leaked = sorted(key for key in FAKE_SECRET_MARKERS if key in env)
    assert leaked == []
    # Enumerated locale categories survive; unlisted categories do not.
    assert env["LC_ALL"] == "C.UTF-8"
    assert "LC_PAPER" not in env
    # Profile-scoped XDG base survives; sibling-profile bases are dropped so the
    # child falls back to XDG defaults under its own HOME.
    assert env["XDG_CONFIG_HOME"] == str(current_base)
    assert "XDG_CACHE_HOME" not in env
    assert "XDG_STATE_HOME" not in env
    assert str(sibling_base) not in env.values()


def test_child_env_admission_is_explicit_enumeration_without_wildcards(monkeypatch, tmp_path):
    """The completion oracle, stated directly: enumeration, never prefixes."""
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    assert not hasattr(module, "_ACP_CHILD_ENV_ALLOW_PREFIXES"), (
        "prefix-based admission is the maintainer-P2 defect; it silently "
        "authorizes arbitrary future LC_*/XDG_* names"
    )
    unapproved = (
        "XDG_ACCESS_TOKEN",
        "XDG_PRIVATE_KEY",
        "XDG_TOKEN",
        "XDG_SESSION_TYPE",
        "XDG_SESSION_CLASS",
        "XDG_CURRENT_DESKTOP",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_DIRS",
        "LC_API_TOKEN",
        "LC_SECRET",
        "LC_PAPER",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_NAME",
        "LC_ADDRESS",
        "LC_TELEPHONE",
        "xdg_private_key",
        "Lc_Api_Token",
    )
    for name in unapproved:
        assert module._is_acp_child_env_key(name) is False, name
    for name in ALLOWED_LOCALE_NAMES + ALLOWED_XDG_HOME_VARS + ALLOWED_WINDOWS_OS_VARS:
        assert module._is_acp_child_env_key(name) is True, name
        assert module._is_acp_child_env_key(name.lower()) is True, name
    narrowed = module._acp_child_env_filter(
        {
            "PATH": "/bin",
            "XDG_ACCESS_TOKEN": "synthetic-xdg-access-value",
            "LC_API_TOKEN": "synthetic-lc-api-value",
            "xdg_private_key": "synthetic-xdg-lowercase-value",
        }
    )
    assert set(narrowed) == {"PATH"}


def test_allowed_xdg_bases_are_verified_against_the_child_profile(monkeypatch, tmp_path):
    """Approved XDG key names still require a path under the child's own home."""
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _clear_ambient_lc_xdg(monkeypatch)
    _poison_parent_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: None)
    fake_home = tmp_path / "home"

    # Current-profile runtime positive control.
    monkeypatch.setenv("XDG_DATA_HOME", str(fake_home / ".local" / "share"))
    # Sibling-profile negative control (approved key name, foreign path).
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "sibling-profile" / ".config"))
    env = module._build_subprocess_env()
    assert env["XDG_DATA_HOME"] == str(fake_home / ".local" / "share")
    assert "XDG_CONFIG_HOME" not in env
    assert str(tmp_path / "sibling-profile" / ".config") not in env.values()

    # Relative or parent-escaping spellings must not smuggle a foreign path.
    monkeypatch.setenv("XDG_CACHE_HOME", "../sibling-profile/.cache")
    monkeypatch.setenv("XDG_STATE_HOME", str(fake_home / ".cache" / ".." / ".."))
    env = module._build_subprocess_env()
    assert "XDG_CACHE_HOME" not in env
    assert "XDG_STATE_HOME" not in env


def test_enumerated_locale_and_xdg_surface_is_the_exact_minimum(monkeypatch, tmp_path):
    """The minimum contract keeps exactly the documented locale/XDG surface."""
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _clear_ambient_lc_xdg(monkeypatch)
    _poison_parent_environment(monkeypatch, tmp_path)
    fake_home = tmp_path / "home"
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: None)
    for name in ALLOWED_LOCALE_NAMES:
        monkeypatch.setenv(name, "C.UTF-8")
    for index, name in enumerate(ALLOWED_XDG_HOME_VARS):
        monkeypatch.setenv(name, str(fake_home / f".xdg{index}"))

    env = module._build_subprocess_env()

    for name in ALLOWED_LOCALE_NAMES:
        assert env[name] == "C.UTF-8"
    for index, name in enumerate(ALLOWED_XDG_HOME_VARS):
        assert env[name] == str(fake_home / f".xdg{index}")
    lc_xdg_keys = sorted(key.upper() for key in env if key.upper().startswith(("LC_", "XDG_")))
    assert lc_xdg_keys == sorted(set(ALLOWED_LOCALE_NAMES) | set(ALLOWED_XDG_HOME_VARS))


def test_offline_fallback_purges_acp_mux_configuration(monkeypatch, tmp_path):
    """The no-host-policy fallback must not forward arbitrary ``ACP_MUX_*`` keys.

    ``_spawn`` supplies the multiplexor coordination keys it owns itself; the
    public default child env must never inherit operator ``ACP_MUX_*``
    configuration (or any other arbitrary key) from the parent environment.
    """
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    _poison_parent_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "build_hermes_subprocess_env", lambda: None)
    monkeypatch.setenv("USER", "synthetic-user")
    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setenv("TEMP", "/synthetic/temp")
    monkeypatch.setenv("GEMINI_HOME", str(tmp_path / "gemini-home"))
    monkeypatch.setenv("ACP_MUX_ACCOUNTS", "/synthetic/acp-accounts.json")
    monkeypatch.setenv("ACP_MUX_PAR", "/synthetic/agy_acp_server.par")
    monkeypatch.setenv("ACP_MUX_TOKEN", "synthetic-mux-value")

    env = module._build_subprocess_env()

    assert not [key for key in env if key.startswith("ACP_MUX_")]
    assert not any(
        value in env.values()
        for value in ("/synthetic/acp-accounts.json", "/synthetic/agy_acp_server.par", "synthetic-mux-value")
    )
    leaked = sorted(key for key in FAKE_SECRET_MARKERS if key in env)
    assert leaked == []
    # The documented legitimate runtime set survives untouched.
    assert env["PATH"] == "/bin"
    assert env["USER"] == "synthetic-user"
    assert env["SHELL"] == "/bin/sh"
    assert env["TEMP"] == "/synthetic/temp"
    assert env["GEMINI_HOME"] == str(tmp_path / "gemini-home")
    assert env["HOME"]
    assert env["HERMES_HOME"]


_FAKE_ACP_CHILD_ENV_TEMPLATE = r'''
import json
import os
import sys

with open(__DUMP_PATH__, "w", encoding="utf-8") as dump:
    json.dump(dict(os.environ), dump)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        emit = {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": 1}}
    elif method == "session/new":
        emit = {"jsonrpc": "2.0", "id": request_id,
                "result": {"sessionId": "child-env-session"}}
    elif method == "session/prompt":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "session/update",
            "params": {"update": {"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": "acp-child-alive"}}}}) + "\n")
        sys.stdout.flush()
        emit = {"jsonrpc": "2.0", "id": request_id, "result": {"stopReason": "end_turn"}}
    else:
        continue
    sys.stdout.write(json.dumps(emit) + "\n")
    sys.stdout.flush()
'''


def test_fake_acp_initialize_session_survives_filtered_child_env(monkeypatch, tmp_path):
    """A credential-free fake ACP still completes initialize/session after filtering.

    The child dumps its own environment back over a side channel so the test
    asserts what the REAL subprocess received, not just what the builder
    returned: zero inherited ``ACP_MUX_*`` configuration, zero provider
    secrets, zero unlisted ``LC_*``/``XDG_*`` names, and a working
    ``PATH``/``HOME``/enumerated locale-and-XDG minimum.
    """
    module, _, client_module = _load(monkeypatch)
    _clear_ambient_lc_xdg(monkeypatch)
    _poison_parent_environment(monkeypatch, tmp_path)
    current_base, sibling_base = _seed_lc_xdg_boundary_state(monkeypatch, tmp_path)
    monkeypatch.setattr(client_module, "build_hermes_subprocess_env", lambda: None)
    monkeypatch.setenv("ACP_MUX_ACCOUNTS", "/synthetic/acp-accounts.json")
    monkeypatch.setenv("ACP_MUX_TOKEN", "synthetic-mux-value")
    dump_path = tmp_path / "child-env.json"
    script = tmp_path / "fake_acp_child_env.py"
    script.write_text(
        _FAKE_ACP_CHILD_ENV_TEMPLATE.replace("__DUMP_PATH__", repr(str(dump_path))),
        encoding="utf-8",
    )
    client = client_module.AntigravityACPClient(
        command=sys.executable,
        args=[str(script)],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )

    reply = client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": "ping"}],
        timeout=30,
    )
    assert reply.choices[0].message.content == "acp-child-alive"

    child_env = json.loads(dump_path.read_text(encoding="utf-8"))
    child_keys = set(child_env)
    for inherited in ("ACP_MUX_ACCOUNTS", "ACP_MUX_TOKEN"):
        assert inherited not in child_keys, f"{inherited} crossed into the ACP child"
    leaked = sorted(key for key in FAKE_SECRET_MARKERS if key in child_keys)
    assert leaked == []
    assert "HERMES_SESSION_KEY" not in child_keys
    assert "PATH" in child_keys
    assert "HOME" in child_keys
    # The maintainer-P2 class, observed in the REAL child: no wildcard-name
    # locale/XDG entries, no sibling-profile paths; the enumerated minimum,
    # including a current-profile XDG base and locale, is present.
    assert _assert_no_lc_xdg_wildcards(child_env) == []
    assert "XDG_CONFIG_HOME" in child_keys
    assert child_env["XDG_CONFIG_HOME"] == str(current_base)
    assert child_env["LC_ALL"] == "C.UTF-8"
    assert str(sibling_base) not in child_env.values()
    assert "/run/user/1000" not in child_env.values()


def test_subprocess_policy_failure_fails_closed_under_hermes_runtime(monkeypatch, tmp_path):
    _, _, compat, _ = _isolation(monkeypatch, tmp_path)

    def exploding_policy(*, inherit_credentials):
        raise RuntimeError("simulated host policy explosion")

    tools_package = types.ModuleType("tools")
    tools_package.__path__ = []
    environments_package = types.ModuleType("tools.environments")
    environments_package.__path__ = []
    local_module = types.ModuleType("tools.environments.local")
    setattr(local_module, "hermes_subprocess_env", exploding_policy)
    fake_agent = types.ModuleType("agent")
    fake_agent.__path__ = []
    monkeypatch.setitem(sys.modules, "tools", tools_package)
    monkeypatch.setitem(sys.modules, "tools.environments", environments_package)
    monkeypatch.setitem(sys.modules, "tools.environments.local", local_module)
    monkeypatch.setitem(sys.modules, "agent", fake_agent)

    with pytest.raises(RuntimeError, match="refusing to start the ACP child"):
        compat.build_hermes_subprocess_env()


def test_subprocess_policy_absent_offline_selects_allowlist_fallback(monkeypatch, tmp_path):
    _, _, compat, _ = _isolation(monkeypatch, tmp_path)
    monkeypatch.setitem(sys.modules, "tools.environments.local", None)
    assert compat.build_hermes_subprocess_env() is None


# ---------------------------------------------------------------------------
# (2) fs/read_text_file: redaction, denial, fail-closed policy absence
# ---------------------------------------------------------------------------

def test_fs_read_redacts_secret_material_before_return(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)
    secret = "synthetic-token-marker-8842"

    def redactor(text, force=True):
        assert force is True
        return text.replace(secret, "[REDACTED]")

    _stub_file_safety(monkeypatch, redact=redactor)
    note = workspace / "config_dump.txt"
    note.write_text(f"header\nkey={secret}\nfooter\n", encoding="utf-8")

    result = module._fs_read_text_file({"path": str(note)}, str(workspace))
    assert "[REDACTED]" in result["content"]
    assert secret not in result["content"]


def test_fs_read_denies_blocked_namespaced_and_vendor_credential_paths(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)

    def read_block(path):
        return "Hermes read-block policy denies this path" if "forbidden" in path else None

    def nt_error(path, verb=None):
        return "NT namespace paths are not permitted" if "hardlink" in path else None

    _stub_file_safety(monkeypatch, read_block=read_block, nt_error=nt_error)

    forbidden = workspace / "forbidden.txt"
    forbidden.write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError, match="read-block policy"):
        module._fs_read_text_file({"path": str(forbidden)}, str(workspace))

    hardlink = workspace / "hardlink.txt"
    hardlink.write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError, match="NT namespace"):
        module._fs_read_text_file({"path": str(hardlink)}, str(workspace))

    vendor = workspace / ".gemini" / "antigravity" / "credentials.json"
    vendor.parent.mkdir(parents=True, exist_ok=True)
    vendor.write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="credential/config"):
        module._fs_read_text_file({"path": str(vendor)}, str(workspace))

    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError, match="outside the permitted"):
        module._fs_read_text_file({"path": str(outside)}, str(workspace))


def test_fs_read_fails_closed_when_policy_is_missing_or_broken(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)
    note = workspace / "note.txt"
    note.write_text("content", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "agent.file_safety", None)
    with pytest.raises(PermissionError, match="file-read safety policy is unavailable"):
        module._fs_read_text_file({"path": str(note)}, str(workspace))

    def exploding_block(path):
        raise RuntimeError("simulated policy crash")

    _stub_file_safety(monkeypatch, read_block=exploding_block)
    with pytest.raises(PermissionError, match="read-block policy failed"):
        module._fs_read_text_file({"path": str(note)}, str(workspace))

    _stub_file_safety(
        monkeypatch,
        redact=lambda text, force=True: (_ for _ in ()).throw(RuntimeError("redactor crash")),
    )
    with pytest.raises(PermissionError, match="redaction policy failed"):
        module._fs_read_text_file({"path": str(note)}, str(workspace))


# ---------------------------------------------------------------------------
# (3) fs/write_text_file: approval gate and fail-closed policy absence
# ---------------------------------------------------------------------------

def test_fs_write_denied_without_hermes_write_approval(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch, needs_approval=lambda path: True)

    target = workspace / "proposal.py"
    with pytest.raises(PermissionError, match="requires interactive approval"):
        module._fs_write_text_file({"path": str(target), "content": "x = 1\n"}, str(workspace))
    assert not target.exists()

    _stub_file_safety(
        monkeypatch, write_denied=lambda path, **kw: f"denied by policy: {Path(path).name}"
    )
    with pytest.raises(PermissionError, match="denied by policy"):
        module._fs_write_text_file({"path": str(target), "content": "x = 1\n"}, str(workspace))
    assert not target.exists()


def test_fs_write_fails_closed_when_policy_is_missing_or_broken(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)
    target = workspace / "target.py"

    monkeypatch.setitem(sys.modules, "agent.file_safety", None)
    with pytest.raises(PermissionError, match="file-write safety policy is unavailable"):
        module._fs_write_text_file({"path": str(target), "content": "x = 1\n"}, str(workspace))
    assert not target.exists()


def test_fs_write_fails_closed_when_approval_policy_raises(monkeypatch, tmp_path):
    _, module, _, workspace = _isolation(monkeypatch, tmp_path)

    def exploding_approval(path):
        raise RuntimeError("simulated approval policy crash")

    _stub_file_safety(monkeypatch, needs_approval=exploding_approval)
    target = workspace / "target.py"
    with pytest.raises(PermissionError, match="file-write safety policy failed"):
        module._fs_write_text_file({"path": str(target), "content": "x = 1\n"}, str(workspace))
    assert not target.exists()


# ---------------------------------------------------------------------------
# (4) Unattended (gateway/cron) permission decisions never hang or allow
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("name", "kind", "raw_input"),
    [
        ("run_command", "execute", {"CommandLine": "pytest -q", "Cwd": "/tmp"}),
        ("client_edit_file", "edit", {"absolute_path": "/etc/cron.d/evil"}),
        ("client_create_file", "edit", {"absolute_path": "/home/victim/.ssh/config"}),
        ("mcp__unknown__send_email", "other", {"to": "someone"}),
    ],
    ids=["named-run", "named-edit", "named-create", "unknown-or-mcp"],
)
def test_unattended_mutation_permission_is_denied_immediately(
    monkeypatch, tmp_path, name, kind, raw_input
):
    client, _, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch)
    assert client._trusted_coding is True

    responses, elapsed = _ask(
        client,
        _permission_params(name, kind, raw_input, _ALLOW_REJECT, tool_call_id=f"call-{name}"),
        str(workspace),
    )
    assert len(responses) == 1, "the harness must answer exactly once, synchronously"
    outcome = responses[0]["result"]["outcome"]
    assert outcome["outcome"] == "selected"
    assert outcome["optionId"] == "deny", f"{name} must be routed to the offered reject option"
    assert elapsed < 5.0, "an unattended permission decision must never wait for a human"


def test_unattended_permission_without_reject_option_fails_closed_cancelled(
    monkeypatch, tmp_path
):
    client, _, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch)

    responses, elapsed = _ask(
        client,
        _permission_params(
            "mcp__unknown__run_command",
            "execute",
            {"CommandLine": "ls", "Cwd": str(workspace)},
            [{"optionId": "always", "kind": "allow_always"}],
        ),
        str(workspace),
    )
    assert len(responses) == 1
    outcome = responses[0]["result"]["outcome"]
    assert outcome["outcome"] == "cancelled"
    assert "optionId" not in outcome
    assert elapsed < 5.0


def test_default_permission_allows_in_workspace_edit(monkeypatch, tmp_path):
    """A vetted workspace edit is auto-allowed but not executed by the permission handler."""
    client, _, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch)
    inside = workspace / "notes.txt"
    inside.write_text("hi", encoding="utf-8")

    responses, _ = _ask(
        client,
        _permission_params(
            "client_edit_file",
            "edit",
            {"absolute_path": str(inside)},
            _ALLOW_REJECT,
        ),
        str(workspace),
    )
    outcome = responses[0]["result"]["outcome"]
    assert outcome["optionId"] == "always"
    assert inside.read_text(encoding="utf-8") == "hi"


# ---------------------------------------------------------------------------
# (5) Trusted coding mode: default-off, exact opt-in, bounded to session cwd
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode_value", ["", "trusted", "trusted_coding", "codex", "TRUSTED-X"])
def test_native_coding_is_default_regardless_of_legacy_mode(monkeypatch, tmp_path, mode_value):
    if mode_value:
        monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", mode_value)
    else:
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", raising=False)
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    assert module._trusted_coding_mode_enabled() is True
    assert client._trusted_coding is True


def test_trusted_coding_requires_explicit_opt_in_and_becomes_active(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "trusted-coding")
    client, module, _, _ = _isolation(monkeypatch, tmp_path)
    assert module._trusted_coding_mode_enabled() is True
    assert client._trusted_coding is True


@pytest.mark.parametrize(
    ("kind", "raw_input", "content", "label"),
    [
        ("edit", {"absolute_path": "/etc/hosts"}, "diff", "named-edit-outside"),
        ("edit", {"absolute_path": str(Path("/etc/cron.d/evil"))}, "diff", "named-edit-cron"),
        ("execute", {"CommandLine": "pytest -q", "Cwd": "/"}, None, "nameless-run-outside-cwd"),
    ],
    ids=lambda value: str(value)[:24],
)
def test_trusted_mode_refuses_out_of_workspace_frames(monkeypatch, tmp_path, kind, raw_input, content, label):
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "trusted-coding")
    client, _, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch)
    assert client._trusted_coding is True

    params = _permission_params("", kind, raw_input, _ALLOW_REJECT, tool_call_id=f"call-{label}")
    if kind == "edit":
        params["toolCall"]["content"] = [
            {"type": "diff", "path": raw_input.get("absolute_path"), "_meta": {"kind": "modify"}}
        ]
    responses, _ = _ask(client, params, str(workspace))
    outcome = responses[0]["result"]["outcome"]
    assert outcome["outcome"] == "selected"
    assert outcome["optionId"] == "deny", f"trusted mode must refuse out-of-workspace frame: {label}"


def test_trusted_mode_positive_control_allows_in_workspace_edit(monkeypatch, tmp_path):
    """Proves the refusals above are the workspace boundary, not a broken test rig."""
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "trusted-coding")
    client, _, _, workspace = _isolation(monkeypatch, tmp_path)
    _stub_file_safety(monkeypatch)
    inside = workspace / "src" / "module.py"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_text("x = 1\n", encoding="utf-8")

    params = _permission_params(
        "client_edit_file",
        "edit",
        {"absolute_path": str(inside)},
        _ALLOW_REJECT,
    )
    responses, _ = _ask(client, params, str(workspace))
    outcome = responses[0]["result"]["outcome"]
    assert outcome["outcome"] == "selected"
    assert outcome["optionId"] == "always"
