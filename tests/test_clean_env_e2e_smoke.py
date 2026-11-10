"""historical reference: credential-free clean-environment install/diagnostic E2E smoke.

A fresh user with an EMPTY ``HERMES_HOME`` and no Docker, no profile-mux,
no account-mux, no custom Hermes Core patches, and no ``/quota`` skill
completes the whole lifecycle here — install (Path A catalog provider bytes,
Path B official server, and the combined standalone script), status, verify,
provider registration + model listing, delete, and reinstall preserving the
reviewed publisher SHA. Every "official server" is a fake ACP subprocess
built from fixture bytes; the registry pin is patched to the fixture digest.
No test here downloads anything, touches a credential, authenticates, or
calls a real model.

Evidence-class separation (historical reference criterion — never conflated; see
docs/clean-env-e2e-smoke.md for the delivery-time record):

  class (a) auth success               — never attempted here; NO-GO
  class (b) ACP initialize handshake   — fake-ACP log rows with ``initialize``
  class (c) model list discovery       — fake-ACP rows with ``session/new``
                                         plus a non-empty model payload
  class (d) real model inference canary — empty in every log; a fake-ACP
                                         ``session/prompt`` is protocol
                                         SIMULATION only and is bucketed as
                                         ``simulated_turn``, never class (d)

RED regression semantics: the lifecycle assertions below fail (go RED) if any
install/status/verify/listing step opens a credential-shaped file, forwards a
credential-shaped environment variable to the provider child, issues an
``authenticate``/login/prompt method on the ACP wire, emits an unsafe
(token-bearing or inactionable) failure diagnostic, or conflates the four
evidence classes above.
"""
from __future__ import annotations

import builtins
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import types
import uuid
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PLUGIN_SOURCE = ROOT / "hermes-plugin" / "antigravity-acp"

# Methods that would prove a step attempted vendor authentication.
_AUTH_METHOD_MARKERS = ("auth", "login", "oauth", "signin", "token")

# Path fragments that prove a step read vendor credential state.
_CREDENTIAL_PATH_RE = re.compile(
    r"(?i)(gcloud|oauth|credential|refresh_token|access_token|id_token|"
    r"accounts\.google|api[-_]?key|\.env)"
)

# Model ids the fake server advertises through the session/new model option.
_FAKE_MODELS = (
    "gemini-3.8-flash-high",
    "gemini-3.8-flash-medium",
    "gemini-3.1-pro-low",
)

# Synthetic, obviously-fake secret material. Never long enough to resemble a
# real token and never a real vendor URL; exists only to prove redaction.
_SYNTHETIC_SECRET = "SYNTHETIC_NOT_A_REAL_TOKEN"


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Fake official-server archive bodies (installed .par contents)
# --------------------------------------------------------------------------

_OK_SERVER_BODY = r'''
import json
import os
import sys

LOG = r"%(log)s"

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(payload):
    if LOG:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method = msg.get("method")
    row = {
        "method": method,
        "env_google_token": "GOOGLE_ACCESS_TOKEN" in os.environ,
        "env_hermes_home": os.environ.get("HERMES_HOME", ""),
    }
    log(row)
    rid = msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "fake-official-acp", "version": "clean-env-smoke"},
            "authMethods": [],
            "agentCapabilities": {},
        }})
    elif method == "session/new":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": "clean-env-session",
            "models": {
                "currentModelId": MODELS[0],
                "availableModels": [{"modelId": m} for m in MODELS],
            },
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": MODELS[0],
                "options": [{"value": m} for m in MODELS],
            }],
        }})
    elif method in ("session/set_config_option", "session/set_model", "session/resume"):
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "session/prompt":
        # Protocol SIMULATION only (evidence bucket ``simulated_turn``), never
        # a real model inference.
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "session/update",
            "params": {"update": {"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": "ok-clean-env-smoke"}}}}) + "\n")
        sys.stdout.flush()
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
    else:
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
'''

# Simulates a server stuck on its login surface: it advertises a
# credential-shaped line on stderr, never answers ``initialize``, and exits.
_AUTH_WAIT_SERVER_BODY = r'''
import sys

sys.stderr.write(
    "login required; access_token=%(secret)s\n"
    "waiting for headless authentication on https://accounts.google.com/o/oauth2/device-auth\n"
)
sys.stderr.flush()
for line in sys.stdin:
    break
sys.exit(3)
'''


def _archive_bytes(body: str, executable_name: str = "agy_acp_server.par") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo(executable_name, date_time=(2026, 1, 1, 0, 0, 0))
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, body)
    return buffer.getvalue()


def _server_log_rows(log_path: Path) -> list[dict]:
    if not log_path.is_file():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


def _methods(rows: list[dict]) -> list[str]:
    return [str(row.get("method") or "") for row in rows]


def _auth_attempts(rows: list[dict]) -> list[str]:
    return [
        method
        for method in _methods(rows)
        if any(marker in method.lower() for marker in _AUTH_METHOD_MARKERS)
    ]


# --------------------------------------------------------------------------
# Credential-file tripwire (RED if any lifecycle step reads credential state)
# --------------------------------------------------------------------------


class _CredentialTripwire:
    """Records every in-process file open; violations() lists credential-shaped ones."""

    def __init__(self) -> None:
        self.opened: list[str] = []

    def install(self, monkeypatch) -> None:
        real_open = builtins.open
        real_os_open = os.open
        opened = self.opened

        def spy_open(file, *args, **kwargs):
            try:
                opened.append(os.fspath(file))
            except TypeError:
                opened.append(str(file))
            return real_open(file, *args, **kwargs)

        def spy_os_open(path, *args, **kwargs):
            try:
                opened.append(os.fspath(path))
            except TypeError:
                opened.append(str(path))
            return real_os_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", spy_open)
        monkeypatch.setattr(os, "open", spy_os_open)

    def violations(self) -> list[str]:
        return sorted({p for p in self.opened if _CREDENTIAL_PATH_RE.search(p)})


def _seed_decoy_credentials(home: Path) -> dict[Path, bytes]:
    decoys = {
        home / ".env": b"GOOGLE_ACCESS_TOKEN=decoy-not-a-real-token\n",
        home / ".config" / "gcloud" / "credentials": b'{"decoy": "gcloud state"}\n',
        home / "credentials.json": b'{"decoy": "oauth state"}\n',
    }
    for path, content in decoys.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return decoys


# --------------------------------------------------------------------------
# Harness: a fresh user, empty HERMES_HOME, fake publisher feed
# --------------------------------------------------------------------------


class _CleanEnv:
    """One fresh-user environment with a fake-pinned official server feed."""

    def __init__(self, tmp_path: Path, monkeypatch, *, body: str = "ok", name: str = ""):
        tag = name or uuid.uuid4().hex[:8]
        monkeypatch.setenv("HOME", str(tmp_path))
        if os.name == "nt":
            monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_COMMAND", raising=False)
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_ARGS", raising=False)
        monkeypatch.delenv("GOOGLE_ACCESS_TOKEN", raising=False)

        self.tmp = tmp_path
        self.home = tmp_path / "hermes-home"  # deliberately NOT created: empty env
        self.prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
        self.bin_dir = tmp_path / ".local" / "bin"
        self.log = tmp_path / f"fake-acp-{tag}.jsonl"

        if body == "ok":
            archive_body = (
                "#!/usr/bin/env python3\n"
                f"MODELS = {_FAKE_MODELS!r}\n"
                + _OK_SERVER_BODY % {"log": str(self.log)}
            )
        elif body == "auth-wait":
            archive_body = (
                "#!/usr/bin/env python3\n" + _AUTH_WAIT_SERVER_BODY % {"secret": _SYNTHETIC_SECRET}
            )
        else:  # pragma: no cover - guard against test typos
            raise AssertionError(f"unknown fake server body {body!r}")

        self.archive = _archive_bytes(archive_body)
        self.sha256 = hashlib.sha256(self.archive).hexdigest()
        # The installed .par is the extracted archive member, not the archive.
        self.executable_sha256 = hashlib.sha256(archive_body.encode("utf-8")).hexdigest()

        self.installer = _load_script(
            SCRIPTS / "install_acp.py", f"clean_env_smoke_installer_{tag}"
        )
        self.downloads: list[str] = []

        def fake_urlretrieve(url: str, filename: str):
            self.downloads.append(url)
            Path(filename).write_bytes(self.archive)
            return filename, {"Content-Length": str(len(self.archive))}

        monkeypatch.setattr(
            self.installer.official_installer.urllib.request, "urlretrieve", fake_urlretrieve
        )
        pinned = self.installer.official_installer.resolve_distribution()
        monkeypatch.setattr(
            self.installer.official_installer,
            "resolve_distribution",
            lambda *_args, **_kwargs: dataclasses.replace(pinned, sha256=self.sha256),
        )

    # CLI-shaped paths mirror the README quick start exactly.
    def args(self, action: str, *extra: str) -> list[str]:
        return [
            action,
            "--hermes-home", str(self.home),
            "--prefix", str(self.prefix),
            "--bin-dir", str(self.bin_dir),
            *extra,
        ]

    def install(self) -> int:
        return self.installer.main(self.args("install"))

    def status(self) -> int:
        return self.installer.main(self.args("status"))

    def verify(self, timeout: str = "5") -> int:
        return self.installer.main(self.args("verify", "--timeout", timeout))

    def delete(self) -> int:
        return self.installer.main(self.args("delete"))

    @property
    def provider_dir(self) -> Path:
        return self.home / "plugins" / "model-providers" / "antigravity-acp"

    @property
    def launcher(self) -> Path:
        return self.bin_dir / (
            "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"
        )

    @property
    def installed_server(self) -> Path:
        return self.prefix / self.installer.official_installer.VERSION / "agy_acp_server.par"

    def rows(self) -> list[dict]:
        return _server_log_rows(self.log)


def _load_provider(monkeypatch, provider_path: Path, name: str):
    """Simulate Hermes' provider discovery over an installed/canonical tree."""
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

    for stale in list(sys.modules):
        if stale == name or stale.startswith(name + "."):
            monkeypatch.delitem(sys.modules, stale, raising=False)
    spec = importlib.util.spec_from_file_location(
        name,
        provider_path / "__init__.py",
        submodule_search_locations=[str(provider_path)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    assert registered == [module.antigravity_acp]  # provider registration itself
    return module


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_empty_hermes_home_lifecycle_preserves_reviewed_sha_and_separates_evidence(
    tmp_path, monkeypatch, capsys
):
    """install -> status -> verify -> delete -> reinstall for a brand-new user.

    RED gates: any auth/prompt method on the wire, any credential-file read,
    any decoy mutation, a reinstalled server that does not byte-match the
    reviewed (patched) publisher pin, or evidence-class conflation.
    """
    env = _CleanEnv(tmp_path, monkeypatch, name="lifecycle")
    tripwire = _CredentialTripwire()
    tripwire.install(monkeypatch)
    # Decoys live under the fake user home (HOME=tmp_path), never inside the
    # hermes home that install is allowed to create.
    decoys = _seed_decoy_credentials(tmp_path)
    assert not env.home.exists()  # HERMES_HOME truly empty (absent)

    assert env.install() == 0
    assert len(env.downloads) == 1
    assert (env.provider_dir / "plugin.yaml").is_file()
    assert env.launcher.is_file()
    # The downloaded archive verified against the reviewed (patched) pin and
    # its member landed byte-intact.
    assert hashlib.sha256(env.installed_server.read_bytes()).hexdigest() == env.executable_sha256

    assert env.status() == 0
    status_out = capsys.readouterr().out
    assert "official_server=available" in status_out
    assert "provider_registered=available" in status_out

    assert env.verify() == 0
    assert "unauthenticated ACP initialize verified" in capsys.readouterr().out

    # Evidence class (b): the ONLY ACP traffic through status/verify was the
    # unauthenticated initialize handshake — zero auth attempts, zero prompts.
    rows = env.rows()
    assert _methods(rows) == ["initialize"]
    assert _auth_attempts(rows) == []
    assert "session/prompt" not in _methods(rows)

    # RED: any lifecycle step opening a credential-shaped path goes RED here.
    assert tripwire.violations() == []
    for path, content in decoys.items():
        assert path.read_bytes() == content

    assert env.delete() == 0
    assert not env.provider_dir.exists()
    assert not (env.prefix / env.installer.official_installer.VERSION).exists()
    assert not env.launcher.exists()
    # delete never reaches user credential state either.
    for path, content in decoys.items():
        assert path.read_bytes() == content

    assert env.install() == 0  # reinstall
    assert len(env.downloads) == 2
    # Reinstall re-downloaded AND re-verified against the SAME reviewed pin:
    # the installed bytes are still byte-identical to the reviewed member.
    assert hashlib.sha256(env.installed_server.read_bytes()).hexdigest() == env.executable_sha256
    assert (env.provider_dir / "install-provenance.json").is_file()
    assert env.verify() == 0
    assert _auth_attempts(env.rows()) == []
    assert tripwire.violations() == []


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_provider_registration_and_model_listing_work_without_quota_skill(
    tmp_path, monkeypatch
):
    """Path B + provider discovery: listing works with /quota nowhere present.

    The provider child must additionally receive NO credential-shaped
    environment variable (``GOOGLE_ACCESS_TOKEN`` canary in the parent env).
    """
    env = _CleanEnv(tmp_path, monkeypatch, name="listing")
    assert env.install() == 0
    # Clean environment invariant: no quota surface exists anywhere in this
    # user's Hermes home (no /quota skill, no quota command installed).
    assert not [p for p in env.home.rglob("*") if "quota" in p.name.lower()]

    provider = _load_provider(monkeypatch, env.provider_dir, "clean_env_smoke_provider")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json"))
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "acp-limits.json")
    )
    # The profile resolves the launcher this installer actually installed.
    assert str(env.launcher) == str(provider.antigravity_acp.process_command)

    client = provider.antigravity_acp.create_client()
    # Scope the canary to the provider's documented credential-free fallback
    # allowlist. Hosts where Hermes' own ``tools`` package happens to be
    # importable route through Hermes' credential-aware env policy instead,
    # which is Hermes Core's contract, not this suite's.
    client_module = sys.modules["clean_env_smoke_provider.client"]
    monkeypatch.setattr(client_module, "build_hermes_subprocess_env", lambda: None)

    # A credential canary in the parent environment must NOT reach the child.
    monkeypatch.setenv("GOOGLE_ACCESS_TOKEN", _SYNTHETIC_SECRET)
    tripwire = _CredentialTripwire()
    tripwire.install(monkeypatch)
    models = client.list_models(timeout_seconds=15.0)
    assert models
    assert list(models) == list(_FAKE_MODELS)

    rows = env.rows()
    # Evidence class (c): model discovery rode on initialize + session/new.
    assert set(_methods(rows)) <= {"initialize", "session/new"}
    assert _auth_attempts(rows) == []
    assert "session/prompt" not in _methods(rows)
    assert all(row["env_google_token"] is False for row in rows)
    assert tripwire.violations() == []


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_catalog_provider_path_a_composes_with_official_server_path_b(
    tmp_path, monkeypatch, capsys
):
    """Path A (catalog-managed provider) + Path B (official server) compose.

    The catalog owns its bytes: the combined installer and ``delete`` must
    refuse to overwrite or remove the catalog-managed provider (recovery is
    ``hermes plugins remove``), while the server lifecycle and model listing
    keep working untouched.
    """
    env = _CleanEnv(tmp_path, monkeypatch, name="catalog")
    deployer = env.installer.provider_installer

    # Simulate the completed Path A install: canonical current bytes plus
    # Hermes core's installer-owned record and the catalog sidecar.
    env.provider_dir.mkdir(parents=True)
    for name in deployer.REQUIRED:
        shutil.copyfile(PLUGIN_SOURCE / name, env.provider_dir / name)
    (env.provider_dir / deployer.CATALOG_SIDECAR).write_text(
        json.dumps({"name": "antigravity-acp-provider", "pin": "0" * 40}) + "\n",
        encoding="utf-8",
    )
    metadata = env.home / "plugins" / deployer.INSTALL_METADATA_FILE
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(
        json.dumps({
            "antigravity-acp-provider": {
                "source": "https://github.com/rhgo1749/hermes-antigravity-acp"
                "/tree/0000000000000000000000000000000000000000/hermes-plugin/antigravity-acp",
                "catalog": {"name": "antigravity-acp-provider", "pin": "0" * 40},
            }
        }) + "\n",
        encoding="utf-8",
    )
    before = {p.name: p.read_bytes() for p in env.provider_dir.iterdir()}
    assert deployer.classify_provider_target(env.provider_dir)[0] == "catalog"

    # Path B through the combined script installs the server beside it with
    # zero writes to the catalog tree (it is current, so it is a no-op).
    assert env.install() == 0
    assert {p.name: p.read_bytes() for p in env.provider_dir.iterdir()} == before
    assert env.status() == 0
    assert "provider_registered=available" in capsys.readouterr().out
    assert env.verify() == 0
    assert _methods(env.rows()) == ["initialize"]

    # delete must fail CLOSED without touching the catalog provider at all.
    assert env.delete() == 2
    refused = capsys.readouterr().err
    assert "hermes plugins remove" in refused
    assert {p.name: p.read_bytes() for p in env.provider_dir.iterdir()} == before

    # Documented Path B recovery: server-only uninstall leaves plugin state
    # entirely alone.
    removed = env.installer.official_installer.uninstall(env.prefix, env.bin_dir)
    assert removed
    assert not (env.prefix / env.installer.official_installer.VERSION).exists()
    assert not env.launcher.exists()
    assert {p.name: p.read_bytes() for p in env.provider_dir.iterdir()} == before

    # Provider registration + listing ride on the catalog bytes themselves.
    env.install()  # reinstall the server for listing
    provider = _load_provider(monkeypatch, env.provider_dir, "clean_env_smoke_catalog_provider")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "cat-state.json"))
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "cat-limits.json")
    )
    models = provider.antigravity_acp.fetch_models(timeout=15.0)
    assert models is not None
    assert list(models) == list(_FAKE_MODELS)
    assert _auth_attempts(env.rows()) == []


# --------------------------------------------------------------------------
# Failure-mode equivalence classes: safe, actionable diagnostics
# --------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="fresh tmp paths only; POSIX-focused text asserts")
def test_missing_server_binary_diagnostic_names_the_pin_and_the_installer(tmp_path):
    official = _load_script(
        SCRIPTS / "install_official.py", "clean_env_smoke_missing_binary"
    )
    with pytest.raises(RuntimeError) as excinfo:
        official.verify(tmp_path / "empty-prefix", tmp_path / "empty-bin")
    message = str(excinfo.value)
    assert "server binary is missing" in message
    assert official.VERSION in message
    assert "install_official.py" in message  # actionable: tells you what to run


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_version_mismatch_diagnostic_names_pinned_and_installed_versions(
    tmp_path, monkeypatch
):
    env = _CleanEnv(tmp_path, monkeypatch, name="vermismatch")
    official = env.installer.official_installer
    pinned_version = official.VERSION
    stale_version = "0.0.9-old"
    monkeypatch.setattr(official, "VERSION", stale_version)
    assert env.install() == 0
    monkeypatch.setattr(official, "VERSION", pinned_version)  # restore the review pin
    with pytest.raises(RuntimeError) as excinfo:
        official.verify(env.prefix, env.bin_dir)
    message = str(excinfo.value)
    assert "version mismatch" in message
    assert pinned_version in message and stale_version in message
    assert "install" in message  # actionable recovery


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_path_misconfiguration_diagnostic_is_actionable(tmp_path, monkeypatch):
    env = _CleanEnv(tmp_path, monkeypatch, name="pathmisconfig")
    assert env.install() == 0
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_COMMAND", raising=False)
    # PATH without the installed launcher: an unrelated host launcher on the
    # developer's real PATH must never satisfy this check by accident.
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    with pytest.raises(RuntimeError) as excinfo:
        env.installer._provider_command(tmp_path / "somewhere-else", require_existing=True)
    message = str(excinfo.value)
    assert "PATH" in message
    assert "HERMES_ANTIGRAVITY_ACP_COMMAND" in message
    assert "install" in message


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_tampered_download_fails_closed_at_script_level(tmp_path, monkeypatch, capsys):
    env = _CleanEnv(tmp_path, monkeypatch, name="tampered")
    # Publisher feed now serves bytes that do not match the reviewed pin.
    original = env.archive

    def poisoned_urlretrieve(url: str, filename: str):
        env.downloads.append(url)
        Path(filename).write_bytes(original + b"tampered")
        return filename, None

    monkeypatch.setattr(
        env.installer.official_installer.urllib.request, "urlretrieve", poisoned_urlretrieve
    )
    assert env.install() == 2
    message = capsys.readouterr().err
    assert "SHA-256 mismatch" in message
    assert "tampered" in message
    assert "untouched" in message or "before extraction" in message
    # Fail-closed: no server, no launcher, and no provider projection landed.
    assert not env.installed_server.exists()
    assert not env.launcher.exists()
    assert not env.provider_dir.exists()


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_headless_login_wait_failure_suppresses_raw_stderr_and_stays_actionable(
    tmp_path, monkeypatch, capsys
):
    """Class: unauthenticated probe timeout / login-surface failure.

    The fake server dumps a credential-shaped line on stderr and never
    completes initialize. The verify diagnostic must NOT echo any raw server
    stderr (secrets in unanticipated shapes survive any fixed scrubber): it
    carries the failure class, a non-reversible fingerprint, and a manual
    next step instead.
    """
    env = _CleanEnv(tmp_path, monkeypatch, body="auth-wait", name="authwait")
    assert env.install() == 0
    assert env.verify(timeout="1") == 2
    message = capsys.readouterr().err
    assert _SYNTHETIC_SECRET not in message  # RED if any secret leaked through
    # No raw server stderr line may appear verbatim, scrubbed or not.
    assert "login required" not in message
    assert "waiting for headless authentication" not in message
    assert "accounts.google.com" not in message
    # Suppression must be explicit and correlated, never a silent drop.
    assert "server stderr suppressed" in message
    assert "sha256=" in message
    assert "credential-shape classes observed" in message
    assert "did not complete the ACP initialize handshake" in message
    assert "no login was attempted" in message
    assert "acp_probe.py" in message  # actionable manual reproduction


@pytest.mark.skipif(os.name == "nt", reason="fresh tmp paths only; POSIX-focused text asserts")
def test_hard_probe_timeout_diagnostic_stays_unauthenticated_and_actionable(
    tmp_path, monkeypatch
):
    """Even the subprocess hard-limit path states the unauthenticated contract."""
    installer = _load_script(SCRIPTS / "install_acp.py", "clean_env_smoke_hard_timeout")
    home = tmp_path / "hermes-home"
    (home / "plugins" / "model-providers" / "antigravity-acp").mkdir(parents=True)
    monkeypatch.setattr(
        installer.official_installer,
        "verify",
        lambda *_a, **_k: {
            "version_dir": tmp_path / "v",
            "executable": tmp_path / "v" / "agy_acp_server.par",
            "launcher": tmp_path / "bin" / "antigravity-acp-official",
        },
    )
    monkeypatch.setattr(installer, "_provider_command", lambda *_a, **_k: "launcher")
    monkeypatch.setattr(installer.provider_installer, "verify", lambda *_a, **_k: [])

    def always_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="acp_probe", timeout=35)

    monkeypatch.setattr(installer.subprocess, "run", always_timeout)
    with pytest.raises(RuntimeError) as excinfo:
        installer.verify(home, tmp_path / "prefix", tmp_path / "bin", None, 30.0)
    message = str(excinfo.value)
    assert "hard limit" in message
    assert "never logs in" in message
    assert "acp_probe.py" in message


def test_probe_timeout_path_suppresses_server_stderr_itself(tmp_path):
    """The probe is the named manual path; its OWN timeout message must also
    stay fingerprint-only, or raw server stderr re-enters diagnostics through
    the traceback that install_acp later summarizes."""
    marker = "SYNTH-PROBE-STDERR-MARKER-9f3d"
    noisy_child = tmp_path / "noisy_child.py"
    noisy_child.write_text(
        "import sys, time\n"
        f"print('{marker}: access_token=SYNTHvalue', file=sys.stderr, flush=True)\n"
        "time.sleep(5)\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "acp_probe.py"), "--timeout", "1", "--",
         sys.executable, str(noisy_child)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert marker not in combined  # RED if the probe echoes raw server stderr
    assert "Server stderr suppressed" in combined
    assert re.search(r"sha256=[0-9a-f]{16}", combined)


def test_server_stderr_summary_echoes_nothing_and_never_reverses_secrets():
    installer = _load_script(SCRIPTS / "install_acp.py", "clean_env_smoke_summary")
    noisy = "\n".join(
        [
            *[f"routine server chatter line {i}" for i in range(40)],
            f"login surface dump: access_token={_SYNTHETIC_SECRET}",
        ]
    )
    summary = installer._server_stderr_summary(noisy)
    assert _SYNTHETIC_SECRET not in summary
    # Not one input line survives verbatim — the summary is fingerprint-only.
    for line in noisy.splitlines():
        assert line not in summary
    assert "server stderr suppressed" in summary
    assert "41 line(s)" in summary
    assert "token-assignment" in summary
    # Deterministic fingerprint for correlation; bounded message.
    assert summary == installer._server_stderr_summary(noisy)
    assert re.search(r"sha256=[0-9a-f]{16}", summary)
    assert len(summary) <= 400
    # Non-reversible: the fingerprint is a truncated sha256, not the payload.
    assert hashlib.sha256(noisy.encode()).hexdigest() not in summary


# Distinct synthetic secrets spanning credential shapes a login-surface dump
# can take. Values are synthetic; real ones must never reach a terminal here.
# The shapes the repository byte-auditor treats as real-credential literals
# (Bearer/ya29./gho_/PEM header) are assembled at RUNTIME from inert
# fragments, so the tree itself stays audit-clean while the classifier and
# leak assertions still operate on the fully-assembled shapes.
_SECRET_SHAPE_CORPUS = (
    ("token-assignment", "login dump: access_token=SYNTHa0ARBgc.TOKEN_VALUE_AAAA"),
    ("token-assignment", "refresh_token=SYNTH-REFRESH-BBBB"),
    ("authorization-header", "Authorization: " + "Bear" + "er " + "SYNTHETICBearerValueCCCC"),
    ("bearer-token", "bea" + "rer SYNTH." + "Etic~Bear-er~Value.DDDD=="),
    ("oauth-url", "open https://accounts.google.com/o/oauth2/device-auth?user_code=SYNTHEEEE"),
    ("google-access-token-prefix", "cached " + "ya29" + "." + "a0ARBgcSYNTHETICya29FFFF"),
    ("google-api-key-prefix", "key=AIzaSYNTHETIC_API_KEY_GGGG00000"),
    ("github-token-prefix", "pushing with " + "gho" + "_" + "SYNTHETICTOKENVALUEHHHH"),
    ("pem-private-key", "-----BEGIN " + "RSA PRIVATE KEY" + "-----"),
    ("cookie-header", "Cookie: OAuth=SYNTHETICCOOKIEVALUEIIII"),
)


def test_secret_shape_corpus_never_appears_in_default_diagnostics():
    """Leak-regression: every corpus secret survives classification as a NAME
    only; the summary must not carry any corpus value substring."""
    installer = _load_script(SCRIPTS / "install_acp.py", "clean_env_smoke_corpus")
    corpus_stderr = "\n".join(line for _name, line in _SECRET_SHAPE_CORPUS)
    summary = installer._server_stderr_summary(corpus_stderr)
    for _name, line in _SECRET_SHAPE_CORPUS:
        secret = line.split()[-1]
        assert secret not in summary, line
        assert line not in summary
    observed = summary.split("credential-shape classes observed: ", 1)[1]
    for name, _line in _SECRET_SHAPE_CORPUS:
        assert name in observed, name
    # PEM material is unguessable-length; guard even the fingerprint framing.
    assert "-----BEGIN" not in summary


def test_empty_stderr_is_still_reported_not_silently_dropped():
    installer = _load_script(SCRIPTS / "install_acp.py", "clean_env_smoke_empty")
    summary = installer._server_stderr_summary("")
    assert "0 line(s)" in summary
    assert "credential-shape classes observed: none" in summary
    assert "sha256=" in summary


# --------------------------------------------------------------------------
# Evidence classes and the OS verification tiers
# --------------------------------------------------------------------------


def test_evidence_classes_are_separated_and_real_inference_stays_unexercised(
    monkeypatch, tmp_path
):
    """Four evidence classes recorded from one fake-ACP session stay distinct.

    The simulated ``session/prompt`` proves the wire works WITHOUT becoming
    class-(d) real-inference evidence: no real server process was ever
    started here (nothing under a real registry URL ran), so class (d) is
    recorded empty by construction.
    """
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "acp-limits.json")
    )
    script = tmp_path / "fake_acp_turn.py"
    script.write_text(
        f"MODELS = {_FAKE_MODELS!r}\n" + _OK_SERVER_BODY % {"log": str(tmp_path / "turn.jsonl")},
        encoding="utf-8",
    )
    module = _load_provider(monkeypatch, PLUGIN_SOURCE, "clean_env_smoke_turn_provider")
    client = module.antigravity_acp.create_client(
        command=sys.executable, args=[str(script)], acp_cwd=str(tmp_path), rate_limit_retries=0
    )
    completion = client.chat.completions.create(
        model=_FAKE_MODELS[0],
        messages=[{"role": "user", "content": "clean env protocol simulation"}],
        timeout=20,
    )
    assert completion.choices[0].message.content == "ok-clean-env-smoke"

    rows = _server_log_rows(tmp_path / "turn.jsonl")
    methods = _methods(rows)
    evidence = {
        "class_a_auth_success": _auth_attempts(rows),
        "class_b_initialize": [m for m in methods if m == "initialize"],
        "class_c_model_list": [m for m in methods if m == "session/new"],
        # Class (d) is empty BY CONSTRUCTION: every process here is a fake
        # script; the real Google server binary was never downloaded or run
        # by this suite. The fake prompt below is a separate bucket.
        "class_d_real_model_inference": [],
        "simulated_turn": [m for m in methods if m == "session/prompt"],
    }
    assert evidence["class_a_auth_success"] == []  # NO-GO: never attempted
    assert evidence["class_b_initialize"]
    assert evidence["class_c_model_list"]
    assert evidence["class_d_real_model_inference"] == []  # never conflated
    assert evidence["simulated_turn"]
    # Truthful telemetry in a quota-free environment: usage None + unavailable.
    assert getattr(completion, "usage", None) is None
    assert completion.antigravity_usage_telemetry["status"] == "unavailable"
    assert all(v is None for v in completion.antigravity_usage_telemetry["request_usage"].values())


def _registry_distributions():
    from antigravity_acp.registry import _DISTRIBUTIONS

    return dict(_DISTRIBUTIONS)


def test_registry_pins_every_pinned_platform_with_a_publisher_digest():
    distributions = _registry_distributions()
    assert set(distributions) >= {
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("darwin", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    }
    for (system, machine), dist in distributions.items():
        assert re.fullmatch(r"[0-9a-f]{64}", dist.sha256), (system, machine)
        assert dist.url.startswith("https://dl.google.com/"), (system, machine)


@pytest.mark.skipif(os.name == "nt", reason="install-flow smoke uses a POSIX fixture body")
@pytest.mark.parametrize(
    "platform_key",
    sorted(_registry_distributions()),
    ids=[f"{s}-{m}" for (s, m) in sorted(_registry_distributions())],
)
def test_offline_install_flow_smoke_for_registry_pinned_unverified_platforms(
    platform_key, tmp_path, monkeypatch
):
    """Credential-free install-flow smoke for every registry-pinned platform.

    This exercises the SAME install/verify mechanics against each pinned
    platform's distribution (fake archive bytes; the executable name comes
    from the registry entry). It is deliberately labelled registry-pinned
    smoke ONLY: it never executes the real Google binary on macOS, Windows,
    or Linux aarch64, and is no substitute for live per-OS verification
    (see README "OS support and verification tiers").
    """
    dist = _registry_distributions()[platform_key]
    from antigravity_acp.registry import VERSION

    official = _load_script(
        SCRIPTS / "install_official.py",
        f"clean_env_smoke_platform_{platform_key[0]}_{platform_key[1]}",
    )
    archive = _archive_bytes("#!/usr/bin/env python3\npass\n", dist.executable)
    # Only the publisher digest is swapped for the fixture's; the URL,
    # executable name, and launcher args stay exactly as pinned.
    fixture_dist = dataclasses.replace(
        dist, sha256=hashlib.sha256(archive).hexdigest()
    )
    monkeypatch.setattr(official, "resolve_distribution", lambda *_a, **_k: fixture_dist)

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_bytes(archive)
        return filename, None

    monkeypatch.setattr(official.urllib.request, "urlretrieve", fake_urlretrieve)
    prefix = tmp_path / "opt"
    bin_dir = tmp_path / "bin"

    result = official.install(prefix, bin_dir)
    assert result["executable"].name == dist.executable
    assert (result["version_dir"] / dist.executable).is_file()
    launcher_text = result["launcher"].read_text(encoding="utf-8")
    assert str(result["executable"]) in launcher_text
    for arg in dist.args:
        assert arg in launcher_text
    verified = official.verify(prefix, bin_dir)
    assert verified["version_dir"] == prefix / VERSION


def test_readme_declares_canary_and_registry_only_os_tiers():
    """The README tier demarcation is itself under test (docs = contract)."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    heading = "## OS support and verification tiers"
    assert heading in readme, "README must declare the verification-tier section"
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    # Tier 1: the hosted lifecycle and historical shared-UID observation
    # must remain distinguishable, with their bounded evidence record.
    assert "Linux x86_64" in section
    assert "historical observation log" in section
    assert "NOT EXECUTED" in section
    assert "official-server-1.4.4-clean-room-e2e-2026-11-07.md" in section, (
        "the Linux x86_64 tier must link the executed clean-room evidence record"
    )
    # Tier 2: every registry-pinned platform must appear as live-unverified.
    for platform in ("macOS arm64", "Windows x64", "Windows arm64", "Linux aarch64"):
        assert platform in section
    assert "not live-verified" in section
    # The four evidence classes and the sanctioned NO-GO must be stated.
    for fragment in (
        "auth success",
        "ACP `initialize` handshake",
        "model list discovery",
        "real model inference",
        "NO-GO",
    ):
        assert fragment in section
