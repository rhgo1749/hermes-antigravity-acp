"""Credential-free tests for the attended official ACP login path."""
from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "hermes-plugin" / "antigravity-acp" / "login.py"


def load_login():
    spec = importlib.util.spec_from_file_location("test_acp_login_module", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FAKE_SERVER = r'''
import json, os, sys
record = os.environ["FAKE_RECORD"]
scenario = os.environ.get("FAKE_SCENARIO", "ok")
for raw in sys.stdin:
    request = json.loads(raw)
    with open(record, "a", encoding="utf-8") as f:
        f.write(request["method"] + "\n")
    if request["method"] == "initialize":
        result = {"protocolVersion": 1, "authMethods": [{"id": "oauth-personal"}]}
        if scenario == "no_method":
            result["authMethods"] = []
        if scenario == "invalid_protocol":
            result["protocolVersion"] = True
        print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}), flush=True)
    elif request["method"] == "authenticate":
        if scenario == "invalid_url":
            url = "https://attacker.invalid/?access_token=PRIVATE_FAKE_TOKEN"
        else:
            url = ("https://" + "accounts.google.com/o/oauth2/v2/auth?"
                   + "client_id=fake-client&response_type=code&"
                   + "redirect_uri=http%3A%2F%2F127.0.0.1%3A12345%2F&state=fake-state")
        print("UNTRUSTED_PRIVATE_FAKE_TOKEN", file=sys.stderr, flush=True)
        print("Open the following link to authenticate the ACP server: " + url,
              file=sys.stderr, flush=True)
        if scenario == "duplicate_url":
            print("Open the following link to authenticate the ACP server: " + url,
                  file=sys.stderr, flush=True)
        if scenario == "wait":
            import time
            time.sleep(10)
        elif scenario == "error":
            print(json.dumps({"jsonrpc":"2.0", "id":2,
                              "error":{"code":-32000,"message":"PRIVATE_FAKE_TOKEN"}}), flush=True)
        else:
            print(json.dumps({"jsonrpc":"2.0", "id":2, "result":{}}), flush=True)
        break
'''


def server(tmp_path, scenario="ok"):
    script = tmp_path / "server.py"
    script.write_text(FAKE_SERVER, encoding="utf-8")
    log = tmp_path / "methods.txt"
    env = dict(os.environ, FAKE_RECORD=str(log), FAKE_SCENARIO=scenario)
    return [sys.executable, str(script)], env, log


def test_login_sends_only_initialize_and_authenticate(tmp_path):
    login = load_login()
    cmd, env, log = server(tmp_path)
    output = io.StringIO()
    login.run_login(cmd, env=env, method="oauth-personal", timeout=5, output=output)
    assert log.read_text().splitlines() == ["initialize", "authenticate"]
    rendered = output.getvalue()
    assert "accounts.google.com/o/oauth2/v2/auth" in rendered
    assert "PRIVATE_FAKE_TOKEN" not in rendered


@pytest.mark.parametrize("scenario", ["no_method", "invalid_protocol"])
def test_invalid_initialize_never_authenticates(tmp_path, scenario):
    login = load_login()
    cmd, env, log = server(tmp_path, scenario)
    output = io.StringIO()
    with pytest.raises(login.LoginError):
        login.run_login(cmd, env=env, method="oauth-personal", timeout=5, output=output)
    assert log.read_text().splitlines() == ["initialize"]
    assert "PRIVATE_FAKE_TOKEN" not in output.getvalue()


def test_untrusted_url_not_echoed(tmp_path):
    login = load_login()
    cmd, env, _ = server(tmp_path, "invalid_url")
    output = io.StringIO()
    with pytest.raises(login.LoginError):
        login.run_login(cmd, env=env, method="oauth-personal", timeout=5, output=output)
    assert "attacker.invalid" not in output.getvalue()
    assert "PRIVATE_FAKE_TOKEN" not in output.getvalue()


def test_server_error_never_exposes_raw_error(tmp_path):
    login = load_login()
    cmd, env, _ = server(tmp_path, "error")
    output = io.StringIO()
    with pytest.raises(login.LoginError) as exc:
        login.run_login(cmd, env=env, method="oauth-personal", timeout=5, output=output)
    assert "PRIVATE_FAKE_TOKEN" not in output.getvalue() + str(exc.value)


def test_timeout_is_bounded_and_does_not_prompt(tmp_path):
    login = load_login()
    cmd, env, log = server(tmp_path, "wait")
    output = io.StringIO()
    with pytest.raises(login.LoginError, match="may have completed"):
        login.run_login(cmd, env=env, method="oauth-personal", timeout=0.4, output=output)
    assert log.read_text().splitlines() == ["initialize", "authenticate"]


def test_duplicate_url_is_refused_without_claiming_auth_rollback(tmp_path):
    login = load_login()
    cmd, env, log = server(tmp_path, "duplicate_url")
    with pytest.raises(login.LoginError, match="may have completed"):
        login.run_login(cmd, env=env, method="oauth-personal", timeout=5, output=io.StringIO())
    assert log.read_text().splitlines() == ["initialize", "authenticate"]


def test_unattended_cli_is_refused_before_spawn(monkeypatch, capsys):
    login = load_login()
    monkeypatch.setattr(login.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(login.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("spawned"))
    assert login.main(["--method", "oauth-personal"]) != 0
    assert "interactive" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("url", [
    "https://accounts.google.com.evil.invalid/o/oauth2/v2/auth?client_id=x",
    "https://evil.invalid@accounts.google.com/o/oauth2/v2/auth?client_id=x",
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&access_token=bad",
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&" + "redirect_uri=http%3A%2F%2Fexample.invalid%2F",
])
def test_rejects_malicious_auth_urls(url):
    login = load_login()
    with pytest.raises(login.LoginError):
        login._safe_auth_url(login._PROMPT + url)


def test_child_environment_excludes_credentials_and_mux(monkeypatch):
    login = load_login()
    monkeypatch.setenv("GOOGLE_API_KEY", "DUMMY_ENV_SECRET")
    monkeypatch.setenv("ACP_MUX_ACCOUNTS", "/private/registry")
    monkeypatch.setenv("HOME", "/isolated/home")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\isolated")
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\isolated\\AppData\\Local")
    env = login._child_env()
    assert env["HOME"] == "/isolated/home"
    # Windows profile roots must survive the filter: the official server has
    # no home directory without them on Windows and dies before initialize.
    assert env["USERPROFILE"] == "C:\\Users\\isolated"
    assert env["LOCALAPPDATA"] == "C:\\Users\\isolated\\AppData\\Local"
    assert "GOOGLE_API_KEY" not in env
    assert "ACP_MUX_ACCOUNTS" not in env


def _fake_registry(tmp_path, executable: Path) -> Path:
    """A test pin registry whose only digest is the fake archive's bytes."""
    import hashlib
    import zipfile

    archive = executable.parent / "official.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(executable.name, executable.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    registry = tmp_path / "registry.py"
    registry.write_text(
        'VERSION = "9.9.9-test"\n'
        "_DISTRIBUTIONS = {\n"
        '    ("linux", "x86_64"): type("D", (), {'
        f'"executable": "{executable.name}", "sha256": "{digest}", "url": "https://fake.google.invalid/agy-acp.zip", "args": ()'
        "})(),\n"
        "}\n",
        encoding="utf-8",
    )
    return registry


@pytest.mark.skipif(os.name == "nt", reason="POSIX pseudo-terminal integration")
def test_public_cli_with_real_tty_and_fake_server(tmp_path):
    import errno
    import pty
    import select
    import subprocess
    import time

    login = load_login()
    executable = tmp_path / ".local" / "opt" / "antigravity-acp" / "9.9.9-test" / "agy_acp_server.par"
    log = tmp_path / "methods.txt"
    body = FAKE_SERVER.replace('record = os.environ["FAKE_RECORD"]', f"record = {str(log)!r}")
    body = body.replace('scenario = os.environ.get("FAKE_SCENARIO", "ok")', 'scenario = "ok"')
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    executable.chmod(0o755)
    registry = _fake_registry(tmp_path, executable)
    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    bodies = sorted(login._managed_launcher_bodies(str(executable), ()))
    launcher.write_text(bodies[-1], encoding="utf-8")
    launcher.chmod(0o755)
    env = dict(os.environ, HOME=str(tmp_path), HERMES_HOME=str(tmp_path / ".hermes"),
               HERMES_ANTIGRAVITY_ACP_REGISTRY=str(registry))
    env.pop("HERMES_ANTIGRAVITY_ACP_COMMAND", None)
    env.pop("HERMES_ANTIGRAVITY_ACP_ARGS", None)
    master, slave = pty.openpty()
    process = subprocess.Popen([sys.executable, str(SCRIPT), "--method", "oauth-personal"],
                               stdin=slave, stdout=slave, stderr=slave, env=env,
                               start_new_session=True)
    os.close(slave)
    transcript = bytearray()
    sent = False
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                transcript.extend(chunk)
                if b"Type LOGIN to continue:" in transcript and not sent:
                    os.write(master, b"LOGIN\n")
                    sent = True
            elif process.poll() is not None:
                break
        rc = process.wait(timeout=2)
        assert rc == 0, transcript.decode(errors="replace")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
    assert sent
    assert b"Official ACP authenticate completed" in transcript
    assert b"PRIVATE_FAKE_TOKEN" not in transcript
    assert log.read_text().splitlines() == ["initialize", "authenticate"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher layout")
def test_cli_refuses_unmanaged_launcher(tmp_path, monkeypatch, capsys):
    login = load_login()
    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\nexec /attacker/agy_acp_server.par \"$@\"\n",
                        encoding="utf-8")
    launcher.chmod(0o755)
    executable = tmp_path / ".local" / "opt" / "antigravity-acp" / "9.9.9-test" / "agy_acp_server.par"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    registry = _fake_registry(tmp_path, executable)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", str(registry))
    monkeypatch.setattr(login.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(login.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(login.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "LOGIN")
    monkeypatch.setattr(login.subprocess, "Popen",
                        lambda *args, **kwargs: pytest.fail("spawned unmanaged launcher"))
    assert login.main([]) == 2
    assert "not managed" in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher layout")
def test_cli_refuses_binary_diverging_from_publisher_pin(tmp_path, monkeypatch, capsys):
    login = load_login()
    executable = tmp_path / ".local" / "opt" / "antigravity-acp" / "9.9.9-test" / "agy_acp_server.par"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    registry = _fake_registry(tmp_path, executable)
    # Tamper the installed bytes after the pin was recorded.
    executable.write_text("#!/bin/sh\nexit 66\n", encoding="utf-8")
    executable.chmod(0o755)
    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(
        sorted(login._managed_launcher_bodies(str(executable), ()))[-1],
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", str(registry))
    monkeypatch.setattr(login.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(login.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(login.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "LOGIN")
    monkeypatch.setattr(login.subprocess, "Popen",
                        lambda *args, **kwargs: pytest.fail("spawned tampered binary"))
    assert login.main([]) == 2
    assert "not managed" in capsys.readouterr().err


def test_cli_method_defaults_and_validates_against_server(tmp_path):
    login = load_login()
    cmd, env, log = server(tmp_path)
    output = io.StringIO()
    # The default route is re-validated against the server's advertised
    # methods; a method the server does not advertise never reaches
    # authenticate.
    with pytest.raises(login.LoginError, match="not advertised"):
        login.run_login(cmd, env=env, method="oauth-nonexistent", timeout=5,
                        output=output)
    assert log.read_text().splitlines() == ["initialize"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher layout")
def test_cli_verifies_with_embedded_pins_without_repo_registry(tmp_path, monkeypatch):
    import hashlib
    import zipfile

    login = load_login()
    # Setup official binary under prefix for the embedded publisher pin (1.4.4)
    version = login._PUBLISHER_VERSION
    version_dir = tmp_path / ".local" / "opt" / "antigravity-acp" / version
    version_dir.mkdir(parents=True)
    executable = version_dir / "agy_acp_server.par"
    content = b"#!/usr/bin/env python3\nimport sys; sys.exit(0)\n"
    executable.write_bytes(content)
    executable.chmod(0o755)

    # Create archive with matching hash
    archive = version_dir / f"agy-acp-server-{version}-linux-x86_64.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("agy_acp_server.par", content)

    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    # Override linux x86_64 pin sha256 to match our fixture archive sha
    fixture_pin = login._DistributionPin(
        url=login._PUBLISHER_PINS[("linux", "x86_64")].url,
        executable="agy_acp_server.par",
        sha256=archive_sha,
        args=("--uid=",),
    )
    monkeypatch.setitem(login._PUBLISHER_PINS, ("linux", "x86_64"), fixture_pin)
    # Ensure HERMES_ANTIGRAVITY_ACP_REGISTRY is not set
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", raising=False)
    # Mock _registry_path to point to non-existent file (simulating installed plugin environment)
    monkeypatch.setattr(login, "_registry_path", lambda: tmp_path / "missing-registry.py")

    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(
        sorted(login._managed_launcher_bodies(str(executable), ("--uid=",)))[-1],
        encoding="utf-8",
    )
    launcher.chmod(0o755)

    monkeypatch.setattr(login.Path, "home", lambda: tmp_path)
    cmd, extra_args = login._resolve_official_command()
    assert cmd == [str(launcher)]
    assert extra_args == ["--uid="]


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher layout")
def test_cli_refuses_when_archive_sha256_mismatches_pin(tmp_path, monkeypatch, capsys):
    import zipfile

    login = load_login()
    version = login._PUBLISHER_VERSION
    version_dir = tmp_path / ".local" / "opt" / "antigravity-acp" / version
    version_dir.mkdir(parents=True)
    executable = version_dir / "agy_acp_server.par"
    content = b"#!/usr/bin/env python3\nimport sys; sys.exit(0)\n"
    executable.write_bytes(content)
    executable.chmod(0o755)

    # Archive does NOT match the expected sha256
    archive = version_dir / f"agy-acp-server-{version}-linux-x86_64.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("agy_acp_server.par", content)

    # Do not override pin; real pin expects Google hash
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", raising=False)
    monkeypatch.setattr(login, "_registry_path", lambda: tmp_path / "missing-registry.py")

    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(
        sorted(login._managed_launcher_bodies(str(executable), ("--uid=",)))[-1],
        encoding="utf-8",
    )
    launcher.chmod(0o755)

    monkeypatch.setattr(login.Path, "home", lambda: tmp_path)
    with pytest.raises(login.LoginError, match="archive is missing or invalid"):
        login._resolve_official_command()


def test_windows_launcher_resolves_to_executable_without_shell(tmp_path, monkeypatch):
    from types import SimpleNamespace

    login = load_login()
    executable = tmp_path / ".local" / "opt" / "antigravity-acp" / "9.9.9-test" / "agy_acp_server.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fake executable")
    registry = _fake_registry(tmp_path, executable)
    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-official.cmd"
    launcher.parent.mkdir(parents=True)
    monkeypatch.setattr(login, "os", SimpleNamespace(name="nt", environ=os.environ))
    monkeypatch.setattr(login, "_normalize_platform", lambda: ("linux", "x86_64"))
    launcher.write_text(next(iter(login._managed_launcher_bodies(str(executable), ()))), encoding="utf-8")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", str(registry))
    monkeypatch.setattr(login.Path, "home", lambda: tmp_path)
    command, args = login._resolve_official_command()
    assert command == [str(executable)]
    assert args == []


def test_installed_plugin_uses_embedded_pins_without_registry(tmp_path, monkeypatch):
    import importlib.util
    import shutil

    installed = tmp_path / "plugins" / "model-providers" / "antigravity-acp" / "login.py"
    installed.parent.mkdir(parents=True)
    shutil.copyfile(SCRIPT, installed)
    spec = importlib.util.spec_from_file_location("installed_login_test", installed)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_REGISTRY", raising=False)
    assert not module._registry_path().exists()
    assert module._load_publisher_pins()[module._PUBLISHER_VERSION] == module._PUBLISHER_PINS


def test_missing_archive_never_causes_network_or_writes(tmp_path, monkeypatch):
    import urllib.request

    login = load_login()
    monkeypatch.setattr(urllib.request, "urlretrieve", lambda *a, **k: pytest.fail("network"))
    assert login._find_or_acquire_archive(tmp_path, login._PUBLISHER_PINS[("windows", "arm64")]) is None
    assert not list(tmp_path.iterdir())


def test_embedded_publisher_pins_match_installer_registry():
    from antigravity_acp.registry import VERSION, _DISTRIBUTIONS

    login = load_login()
    assert login._PUBLISHER_VERSION == VERSION
    assert set(login._PUBLISHER_PINS) == set(_DISTRIBUTIONS)
    for key, expected in _DISTRIBUTIONS.items():
        actual = login._PUBLISHER_PINS[key]
        assert (actual.url, actual.executable, actual.sha256, actual.args) == (
            expected.url, expected.executable, expected.sha256, expected.args
        )


def test_platform_normalization():
    login = load_login()
    assert login._normalize_platform("Windows", "x86_64") == ("windows", "amd64")
    assert login._normalize_platform("Windows", "aarch64") == ("windows", "arm64")
    assert login._normalize_platform("Linux", "arm64") == ("linux", "aarch64")
    assert login._normalize_platform("Darwin", "aarch64") == ("darwin", "arm64")
