"""historical reference: portable ACP home, registry, and account-layout contract.

Credential-free regressions for the path contract documented in
docs/acp-path-contract.md.  Every scenario runs a fresh process (paths are
resolved at import/run time), uses temp homes, and a fake ACP server that
records the HOME/GEMINI_HOME it was spawned with.  No real credentials, no
Google services, no writes outside tmp_path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
MUX = ROOT / "scripts" / "acp_mux.py"
GUARD = ROOT / "scripts" / "antigravity-acp-mux.py"
WRAPPER = ROOT / "scripts" / "antigravity-acp-mux"

_CONTROL_ENV_NAMES = (
    "ACP_MUX_HOME",
    "ACP_MUX_ACCOUNTS",
    "ACP_MUX_STATE",
    "ACP_MUX_CACHE",
    "ACP_MUX_LOG",
    "ACP_MUX_PAR",
    "ACP_MUX_DEFAULT_HOME",
    "ACP_MUX_AFFINITY",
    "ACP_MUX_AFFINITY_PIN",
    "ACP_MUX_SESSION_GC",
    "HERMES_ACP_ACCOUNTS",
    "HERMES_ANTIGRAVITY_ACP_PAR",
    "HERMES_REAL_HOME",
    "HERMES_HOME",
    "GEMINI_HOME",
)

_FAKE_SERVER = """#!/usr/bin/env python3
import json
import os
import sys

home = os.environ.get("HOME", "")
if home:
    open(os.path.join(home, ".fake-acp-spawn"), "a").close()
    with open(os.path.join(home, ".fake-acp-env.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "HOME": home,
                "GEMINI_HOME": os.environ.get("GEMINI_HOME", ""),
            },
            fh,
        )
for line in sys.stdin:
    try:
        request = json.loads(line)
    except ValueError:
        continue
    print(
        json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": {"ok": True}}),
        flush=True,
    )
"""


def _interpreters() -> list[str]:
    extra = os.environ.get("ACP_TEST_PYTHONS", "")
    values = [sys.executable]
    if extra:
        for candidate in json.loads(extra):
            if Path(candidate).is_file() and candidate not in values:
                values.append(candidate)
    return values


def _env(tmp_path: Path, **overrides: object) -> dict[str, str]:
    """Minimal environment: no ambient ACP_MUX_*/HERMES_* can leak in."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "process-home"),
    }
    for name in _CONTROL_ENV_NAMES:
        env.pop(name, None)
    for key, value in overrides.items():
        if value is not None:
            env[key] = str(value)
    return env


@pytest.fixture()
def fake_launcher(tmp_path: Path) -> Path:
    fake = tmp_path / "fake_acp_server.py"
    fake.write_text(_FAKE_SERVER, encoding="utf-8")
    fake.chmod(0o755)
    launcher = tmp_path / "fake-par"
    launcher.write_text(
        "#!/bin/sh\n" f'exec "{sys.executable}" "{fake}" "$@"\n', encoding="utf-8"
    )
    launcher.chmod(0o755)
    return launcher


def _run_mux(interpreter: str, env: dict[str, str], methods: tuple[str, ...] = ("initialize",)):
    requests = "".join(
        json.dumps({"jsonrpc": "2.0", "id": index, "method": method}) + "\n"
        for index, method in enumerate(methods, start=1)
    )
    return subprocess.run(
        [interpreter, str(MUX)],
        input=requests,
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )


def _run_doctor(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), "doctor"],
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )


def _module_constants(interpreter: str, env: dict[str, str]) -> dict[str, str]:
    code = (
        "import importlib.util, json;"
        f"s=importlib.util.spec_from_file_location('m', {str(MUX)!r});"
        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m);"
        "print(json.dumps({k: getattr(m, k) for k in ("
        "'REGISTRY_PATH','STATE_PATH','LOG_PATH','DEFAULT_HOME','PAR')}))"
    )
    completed = subprocess.run(
        [interpreter, "-c", code],
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _write_registry(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _spawned_homes(homes: list[Path]) -> list[Path]:
    return [home for home in homes if (home / ".fake-acp-spawn").exists()]


def _poison_mcp_config(home: Path) -> None:
    config = home / ".gemini" / "config" / "mcp_config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"mcpServers": {"rogue": {}}}), encoding="utf-8")


# --- 1. fresh-process path precedence (contract section 2) -----------------


@pytest.mark.parametrize("interpreter", _interpreters())
def test_import_time_layout_follows_documented_precedence(tmp_path: Path, interpreter: str) -> None:
    mux_home = tmp_path / "mux-home"
    real_home = tmp_path / "real-home"
    for name in (mux_home, real_home, tmp_path / "process-home"):
        Path(name).mkdir()

    explicit = str(tmp_path / "explicit-accounts.json")
    constants = _module_constants(
        interpreter,
        _env(
            tmp_path,
            ACP_MUX_HOME=mux_home,
            HERMES_REAL_HOME=real_home,
            ACP_MUX_ACCOUNTS=explicit,
            ACP_MUX_STATE=str(tmp_path / "state.json"),
            ACP_MUX_LOG=str(tmp_path / "mux.log"),
            ACP_MUX_PAR=str(tmp_path / "server.par"),
            ACP_MUX_DEFAULT_HOME=str(tmp_path / "default-lane"),
        ),
    )
    assert constants["REGISTRY_PATH"] == os.path.normpath(explicit)
    assert constants["DEFAULT_HOME"] == os.path.normpath(str(tmp_path / "default-lane"))

    legacy_alias = _env(
        tmp_path,
        HERMES_REAL_HOME=real_home,
        HERMES_ACP_ACCOUNTS=str(tmp_path / "legacy-accounts.json"),
        ACP_MUX_CACHE=str(tmp_path / "legacy-state.json"),
        HERMES_ANTIGRAVITY_ACP_PAR=str(tmp_path / "legacy.par"),
    )
    constants = _module_constants(interpreter, legacy_alias)
    assert constants["REGISTRY_PATH"] == os.path.normpath(
        str(tmp_path / "legacy-accounts.json")
    )
    assert constants["STATE_PATH"] == os.path.normpath(str(tmp_path / "legacy-state.json"))
    assert constants["DEFAULT_HOME"] == os.path.normpath(str(real_home))
    assert constants["PAR"] == os.path.normpath(str(tmp_path / "legacy.par"))

    control_home = _env(tmp_path, ACP_MUX_HOME=mux_home, HERMES_REAL_HOME=real_home)
    constants = _module_constants(interpreter, control_home)
    # ACP_MUX_HOME wins over HERMES_REAL_HOME for every derived path.
    assert constants["REGISTRY_PATH"] == os.path.normpath(
        os.path.join(str(mux_home), ".hermes", "acp-accounts.json")
    )
    assert constants["DEFAULT_HOME"] == os.path.normpath(str(mux_home))

    real_only = _env(tmp_path, HERMES_REAL_HOME=real_home)
    constants = _module_constants(interpreter, real_only)
    assert constants["DEFAULT_HOME"] == os.path.normpath(str(real_home))

    # Contract: an empty value is unset, not an empty path.
    empty = _env(tmp_path, ACP_MUX_HOME=mux_home, ACP_MUX_ACCOUNTS="")
    constants = _module_constants(interpreter, empty)
    assert constants["REGISTRY_PATH"] == os.path.normpath(
        os.path.join(str(mux_home), ".hermes", "acp-accounts.json")
    )


# --- 2. per-lane HOME / GEMINI_HOME pinning ---------------------------------


def test_child_home_and_gemini_home_are_pinned_per_lane(
    tmp_path: Path, fake_launcher: Path
) -> None:
    lane = tmp_path / "lane-a"
    lane.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(registry, {"accounts": [{"home": str(lane), "label": "a", "priority": 0}]})
    env = _env(
        tmp_path,
        ACP_MUX_HOME=tmp_path / "mux-home",
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
        GEMINI_HOME=str(tmp_path / "parent-decoy-gemini"),
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 0, completed.stderr
    recorded = json.loads((lane / ".fake-acp-env.json").read_text())
    assert recorded["HOME"] == str(lane)
    assert recorded["GEMINI_HOME"] == os.path.join(str(lane), ".gemini")
    assert not (tmp_path / "parent-decoy-gemini").exists()


# --- 3. default-home policy (no silent process-HOME adoption) ---------------


def test_legacy_registry_missing_home_keeps_control_home_with_diagnostic(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    control.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(registry, {"accounts": [{"label": "legacy", "priority": 0}]})
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 0, completed.stderr
    assert _spawned_homes([control]) == [control]
    log = Path(env["ACP_MUX_LOG"]).read_text()
    assert "account-legacy-home idx=0 resolved=control-home-fallback" in log


def test_versioned_registry_missing_home_without_default_fails_closed(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    control.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry, {"schema_version": 1, "accounts": [{"home": None, "label": "x"}]}
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 2
    assert "account registry is present but unusable" in completed.stderr
    assert _spawned_homes([control, tmp_path / "process-home"]) == []


def test_versioned_registry_missing_home_uses_declared_default(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    declared = tmp_path / "declared-default"
    for directory in (control, declared):
        directory.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry,
        {
            "schema_version": 1,
            "default_home": str(declared),
            "accounts": [{"home": None, "label": "primary"}],
        },
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 0, completed.stderr
    assert _spawned_homes([declared, control]) == [declared]


def test_env_default_home_overrides_registry_default(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    declared = tmp_path / "declared-default"
    override = tmp_path / "env-default"
    for directory in (control, declared, override):
        directory.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry,
        {
            "schema_version": 1,
            "default_home": str(declared),
            "accounts": [{"label": "primary"}],
        },
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
        ACP_MUX_DEFAULT_HOME=override,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 0, completed.stderr
    assert _spawned_homes([override, declared, control]) == [override]


def test_relative_entry_home_is_excluded(tmp_path: Path, fake_launcher: Path) -> None:
    control = tmp_path / "mux-home"
    control.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry, {"accounts": [{"home": "relative/lane", "label": "bad"}]}
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 2
    assert "account-excluded idx=0 reason=home-not-absolute" in Path(
        env["ACP_MUX_LOG"]
    ).read_text()


# --- 4. registry failure modes fail closed, never silently re-route --------


def test_unsupported_schema_version_fails_closed(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    lane = tmp_path / "lane-a"
    for directory in (control, lane):
        directory.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry, {"schema_version": 99, "accounts": [{"home": str(lane)}]}
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 2
    assert "account registry is present but unusable" in completed.stderr
    assert _spawned_homes([control, lane]) == []


def test_malformed_registry_fails_closed(tmp_path: Path, fake_launcher: Path) -> None:
    control = tmp_path / "mux-home"
    control.mkdir()
    registry = tmp_path / "accounts.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text("{not-json", encoding="utf-8")
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 2
    doctor = _run_doctor(MUX, env)
    assert doctor.returncode == 2
    assert "registry-problem=malformed-json" in doctor.stdout


def test_selected_lane_spawn_failure_does_not_reroute_to_default_home(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    lane = tmp_path / "lane-a"
    lane.mkdir()
    _poison_mcp_config(lane)
    registry = tmp_path / "accounts.json"
    _write_registry(registry, {"accounts": [{"home": str(lane), "label": "a"}]})
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 2
    assert "refusing a silent account fallback" in completed.stderr
    assert _spawned_homes([lane, control]) == []


def test_registry_invalid_message_is_identical_on_resilient_entrypoint(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    control.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(registry, {"schema_version": 99, "accounts": []})
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    requests = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(GUARD)],
        input=requests,
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 2
    assert "account registry is present but unusable" in completed.stderr


# --- 5. affinity / state stability across process restarts ------------------


def test_affinity_and_state_paths_stable_across_restart(
    tmp_path: Path, fake_launcher: Path
) -> None:
    lanes = [tmp_path / f"lane-{index}" for index in range(3)]
    for lane in lanes:
        lane.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry,
        {
            "accounts": [
                {"home": str(lane), "label": f"lane{index}", "priority": 0}
                for index, lane in enumerate(lanes)
            ]
        },
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=tmp_path / "mux-home",
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
        ACP_MUX_AFFINITY="conversation-portable-106",
        ACP_MUX_AFFINITY_PIN="1",
    )
    Path(env["ACP_MUX_HOME"]).mkdir()
    first = _run_mux(sys.executable, env)
    second = _run_mux(sys.executable, env)
    assert first.returncode == 0 and second.returncode == 0
    marked = _spawned_homes(lanes)
    assert len(marked) == 1, "affinity must re-bind the same lane after restart"
    assert Path(env["ACP_MUX_STATE"]).is_file()
    state = json.loads(Path(env["ACP_MUX_STATE"]).read_text())
    assert state["affinities"], "affinity assignment must survive in the state path"


def test_priority_lane_selection_survives_legacy_registry_env(
    tmp_path: Path, fake_launcher: Path
) -> None:
    # The selector works the lowest numeric priority tier first; lane A owns
    # that tier and must be chosen on every fresh process while healthy.
    preferred = tmp_path / "lane-preferred"
    fallback = tmp_path / "lane-fallback"
    for lane in (preferred, fallback):
        lane.mkdir()
    registry = tmp_path / "via-legacy-env.json"
    _write_registry(
        registry,
        {
            "accounts": [
                {"home": str(fallback), "label": "fallback", "priority": 1},
                {"home": str(preferred), "label": "preferred", "priority": 0},
            ]
        },
    )
    env = _env(
        tmp_path,
        HERMES_REAL_HOME=tmp_path / "real-home",
        HERMES_ACP_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    for _ in range(3):
        completed = _run_mux(sys.executable, env)
        assert completed.returncode == 0, completed.stderr
    assert _spawned_homes([preferred, fallback]) == [preferred]


# --- 6. doctor (read-only diagnostics) --------------------------------------


def test_doctor_absent_registry_reports_single_lane_and_writes_nothing(
    tmp_path: Path,
) -> None:
    (tmp_path / "process-home").mkdir()
    env = _env(tmp_path, ACP_MUX_HOME=tmp_path / "mux-home")
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    doctor = _run_doctor(MUX, env)
    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert before == after == ["process-home"]
    assert "registry=absent (single-lane mode" in doctor.stdout
    assert "server launcher is unset" in doctor.stdout  # honest MUX finding
    assert doctor.returncode == 1  # findings exist (no launcher); not fatal


def test_doctor_reports_paths_schema_and_counts(tmp_path: Path) -> None:
    (tmp_path / "process-home").mkdir()
    control = tmp_path / "mux-home"
    lane = tmp_path / "lane-a"
    lane.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry,
        {
            "schema_version": 1,
            "default_home": str(tmp_path / "declared-default"),
            "accounts": [
                {"home": str(lane), "label": "SECRET-LABEL-MUST-NOT-PRINT"},
                {"home": None, "label": "another-secret-label"},
            ],
        },
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=tmp_path / "server.par",
    )
    doctor = _run_doctor(MUX, env)
    out = doctor.stdout
    assert "registry-schema=1" in out
    assert "registry-accounts=2" in out
    assert f"registry-path={os.path.normpath(str(registry))}" in out
    assert "registry-source=ACP_MUX_ACCOUNTS" in out
    assert f"home={lane}" in out
    assert "gemini-home-exists=False" in out  # missing .gemini is detected
    assert "auth-store-dir-exists=False" in out
    assert "resolved-default:explicit" in out
    assert "SECRET-LABEL-MUST-NOT-PRINT" not in out
    assert "another-secret-label" not in out
    assert "lane=" in out  # fingerprint tokens are present instead


def test_doctor_flags_aliasing_duplicate_homes_and_labels_are_hidden(
    tmp_path: Path,
) -> None:
    (tmp_path / "process-home").mkdir()
    control = tmp_path / "mux-home"
    canonical = control / ".hermes" / "acp-accounts.json"
    _write_registry(
        canonical,
        {
            "schema_version": 1,
            "default_home": str(tmp_path / "declared-default"),
            "accounts": [
                {"home": str(tmp_path / "dup-lane"), "label": "dup-SECRET-one"},
                {"home": str(tmp_path / "dup-lane"), "label": "dup-SECRET-two"},
            ],
        },
    )
    alias = tmp_path / "alias-accounts.json"
    alias.symlink_to(canonical)
    env = _env(tmp_path, ACP_MUX_HOME=control, ACP_MUX_ACCOUNTS=alias)
    doctor = _run_doctor(MUX, env)
    out = doctor.stdout
    assert "resolve to the same object" in out  # overlapping alias detected
    assert "share the same home" in out
    assert "dup-SECRET" not in out


def test_doctor_flags_broken_links_and_symlinked_homes(tmp_path: Path) -> None:
    (tmp_path / "process-home").mkdir()
    control = tmp_path / "mux-home"
    registry = control / ".hermes" / "acp-accounts.json"
    registry.parent.mkdir(parents=True)
    lane_target = tmp_path / "real-lane"
    lane_target.mkdir()
    lane_link = tmp_path / "lane-link"
    lane_link.symlink_to(lane_target)
    broken_lane_link = tmp_path / "lane-broken"
    broken_lane_link.symlink_to(tmp_path / "no-such-lane")
    registry.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "default_home": str(tmp_path / "declared-default"),
                "accounts": [
                    {"home": str(lane_link), "label": "l1"},
                    {"home": str(broken_lane_link), "label": "l2"},
                ],
            }
        ),
        encoding="utf-8",
    )
    alias_registry = tmp_path / "accounts-alias.json"
    alias_registry.symlink_to(registry)
    env = _env(tmp_path, ACP_MUX_HOME=control, ACP_MUX_ACCOUNTS=alias_registry)
    doctor = _run_doctor(MUX, env)
    out = doctor.stdout
    assert "registry-kind=symlink" in out
    assert "home-kind=symlink" in out
    assert "home-kind=broken-symlink" in out
    assert "home is a symlink" in out
    assert "home is a broken symlink" in out


def test_doctor_detects_overlapping_home_identity(tmp_path: Path) -> None:
    # Two distinct home strings (e.g. a bind-mounted duplicate of the same
    # host directory) that stat to one object must surface as a finding.
    real = tmp_path / "real-home"
    real.mkdir()
    (tmp_path / "process-home").mkdir()
    mount_alias = tmp_path / "mount-alias"
    mount_alias.symlink_to(real)
    env = _env(tmp_path, HERMES_REAL_HOME=real, HOME=mount_alias)
    doctor = _run_doctor(MUX, env)
    assert "resolve to the same object" in doctor.stdout


def test_doctor_output_identical_across_entrypoints(tmp_path: Path) -> None:
    (tmp_path / "process-home").mkdir()
    lane = tmp_path / "lane-a"
    lane.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(
        registry, {"accounts": [{"home": str(lane), "label": "identity-lane"}]}
    )
    env = _env(
        tmp_path,
        ACP_MUX_HOME=tmp_path / "mux-home",
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_STATE=tmp_path / "state.json",
        ACP_MUX_LOG=tmp_path / "mux.log",
        ACP_MUX_PAR=tmp_path / "server.par",
        HERMES_REAL_HOME=tmp_path / "real-home",
    )
    base = _run_doctor(MUX, env)
    guard = _run_doctor(GUARD, env)
    assert base.stdout == guard.stdout
    assert base.returncode == guard.returncode
    wrapper = subprocess.run(
        ["sh", str(WRAPPER), "doctor"],
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert wrapper.returncode == guard.returncode
    assert wrapper.stdout == guard.stdout


@pytest.mark.parametrize("interpreter", _interpreters())
def test_all_interpreters_compile_and_run_doctor(
    tmp_path: Path, interpreter: str
) -> None:
    for script in (MUX, GUARD):
        completed = subprocess.run(
            [interpreter, "-m", "py_compile", str(script)],
            text=True,
            capture_output=True,
            env=_env(tmp_path),
            timeout=20,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
    (tmp_path / "process-home").mkdir()
    doctor = subprocess.run(
        [interpreter, str(MUX), "doctor"],
        text=True,
        capture_output=True,
        env=_env(tmp_path, ACP_MUX_HOME=tmp_path / "mux-home"),
        timeout=20,
        check=False,
    )
    assert "contract-version=1" in doctor.stdout


# --- 7. state/log path contract ---------------------------------------------


def test_state_and_log_land_only_on_resolved_paths(
    tmp_path: Path, fake_launcher: Path
) -> None:
    control = tmp_path / "mux-home"
    lane = tmp_path / "lane-a"
    lane.mkdir()
    registry = tmp_path / "accounts.json"
    _write_registry(registry, {"accounts": [{"home": str(lane), "label": "a"}]})
    env = _env(
        tmp_path,
        ACP_MUX_HOME=control,
        ACP_MUX_ACCOUNTS=registry,
        ACP_MUX_CACHE=str(tmp_path / "legacy-state.json"),  # legacy alias
        ACP_MUX_LOG=tmp_path / "nested" / "mux.log",
        ACP_MUX_PAR=fake_launcher,
    )
    completed = _run_mux(sys.executable, env)
    assert completed.returncode == 0, completed.stderr
    assert Path(env["ACP_MUX_CACHE"]).is_file()
    assert Path(env["ACP_MUX_LOG"]).is_file()
    assert not (control / ".hermes").exists()  # defaults never materialized
    doctor = _run_doctor(MUX, env)
    assert "state-source=ACP_MUX_CACHE" in doctor.stdout
    assert "log-source=ACP_MUX_LOG" in doctor.stdout


# --- 8. public Single-mode boundary (must stay untouched) -------------------


def test_single_mode_provider_never_references_mux_plumbing() -> None:
    client = (ROOT / "hermes-plugin" / "antigravity-acp" / "client.py").read_text()
    assert "acp_mux" not in client
    assert "acp-accounts" not in client


def test_mux_module_import_creates_nothing(tmp_path: Path) -> None:
    (tmp_path / "process-home").mkdir()
    env = _env(tmp_path, ACP_MUX_HOME=tmp_path / "mux-home")
    code = (
        "import importlib.util;"
        f"s=importlib.util.spec_from_file_location('m', {str(MUX)!r});"
        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert list(tmp_path.rglob("*")) == [tmp_path / "process-home"]


def test_registry_examples_validate_against_the_loader(tmp_path: Path) -> None:
    # The checked-in examples are executable examples of the contract, not
    # decoration: both layouts must parse through the real registry loader.
    for name, expect_schema in (
        ("acp-accounts.example.json", 1),
        ("acp-accounts.legacy.example.json", None),
    ):
        example = ROOT / "examples" / name
        payload = json.loads(example.read_text(encoding="utf-8"))
        target = tmp_path / name
        target.write_text(json.dumps(payload), encoding="utf-8")
        # Execute the checked-in example through the real registry loader.
        code = (
            "import importlib.util, json;"
            f"s=importlib.util.spec_from_file_location('m', {str(MUX)!r});"
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m);"
            f"e,meta,p=m._load_registry_data({str(target)!r});"
            "print(json.dumps({'problem': p, 'count': len(e or []),"
            " 'schema': meta.get('schema_version')}))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            text=True,
            capture_output=True,
            env=_env(tmp_path),
            timeout=20,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        result = json.loads(completed.stdout)
        assert result["problem"] == "", name
        assert result["schema"] == expect_schema, name
        assert result["count"] == len(payload["accounts"]) >= 2, name
