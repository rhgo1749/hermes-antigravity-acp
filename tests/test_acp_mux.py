"""Routing/health tests for scripts/acp_mux.py — no live credentials required."""

from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("acp_mux", ROOT / "scripts" / "acp_mux.py")
assert spec is not None and spec.loader is not None
acp_mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acp_mux)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(acp_mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(acp_mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(acp_mux, "LOG_PATH", str(tmp_path / "mux.log"))
    monkeypatch.setattr(acp_mux, "DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(acp_mux, "AUTH_COOLDOWN", 300.0)
    monkeypatch.setattr(acp_mux, "QUOTA_COOLDOWN", 900.0)
    monkeypatch.setattr(acp_mux, "CRASH_COOLDOWN", 60.0)
    (tmp_path / "default-home").mkdir()
    return tmp_path


def _registry(env: Path, accounts: list[dict]) -> None:
    Path(acp_mux.REGISTRY_PATH).write_text(json.dumps({"accounts": accounts}))


def _health_key(label: str, home: str) -> str:
    return f"{label}\t{home}"


def _write_session_bundle(home: Path, session_id: str, mtime: float) -> list[Path]:
    conversations = home / ".gemini" / "antigravity-acp" / "conversations"
    brain = home / ".gemini" / "antigravity-acp" / "brain" / session_id
    conversations.mkdir(parents=True, exist_ok=True)
    brain.mkdir(parents=True, exist_ok=True)
    paths = [
        conversations / f"{session_id}.db",
        conversations / f"{session_id}.meta",
        brain / ".system_generated" / "logs" / "transcript_full.jsonl",
    ]
    paths[2].parent.mkdir(parents=True)
    for path in paths:
        path.write_text("fixture", encoding="utf-8")
        os.utime(path, (mtime, mtime))
    os.utime(brain, (mtime, mtime))
    return paths


def test_no_registry_falls_back_to_default_home(env):
    home, label, reason = acp_mux._pick_account(now=100.0)
    assert reason == "no-registry"
    assert home == str(env / "default-home")
    assert label == "default"


def test_legacy_mux_state_defaults_to_empty_affinity_assignments(env):
    Path(acp_mux.STATE_PATH).write_text(json.dumps({
        "version": 1,
        "cursor": {"0": 1},
        "accounts": {},
    }))

    assert acp_mux._load_state_unlocked()["affinities"] == {}


def test_control_home_prefers_explicit_then_hermes_real_home():
    assert acp_mux._control_home({
        "ACP_MUX_HOME": "/mux-control",
        "HERMES_REAL_HOME": "/real-home",
        "HOME": "/profile-home",
    }) == "/mux-control"
    assert acp_mux._control_home({
        "HERMES_REAL_HOME": "/real-home",
        "HOME": "/profile-home",
    }) == "/real-home"
    assert acp_mux._control_home({"HOME": "/profile-home"}) == "/profile-home"


def test_imported_default_home_uses_hermes_real_home(tmp_path):
    real_home = tmp_path / "real-home"
    profile_home = tmp_path / "profile-home"
    real_home.mkdir()
    profile_home.mkdir()
    proc_env = os.environ.copy()
    proc_env.update({
        "HOME": str(profile_home),
        "HERMES_REAL_HOME": str(real_home),
    })
    proc_env.pop("ACP_MUX_HOME", None)
    module_path = ROOT / "scripts" / "acp_mux.py"
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib.util; "
                f"s=importlib.util.spec_from_file_location('m',{str(module_path)!r}); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.DEFAULT_HOME)"
            ),
        ],
        text=True,
        capture_output=True,
        env=proc_env,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == str(real_home)


def test_round_robin_within_same_priority_tier(env):
    a = str(env / "a")
    b = str(env / "b")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 0},
    ])

    assert acp_mux._pick_account(now=100.0)[1:] == ("a", "round-robin")
    assert acp_mux._pick_account(now=100.0)[1:] == ("b", "round-robin")
    assert acp_mux._pick_account(now=100.0)[1:] == ("a", "round-robin")


def test_affinity_sticks_to_same_account_without_advancing_round_robin(env):
    a = str(env / "a")
    b = str(env / "b")
    c = str(env / "c")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 0},
        {"home": c, "label": "c", "priority": 0},
    ])

    first_session = acp_mux._pick_account(now=100.0, affinity="conversation-1")
    picks = [
        acp_mux._pick_account(
            now=101.0 + index,
            affinity="conversation-1",
            pin_affinity=True,
        )
        for index in range(5)
    ]
    assert len({pick[1] for pick in [first_session, *picks]}) == 1
    assert all(pick[2] == "affinity" for pick in picks)

    # Affinity selection must not consume the legacy round-robin cursor.
    assert acp_mux._pick_account(now=100.0)[1:] == ("a", "round-robin")


def test_affinity_distributes_independent_conversations(env):
    homes = [str(env / name) for name in ("a", "b", "c")]
    _registry(env, [
        {"home": home, "label": label, "priority": 0}
        for home, label in zip(homes, ("a", "b", "c"), strict=True)
    ])

    labels = [
        acp_mux._pick_account(now=100.0, affinity=f"conversation-{i}")[1]
        for i in range(32)
    ]
    counts = Counter(labels)
    assert set(counts) == {"a", "b", "c"}
    assert max(counts.values()) - min(counts.values()) <= 1


def test_affinity_balancing_uses_only_best_healthy_priority_tier(env):
    homes = [str(env / name) for name in ("a", "b", "c")]
    _registry(env, [
        {"home": homes[0], "label": "a", "priority": 0},
        {"home": homes[1], "label": "b", "priority": 0},
        {"home": homes[2], "label": "c", "priority": 1},
    ])

    labels = [
        acp_mux._pick_account(now=100.0, affinity=f"tier-conversation-{i}")[1]
        for i in range(12)
    ]

    assert set(labels) == {"a", "b"}
    assert labels.count("a") == labels.count("b")


def test_legacy_resume_keeps_rendezvous_assignment_and_persists_only_digest(env):
    homes = [str(env / name) for name in ("a", "b", "c")]
    _registry(env, [
        {"home": home, "label": label, "priority": 0}
        for home, label in zip(homes, ("a", "b", "c"), strict=True)
    ])
    affinity = "legacy-conversation-private"
    rows = [
        (0, index, home, label, f"{label}\t{home}")
        for index, (home, label) in enumerate(zip(homes, ("a", "b", "c"), strict=True))
    ]
    expected = acp_mux._affinity_pick(rows, affinity)

    selected = acp_mux._pick_account(
        now=100.0,
        affinity=affinity,
        pin_affinity=True,
    )

    state_text = Path(acp_mux.STATE_PATH).read_text(encoding="utf-8")
    state = json.loads(state_text)
    affinity_digest = hashlib.sha256(affinity.encode()).hexdigest()
    assert selected[1] == expected[3]
    assert state["affinities"][affinity_digest]["account_key"] == expected[4]
    assert affinity not in state_text


def test_affinity_assignments_expire_with_continuation_ttl(env, monkeypatch):
    _registry(env, [
        {"home": str(env / "a"), "label": "a", "priority": 0},
        {"home": str(env / "b"), "label": "b", "priority": 0},
    ])
    monkeypatch.setattr(acp_mux, "AFFINITY_TTL_SECONDS", 60)
    expired_affinity = "conversation-to-expire"
    expired_digest = hashlib.sha256(expired_affinity.encode()).hexdigest()

    acp_mux._pick_account(now=100.0, affinity=expired_affinity)
    acp_mux._pick_account(now=161.0, affinity="conversation-still-active")

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    assert expired_digest not in state["affinities"]


def test_affinity_assignments_are_lru_bounded(env, monkeypatch):
    _registry(env, [
        {"home": str(env / "a"), "label": "a", "priority": 0},
        {"home": str(env / "b"), "label": "b", "priority": 0},
    ])
    monkeypatch.setattr(acp_mux, "AFFINITY_MAX_ENTRIES", 2)
    digests = [
        hashlib.sha256(value.encode()).hexdigest()
        for value in ("oldest", "newer", "newest")
    ]

    for timestamp, affinity in zip(
        (100.0, 101.0, 102.0),
        ("oldest", "newer", "newest"),
        strict=True,
    ):
        acp_mux._pick_account(now=timestamp, affinity=affinity)

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    assert set(state["affinities"]) == set(digests[1:])


def test_local_session_gc_applies_ttl_and_cap_but_preserves_checkpoint_ids(
    env, monkeypatch
):
    home = env / "account-home"
    home.mkdir()
    now = 1_000_000.0
    monkeypatch.setattr(acp_mux, "AFFINITY_TTL_SECONDS", 60)
    monkeypatch.setattr(acp_mux, "AFFINITY_MAX_ENTRIES", 2)

    active_id = "11111111-1111-4111-8111-111111111111"
    expired_id = "22222222-2222-4222-8222-222222222222"
    older_live_id = "33333333-3333-4333-8333-333333333333"
    newest_id = "44444444-4444-4444-8444-444444444444"
    bundles = {
        active_id: _write_session_bundle(home, active_id, now - 500),
        expired_id: _write_session_bundle(home, expired_id, now - 500),
        older_live_id: _write_session_bundle(home, older_live_id, now - 30),
        newest_id: _write_session_bundle(home, newest_id, now - 10),
    }

    result = acp_mux._prune_session_store(
        str(home), {active_id}, now=now
    )

    assert result["expired"] == 1
    assert result["capacity"] == 1
    assert result["failed"] == 0
    assert result["bytes"] > 0
    assert all(path.exists() for path in bundles[active_id])
    assert not any(path.exists() for path in bundles[expired_id])
    assert not any(path.exists() for path in bundles[older_live_id])
    assert all(path.exists() for path in bundles[newest_id])


def test_local_session_gc_fails_closed_on_store_symlink(env):
    outside_home = env / "outside"
    outside_home.mkdir()
    session_id = "55555555-5555-4555-8555-555555555555"
    bundle = _write_session_bundle(outside_home, session_id, 1.0)

    home = env / "account-home"
    (home / ".gemini").mkdir(parents=True)
    (home / ".gemini" / "antigravity-acp").symlink_to(
        outside_home / ".gemini" / "antigravity-acp", target_is_directory=True
    )

    result = acp_mux._prune_session_store(str(home), set(), now=10_000_000.0)

    assert result == {"expired": 0, "capacity": 0, "bytes": 0, "failed": 0}
    assert all(path.exists() for path in bundle)


def test_active_session_inventory_reads_default_and_profile_checkpoints(tmp_path):
    real_home = tmp_path / "real-home"
    hermes_home = real_home / ".hermes"
    profile_home = hermes_home / "profiles" / "worker"
    default_cache = hermes_home / "cache" / acp_mux._SESSION_STATE_FILENAME
    profile_cache = profile_home / "cache" / acp_mux._SESSION_STATE_FILENAME
    now = 2_000_000.0
    default_id = "66666666-6666-4666-8666-666666666666"
    profile_id = "77777777-7777-4777-8777-777777777777"
    expired_id = "88888888-8888-4888-8888-888888888888"

    for path, session_id, updated_at in (
        (default_cache, default_id, now - 30),
        (profile_cache, profile_id, now - 30),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "version": 1,
                "states": {
                    session_id: {"session_id": session_id, "updated_at": updated_at},
                    expired_id: {
                        "session_id": expired_id,
                        "updated_at": now - acp_mux.AFFINITY_TTL_SECONDS - 1,
                    },
                },
            }),
            encoding="utf-8",
        )

    active = acp_mux._active_hermes_session_ids(
        now=now,
        env={"HERMES_HOME": str(hermes_home), "HERMES_REAL_HOME": str(real_home)},
    )

    assert active == {default_id, profile_id}


def test_active_session_inventory_fails_closed_on_corrupt_checkpoint(tmp_path):
    hermes_home = tmp_path / ".hermes"
    cache = hermes_home / "cache" / acp_mux._SESSION_STATE_FILENAME
    cache.parent.mkdir(parents=True)
    cache.write_text("not-json", encoding="utf-8")

    assert acp_mux._active_hermes_session_ids(
        now=1_000_000.0, env={"HERMES_HOME": str(hermes_home)}
    ) is None


def test_failed_assignment_persistence_uses_legacy_stable_route(env, monkeypatch):
    homes = [str(env / name) for name in ("a", "b", "c")]
    _registry(env, [
        {"home": home, "label": label, "priority": 0}
        for home, label in zip(homes, ("a", "b", "c"), strict=True)
    ])
    affinity = "persistence-failure"
    rows = [
        (0, index, home, label, f"{label}\t{home}")
        for index, (home, label) in enumerate(zip(homes, ("a", "b", "c"), strict=True))
    ]
    expected = acp_mux._affinity_pick(rows, affinity)
    monkeypatch.setattr(acp_mux, "_save_state_unlocked", lambda _state: False)

    selected = acp_mux._pick_account(now=100.0, affinity=affinity)

    assert selected[1] == expected[3]
    assert selected[2] == "affinity-state-fallback"


def test_affinity_fails_over_during_cooldown_then_returns(env):
    a = str(env / "a")
    b = str(env / "b")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 0},
    ])
    affinity = "conversation-sticky"
    original = acp_mux._pick_account(now=100.0, affinity=affinity)
    original_home, original_label, _ = original

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    state["accounts"][_health_key(original_label, original_home)] = {"cooldown_until": 200.0}
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))

    failover = acp_mux._pick_account(
        now=101.0,
        affinity=affinity,
        pin_affinity=True,
    )
    assert failover[1] != original_label
    assert failover[2] == "affinity-failover"

    recovered = acp_mux._pick_account(
        now=201.0,
        affinity=affinity,
        pin_affinity=True,
    )
    assert recovered[1] == original_label
    assert recovered[2] == "affinity"


def test_resume_pin_survives_recovery_of_higher_priority_account(env):
    a = str(env / "a")
    b = str(env / "b")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 1},
    ])
    state = acp_mux._empty_state()
    state["accounts"][_health_key("a", a)] = {"cooldown_until": 200.0}
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))

    initial = acp_mux._pick_account(now=100.0, affinity="lower-tier-session")
    assert initial[1] == "b"

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    state["accounts"][_health_key("a", a)]["cooldown_until"] = 0.0
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))
    resumed = acp_mux._pick_account(
        now=101.0,
        affinity="lower-tier-session",
        pin_affinity=True,
    )

    assert resumed[1] == "b"
    assert resumed[2] == "affinity"


def test_resume_pin_keeps_failover_lane_when_healthy_pool_changes(env):
    homes = [str(env / name) for name in ("a", "b", "c", "d")]
    _registry(env, [
        {"home": homes[0], "label": "a", "priority": 0},
        {"home": homes[1], "label": "b", "priority": 1},
        {"home": homes[2], "label": "c", "priority": 1},
        {"home": homes[3], "label": "d", "priority": 1},
    ])
    rows = [
        (1, index, homes[index], label, f"{label}\t{homes[index]}")
        for index, label in ((1, "b"), (2, "c"), (3, "d"))
    ]
    fallback_rows = rows[:2]
    affinity = next(
        f"failover-{index}"
        for index in range(100)
        if acp_mux._affinity_pick(fallback_rows, f"failover-{index}")[3] == "b"
        and acp_mux._affinity_pick(rows, f"failover-{index}")[3] != "b"
    )

    initial = acp_mux._pick_account(now=100.0, affinity=affinity)
    assert initial[1] == "a"

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    state["accounts"][_health_key("a", homes[0])] = {"cooldown_until": 200.0}
    state["accounts"][_health_key("d", homes[3])] = {"cooldown_until": 200.0}
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))
    failover = acp_mux._pick_account(
        now=101.0,
        affinity=affinity,
        pin_affinity=True,
    )
    assert failover[1:] == ("b", "affinity-failover")

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    state["accounts"][_health_key("d", homes[3])]["cooldown_until"] = 0.0
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))
    failover_resume = acp_mux._pick_account(
        now=102.0,
        affinity=affinity,
        pin_affinity=True,
    )
    assert failover_resume[1:] == ("b", "affinity-failover")

    state = json.loads(Path(acp_mux.STATE_PATH).read_text(encoding="utf-8"))
    state["accounts"][_health_key("a", homes[0])]["cooldown_until"] = 0.0
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))
    recovered = acp_mux._pick_account(
        now=201.0,
        affinity=affinity,
        pin_affinity=True,
    )

    assert recovered[1:] == ("a", "affinity")


def test_lower_priority_is_used_when_preferred_tier_is_quarantined(env, monkeypatch):
    a = str(env / "a")
    b = str(env / "b")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 1},
    ])
    monkeypatch.setattr(acp_mux.time, "time", lambda: 100.0)
    acp_mux._mark_failure(a, "a", "quota", "429 quota exhausted")

    home, label, reason = acp_mux._pick_account(now=101.0)
    assert (home, label, reason) == (b, "b", "priority")


def test_all_quarantined_probes_earliest_recovery(env):
    a = str(env / "a")
    b = str(env / "b")
    _registry(env, [
        {"home": a, "label": "a", "priority": 0},
        {"home": b, "label": "b", "priority": 0},
    ])
    state = acp_mux._empty_state()
    state["accounts"] = {
        _health_key("a", a): {"cooldown_until": 500.0},
        _health_key("b", b): {"cooldown_until": 300.0},
    }
    Path(acp_mux.STATE_PATH).write_text(json.dumps(state))

    home, label, reason = acp_mux._pick_account(now=200.0)
    assert (home, label, reason) == (b, "b", "cooldown-probe")


def test_failure_classification_is_strong_and_does_not_scan_normal_content():
    assert acp_mux._classify_failure("HTTP 429 RESOURCE_EXHAUSTED") == "quota"
    assert acp_mux._classify_failure("rate limit exceeded") == "quota"
    assert acp_mux._classify_failure("401 unauthenticated") == "auth"
    assert acp_mux._classify_failure("refresh token revoked") == "auth"
    assert acp_mux._classify_failure("ordinary model response about quotas") is None

    normal = json.dumps({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {"update": {"content": "429 quota exceeded is an example"}},
    })
    assert acp_mux._classify_json_error(normal) is None

    error = json.dumps({"jsonrpc": "2.0", "id": 7, "error": {"code": 429, "message": "quota exceeded"}})
    assert acp_mux._classify_json_error(error) == ("quota", '{"code": 429, "message": "quota exceeded"}')

    nested_quota = json.dumps({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "update": {
                "stepUpdate": {
                    "state": "STATE_ERROR",
                    "errorMessage": "Agent execution terminated due to error.",
                    "error": {
                        "errorMessage": "request failed (code 429): Individual quota reached",
                        "httpCode": 429,
                    },
                }
            }
        },
    })
    classified = acp_mux._classify_json_error(nested_quota)
    assert classified is not None
    assert classified[0] == "quota"
    assert '"httpCode": 429' in classified[1]

    nested_auth = json.dumps({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "update": {
                "state": "STATE_ERROR",
                "errorMessage": "401 unauthenticated",
                "httpCode": 401,
            }
        },
    })
    classified = acp_mux._classify_json_error(nested_auth)
    assert classified is not None
    assert classified[0] == "auth"

    normal_nested_content = json.dumps({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "update": {
                "content": {
                    "text": "Example JSON: {\"error\": {\"code\": 429}}",
                    "error": {"code": 429, "message": "quota exceeded"},
                }
            }
        },
    })
    assert acp_mux._classify_json_error(normal_nested_content) is None


def test_mark_failure_persists_cooldown_without_vendor_credentials(env, monkeypatch):
    home = str(env / "account")
    monkeypatch.setattr(acp_mux.time, "time", lambda: 100.0)
    acp_mux._mark_failure(home, "account", "auth", "401 unauthenticated")

    state = json.loads(Path(acp_mux.STATE_PATH).read_text())
    record = state["accounts"][_health_key("account", home)]
    assert record["reason"] == "auth"
    assert record["cooldown_until"] == 400.0
    assert record["failures"] == 1


def test_duplicate_failure_lines_do_not_extend_same_event(env, monkeypatch):
    home = str(env / "account")
    times = iter([100.0, 102.0])
    monkeypatch.setattr(acp_mux.time, "time", lambda: next(times))

    acp_mux._mark_failure(home, "account", "quota", "429")
    acp_mux._mark_failure(home, "account", "quota", "RESOURCE_EXHAUSTED")

    state = json.loads(Path(acp_mux.STATE_PATH).read_text())
    record = state["accounts"][_health_key("account", home)]
    assert record["cooldown_until"] == 1000.0
    assert record["failures"] == 1


def test_secret_redaction_never_leaks_tokens():
    line = "refresh_token=0Aabcdef... ya29.sometokenhere"
    out = acp_mux._redact(line)
    assert "0Aabcdef" not in out
    assert "ya29.sometokenhere" not in out


def test_mux_has_no_direct_google_auth_or_internal_quota_client():
    source = (ROOT / "scripts" / "acp_mux.py").read_text(encoding="utf-8")
    assert "cloudcode-pa.googleapis.com" not in source
    assert "retrieveUserQuotaSummary" not in source
    assert "urllib.request" not in source
    assert "acp_token.json" not in source


def test_protocol_relay_with_fake_official_acp(tmp_path):
    fake = tmp_path / "fake_acp.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':request.get('id'),'result':{'ok':True}}), flush=True)\n"
    )
    fake.chmod(0o755)

    home = tmp_path / "account-home"
    home.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(json.dumps({"accounts": [{"home": str(home), "label": "fake", "priority": 0}]}))
    state = tmp_path / "state.json"
    log = tmp_path / "mux.log"

    proc_env = os.environ.copy()
    proc_env.update({
        "ACP_MUX_ACCOUNTS": str(registry),
        "ACP_MUX_STATE": str(state),
        "ACP_MUX_LOG": str(log),
        "ACP_MUX_PAR": str(fake),
        "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"),
    })
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        input=request,
        text=True,
        capture_output=True,
        env=proc_env,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    reply = json.loads(completed.stdout.strip())
    assert reply == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert "selected fake" in log.read_text()


def test_official_mux_prunes_expired_sessions_and_keeps_resumable_ones(tmp_path):
    fake = tmp_path / "fake_acp.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':request.get('id'),'result':{'ok':True}}), flush=True)\n"
    )
    fake.chmod(0o755)

    home = tmp_path / "account-home"
    home.mkdir()
    now = time.time()
    stale_id = "99999999-9999-4999-8999-999999999999"
    active_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    stale_bundle = _write_session_bundle(home, stale_id, now - 2 * 86400)
    active_bundle = _write_session_bundle(home, active_id, now - 2 * 86400)

    hermes_home = tmp_path / ".hermes"
    checkpoint = hermes_home / "cache" / acp_mux._SESSION_STATE_FILENAME
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_text(
        json.dumps({
            "version": 1,
            "states": {
                active_id: {"session_id": active_id, "updated_at": now - 60},
            },
        }),
        encoding="utf-8",
    )
    registry = tmp_path / "accounts.json"
    registry.write_text(json.dumps({"accounts": [{"home": str(home), "label": "test", "priority": 0}]}))
    mux_state = tmp_path / "mux-state.json"
    log = tmp_path / "mux.log"
    proc_env = os.environ.copy()
    proc_env.update({
        "ACP_MUX_ACCOUNTS": str(registry),
        "ACP_MUX_STATE": str(mux_state),
        "ACP_MUX_LOG": str(log),
        "ACP_MUX_PAR": str(fake),
        "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
        "HERMES_HOME": str(hermes_home),
        "ACP_MUX_SESSION_GC": "1",
    })
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "antigravity-acp-mux.py")],
        input=request,
        text=True,
        capture_output=True,
        env=proc_env,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert not any(path.exists() for path in stale_bundle)
    assert all(path.exists() for path in active_bundle)
    assert "session-gc expired=1" in log.read_text(encoding="utf-8")


def test_nested_quota_error_quarantines_account_and_remaps_affinity(tmp_path):
    fake = tmp_path / "fake_acp.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    rid = request.get('id')\n"
        "    if request.get('method') == 'initialize':\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':rid,'result':{'ok':True}}), flush=True)\n"
        "    else:\n"
        "        print(json.dumps({'jsonrpc':'2.0','method':'session/update','params':{'update':{'stepUpdate':{'state':'STATE_ERROR','error':{'httpCode':429,'errorMessage':'Individual quota reached'}}}}}), flush=True)\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':rid,'result':{'ok':False}}), flush=True)\n"
    )
    fake.chmod(0o755)

    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "a", "priority": 0},
        {"home": str(b), "label": "b", "priority": 0},
    ]}))
    state = tmp_path / "state.json"
    log = tmp_path / "mux.log"
    affinity = "conversation-sticky"

    # Determine which account this affinity initially selects, then execute the
    # mux with that exact registry/state and emit a nested quota error.
    old_registry, old_state, old_log = acp_mux.REGISTRY_PATH, acp_mux.STATE_PATH, acp_mux.LOG_PATH
    try:
        acp_mux.REGISTRY_PATH = str(registry)
        acp_mux.STATE_PATH = str(state)
        acp_mux.LOG_PATH = str(log)
        original = acp_mux._pick_account(now=acp_mux.time.time(), affinity=affinity)
    finally:
        acp_mux.REGISTRY_PATH, acp_mux.STATE_PATH, acp_mux.LOG_PATH = old_registry, old_state, old_log

    proc_env = os.environ.copy()
    proc_env.update({
        "ACP_MUX_ACCOUNTS": str(registry),
        "ACP_MUX_STATE": str(state),
        "ACP_MUX_LOG": str(log),
        "ACP_MUX_PAR": str(fake),
        "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"),
        "ACP_MUX_AFFINITY": affinity,
        "ACP_MUX_AFFINITY_PIN": "1",
        "ACP_MUX_QUOTA_COOLDOWN": "900",
    })
    requests = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "session/prompt"}),
        "",
    ])
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        input=requests,
        text=True,
        capture_output=True,
        env=proc_env,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    persisted = json.loads(state.read_text())
    original_home, original_label, _ = original
    record = persisted["accounts"][_health_key(original_label, original_home)]
    assert record["reason"] == "quota"
    assert record["failures"] == 1

    old_registry, old_state = acp_mux.REGISTRY_PATH, acp_mux.STATE_PATH
    try:
        acp_mux.REGISTRY_PATH = str(registry)
        acp_mux.STATE_PATH = str(state)
        remapped = acp_mux._pick_account(now=record["last_failure_at"] + 1, affinity=affinity)
    finally:
        acp_mux.REGISTRY_PATH, acp_mux.STATE_PATH = old_registry, old_state
    assert remapped[1] != original_label
