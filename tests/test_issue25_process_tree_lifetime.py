"""Issue #25 (F4 Gate B evidence): process-tree / descendant lifetime.

Question this file answers with executable evidence, not estimation:

    Does the end of a mux lane/process lease sufficiently guarantee that
    the official ACP server AND its vendor-spawned descendants
    (``localharness_external``) have ended all native-store access?

Fidelity contract: the REAL mux (``scripts/acp_mux.py``) runs against a
credential-free fake vendor that spawns credential-free fake descendants.
The descendant model is an ADMISSIBLE safety counterexample — behavior no
contract forbids — not a claim about observed vendor 1.4.4 teardown
behavior: ``subprocess`` default ``close_fds=True`` (descendants hold no
lease fd) and (configurably) no descendant teardown on vendor exit.  What
live 1.4.4 observation (issue #25 read-only audit) actually established is
only that descendants were inside the mux's PGID/SID; there is NO live
proof that descendants survive the direct child's exit, and none is
claimed here.

What the tests establish:

* ``test_graceful_lane_close_...`` / ``test_vendor_crash_...`` /
  ``test_grace_expiry_...`` — COUNTEREXAMPLES: lease release (and even the
  full grace window) does NOT imply descendant store access ended.
* ``test_mux_sigkill_lane_stays_live_...`` — positive control: the F3
  inherited-fd coverage works for the DIRECT child.
* ``test_plugin_group_teardown_...`` — positive control: the plugin's
  ``terminate_process_tree`` (group kill + sweep) DOES reach same-group
  descendants; protection depends on that path running, not on the lease.
* ``test_sibling_lane_teardown_...`` — teardown of one lane never touches
  a sibling lane's live work.
* ``test_vendor_propagating_teardown_...`` — the fully safe close only
  holds when the vendor itself reaps its descendants; the mux contract
  provides no such guarantee.

POSIX/Linux only (flock + /proc); skipped elsewhere.  No live vendor, no
credentials, no GitHub, no deletion.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="lease/proc descendant evidence is Linux-specific",
)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pt_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

sys.path.insert(0, str(ROOT / "hermes-plugin" / "antigravity-acp"))
_pt_spec = importlib.util.spec_from_file_location(
    "pt_teardown", ROOT / "hermes-plugin" / "antigravity-acp" / "process_teardown.py"
)
assert _pt_spec and _pt_spec.loader
teardown = importlib.util.module_from_spec(_pt_spec)
_pt_spec.loader.exec_module(teardown)

HARNESS_SRC = '''
import os, sys, time
if os.environ.get("FAKE_HARNESS_SETSID") == "1":
    os.setsid()
store, pidfile = sys.argv[1], sys.argv[2]
fh = os.open(store, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fh, b"open\\n"); os.fsync(fh)
with open(pidfile, "w") as p:
    p.write(str(os.getpid()))
deadline = time.time() + 120
while time.time() < deadline:
    try:
        with open(store) as r:
            if "STOP" in r.read():
                break
    except OSError:
        break
    time.sleep(0.1)
os.write(fh, b"closed\\n"); os.fsync(fh); os.close(fh)
'''

VENDOR_SRC = '''
import json, os, subprocess, sys
harness = os.environ["FAKE_HARNESS"]
store = os.environ["FAKE_STORE"]
piddir = os.environ["FAKE_PIDDIR"]
count = int(os.environ.get("FAKE_HARNESS_COUNT", "1"))
propagate = os.environ.get("FAKE_PROPAGATE") == "1"
kids = [subprocess.Popen([sys.executable, harness, store,
                          os.path.join(piddir, "h%d.pid" % i)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        for i in range(count)]
with open(os.path.join(piddir, "vendor.pid"), "w") as fh:
    fh.write(str(os.getpid()))
for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    result = {"home": os.environ.get("HOME", "")}
    if req.get("method") == "session/new":
        result["sessionId"] = "d0d0d0d0-d0d0-4d0d-8d0d-d0d0d0d0d0d0"
    if req.get("method") == "session/prompt":
        result["stopReason"] = "end_turn"
    print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}), flush=True)
if os.environ.get("FAKE_STUCK") == "1":
    import time
    time.sleep(120)  # hung vendor: ignores the stdin-EOF shutdown contract
if propagate:
    for k in kids:
        try:
            k.kill()
        except OSError:
            pass
    for k in kids:
        try:
            k.wait(timeout=5)
        except Exception:
            pass
'''


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _ppid(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
    return int(fields[1])


def _proc_state(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]


def _holds_store(pid: int, store: Path) -> bool:
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        return any(
            os.readlink(fd_dir / name) == str(store) for name in os.listdir(fd_dir)
        )
    except OSError:
        return False


def _flock_free(lease_path: str) -> bool:
    """True iff an EXCLUSIVE probe succeeds: the kernel sees zero holders."""
    try:
        fd = os.open(lease_path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return True
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def _wait(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class _Tree:
    """One real mux + fake vendor + fake descendants, fully tracked."""

    def __init__(self, slot: Path, label: str, *, propagate: bool, harnesses: int,
                 setsid: bool = False, stuck: bool = False,
                 state_path: str = "", log_path: str = ""):
        slot.mkdir(parents=True, exist_ok=True)
        self.slot = slot
        self.label = label
        self.home = slot / "home"
        (self.home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
        self.piddir = slot / "pids"
        self.piddir.mkdir()
        self.store = slot / "native-store.db"
        self.harness = slot / "fake_harness.py"
        self.harness.write_text(HARNESS_SRC)
        vendor = slot / "fake_vendor.py"
        vendor.write_text("#!/usr/bin/env python3\n" + VENDOR_SRC)
        vendor.chmod(0o755)
        registry = slot / "accounts.json"
        registry.write_text(json.dumps({"accounts": [{"home": str(self.home), "label": label}]}))
        env = os.environ.copy()
        env.update({
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": state_path or str(slot / "state.json"),
            "ACP_MUX_LOG": log_path or str(slot / "mux.log"),
            "ACP_MUX_PAR": str(vendor),
            "ACP_MUX_AFFINITY": f"affinity-{label}",
            "ACP_MUX_DEFAULT_HOME": str(slot / "default-home"),
            "HOME": str(slot),
            "HERMES_REAL_HOME": str(slot),
            "FAKE_HARNESS": str(self.harness),
            "FAKE_STORE": str(self.store),
            "FAKE_PIDDIR": str(self.piddir),
            "FAKE_HARNESS_COUNT": str(harnesses),
            "FAKE_PROPAGATE": "1" if propagate else "0",
            "FAKE_HARNESS_SETSID": "1" if setsid else "0",
            "FAKE_STUCK": "1" if stuck else "0",
        })
        self.env = env
        self.proc: subprocess.Popen | None = None

    def spawn(self, *, new_session: bool = False) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            env=self.env, bufsize=1, start_new_session=new_session,
        )
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        self.proc.stdin.flush()
        reply = json.loads(self.proc.stdout.readline())
        assert "error" not in reply, reply

    def lease_state(self) -> str:
        return mux._lane_lease_state(str(self.home), self.label, now=time.time())

    def lease_path(self) -> str:
        return mux._lane_lease_path(str(self.home), self.label)

    def vendor_pid(self) -> int:
        return int((self.piddir / "vendor.pid").read_text())

    def harness_pids(self) -> list[int]:
        return [int(p.read_text()) for p in sorted(self.piddir.glob("h*.pid"))]

    def wait_bound(self) -> None:
        assert _wait(lambda: (self.piddir / "vendor.pid").exists()
                     and len(self.harness_pids()) >= 1, 15), "fake tree never spawned"

    def kill_all(self) -> None:
        pids = self.harness_pids()
        if (self.piddir / "vendor.pid").exists():
            pids.append(self.vendor_pid())
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except Exception:
            pass


@pytest.fixture
def trees(tmp_path, monkeypatch):
    monkeypatch.setattr(mux, "LEASE_GRACE_SECONDS", 600)
    # In-process lease lookups resolve via module globals; pin them to the
    # same paths the child muxes receive through env (shared state dir, per
    # lane fingerprints keep lanes distinct).
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    created: list[_Tree] = []

    def make(name: str, *, propagate: bool = False, harnesses: int = 1,
             setsid: bool = False, stuck: bool = False) -> _Tree:
        tree = _Tree(tmp_path / name, f"lane-{name}", propagate=propagate,
                     harnesses=harnesses, setsid=setsid, stuck=stuck,
                     state_path=str(tmp_path / "state.json"),
                     log_path=str(tmp_path / "mux.log"))
        created.append(tree)
        return tree

    yield make
    for tree in created:
        tree.kill_all()


# ---------------------------------------------------------------------------
# Counterexamples: lease end does NOT imply descendant store-access end.
# ---------------------------------------------------------------------------

def test_graceful_lane_close_releases_lease_while_descendant_holds_store(trees):
    tree = trees("close-gap")
    tree.spawn()
    tree.wait_bound()
    assert tree.lease_state() == "live"

    tree.proc.stdin.close()  # ACP graceful shutdown contract
    tree.proc.wait(timeout=20)

    assert _wait(lambda: not _alive(tree.vendor_pid()), 15), "fake vendor never exited"
    harness = tree.harness_pids()[0]
    assert _alive(harness), "precondition: descendant must survive a non-propagating vendor"
    assert _holds_store(harness, tree.store), "descendant must hold the store fd open"
    assert tree.lease_state() != "live"
    assert _flock_free(tree.lease_path()), (
        "GATE B FINDING: the kernel reports zero lease holders while a "
        "descendant still holds the native store open — lease release does "
        "not imply descendant store-access termination"
    )


def test_vendor_crash_releases_lease_and_orphans_descendant(trees):
    tree = trees("crash-gap")
    tree.spawn()
    tree.wait_bound()
    vendor = tree.vendor_pid()
    harness = tree.harness_pids()[0]

    os.kill(vendor, signal.SIGKILL)  # simulate vendor crash
    time.sleep(0.5)
    tree.proc.terminate()  # plugin-equivalent: client notices and stops the mux
    tree.proc.wait(timeout=20)

    assert _alive(harness), "counterexample requires descendant survival of the vendor crash"
    assert _ppid(harness) != vendor, "descendant should be reparented (orphaned)"
    assert _proc_state(harness) != "Z", "descendant is a live orphan, not a zombie"
    assert _holds_store(harness, tree.store)
    assert _flock_free(tree.lease_path()), (
        "GATE B FINDING: vendor crash releases the lease immediately while "
        "the orphaned descendant keeps the store open"
    )


def test_grace_expiry_exposes_surviving_descendant_to_gc(trees, monkeypatch):
    monkeypatch.setattr(mux, "LEASE_GRACE_SECONDS", 1)
    tree = trees("grace-gap")
    tree.spawn()
    tree.wait_bound()

    tree.proc.stdin.close()
    tree.proc.wait(timeout=20)
    assert _wait(lambda: not _alive(tree.vendor_pid()), 15)

    harness = tree.harness_pids()[0]
    assert _wait(lambda: tree.lease_state() == "stale", 10), (
        "lease must age to stale once the grace window passes"
    )
    assert _alive(harness) and _holds_store(harness, tree.store)
    assert not mux._lane_lease_protected(tree.lease_state()), (
        "GATE B FINDING: after the fixed grace window the GC contract treats "
        "the lane as unprotected while a live descendant still accesses the "
        "store; a time window is not a lifetime guarantee"
    )


# ---------------------------------------------------------------------------
# Positive controls: what DOES cover descendants, and what stays safe.
# ---------------------------------------------------------------------------

def test_mux_sigkill_lane_stays_live_until_direct_child_exits(trees):
    # A hung vendor (ignores the stdin-EOF contract) models the worst case
    # for the F3 inherited-fd coverage claim: only the DIRECT child keeps
    # the lane live; coverage ends the moment it exits, descendants or not.
    tree = trees("sigkill-cover", stuck=True)
    tree.spawn()
    tree.wait_bound()
    vendor = tree.vendor_pid()

    tree.proc.kill()  # mux dies without running its finally
    tree.proc.wait(timeout=10)

    assert _alive(vendor), "hung fake vendor (direct child) survives the mux kill"
    assert tree.lease_state() == "live", (
        "F3 inherited-fd coverage: the direct child alone keeps the lane live"
    )
    os.kill(vendor, signal.SIGKILL)
    assert _wait(lambda: tree.lease_state() != "live", 15)
    assert all(_alive(h) for h in tree.harness_pids()), (
        "descendants outlive the lease the instant the direct child dies"
    )


def test_plugin_group_teardown_reaches_same_group_descendant(trees):
    tree = trees("group-sweep", harnesses=2)
    tree.spawn(new_session=True)  # plugin contract: start_new_session=True
    tree.wait_bound()
    harnesses = tree.harness_pids()
    assert len(harnesses) == 2, "parked/warm server with multiple descendants"

    verified = teardown.terminate_process_tree(tree.proc, graceful_stdin=True)
    assert verified is True, "tree sweep must be verified, not assumed"
    assert _wait(lambda: all(not _alive(p) for p in harnesses), 15), (
        "group kill + sweep reaches same-group descendants (the live 1.4.4 "
        "audit observed descendants inside the mux group; this control shows "
        "that where that containment holds, the protection comes from the "
        "plugin's tree teardown, not the lease)"
    )
    assert tree.lease_state() != "live"


def test_sibling_lane_teardown_leaves_other_lane_live(trees):
    a = trees("sibling-a")
    b = trees("sibling-b")
    a.spawn(new_session=True)
    a.wait_bound()
    b.spawn(new_session=True)
    b.wait_bound()

    assert teardown.terminate_process_tree(a.proc, graceful_stdin=True) is True
    assert _wait(lambda: all(not _alive(p) for p in a.harness_pids()), 15)

    assert b.proc.poll() is None, "sibling mux must be untouched"
    assert b.lease_state() == "live", "sibling lease must be untouched"
    assert all(_alive(p) for p in b.harness_pids()), "sibling work must survive"


def test_vendor_propagating_teardown_is_safe_but_not_guaranteed(trees):
    tree = trees("propagate", propagate=True)
    tree.spawn()
    tree.wait_bound()
    harnesses = tree.harness_pids()

    tree.proc.stdin.close()
    tree.proc.wait(timeout=20)
    assert _wait(lambda: all(not _alive(p) for p in harnesses), 15), (
        "when (and only when) the vendor itself reaps descendants the close "
        "is fully safe; the mux teardown (direct child only) provides no "
        "such guarantee, so safety must not be assumed from vendor behavior"
    )


# ---------------------------------------------------------------------------
# Reviewer boundary cases (issue #25 independent review, points A–D):
# the exact paths the existing issue #23 contract already refuses to cover.
# ---------------------------------------------------------------------------

def test_group_teardown_misses_setsid_detached_descendant(trees):
    tree = trees("setsid-escape", setsid=True, harnesses=2)
    tree.spawn(new_session=True)
    tree.wait_bound()
    harnesses = tree.harness_pids()
    assert len(harnesses) == 2
    for h in harnesses:
        assert os.getpgid(h) != os.getpgid(tree.proc.pid), (
            "precondition: descendants detached their session (setpgid/setsid)"
        )

    verified = teardown.terminate_process_tree(tree.proc, graceful_stdin=True)
    tree.proc.wait(timeout=20)
    assert verified is True, (
        "the owned group IS observed empty — the sweep reports success while "
        "detached descendants are simply outside the group it can verify"
    )
    assert _wait(lambda: not _alive(tree.vendor_pid()), 15)
    survivors = [h for h in harnesses if _alive(h)]
    assert survivors, (
        "GATE B FINDING (point C): a vendor descendant that detaches its "
        "process group escapes even the verified tree teardown; the group "
        "guarantee is conditional on vendor behavior no contract enforces"
    )
    assert all(_holds_store(h, tree.store) for h in survivors)
    assert _wait(lambda: tree.lease_state() != "live", 15), (
        "lease coverage died with the direct child; survivors hold the store "
        "with zero lease evidence"
    )


def test_reaped_leader_refuses_sweep_and_leaves_whole_vendor_tree(trees):
    # Point A/B exact boundary, mirroring issue #23's
    # test_teardown_after_reap_refuses_unverifiable_group_sweep contract:
    # once the group leader is reaped, killpg is PID/PGID-reuse-unsafe and
    # terminate_process_tree must refuse (result is not True).  The whole
    # vendor tree then survives teardown with no lease coverage once the
    # direct child itself exits.
    tree = trees("reaped-leader", harnesses=2)
    tree.spawn(new_session=True)
    tree.wait_bound()
    vendor = tree.vendor_pid()
    harnesses = tree.harness_pids()

    tree.proc.kill()  # abrupt mux (group leader) death
    assert _wait(lambda: tree.proc.poll() is not None, 10)
    # poll() above reaped the zombie leader: ownership is now unverifiable.
    result = teardown.terminate_process_tree(tree.proc)
    assert result is not True, "a reaped leader must never claim a tree sweep"

    # The vendor notices its closed stdin pipe and exits (ACP contract);
    # a non-propagating vendor leaves its descendants behind with the
    # leader reaped and no teardown path allowed to signal the group.
    assert _wait(lambda: not _alive(vendor), 15)
    assert all(_alive(h) for h in harnesses), (
        "GATE B FINDING (point A): with the leader already reaped the "
        "contract refuses any group signal, so the vendor descendants "
        "survive the plugin-side teardown"
    )
    assert _wait(lambda: tree.lease_state() != "live", 15), (
        "point B: the lease dies with the direct child"
    )
    assert all(_alive(h) for h in harnesses) and all(
        _holds_store(h, tree.store) for h in harnesses
    ), (
        "GATE B FINDING (point B): lease FD released while descendants keep "
        "the native store open — lease end does not imply store-access end"
    )
