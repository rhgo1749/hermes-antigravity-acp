"""Issue #25 slice: the Linux cgroup-v2 containment seam (production wiring).

Covers the seam introduced on top of PR #50 (non-reaping liveness):
``cgroup_containment`` (gate + nonce cgroup + pre-exec trampoline handshake)
and ``process_teardown.terminate_contained_tree`` (cgroup ladder), wired at
the single plugin->mux ``Popen`` and the two teardown funnels.

Contracts pinned here:

1. Fail-closed gate: unset/relative/mount-root/non-cgroup/non-writable roots,
   roots outside our own cgroup subtree (migration containment), and
   non-Linux platforms all yield containment=UNKNOWN — this module
   contributes NOTHING to the spawn in those cases.
2. The trampoline NEVER execs the mux unless it joined the nonce cgroup and
   verified membership via /proc/self/cgroup; a failed join exits 87 with an
   "F" verdict and the mux command never runs.  Confirmation is TWO-stage:
   "J" (joined) alone is not enough — the CLOEXEC errpipe must reach EOF
   (exec succeeded); a failed execvp reports "E" and confirm() refuses.
3. Handshake failure at spawn degrades to a plain (UNKNOWN) spawn with the
   original argv and removes only the cgroup dir we created.
4. Teardown refuses a cgroup path whose inode no longer matches the
   creation-time record (path-reuse guard): a foreign object is never
   swept or removed; the containment claim degrades to UNVERIFIED (None).
5. The cgroup ladder: cooperative stdin EOF -> own ``cgroup.kill`` -> reap
   direct child -> empty proof -> own-dir removal; fake-cgroup tests tolerate
   exactly one documented artifact (regular files make ``rmdir`` ENOTEMPTY —
   real cgroup files are virtual and vanish with the cgroup).
6. Windows/macOS: the gate is inert (platform checks), legacy paths untouched.

Real-cgroup tests (production-equivalent spawn through the seam, membership
before first fork, escaped-descendant sweep, sibling untouched, empty proof,
dir removal) run ONLY under an operator-delegated root via
``HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT`` inside that root's own subtree;
everywhere else they SKIP — recorded NOT RUN, never PASS.  On the deployment
container and hosted CI the cgroupfs is read-only, so the gate yields
UNKNOWN and these tests skip by design.

No sudo, no chmod, no mounts, no mutation of any pre-existing cgroup, no
moving of any pre-existing process.  Consistency with PR #49/#50/#51
evidence: the leader is reaped only by the teardown itself (non-reaping
liveness preserved — this seam never adds a pre-teardown ``poll()`` reap),
and the detached/setsid boundary that #51 pinned as a GAP is exactly what
the cgroup ladder closes when — and only when — containment was confirmed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import contextlib
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="Linux cgroup v2 semantics under test",
)

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cgc = _load("cs_cgroup_containment", "cgroup_containment.py")
teardown = _load("cs_process_teardown", "process_teardown.py")

_REAL_ROOT = cgc.delegated_root()
_real_gate = pytest.mark.skipif(
    _REAL_ROOT is None,
    reason=(
        "BLOCKED (fail-closed): no delegated cgroup subtree via "
        f"${cgc.CONTAINMENT_ENV}; real-seam tests are NOT RUN, never PASS"
    ),
)


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return False
    except (PermissionError, IndexError):
        return True
    return state != "Z"


def _cgroup_of(pid: int) -> str:
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def _fake_handle(tmp_path: Path, name: str = "acpmux-fake0000000000"):
    """A hand-built Containment over a FAKE cgroup dir (regular files).

    Bypasses the real gate on purpose: these tests exercise the ladder and
    ownership logic, not kernel semantics (those are the gated tests).
    """
    directory = tmp_path / name
    directory.mkdir()
    (directory / "cgroup.kill").touch()
    (directory / "cgroup.type").write_text("domain\n")
    (directory / "cgroup.procs").write_text("")
    (directory / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    handle = cgc.Containment(directory, os.stat(directory))
    handle.killfile_ready = True
    return directory, handle


# -- 1. fail-closed gate -----------------------------------------------------


def test_gate_rejects_unusable_roots(tmp_path, monkeypatch):
    for bad in ("", "relative/path", "/sys/fs/cgroup", str(tmp_path / "nope")):
        monkeypatch.setenv(cgc.CONTAINMENT_ENV, bad)
        assert cgc.delegated_root() is None, bad


def test_gate_requires_own_subtree(tmp_path, monkeypatch):
    # A fully "capable" fake root outside our own cgroup subtree must still
    # be refused: migration containment (2026-11-17 bare-app.slice EACCES
    # finding) is a hard gate, not a runtime accident to discover later.
    fake = tmp_path / "cg"
    fake.mkdir()
    (fake / "cgroup.procs").touch()
    (fake / "cgroup.kill").touch()
    monkeypatch.setenv(cgc.CONTAINMENT_ENV, str(fake))
    assert cgc.delegated_root() is None


def test_gate_platform_inert(monkeypatch):
    monkeypatch.setenv(cgc.CONTAINMENT_ENV, "/sys/fs/cgroup/user.slice/x")
    monkeypatch.setattr(cgc.sys, "platform", "darwin")
    assert cgc.delegated_root() is None
    monkeypatch.setattr(cgc.sys, "platform", "linux")
    monkeypatch.setattr(cgc.os, "name", "nt")
    assert cgc.delegated_root() is None


def test_begin_none_without_env(monkeypatch):
    monkeypatch.delenv(cgc.CONTAINMENT_ENV, raising=False)
    assert cgc.Containment.begin() is None


# -- 2. trampoline: never execs the mux without a verified join --------------


def test_trampoline_aborts_without_exec(tmp_path):
    directory = tmp_path / "acpmux-abort00000000"
    directory.mkdir()
    procs = directory / "cgroup.procs"
    procs.touch()  # regular file: the pid write "succeeds"...
    touched = tmp_path / "mux-ran"
    read_fd, write_fd = os.pipe()
    err_read, err_write = os.pipe()
    try:
        completed = subprocess.run(
            [
                sys.executable, "-c", cgc.TRAMPOLINE_SRC,
                str(procs), str(write_fd), str(err_write),
                sys.executable, "-c", f"import pathlib; pathlib.Path({str(touched)!r}).write_text('x')",
            ],
            pass_fds=(write_fd, err_write),
            capture_output=True,
            timeout=30,
        )
        # Parent must drop its OWN write ends before reading: the
        # trampoline's copies are gone with it, and EOF only happens when
        # NO writer remains.
        os.close(write_fd)
        os.close(err_write)
        verdict = os.read(read_fd, 1)
        err_verdict = os.read(err_read, 1)
    finally:
        for fd in (read_fd, write_fd, err_read, err_write):
            with contextlib.suppress(OSError):
                os.close(fd)
    # ...but membership is not observable, so the trampoline aborts and the
    # mux command NEVER runs.
    assert completed.returncode == 87, completed.stderr.decode()
    assert verdict == b"F"
    assert err_verdict == b"", "join-failure path must exit without an exec verdict"
    assert not touched.exists(), "trampoline exec'd the mux without verified join"


# The container's own cgroup is the v2 root ("0::/"), so a RELATIVE procs
# path gives target="" and the membership check passes against our real
# (unchanged) cgroup — no cgroup mutation, just a regular file in tmp.
# That lets the EXEC verdict (errpipe) be tested without delegation.
_ROOT_CGROUP = next(
    (line[3:].strip() for line in open("/proc/self/cgroup") if line.startswith("0::")), "?"
) == "/"


@unittest.skipUnless(_ROOT_CGROUP, "exec-verdict trick needs cgroup root '/'")
def test_trampoline_exec_failure_writes_E_and_exits_87(tmp_path):
    err_read, err_write = os.pipe()
    read_fd, write_fd = os.pipe()
    try:
        completed = subprocess.run(
            [
                sys.executable, "-c", cgc.TRAMPOLINE_SRC,
                "cgroup.procs", str(write_fd), str(err_write),
                "/nonexistent-acp-mux-binary-xyz",
            ],
            cwd=str(tmp_path),
            pass_fds=(write_fd, err_write),
            capture_output=True,
            timeout=30,
        )
        # Parent must drop its OWN write ends before reading: the
        # trampoline's copies are gone with it, and EOF only happens when
        # NO writer remains.
        os.close(write_fd)
        os.close(err_write)
        verdict = os.read(read_fd, 1)
        err_verdict = os.read(err_read, 1)
    finally:
        for fd in (read_fd, write_fd, err_read, err_write):
            with contextlib.suppress(OSError):
                os.close(fd)
    assert completed.returncode == 87, completed.stderr.decode()
    assert verdict == b"J", "join was observable; the join verdict is J"
    assert err_verdict == b"E", "failed execvp must report E, never silence"
    assert (tmp_path / "cgroup.procs").read_text().strip().isdigit()


@unittest.skipUnless(_ROOT_CGROUP, "exec-verdict trick needs cgroup root '/'")
def test_trampoline_successful_exec_closes_errpipe(tmp_path):
    err_read, err_write = os.pipe()
    read_fd, write_fd = os.pipe()
    try:
        completed = subprocess.run(
            [
                sys.executable, "-c", cgc.TRAMPOLINE_SRC,
                "cgroup.procs", str(write_fd), str(err_write),
                sys.executable, "-c", "raise SystemExit(3)",
            ],
            cwd=str(tmp_path),
            pass_fds=(write_fd, err_write),
            capture_output=True,
            timeout=30,
        )
        # Parent must drop its OWN write ends before reading: the
        # trampoline's copies are gone with it, and EOF only happens when
        # NO writer remains.
        os.close(write_fd)
        os.close(err_write)
        verdict = os.read(read_fd, 1)
        err_verdict = os.read(err_read, 1)
    finally:
        for fd in (read_fd, write_fd, err_read, err_write):
            with contextlib.suppress(OSError):
                os.close(fd)
    assert completed.returncode == 3, "exec'd command's exit code must surface"
    assert verdict == b"J"
    assert err_verdict == b"", "successful exec closes the CLOEXEC errpipe (EOF)"


# -- 2b. parent-side confirm(): J alone is NOT confirmation -------------------


def test_confirm_requires_exec_eof(tmp_path):
    directory, handle = _fake_handle(tmp_path, "acpmux-conf000000000")
    read_fd, write_fd = os.pipe()
    err_read, err_write = os.pipe()
    handle._notify_read, handle._notify_write = read_fd, write_fd
    handle._err_read, handle._err_write = err_read, err_write
    # Simulate a trampoline that JOINED (J) but whose execvp then FAILED (E):
    # the exact defect the two-pipe protocol closes — a never-exec'd mux
    # must never be marked CONFIRMED.
    os.write(write_fd, b"J")
    os.write(err_write, b"E")
    os.close(write_fd)
    os.close(err_write)
    handle._notify_write = handle._err_write = None
    assert handle.confirm(timeout=5.0) is False
    assert handle.confirmed is False


def test_confirm_true_only_on_join_and_exec_eof(tmp_path):
    directory, handle = _fake_handle(tmp_path, "acpmux-conf010000000")
    read_fd, write_fd = os.pipe()
    err_read, err_write = os.pipe()
    handle._notify_read, handle._notify_write = read_fd, write_fd
    handle._err_read, handle._err_write = err_read, err_write
    os.write(write_fd, b"J")
    os.close(write_fd)
    os.close(err_write)  # EOF on errpipe = exec succeeded
    handle._notify_write = handle._err_write = None
    assert handle.confirm(timeout=5.0) is True
    assert handle.confirmed is True


def test_production_spawn_sequence_confirms_exec_eof(tmp_path):
    # Round-2 regression: the PRODUCTION sequence wrap_argv -> Popen(
    # pass_fds) -> confirm must reach exec EOF.  The parent's own write
    # ends must not keep the errpipe open forever (that timeout degraded
    # every otherwise-successful contained spawn to UNKNOWN).  Uses the
    # container-root target="" trick: directory "." resolves the procs
    # path to a regular file in cwd, membership passes against our real
    # (unchanged) root cgroup — zero cgroup mutation.
    if next(
        (line[3:].strip() for line in open("/proc/self/cgroup") if line.startswith("0::")), "?"
    ) != "/":
        pytest.skip("exec-EOF integration trick needs cgroup root '/'")
    handle = cgc.Containment(Path("."), os.stat(Path(".")))
    handle.killfile_ready = True
    handle._notify_read, handle._notify_write = os.pipe()
    handle._err_read, handle._err_write = os.pipe()
    argv = handle.wrap_argv([sys.executable, "-c", "import time; time.sleep(300)"])
    proc = subprocess.Popen(
        argv,
        cwd=str(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        pass_fds=handle.pass_fds(),
    )
    try:
        assert handle.confirm(timeout=10.0) is True, (
            "parent-held write ends must never block the exec verdict"
        )
        assert proc.poll() is None, "confirmed mux must be the live exec'd process"
        assert (tmp_path / "cgroup.procs").read_text().strip().isdigit()
    finally:
        proc.kill()
        proc.wait(timeout=10)


# -- 3. spawn-side abort: sweeps own cgroup, touches nothing else ------------


def test_abort_sweeps_own_and_never_touches_others(tmp_path):
    directory, handle = _fake_handle(tmp_path, "acpmux-abortsw11111")
    other = tmp_path / "preexisting-cgroup"
    other.mkdir()
    sentinel = other / "sentinel"
    sentinel.write_text("not mine")
    handle.abort()
    assert (directory / "cgroup.kill").read_text() == "1"
    # Documented fake artifact: the regular cgroup.kill file keeps the fake
    # dir non-empty (real cgroup files are virtual); only OUR own files are
    # in there and nothing else was touched.
    assert {p.name for p in directory.iterdir()} == {
        "cgroup.kill", "cgroup.type", "cgroup.procs", "cgroup.events",
    }
    assert sentinel.exists() and other.exists()
    for name in ("cgroup.kill", "cgroup.type", "cgroup.procs", "cgroup.events"):
        (directory / name).unlink()
    directory.rmdir()


# -- 4. teardown ownership guards --------------------------------------------


def test_teardown_refuses_path_replaced_dir(tmp_path):
    directory = tmp_path / "acpmux-reuse000000000"
    directory.mkdir()
    handle = cgc.Containment(directory, os.stat(directory))
    handle.killfile_ready = True
    # Path reuse: our dir moves aside (kept alive elsewhere, so the inode is
    # definitely NOT recycled) and a FOREIGN dir appears at the same path.
    directory.rename(tmp_path / "our-old-dir")
    directory.mkdir()
    sentinel = directory / "sentinel"
    sentinel.write_text("foreign")
    assert not handle.ownership_intact()
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        start_new_session=True,
    )
    try:
        result = teardown.terminate_contained_tree(proc, handle)
        assert result is None, "lost ownership must never claim contained-verified"
        # The legacy group ladder still did its job on OUR direct child.
        assert proc.poll() is not None and proc.returncode < 0
        # The foreign object at the reused path is untouched.
        assert sentinel.read_text() == "foreign"
    finally:
        with open(directory / "sentinel", "w") as fh:
            fh.write("")
        sentinel.unlink()
        directory.rmdir()


# -- 5. the cgroup ladder over a fake cgroup ---------------------------------


def test_fake_ladder_cooperative_then_sweep(tmp_path):
    directory, handle = _fake_handle(tmp_path, "acpmux-ladder00000000")
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys\nfor _ in sys.stdin: pass\n"],
        stdin=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    result = teardown.terminate_contained_tree(proc, handle, graceful_stdin=True)
    # Cooperative exit -> own cgroup.kill sweep ran -> fake empty proof.
    # rmdir of the FAKE dir fails (regular files; real cgroup files are
    # virtual) -> documented artifact -> tri-state contract: False = tree
    # verified dead, own-dir residue logged, NO group escalation after the
    # empty proof (pgid-reuse hazard, #50).  Never a silent "success".
    assert result is False
    assert (directory / "cgroup.kill").read_text() == "1"
    assert proc.poll() is not None
    for name in ("cgroup.kill", "cgroup.type", "cgroup.procs", "cgroup.events"):
        (directory / name).unlink()
    directory.rmdir()


def test_teardown_verified_handle_is_idempotent_noop(tmp_path):
    # A handle whose ladder already completed and VERIFIED returns True on
    # re-entry without touching the (here still live) process — and the
    # flag is teardown_verified, NOT cleaned_up, which finish()/abort()
    # also set for pipe-closing purposes.
    directory, handle = _fake_handle(tmp_path, "acpmux-idem00000000000")
    handle.teardown_verified = True
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        start_new_session=True,
    )
    try:
        assert teardown.terminate_contained_tree(proc, handle) is True
        assert proc.poll() is None, "verified handle must be a pure no-op"
    finally:
        teardown.terminate_process_tree(proc)
    for name in ("cgroup.kill", "cgroup.type", "cgroup.procs", "cgroup.events"):
        (directory / name).unlink()
    directory.rmdir()


def test_fake_ladder_stuck_leader_escalates_unverified(tmp_path):
    directory, handle = _fake_handle(tmp_path, "acpmux-stuck0000000000")
    # A leader that ignores stdin EOF: the fake cgroup.kill (a regular file)
    # kills nothing, so proc.wait must time out and the ladder must escalate
    # through the legacy group ladder and report UNVERIFIED (None).
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys,time\nsys.stdin.buffer.read(1)\ntime.sleep(300)"],
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    result = teardown.terminate_contained_tree(
        proc, handle, graceful_stdin=True, kill_timeout=2.0
    )
    assert result is None
    assert proc.poll() is not None and proc.returncode < 0, "group escalation must kill it"
    for name in ("cgroup.kill", "cgroup.type", "cgroup.procs", "cgroup.events"):
        (directory / name).unlink()
    directory.rmdir()


# -- 6. client._spawn fallback: handshake failure => UNKNOWN spawn -----------


def _load_plugin_package(monkeypatch, tmp_path):
    """Load the plugin as a pseudo-package (test_130 pattern)."""
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json"))
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "acp-limits.json")
    )

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = lambda *a, **k: None
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

    module_name = "antigravity_acp_containment_seam"
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
    return module


def test_spawn_handshake_failure_falls_back_to_unknown(tmp_path, monkeypatch):
    package = _load_plugin_package(monkeypatch, tmp_path)
    pkg_cgc = importlib.import_module(f"{package.__name__}.cgroup_containment")
    # A fake handle over regular files: the trampoline's join cannot be
    # observed, so confirm() must fail and _spawn must fall back.
    directory = tmp_path / "acpmux-fallback000000"
    directory.mkdir()
    (directory / "cgroup.kill").touch()
    (directory / "cgroup.type").write_text("domain\n")
    (directory / "cgroup.procs").touch()
    handle = pkg_cgc.Containment(directory, os.stat(directory))
    handle.killfile_ready = True
    read_fd, write_fd = os.pipe()  # what begin() would have created
    err_read, err_write = os.pipe()
    handle._notify_read, handle._notify_write = read_fd, write_fd
    handle._err_read, handle._err_write = err_read, err_write
    monkeypatch.setattr(
        pkg_cgc.Containment, "begin", classmethod(lambda cls: handle)
    )
    client = package.antigravity_acp.create_client(
        command=sys.executable, args=["-c", "import time; time.sleep(300)"],
        acp_cwd=str(tmp_path),
    )
    proc = client._spawn()
    try:
        assert proc.poll() is None, "fallback must still deliver a live mux process"
        assert pkg_cgc.of(proc) is None, "UNKNOWN spawn must carry no containment"
        assert (directory / "cgroup.kill").read_text() == "1", "abort must sweep own cgroup"
        assert {p.name for p in directory.iterdir()} == {
            "cgroup.kill", "cgroup.type", "cgroup.procs",
        }
    finally:
        teardown.terminate_process_tree(proc)
        for name in ("cgroup.kill", "cgroup.type", "cgroup.procs"):
            (directory / name).unlink()
        directory.rmdir()


# -- 7. real-cgroup tests (delegated root only; else NOT RUN) ----------------

LEADER_SRC = """
import json, os, subprocess, sys, time
from pathlib import Path

here = Path(sys.argv[1])

# Production parity: this process was exec'd by the trampoline INSIDE the
# target cgroup; refuse to fork descendants until membership is confirmed.
target = sys.argv[2]
deadline = time.monotonic() + 20
while not Path("/proc/self/cgroup").read_text().rstrip().endswith("/" + target):
    if time.monotonic() > deadline:
        raise SystemExit("leader never joined target cgroup")
    time.sleep(0.02)

same = subprocess.Popen([sys.executable, str(here / "sleep.py")])
det = subprocess.Popen([sys.executable, str(here / "sleep.py")],
                       start_new_session=True)
payload = {"leader": os.getpid(), "same": same.pid, "det": det.pid}
tmp = here / "pids.json.tmp"
tmp.write_text(json.dumps(payload))
os.replace(tmp, here / "pids.json")
time.sleep(600)
"""


def _real_tree(role: str, work_root: Path):
    """Containment.begin() + trampoline-wrapped leader; returns (handle, proc, pids)."""
    containment = cgc.Containment.begin()
    assert containment is not None, "gate passed at collection but not at spawn"
    work = work_root / f"work-{role}"
    work.mkdir()
    (work / "leader.py").write_text(LEADER_SRC)
    (work / "sleep.py").write_text("import time; time.sleep(600)\n")
    argv = containment.wrap_argv(
        [sys.executable, str(work / "leader.py"), str(work), containment.directory.name]
    )
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        pass_fds=containment.pass_fds(),
    )
    assert containment.confirm(), "real delegated join must confirm"
    deadline = time.monotonic() + 25
    pids = None
    while time.monotonic() < deadline:
        try:
            pids = json.loads((work / "pids.json").read_text())
            break
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.05)
    assert pids is not None, "leader failed to publish pids"
    return containment, proc, pids, work


@_real_gate
def test_real_seam_membership_before_first_fork_and_verified_teardown(tmp_path):
    containment, proc, pids, _work = _real_tree("target", tmp_path)
    nonce = containment.directory.name
    # Membership was fixed by the trampoline BEFORE the leader forked:
    # leader AND both descendants (same-group + setsid-escaped) name the
    # nonce cgroup, and all appear in cgroup.procs.
    for key in ("leader", "same", "det"):
        assert _cgroup_of(pids[key]).endswith("/" + nonce), key
        assert pids[key] in containment.procs(), key
    # Teardown through the real ladder: everything in ours dies, empty
    # proof holds, ONLY our own dir is removed.
    result = teardown.terminate_contained_tree(proc, containment)
    assert result is True, "real contained teardown must be cgroup-verified"
    for key in ("leader", "same", "det"):
        assert not _alive(pids[key]), key
    assert not containment.directory.exists()


@_real_gate
def test_real_teardown_sweeps_escaped_and_spares_sibling(tmp_path):
    target, t_proc, t_pids, _tw = _real_tree("target", tmp_path)
    sibling, s_proc, s_pids, _sw = _real_tree("sibling", tmp_path)
    try:
        result = teardown.terminate_contained_tree(t_proc, target)
        assert result is True
        for key in ("leader", "same", "det"):
            assert not _alive(t_pids[key]), key
        # The sibling cgroup (separate owned nonce dir) is untouched.
        for key in ("leader", "same", "det"):
            assert _alive(s_pids[key]), f"sibling {key} was hit"
        assert sibling.directory.exists()
        assert target.directory.name != sibling.directory.name
    finally:
        teardown.terminate_contained_tree(s_proc, sibling)
        for key in ("leader", "same", "det"):
            assert not _alive(s_pids[key]), key
        assert not sibling.directory.exists()
