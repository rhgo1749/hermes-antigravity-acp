"""Linux cgroup-v2 containment seam for the plugin-spawned mux tree.

Issue #25 (F4 Gate B candidate B).  The spike (``tests/test_issue25_cgroup_spike.py``,
docs/issue25-cgroup-spike-preflight.md §8) CONFIRMED on a real kernel that cgroup
membership is a containment primitive strictly stronger than the process group:
membership survives ``setsid``/``setpgid``/``exec``, and ``cgroup.kill`` sweeps
escaped descendants while a sibling cgroup is untouched.  This module turns that
primitive into the production spawn/teardown seam for the plugin→mux Popen.

Containment is claimed ONLY when every one of these holds (fail closed):

* Linux, cgroup v2 mounted, and an operator-provided DELEGATED root via
  ``HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT`` (unset/relative/mount-root/not a
  cgroup dir/not effectively writable/no writable ``cgroup.kill`` ⇒ UNKNOWN).
* Migration containment: the root lies inside THIS process's own cgroup
  subtree, so a spawned child can legally move itself into the root's
  children (the 2026-11-17 bare-``app.slice`` EACCES finding).
* The nonce child cgroup was created by US (``dir_created`` only after
  ``mkdir`` succeeded), validated ``domain`` with a writable ``cgroup.kill``,
  and its (st_dev, st_ino) is recorded — a teardown that finds a different
  inode at the path treats it as a FOREIGN object and refuses to touch it
  (path-reuse guard; the containment claim degrades, it is never transferred).
* The spawn trampoline joined ITSELF into the nonce cgroup and verified it
  via ``/proc/self/cgroup`` BEFORE exec'ing the mux, and reported success to
  the parent over a pipe handshake.  The trampoline forks nothing before the
  join, so no mux/vendor descendant can ever be born outside the cgroup
  (pre-join fork race closed at the only place it could occur).  A parent
  that moves a pid in AFTER ``Popen`` would race the child's first fork —
  that design is deliberately NOT used, and ``preexec_fn`` is unsafe in this
  threaded client, so it is not used either.

Anything else — non-Linux, gate failure, mkdir/type/handshake failure,
timeout — means containment=UNKNOWN: the mux is spawned exactly as before
(this module contributes nothing) and the legacy group-teardown contract
(process_teardown.terminate_process_tree) applies unchanged.  A UNKNOWN
spawn is NEVER promoted to fully-contained later.

Windows/macOS code paths are untouched by design; Job Object / macOS
alternatives are explicitly out of scope (mandate §5).

Ownership discipline mirrors process_teardown: every resource is owned only
after its own creation call succeeded, cleanup removes only what this handle
created, and residue is logged loudly — never hidden, never re-attributed.
"""

from __future__ import annotations

import contextlib
import logging
import os
import select
import sys
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

CONTAINMENT_ENV = "HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT"
_NONCE_PREFIX = "acpmux-"
_HANDSHAKE_TIMEOUT_SECONDS = 10.0
_TRAMPOLINE_ABORT_CODE = 87
_EMPTY_PROOF_TIMEOUT_SECONDS = 5.0

# A confirmed Containment rides on the Popen object itself (identity, not
# pid): pid reuse must never be able to redirect a teardown to a foreign
# cgroup, and the attribute flows with the proc through warm-pool entries.
CONTAINMENT_ATTR = "_acp_cgroup_containment"


def _cgroup2_mounted() -> bool:
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "cgroup2":
                    return True
    except OSError:
        return False
    return False


def _own_cgroup_path() -> str | None:
    """This process's cgroup path (v2 unified line), or None."""
    try:
        with open("/proc/self/cgroup") as fh:
            for line in fh:
                if line.startswith("0::"):
                    return line[3:].strip() or None
    except OSError:
        return None
    return None


def _within_own_subtree(root: Path, own: str) -> bool:
    """True when ``root`` IS or LIVES UNDER this process's own cgroup.

    Migration containment: a process may only move between cgroups whose
    common ancestor is inside the writable delegated branch.  Requiring the
    root to sit in our own subtree makes the common ancestor of "us" and
    "root/nonce" our own cgroup — the standard delegation shape.
    """
    base = os.path.normpath(f"/sys/fs/cgroup{own}")
    resolved = os.path.normpath(str(root))
    return resolved == base or resolved.startswith(base + "/")


def delegated_root() -> Path | None:
    """Capability-gated delegated root for containment, or None (UNKNOWN).

    Capability checks (``os.access``), never ownership checks; the mount root
    is never usable; the root must be inside our own cgroup subtree.
    """
    if os.name == "nt" or sys.platform != "linux":
        return None
    raw = os.environ.get(CONTAINMENT_ENV, "").strip()
    if not raw or not os.path.isabs(raw):
        return None
    if not _cgroup2_mounted():
        return None
    root = Path(raw)
    try:
        if root.resolve() == Path("/sys/fs/cgroup").resolve():
            return None
        if not (root / "cgroup.procs").is_file():
            return None
        if not os.access(root, os.W_OK) or not os.access(root / "cgroup.procs", os.W_OK):
            return None
        if not (root / "cgroup.kill").is_file():
            return None
        if not os.access(root / "cgroup.kill", os.W_OK):
            return None
        own = _own_cgroup_path()
        if own is None or not _within_own_subtree(root, own):
            return None
    except OSError:
        return None
    return root


# Runs in the forked child BEFORE the mux exists.  Joins its OWN pid into
# the nonce cgroup, verifies membership through /proc/self/cgroup, reports
# over the notify pipe, closes the fd, then execs the real command.  Any
# failure path exits with _TRAMPOLINE_ABORT_CODE without ever exec'ing the
# mux, so a failed join can never leak an uncontained mux.
TRAMPOLINE_SRC = """
import os, sys
procs_path, notify_fd, *cmd = sys.argv[1:]
notify_fd = int(notify_fd)
target = os.path.basename(os.path.dirname(procs_path))
try:
    with open(procs_path, "w") as fh:
        fh.write(str(os.getpid()) + "\\n")
    joined = False
    with open("/proc/self/cgroup") as fh:
        for line in fh:
            if line.startswith("0::") and line.strip().endswith("/" + target):
                joined = True
    if not joined:
        raise RuntimeError("cgroup join not observable in /proc/self/cgroup")
except BaseException:
    try:
        os.write(notify_fd, b"F")
    except OSError:
        pass
    os._exit(87)
try:
    os.write(notify_fd, b"J")
except OSError:
    pass
os.close(notify_fd)
os.execvp(cmd[0], cmd)
"""


class Containment:
    """One owned nonce child cgroup + handshake state for ONE spawn.

    Constructed only through :meth:`begin`, which flips ``dir_created`` only
    after ``mkdir`` actually succeeded.  Every cleanup path touches nothing
    it did not create; teardown refuses paths whose inode no longer matches
    the creation-time record.
    """

    def __init__(self, directory: Path, stat_result) -> None:
        self.directory = directory
        self.dir_created = True
        self._dev = stat_result.st_dev
        self._ino = stat_result.st_ino
        self.killfile = directory / "cgroup.kill"
        self.killfile_ready = False  # flipped only after positive validation
        self.confirmed = False
        self.cleaned_up = False
        self._notify_read: int | None = None
        self._notify_write: int | None = None

    @classmethod
    def begin(cls) -> "Containment | None":
        """Gate + create + validate the nonce cgroup.  None ⇒ UNKNOWN."""
        root = delegated_root()
        if root is None:
            return None
        directory = root / f"{_NONCE_PREFIX}{uuid.uuid4().hex[:12]}"
        try:
            directory.mkdir()  # EEXIST propagates; nothing is owned yet
        except OSError as exc:
            logger.warning(
                "mux containment disabled for one spawn: mkdir %s failed (%s); "
                "spawning with containment=UNKNOWN",
                directory,
                exc,
            )
            return None
        inst = cls(directory, os.stat(directory))
        try:
            ctype = (directory / "cgroup.type").read_text().strip()
            if ctype != "domain":
                raise RuntimeError(f"child cgroup.type={ctype!r}, not domain")
            if not inst.killfile.is_file() or not os.access(inst.killfile, os.W_OK):
                raise RuntimeError("child cgroup lacks a writable cgroup.kill")
            inst.killfile_ready = True
            inst._notify_read, inst._notify_write = os.pipe()
        except (OSError, RuntimeError) as exc:
            logger.warning(
                "mux containment disabled for one spawn: %s: %s; "
                "removing own dir and spawning containment=UNKNOWN",
                directory.name,
                exc,
            )
            with contextlib.suppress(OSError):
                directory.rmdir()
            inst._close_pipes()
            return None
        return inst

    # -- spawn side ---------------------------------------------------------

    def wrap_argv(self, argv: list[str]) -> list[str]:
        assert self._notify_write is not None
        return [
            sys.executable,
            "-c",
            TRAMPOLINE_SRC,
            str(self.directory / "cgroup.procs"),
            str(self._notify_write),
            *argv,
        ]

    def pass_fds(self) -> tuple[int, ...]:
        return (self._notify_write,) if self._notify_write is not None else ()

    def confirm(self, timeout: float = _HANDSHAKE_TIMEOUT_SECONDS) -> bool:
        """Read the trampoline's one-byte verdict; always closes both ends."""
        read_fd = self._notify_read
        if read_fd is None:  # pipes already consumed: verdict is unrecoverable
            self.confirmed = False
            return False
        deadline = time.monotonic() + timeout
        verdict = b""
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([read_fd], [], [], 0.1)
                if not ready:
                    continue
                chunk = os.read(read_fd, 1)
                if not chunk:  # EOF without verdict: trampoline died oddly
                    break
                verdict = chunk
                break
        except OSError:
            verdict = b""
        finally:
            self._close_pipes()
        self.confirmed = verdict == b"J"
        if not self.confirmed:
            logger.warning(
                "mux containment handshake failed for %s (verdict=%r); "
                "this spawn degrades to containment=UNKNOWN",
                self.directory.name,
                verdict,
            )
        return self.confirmed

    def _close_pipes(self) -> None:
        for attr in ("_notify_read", "_notify_write"):
            fd = getattr(self, attr)
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
                setattr(self, attr, None)

    # -- teardown side ------------------------------------------------------

    def ownership_intact(self) -> bool:
        """Path still names the cgroup dir WE created (st_dev + st_ino)."""
        try:
            st = os.stat(self.directory)
        except OSError:
            return False
        return st.st_dev == self._dev and st.st_ino == self._ino

    def parse_populated(self) -> str:
        """Strict ``cgroup.events`` parser: '0', '1', or '?' (fail closed)."""
        try:
            with open(self.directory / "cgroup.events") as fh:
                text = fh.read()
        except OSError:
            return "?"
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "populated" and parts[1] in {"0", "1"}:
                return parts[1]
        return "?"

    def procs(self) -> set[int] | None:
        try:
            with open(self.directory / "cgroup.procs") as fh:
                return {int(x) for x in fh.read().split()}
        except (OSError, ValueError):
            return None

    def wait_empty(self, timeout: float = _EMPTY_PROOF_TIMEOUT_SECONDS) -> bool:
        """Authoritative whole-cgroup proof: populated=0 AND procs empty."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.parse_populated() == "0" and self.procs() == set():
                return True
            time.sleep(0.05)
        return self.parse_populated() == "0" and self.procs() == set()

    def sweep_own_cgroup(self) -> bool:
        """Write cgroup.kill on OUR OWN validated dir only."""
        if not self.killfile_ready:
            return False
        try:
            with open(self.killfile, "w") as fh:
                fh.write("1")
            return True
        except OSError as exc:
            logger.error("containment %s: cgroup.kill write failed: %s", self.directory.name, exc)
            return False

    def remove_own_dir(self) -> bool:
        try:
            self.directory.rmdir()
        except OSError as exc:
            logger.error(
                "containment %s: RESIDUE — rmdir of our own cgroup dir failed (%s); "
                "leaving it in place, never touching anything else",
                self.directory.name,
                exc,
            )
            return False
        return True

    def abort(self) -> None:
        """Spawn-side failure path: sweep own cgroup, remove own dir.

        Called when the trampoline never exec'd the mux or the handshake
        failed; the caller has already killed/reaped the direct child.
        """
        if self.cleaned_up:
            return
        self._close_pipes()
        if self.dir_created and self.killfile_ready:
            if self.ownership_intact():
                self.sweep_own_cgroup()
                self.wait_empty(timeout=2.0)
                self.remove_own_dir()
            else:
                logger.error(
                    "containment %s: RESIDUE — own dir was replaced mid-flight; "
                    "refusing to sweep or remove a foreign object",
                    self.directory.name,
                )
        self.cleaned_up = True

    def finish(self) -> None:
        if self.cleaned_up:
            return
        self._close_pipes()
        self.cleaned_up = True


def attach(proc, containment: Containment) -> None:
    setattr(proc, CONTAINMENT_ATTR, containment)


def of(proc) -> Containment | None:
    value = getattr(proc, CONTAINMENT_ATTR, None)
    return value if isinstance(value, Containment) else None
