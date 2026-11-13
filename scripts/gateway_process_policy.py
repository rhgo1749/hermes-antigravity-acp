"""Fail-closed subprocess admission for the disposable Gateway fixture.

The original Core scratch pruner enumerates unrelated processes, even with an
empty scratch target. Exact argv/path checks do NOT confine a Python -I child.
Without an independently verified process namespace it must remain BLOCKED.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

PRUNE_BODY = ("import sys; sys.path[:] = sys.argv[3:]; "
              "import hermes_constants_scratch_detach as d; d.run(*sys.argv[1:3])")


def canonical_owned_path(value: str, root: Path) -> Path | None:
    """Require exact absolute spelling, no dot segments, aliases or symlink components."""
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        return None
    path = Path(value)
    if value != os.fspath(path) or any(part in {".", ".."} for part in path.parts):
        return None
    try:
        if not path.is_relative_to(root) or path.resolve(strict=True) != path:
            return None
        if any(component.is_symlink() for component in (path, *path.parents)):
            return None
        if path.stat().st_uid != os.getuid():
            return None
    except (OSError, RuntimeError):
        return None
    return path


def scratch_command_verdict(
    executable: str, argv: Sequence[str], root: Path, core: Path, python: str,
    expected_sys_path: Sequence[str],
) -> str:
    """Check original Core argv precisely, then refuse its unconfined process scan.

    No opt-in flag can manufacture namespace proof. A future isolated-runner
    implementation needs independently exercised confinement, not another boolean.
    """
    if not isinstance(argv, (list, tuple)) or len(argv) != 7 + len(expected_sys_path):
        return "scratch_argv_mismatch"
    if executable != python or argv[0] != python:
        return "scratch_executable_mismatch"
    try:
        # Interpreter symlinks are normal venv launchers, but the exact launcher and
        # resolved executable must be the source-attested running interpreter.
        if Path(executable).resolve(strict=True) != Path(python).resolve(strict=True):
            return "scratch_executable_mismatch"
    except OSError:
        return "scratch_executable_missing"
    if list(argv[1:5]) != ["-I", "-B", "-c", PRUNE_BODY]:
        return "scratch_argv_mismatch"
    target = canonical_owned_path(argv[5], root)
    targets = {root / "hermes" / "cache" / "scratch",
               root / "hermes" / "profiles" / "phasec" / "cache" / "scratch"}
    if target not in targets:
        return "scratch_target_escape_or_alias"
    if list(argv[7:]) != list(expected_sys_path) or not expected_sys_path or expected_sys_path[0] != str(core):
        return "scratch_import_path_mismatch"
    # lineage in argv[6] includes ancestors outside this fixture. Passing through the
    # original command allows process_iter over the HOST: a target-path check cannot
    # grant the stronger no-outside-process-access property.
    return "scratch_process_namespace_unverified"
