"""Candidate/home provenance for direct and observed official provider snapshots.

Trusted test instrumentation, not a hostile-Python sandbox. No Core callable,
registry, snapshot or loader is replaced. An identical arbitrary copy is NOT an
origin: only the unchanged Core's observed source-to-snapshot return can bind it.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import sys
from types import CodeType


def tree_files(root: Path) -> dict[str, str]:
    """All deployed payload bytes, not Core's size/mtime cache fingerprint."""
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError("unsafe_provider_tree")
    result = {}
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise ValueError("provider_tree_symlink")
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        for name in sorted(files):
            file = Path(directory) / name
            if not stat.S_ISREG(file.stat().st_mode):
                raise ValueError("provider_tree_nonregular")
            result[str(file.relative_to(root))] = hashlib.sha256(file.read_bytes()).hexdigest()
    if "__init__.py" not in result:
        raise ValueError("provider_entry_missing")
    return result


class ProviderOrigin:
    def __init__(self, installed: Path, home: Path, core: Path, *, owned_root: Path | None = None):
        self.installed, self.home, self.core = installed, home, core.resolve(strict=True)
        if installed != home / "plugins/model-providers/antigravity-acp" or home.resolve(strict=True) != home:
            raise ValueError("provider_home_mismatch")
        self.expected = tree_files(installed)
        self.owned_root = owned_root.resolve(strict=True) if owned_root is not None else None
        self.roots = {installed}
        self.errors: list[str] = []
        self.compiled: dict[tuple[str, str], list[CodeType]] = {}

    def observe(self, frame, event, value) -> None:
        if (event != "return" or frame.f_code.co_name != "_snapshot"
                or Path(frame.f_code.co_filename).resolve() != self.core / "providers/plugin_reload.py"):
            return
        if frame.f_locals.get("plugin_dir") != self.installed:
            return  # Another home's plugin never grants a binding in this origin.
        try:
            if (frame.f_code is not getattr(frame.f_globals.get("_snapshot"), "__code__", None)
                    or Path(frame.f_globals["__file__"]).resolve() != self.core / "providers/plugin_reload.py"):
                raise ValueError("snapshot_loader_not_original")
            root = Path(frame.f_globals["_snapshot_root"])
            target = Path(value)
            if (not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir()
                    or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077
                    or target != root / frame.f_locals["module_name"] / self.installed.name
                    or not target.is_relative_to(root)
                    or self.owned_root is not None and not target.is_relative_to(self.owned_root)):
                raise ValueError("snapshot_scope_mismatch")
            if tree_files(target) != self.expected or tree_files(self.installed) != self.expected:
                raise ValueError("snapshot_payload_mismatch")
            self.roots.add(target)
        except (OSError, ValueError, TypeError, KeyError):
            self.errors.append("snapshot_provenance_unverified")

    def accepts(self, filename: str | Path, relative: str) -> bool:
        if self.errors or relative not in self.expected:
            return False
        file = Path(filename)
        root = next((root for root in tuple(self.roots) if file == root / relative), None)
        if root is None:
            return False
        try:
            if tree_files(self.installed) == self.expected and tree_files(root) == self.expected:
                return True
        except (OSError, ValueError):
            pass
        self.errors.append("runtime_payload_drift")
        return False

    def receipt(self) -> dict:
        payload = "\n".join(f"{name}:{value}" for name, value in sorted(self.expected.items()))
        return {"tree_sha256": hashlib.sha256(payload.encode()).hexdigest(),
                "home_sha256": hashlib.sha256(str(self.home).encode()).hexdigest(),
                "frozen_copies": len(self.roots) - 1, "errors": sorted(set(self.errors))}

    def accepts_frame(self, frame, relative: str) -> bool:
        """Match executing code too, not just its co_filename and current disk bytes."""
        if not self.accepts(frame.f_code.co_filename, relative):
            return False
        key = (frame.f_code.co_filename, relative)
        if key not in self.compiled:
            code = compile((self.installed / relative).read_bytes(), key[0], "exec", dont_inherit=True)
            stack, found = [code], []
            while stack:
                item = stack.pop()
                found.append(item)
                stack.extend(value for value in item.co_consts if isinstance(value, CodeType))
            self.compiled[key] = found
        if frame.f_code in self.compiled[key]:
            return True
        self.errors.append("runtime_code_mismatch")
        return False

    @contextmanager
    def observing(self):
        previous = sys.getprofile()
        def observer(frame, event, value):
            self.observe(frame, event, value)
            if previous is not None:
                previous(frame, event, value)
        sys.setprofile(observer)
        try:
            yield self
        finally:
            sys.setprofile(previous)
