"""Owned Windows removal negatives; stdlib native runner + pytest discovery."""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import ci_provider_lifecycle as lifecycle

install = lifecycle.install_acp
official = install.official_installer
provider = install.provider_installer


class LifecycleRemovalGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="acp-lifecycle-negative-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.prefix = self.root / "official"
        self.bin_dir = self.root / "bin"
        self.home.mkdir()
        self.bin_dir.mkdir()
        self.version_dir = self.prefix / official.VERSION
        self.version_dir.mkdir(parents=True)
        self.executable = self.version_dir / official.resolve_distribution().executable
        self.executable.write_bytes(b"owned fixture, never executed")
        self.launcher = self.bin_dir / official._launcher_name()
        official._write_launcher(self.launcher, self.executable, official.resolve_distribution().args)

    def test_unmanaged_launcher_is_preserved_before_deletion(self):
        self.launcher.write_text("unmanaged fixture\n", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            official.uninstall(self.prefix, self.bin_dir)
        self.assertTrue(self.executable.exists())
        self.assertEqual(self.launcher.read_text(encoding="utf-8"), "unmanaged fixture\n")

    def test_unknown_provider_prevents_combined_removal(self):
        target = self.home / "plugins/model-providers/antigravity-acp"
        target.mkdir(parents=True)
        (target / "foreign.txt").write_text("foreign fixture")
        (target / "plugin.yaml").write_text("name: antigravity-acp-provider\nkind: model-provider\n")
        with self.assertRaises(ValueError):
            install.delete(self.home, self.prefix, self.bin_dir)
        self.assertTrue((target / "foreign.txt").exists())
        self.assertTrue(self.executable.exists())
        self.assertTrue(self.launcher.exists())

    def test_permission_denial_is_not_retried_or_reclassified_success(self):
        original = Path.unlink
        calls = []

        def denied(path, *a, **kw):
            if path == self.launcher:
                calls.append(path)
                raise PermissionError(errno.EACCES, "fixture-only secret path", str(path))
            return original(path, *a, **kw)
        with patch.object(Path, "unlink", denied):
            with self.assertRaises(PermissionError):
                official.uninstall(self.prefix, self.bin_dir)
        self.assertEqual(len(calls), 1)
        self.assertTrue(self.executable.exists())
        self.assertTrue(self.launcher.exists())

    @unittest.skipUnless(os.name == "nt", "native Windows no-delete-share handle required")
    def test_locked_owned_executable_is_a_real_failure_and_remains(self):
        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        dll.CreateFileW.restype = ctypes.c_void_p
        handle = dll.CreateFileW(str(self.executable), 0x80000000, 1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaises(PermissionError) as caught:
                official.uninstall(self.prefix, self.bin_dir)
            self.assertTrue(self.executable.exists())
            record = lifecycle.failure_record(caught.exception, self.home, self.prefix, self.bin_dir)
            self.assertEqual(record["status"], "FAIL")
            self.assertEqual(record["path_type"], "official_executable")
            self.assertNotIn(str(self.root), json.dumps(record))
        finally:
            dll.CloseHandle(ctypes.c_void_p(handle))
        # Release ONLY the fixture-owned handle, then the owning public
        # remover works; no chmod, PID kill, broad grant or retry policy.
        official.uninstall(self.prefix, self.bin_dir)
        self.assertFalse(self.version_dir.exists())


if __name__ == "__main__":
    unittest.main()
