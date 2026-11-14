"""Offline provenance controls; the tiny loader fixture is NOT real Core execution."""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from scripts.provider_origin import ProviderOrigin


class ProviderOriginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="provider-origin-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.plugin = self.home / "plugins/model-providers/antigravity-acp"
        self.plugin.mkdir(parents=True)
        (self.plugin / "__init__.py").write_text("# candidate factory\n")
        (self.plugin / "client.py").write_text("# candidate cancel\n")
        (self.plugin / "plugin.yaml").write_text("name: candidate\n")
        self.core = self.root / "core"
        (self.core / "providers").mkdir(parents=True)
        self.private = self.root / "snapshots"
        self.private.mkdir(mode=0o700)
        # Same observable call shape as the official loader; no real providers
        # module is imported or substituted, and no Core action is executed.
        file = self.core / "providers/plugin_reload.py"
        file.write_text("def _snapshot(plugin_dir, module_name):\n    return result\n")
        spec = importlib.util.spec_from_file_location("origin_fixture_loader", file)
        assert spec and spec.loader
        self.loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.loader)
        self.loader.__dict__.update({"_snapshot_root": self.private})
        self.origin = ProviderOrigin(self.plugin, self.home, self.core, owned_root=self.root)

    def snapshot(self, source=None, name="version-one"):
        source = source or self.plugin
        target = self.private / name / source.name
        target.parent.mkdir()
        shutil.copytree(source, target)
        return target

    @contextmanager
    def observe_fixture(self, origin=None):
        origin = origin or self.origin
        prior = sys.getprofile()
        def callback(frame, event, value):
            origin.observe(frame, event, value)
        sys.setprofile(callback)
        try:
            yield
        finally:
            sys.setprofile(prior)

    def bind(self, target, source=None, origin=None):
        self.loader.__dict__["result"] = target
        with self.observe_fixture(origin):
            self.loader.__dict__["_snapshot"](source or self.plugin, target.parent.name)

    def test_legacy_exact_installed_tree_still_passes(self):
        self.assertTrue(self.origin.accepts(self.plugin / "__init__.py", "__init__.py"))
        self.assertTrue(self.origin.accepts(self.plugin / "client.py", "client.py"))
        self.assertEqual([], self.origin.errors)

    def test_observed_original_loader_copy_passes_for_factory_and_cancel(self):
        frozen = self.snapshot()
        self.bind(frozen)
        self.assertTrue(self.origin.accepts(frozen / "__init__.py", "__init__.py"))
        self.assertTrue(self.origin.accepts(frozen / "client.py", "client.py"))
        self.assertEqual(1, self.origin.receipt()["frozen_copies"])
        self.assertEqual([], self.origin.errors)

    def test_identical_but_unobserved_copy_is_not_provenance(self):
        frozen = self.snapshot()
        self.assertFalse(self.origin.accepts(frozen / "__init__.py", "__init__.py"))

    def test_same_bytes_from_sibling_home_cannot_bind(self):
        foreign = self.root / "sibling/plugins/model-providers/antigravity-acp"
        shutil.copytree(self.plugin, foreign)
        frozen = self.snapshot(foreign)
        self.bind(frozen, source=foreign)
        self.assertFalse(self.origin.accepts(frozen / "__init__.py", "__init__.py"))

    def test_changed_missing_or_extra_snapshot_file_fails_closed(self):
        for mode in ("changed", "missing", "extra"):
            with self.subTest(mode=mode):
                origin = ProviderOrigin(self.plugin, self.home, self.core, owned_root=self.root)
                frozen = self.snapshot(name=mode)
                if mode == "changed":
                    file = frozen / "client.py"
                    before = file.stat()
                    data = file.read_bytes()
                    file.write_bytes(b"X" + data[1:])
                    os.utime(file, ns=(before.st_atime_ns, before.st_mtime_ns))
                elif mode == "missing":
                    (frozen / "client.py").unlink()
                else:
                    (frozen / "extra.py").write_text("# unexpected code\n")
                self.bind(frozen, origin=origin)
                self.assertFalse(origin.accepts(frozen / "__init__.py", "__init__.py"))
                self.assertTrue(origin.errors)

    def test_installed_tree_drift_cannot_upgrade_an_existing_origin(self):
        frozen = self.snapshot()
        self.bind(frozen)
        (self.plugin / "client.py").write_text("# another candidate\n")
        self.assertFalse(self.origin.accepts(frozen / "client.py", "client.py"))
        self.assertTrue(self.origin.errors)

    def test_snapshot_drift_after_binding_is_rejected(self):
        frozen = self.snapshot()
        self.bind(frozen)
        (frozen / "client.py").write_text("# changed after binding\n")
        self.assertFalse(self.origin.accepts(frozen / "client.py", "client.py"))

    def test_untrusted_loader_file_cannot_bind_identical_copy(self):
        frozen = self.snapshot()
        original = self.loader.__dict__["_snapshot"]
        self.loader.__dict__["_snapshot"] = lambda *args: frozen
        self.bind(frozen)
        self.assertFalse(self.origin.accepts(frozen / "__init__.py", "__init__.py"))
        self.loader.__dict__["_snapshot"] = original

    def test_symlink_snapshot_or_code_file_cannot_escape(self):
        frozen = self.snapshot()
        link = self.private / "alias"
        link.symlink_to(frozen, target_is_directory=True)
        self.bind(link)
        self.assertFalse(self.origin.accepts(link / "__init__.py", "__init__.py"))
        self.assertTrue(self.origin.errors)
        (self.plugin / "client.py").unlink()
        (self.plugin / "client.py").symlink_to(frozen / "client.py")
        with self.assertRaises(ValueError):
            ProviderOrigin(self.plugin, self.home, self.core, owned_root=self.root)

    def test_wrong_home_and_nonprivate_or_outside_snapshot_root_rejected(self):
        with self.assertRaises(ValueError):
            ProviderOrigin(self.plugin, self.root / "wrong-home", self.core)
        frozen = self.snapshot()
        self.private.chmod(0o755)
        self.bind(frozen)
        self.assertTrue(self.origin.errors)
        self.assertFalse(self.origin.accepts(frozen / "__init__.py", "__init__.py"))
        self.private.chmod(0o700)
        origin = ProviderOrigin(self.plugin, self.home, self.core, owned_root=self.home)
        self.bind(frozen, origin=origin)
        self.assertFalse(origin.accepts(frozen / "__init__.py", "__init__.py"))

    def test_receipt_has_hashes_not_home_paths_and_errors_are_sticky(self):
        frozen = self.snapshot()
        self.bind(frozen)
        value = self.origin.receipt()
        self.assertNotIn(str(self.root), str(value))
        self.assertEqual(64, len(value["tree_sha256"]))
        self.assertEqual(64, len(value["home_sha256"]))
        (frozen / "client.py").write_text("bad")
        self.assertFalse(self.origin.accepts(frozen / "client.py", "client.py"))
        shutil.copy2(self.plugin / "client.py", frozen / "client.py")
        self.assertFalse(self.origin.accepts(frozen / "client.py", "client.py"))

    def test_bytecode_cache_does_not_change_code_tree_identity(self):
        cache = self.plugin / "__pycache__"
        cache.mkdir()
        (cache / "unused.pyc").write_bytes(b"not candidate source")
        self.assertTrue(self.origin.accepts(self.plugin / "__init__.py", "__init__.py"))

    def test_executing_code_not_just_matching_filename_is_required(self):
        source = "def create_client():\n    return 42\n"
        (self.plugin / "__init__.py").write_text(source)
        origin = ProviderOrigin(self.plugin, self.home, self.core, owned_root=self.root)
        frozen = self.snapshot()
        self.bind(frozen, origin=origin)
        results = []
        def observe(frame, event, value):
            if event == "return" and frame.f_code.co_name == "create_client":
                results.append(origin.accepts_frame(frame, "__init__.py"))
        previous = sys.getprofile()
        try:
            sys.setprofile(observe)
            for code in (source, source.replace("42", "99")):
                namespace = {}
                exec(compile(code, str(frozen / "__init__.py"), "exec", dont_inherit=True), namespace)
                namespace["create_client"]()
        finally:
            sys.setprofile(previous)
        self.assertEqual([True, False], results)
        self.assertIn("runtime_code_mismatch", origin.errors)


if __name__ == "__main__":
    unittest.main()
