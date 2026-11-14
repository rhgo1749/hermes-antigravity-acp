"""Offline diagnostics only: no Docker, Core import, credentials or live cgroup writes."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import xml.etree.ElementTree as ET

import pytest

from scripts import gateway_diagnostics as diag
from scripts import gateway_docker as docker


@pytest.fixture
def junit(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_sample.py").write_text(
        "def test_one(): pass\nclass TestSafe:\n    def test_two(self): pass\n")
    def write(cases):
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite", tests=str(len(cases)), failures=str(len(cases)), errors="0", skipped="0")
        for name, cls, typ, text in cases:
            case = ET.SubElement(suite, "testcase", name=name, classname=cls)
            failure = ET.SubElement(case, "failure", type=typ, message="sensitive-message")
            failure.text = text
            ET.SubElement(case, "system-out").text = "sensitive-stdout"
        xml = tmp_path / "regression.xml"
        ET.ElementTree(root).write(xml)
        return xml
    return tmp_path, write


def test_junit_group_counts_and_source_bound_cases(junit):
    repo, write = junit
    xml = write([("test_one[secret-session]", "tests.test_sample", "AssertionError", "raw prompt")] * 199)
    result = diag.junit_summary(xml, repo)
    assert result["status"] == "AVAILABLE"
    assert result["failure_records"] == 199
    assert result["groups"] == [{"phase": "failure", "exception": "AssertionError", "count": 199,
                                 "cases": ["tests.test_sample::test_one"]}]
    assert result["omitted_records"] == 0
    assert set(result) == {"schema_version", "status", "reason", "failure_records", "omitted_records", "groups"}


def test_junit_empty_and_class_case(junit):
    repo, write = junit
    assert diag.junit_summary(write([]), repo)["groups"] == []
    result = diag.junit_summary(write([("test_two", "tests.test_sample.TestSafe", "ValueError", "secret")]), repo)
    assert result["groups"][0]["cases"] == ["tests.test_sample.TestSafe::test_two"]


def test_junit_never_exports_free_form_data_even_if_ascii(junit):
    repo, write = junit
    secrets = ["sk_abcdefghijklmnopqrstuvwxyz", "/host/home/private", "SESSION_123", "sensitive-message",
               "sensitive-stdout", "raw-prompt", "A" * 1000, "bad\nidentifier", "토큰"]
    xml = write([(value, value, value, "raw-prompt") for value in secrets])
    result = diag.junit_summary(xml, repo)
    rendered = json.dumps(result)
    assert all(value not in rendered for value in secrets)
    assert {case for group in result["groups"] for case in group["cases"]} == {"UNIDENTIFIED_CASE"}
    assert {g["exception"] for g in result["groups"]} == {"UNCLASSIFIED"}
    # Even a safe-looking token on an otherwise genuine testcase cannot escape through the type.
    result = diag.junit_summary(write([("test_one", "tests.test_sample", "TOKEN_ABC", "raw-prompt")]), repo)
    assert "TOKEN_ABC" not in json.dumps(result)


def test_junit_exception_fallback_uses_only_fixed_type_names(junit):
    repo, write = junit
    xml = write([("test_one", "tests.test_sample", "", "E   PermissionError: /host/SECRET"),
                 ("test_one", "tests.test_sample", "", "E   ArbitrarySecret: TOKEN")])
    result = diag.junit_summary(xml, repo)
    assert {g["exception"] for g in result["groups"]} == {"PermissionError", "UNCLASSIFIED"}
    assert "SECRET" not in json.dumps(result) and "TOKEN" not in json.dumps(result)


def test_junit_group_case_string_and_byte_bounds(junit):
    repo, write = junit
    # Exercise >40 groups and >3 distinct examples per group using trusted synthetic source.
    definitions = "\n".join(f"def test_case_{i}(): pass" for i in range(120))
    (repo / "tests/test_sample.py").write_text(definitions)
    cases = [(f"test_case_{i}", "tests.test_sample", typ, "x")
             for typ in diag.EXCEPTION_TYPES for i in range(120)]
    xml = write(cases)
    result = diag.junit_summary(xml, repo)
    assert len(result["groups"]) <= 40
    assert all(len(g["cases"]) <= 3 for g in result["groups"])
    assert all(len(c) <= diag.MAX_IDENTIFIER for g in result["groups"] for c in g["cases"])
    assert len(json.dumps(result).encode()) <= diag.MAX_SUMMARY_BYTES
    assert sum(g["count"] for g in result["groups"]) + result["omitted_records"] == len(cases)
    assert result["omitted_records"] > 0


@pytest.mark.parametrize("content,reason", [(None, "missing"), ("<bad", "malformed"),
    ('<!DOCTYPE x [<!ENTITY secret "TOKEN">]><testsuites/>', "unsafe_xml"),
    ("<testsuites/>", "malformed")])
def test_junit_unavailable_never_echoes_parse_errors(tmp_path, content, reason):
    xml = tmp_path / "input.xml"
    if content is not None:
        xml.write_text(content)
    result = diag.junit_summary(xml, tmp_path)
    assert result["status"] == "NOT_AVAILABLE"
    assert result["reason"] == reason
    assert result["groups"] == []
    assert "TOKEN" not in json.dumps(result)


def test_junit_oversized_input_and_source_failure(junit):
    repo, write = junit
    xml = write([("test_one", "tests.test_sample", "AssertionError", "x")])
    with patch.object(diag, "MAX_XML_BYTES", 10):
        assert diag.junit_summary(xml, repo)["reason"] == "input_limit"
    (repo / "tests/test_sample.py").write_text("not valid python :")
    assert diag.junit_summary(xml, repo)["status"] == "NOT_AVAILABLE"


@pytest.fixture
def cgroup(tmp_path):
    proc, mount = tmp_path / "proc", tmp_path / "cgroup"
    (proc / "self").mkdir(parents=True)
    mount.mkdir()
    def setup(version=2, membership="/job", root="/", files=None):
        (proc / "self/cgroup").write_text("0::" + membership + "\n" if version == 2 else "7:cpu,memory:" + membership + "\n")
        fs = "cgroup2 cgroup rw" if version == 2 else "cgroup cgroup rw,memory"
        (proc / "self/mountinfo").write_text(f"31 20 0:27 {root} {mount} ro - {fs}\n")
        relative = Path(membership).relative_to(root)
        own = mount / relative
        own.mkdir(parents=True, exist_ok=True)
        values = files if files is not None else ({"memory.max": "2147483648", "memory.peak": "123456",
            "memory.events": "low 0\nhigh 0\nmax 5\noom 2\noom_kill 1\noom_group_kill 0\n"} if version == 2 else {
            "memory.limit_in_bytes": "2147483648", "memory.max_usage_in_bytes": "654321",
            "memory.oom_control": "oom_kill_disable 0\nunder_oom 0\noom_kill 3\n"})
        for name, value in values.items():
            (own / name).write_text(value)
        return own
    return proc, mount, setup


def test_cgroup_v2_own_membership_delta_and_no_paths(cgroup):
    proc, mount, setup = cgroup
    own = setup()
    before = diag.memory_snapshot(proc)
    (own / "memory.events").write_text("oom 5\noom_kill 3\n")
    after = diag.memory_snapshot(proc)
    result = diag.memory_diagnostics(before, after)
    assert result["status"] == "AVAILABLE"
    assert result["version"] == "v2" and result["membership_verified"] is True
    assert result["limit_bytes"] == 2147483648
    assert result["oom_kill_delta"] == 2
    assert result["before"]["oom_kill"] == 1 and result["after"]["oom_kill"] == 3
    assert result["peak_bytes"] == 123456
    assert result["peak_scope"] == "CGROUP_LIFETIME"
    assert str(mount) not in json.dumps(result)
    assert "/job" not in json.dumps(result)
    assert all(p.read_text() for p in own.iterdir())  # probes only read


def test_cgroup_v1_and_mount_root_mapping(cgroup):
    proc, _, setup = cgroup
    own = setup(1, "/docker/container/job", "/docker/container")
    before = diag.memory_snapshot(proc)
    (own / "memory.oom_control").write_text("oom_kill_disable 0\nunder_oom 0\noom_kill 7\n")
    result = diag.memory_diagnostics(before, diag.memory_snapshot(proc))
    assert result["version"] == "v1" and result["oom_kill_delta"] == 4
    assert result["peak_bytes"] == 654321
    assert result["before"]["oom"] == "NOT_AVAILABLE"  # v1 has no oom count


def test_cgroup_namespaced_root_zero_is_observed_not_fabricated(cgroup):
    proc, _, setup = cgroup
    setup(2, "/", "/", {"memory.max": "max", "memory.events": "oom 0\noom_kill 0\n"})
    result = diag.memory_diagnostics(diag.memory_snapshot(proc), diag.memory_snapshot(proc))
    assert result["limit_bytes"] == "UNLIMITED"
    assert result["peak_bytes"] == "NOT_AVAILABLE"
    assert result["oom_kill_delta"] == 0
    assert result["status"] == "PARTIAL"


@pytest.mark.parametrize("damage", ["no_proc", "no_files", "bad_counter", "reset", "moved", "root_mismatch", "traversal"])
def test_cgroup_unavailable_reset_and_membership_drift(cgroup, damage):
    proc, _, setup = cgroup
    own = setup()
    before = diag.memory_snapshot(proc)
    if damage == "no_proc":
        (proc / "self/cgroup").unlink()
    elif damage == "no_files":
        for p in own.iterdir():
            p.unlink()
    elif damage == "bad_counter":
        (own / "memory.events").write_text("oom_kill TOKEN_SECRET\n")
    elif damage == "reset":
        (own / "memory.events").write_text("oom 0\noom_kill 0\n")
    elif damage == "moved":
        (proc / "self/cgroup").write_text("0::/other\n")
    elif damage == "root_mismatch":
        (proc / "self/mountinfo").write_text((proc / "self/mountinfo").read_text().replace("0:27 / ", "0:27 /foreign "))
    else:
        (proc / "self/cgroup").write_text("0::/../escape\n")
    result = diag.memory_diagnostics(before, diag.memory_snapshot(proc))
    assert result["oom_kill_delta"] == "NOT_AVAILABLE"
    assert result["status"] != "AVAILABLE"
    assert "TOKEN_SECRET" not in json.dumps(result)


def test_diagnostic_failure_does_not_change_regression_verdict(junit):
    repo, write = junit
    xml = write([("test_one", "tests.test_sample", "AssertionError", "secret")])
    def fake_run(*args, **kwargs):
        assert args[0][1:7] == ["-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"]
        assert kwargs["timeout"] == 180
        assert kwargs["cwd"] == repo
        (xml.parent / "regression.xml").write_bytes(xml.read_bytes())
        return SimpleNamespace(returncode=1)
    with patch.object(docker.subprocess, "run", side_effect=fake_run), patch.object(docker.diagnostics, "memory_snapshot", return_value=None):
        result = docker.run_regression(repo, {}, xml.parent)
    assert result["regression"]["status"] == "FAIL"
    assert result["regression_summary"]["groups"][0]["count"] == 1
    assert result["regression_memory"]["status"] == "NOT_AVAILABLE"
    assert "container_regression_not_pass" in docker.validate_docker_receipt(result)


@pytest.mark.parametrize("mode", ["bad_xml", "no_xml", "timeout"])
def test_regression_errors_still_preserve_bounded_diagnostics(tmp_path, mode):
    def fake_run(*args, **kwargs):
        if mode == "bad_xml":
            (tmp_path / "regression.xml").write_text("<bad TOKEN_SECRET")
        if mode == "timeout":
            raise docker.subprocess.TimeoutExpired("private-path", 180)
        return SimpleNamespace(returncode=0)
    with patch.object(docker.subprocess, "run", side_effect=fake_run), patch.object(docker.diagnostics, "memory_snapshot", return_value=None):
        result = docker.run_regression(tmp_path, {}, tmp_path)
    assert result["regression"]["status"] == "FAIL"
    assert result["regression_summary"]["status"] == "NOT_AVAILABLE"
    assert "TOKEN_SECRET" not in json.dumps(result) and "private-path" not in json.dumps(result)


def test_junit_internal_failure_long_source_name_and_error_records(junit):
    repo, write = junit
    long_name = "test_" + "x" * 200
    (repo / "tests/test_sample.py").write_text(f"def {long_name}(): pass\n")
    xml = write([(long_name, "tests.test_sample", "AssertionError", "private")])
    result = diag.junit_summary(xml, repo)
    assert result["groups"][0]["cases"] == ["UNIDENTIFIED_CASE"]
    root = ET.parse(xml)
    failure = root.find("testsuite/testcase/failure")
    assert failure is not None
    failure.tag = "error"
    root.write(xml)
    assert diag.junit_summary(xml, repo)["groups"][0]["phase"] == "error"
    with patch.object(diag, "_source_cases", side_effect=RuntimeError("TOKEN_PRIVATE")):
        result = diag.junit_summary(xml, repo)
    assert result["status"] == "NOT_AVAILABLE" and result["reason"] == "summary_failed"
    assert "TOKEN_PRIVATE" not in json.dumps(result)


def test_cgroup_missing_legacy_kill_counter_and_no_metrics(cgroup):
    proc, _, setup = cgroup
    setup(1, files={"memory.limit_in_bytes": "2147483648",
                    "memory.oom_control": "oom_kill_disable 0\nunder_oom 0\n"})
    result = diag.memory_diagnostics(diag.memory_snapshot(proc), diag.memory_snapshot(proc))
    assert result["status"] == "PARTIAL" and result["oom_kill_delta"] == "NOT_AVAILABLE"
    setup(2, files={})
    result = diag.memory_diagnostics(diag.memory_snapshot(proc), diag.memory_snapshot(proc))
    assert result["status"] == "NOT_AVAILABLE"


def test_real_pytest_child_yields_safe_summary_and_keeps_fail(tmp_path):
    import sys
    tests = tmp_path / "tests"
    tests.mkdir()
    secret = "PRIVATE_PROMPT_TOKEN_123"
    (tests / "test_child.py").write_text(
        'import pytest\n@pytest.mark.parametrize("value", ["' + secret + '"])\n'
        'def test_denied(value):\n    raise PermissionError("/host/private/" + value)\n')
    env = {"PATH": str(Path(sys.executable).parent), "HOME": str(tmp_path), "HERMES_HOME": str(tmp_path / "home"),
           "TMPDIR": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    # Real pytest child; no Core import or container launch.
    with patch.object(docker.diagnostics, "memory_snapshot", return_value=None):
        result = docker.run_regression(tmp_path, env, tmp_path)
    assert result["regression"]["status"] == "FAIL" and result["regression"]["failures"] == 1
    assert result["regression_summary"]["groups"][0]["exception"] == "PermissionError"
    # A non-package tmp tests directory can omit tests. in JUnit: do not guess attribution.
    assert result["regression_summary"]["groups"][0]["cases"] in (
        ["tests.test_child::test_denied"], ["UNIDENTIFIED_CASE"])
    rendered = json.dumps(result)
    assert secret not in rendered and "/host/private" not in rendered and str(tmp_path) not in rendered
    assert secret in (tmp_path / "regression.xml").read_text()  # raw data existed, stayed private
    assert result["regression_summary"]["runtime"]["pytest"] != "NOT_AVAILABLE"
    assert (tmp_path / "regression.log").stat().st_size > 0
