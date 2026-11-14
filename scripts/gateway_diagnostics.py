"""Bounded, read-only diagnostics. Never serialize free-form runtime strings.

JUnit names must match test definitions in the candidate source, parameters are
never exported, and exception labels come only from a fixed vocabulary. Cgroup
paths/stat identities are private snapshot state, not receipt fields.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET

MAX_XML_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 32768
MAX_IDENTIFIER = 128
MAX_GROUPS = 40
MAX_CASES = 3
NA = "NOT_AVAILABLE"
# Fixed built-in labels only, not arbitrary XML type/class names or messages.
EXCEPTION_TYPES = frozenset({
    "AssertionError", "AttributeError", "BlockingIOError", "BrokenPipeError", "BufferError",
    "ChildProcessError", "ConnectionAbortedError", "ConnectionError", "ConnectionRefusedError",
    "ConnectionResetError", "EOFError", "FileExistsError", "FileNotFoundError", "FloatingPointError",
    "ImportError", "IndexError", "InterruptedError", "IsADirectoryError", "KeyError", "LookupError",
    "MemoryError", "ModuleNotFoundError", "NameError", "NotADirectoryError", "NotImplementedError",
    "OSError", "OverflowError", "PermissionError", "ProcessLookupError", "RecursionError",
    "ReferenceError", "RuntimeError", "StopAsyncIteration", "StopIteration", "SyntaxError",
    "SystemError", "SystemExit", "TabError", "TimeoutError", "TypeError", "UnboundLocalError",
    "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError",
    "ValueError", "ZeroDivisionError",
})
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:]{0,127}\Z", re.ASCII)
EXCEPTION_LINE = re.compile(r"^(?:E\s+)?([A-Za-z]+):", re.MULTILINE)


def _source_cases(repo: Path) -> set[str]:
    """Source allowlist: ASCII syntax alone does not make a token safe to emit."""
    names = set()
    for path in sorted((repo / "tests").glob("test_*.py")):
        if path.is_symlink() or path.stat().st_size > 512 * 1024:
            raise ValueError("source_unavailable")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module = "tests." + path.stem
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.add(module + "::" + node.name)
            elif isinstance(node, ast.ClassDef) and (node.name.startswith("Test") or any(
                    isinstance(base, ast.Attribute) and base.attr == "TestCase" for base in node.bases)):
                for member in node.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_"):
                        names.add(module + "." + node.name + "::" + member.name)
    return {name for name in names if IDENTIFIER.fullmatch(name) and len(name) <= MAX_IDENTIFIER}


def _unavailable(reason: str) -> dict:
    return {"schema_version": 1, "status": NA, "reason": reason,
            "failure_records": NA, "omitted_records": NA, "groups": []}


def junit_summary(xml: Path, repo: Path) -> dict:
    """Count failure/error *records*, not unique nodes (teardown can duplicate nodes)."""
    try:
        with xml.open("rb") as stream:
            data = stream.read(MAX_XML_BYTES + 1)
        if len(data) > MAX_XML_BYTES:
            return _unavailable("input_limit")
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper() or b"\x00" in data:
            return _unavailable("unsafe_xml")
        root = ET.fromstring(data)
        if root.tag != "testsuites" or len(root.findall("testsuite")) != 1:
            return _unavailable("malformed")
        allowed = _source_cases(repo)
        groups: dict[tuple[str, str], dict] = {}
        total = omitted = 0
        for case in root.findall("testsuite/testcase"):
            name = case.get("name", "").split("[", 1)[0]  # no param IDs, even if ASCII
            candidate = case.get("classname", "") + "::" + name
            identity = candidate if candidate in allowed else "UNIDENTIFIED_CASE"
            for failure in case:
                if failure.tag not in {"failure", "error"}:
                    continue
                total += 1
                kind = failure.get("type", "")
                if kind not in EXCEPTION_TYPES:
                    # pytest commonly omits type=. Recognize exact built-in line prefixes
                    # from the private traceback, but never export any of that line's text.
                    kind = next((m[1] for m in EXCEPTION_LINE.finditer(failure.text or "")
                                 if m[1] in EXCEPTION_TYPES), "UNCLASSIFIED")
                key = (failure.tag, kind)
                if key not in groups:
                    if len(groups) == MAX_GROUPS:
                        omitted += 1
                        continue
                    groups[key] = {"phase": key[0], "exception": key[1], "count": 0, "cases": []}
                group = groups[key]
                group["count"] += 1
                if identity not in group["cases"] and len(group["cases"]) < MAX_CASES:
                    group["cases"].append(identity)
        result = {"schema_version": 1, "status": "AVAILABLE", "reason": "ok", "failure_records": total,
                  "omitted_records": omitted, "groups": list(groups.values())}
        if len(json.dumps(result).encode("utf-8")) > MAX_SUMMARY_BYTES:
            return _unavailable("output_limit")
        return result
    except FileNotFoundError:
        return _unavailable("missing")
    except ET.ParseError:
        return _unavailable("malformed")
    except Exception:
        # Optional observation must fail explicitly without emitting exception text.
        # This does not catch BaseException or change the separately computed suite verdict.
        return _unavailable("summary_failed")


def _read(path: Path) -> str:
    with path.open(encoding="utf-8") as stream:
        text = stream.read(131073)
    if len(text) > 131072:
        raise ValueError("input_limit")
    return text


def _number(text: str) -> int | str:
    return int(text) if re.fullmatch(r"[0-9]{1,19}", text) and int(text) <= 2**63 - 1 else NA


def _metric(path: Path) -> int | str:
    try:
        return _number(_read(path).strip())
    except (OSError, ValueError, UnicodeError):
        return NA


def _unescape(text: str) -> str:
    return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), text)


def _absolute(text: str) -> PurePosixPath:
    if not text.startswith("/") or ".." in text.split("/"):
        raise ValueError("invalid_cgroup_path")
    return PurePosixPath(text)


def _own_cgroup(proc: Path) -> tuple[str, Path, tuple]:
    """Intersect actual membership with mount root; never guess /sys/fs/cgroup/."""
    memberships = []
    for line in _read(proc / "self/cgroup").splitlines():
        hierarchy, controllers, member = line.split(":", 2)
        if hierarchy == "0" and controllers == "":
            memberships.append(("v2", _absolute(member)))
        elif "memory" in controllers.split(","):
            memberships.append(("v1", _absolute(member)))
    matches = []
    for line in _read(proc / "self/mountinfo").splitlines():
        left, right = line.split(" - ", 1)
        fields, fs = left.split(), right.split()
        for version, member in memberships:
            if (version == "v2" and fs[0] == "cgroup2") or (
                    version == "v1" and fs[0] == "cgroup" and "memory" in fs[2].split(",")):
                root = _absolute(_unescape(fields[3]))
                if not member.is_relative_to(root):
                    continue
                mount = Path(_unescape(fields[4])).resolve(strict=True)
                own = (mount / member.relative_to(root)).resolve(strict=True)
                if not own.is_relative_to(mount):
                    raise ValueError("cgroup_escape")
                stat = own.stat()
                identity = (version, str(member), str(root), str(own), stat.st_dev, stat.st_ino)
                matches.append((len(root.parts), version, own, identity))
    # Prefer the explicit v1 memory controller on a hybrid hierarchy.
    matches.sort(key=lambda row: (row[1] == "v1", row[0]), reverse=True)
    if not matches:
        raise ValueError("cgroup_not_mapped")
    _, version, own, identity = matches[0]
    return version, own, identity


def memory_snapshot(proc: Path = Path("/proc")) -> dict | None:
    """Private pre/post snapshot. Missing counters remain NA, never synthetic zero."""
    try:
        version, own, identity = _own_cgroup(proc)
        limit_file, peak_file, event_file = ("memory.max", "memory.peak", "memory.events") if version == "v2" else (
            "memory.limit_in_bytes", "memory.max_usage_in_bytes", "memory.oom_control")
        limit = _metric(own / limit_file)
        try:
            if version == "v2" and _read(own / limit_file).strip() == "max":
                limit = "UNLIMITED"
        except (OSError, ValueError, UnicodeError):
            pass
        if version == "v1" and isinstance(limit, int) and limit >= 2**60:
            limit = "UNLIMITED"  # kernel's page-aligned LONG_MAX sentinel
        events: dict[str, int | str] = {"oom": NA, "oom_kill": NA}
        try:
            for line in _read(own / event_file).splitlines():
                key, value = line.split()
                if key in events:
                    events[key] = _number(value)
        except (OSError, ValueError, UnicodeError):
            events = {"oom": NA, "oom_kill": NA}
        snapshot = {"version": version, "identity": identity, "limit_bytes": limit,
                    "peak_bytes": _metric(own / peak_file), "events": events}
        # No membership movement during the individual probe either.
        return snapshot if _own_cgroup(proc)[2] == identity else None
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def memory_diagnostics(before: dict | None, after: dict | None) -> dict:
    """Only fixed labels/numbers leave this function. Peak is lifetime, not test RSS."""
    result = {"schema_version": 1, "status": NA, "version": NA, "membership_verified": False,
              "limit_bytes": NA, "before": {"oom": NA, "oom_kill": NA},
              "after": {"oom": NA, "oom_kill": NA}, "oom_kill_delta": NA,
              "peak_bytes": NA, "peak_scope": "CGROUP_LIFETIME"}
    if before is None or after is None or before["identity"] != after["identity"]:
        return result
    result.update(version=after["version"], membership_verified=True, limit_bytes=after["limit_bytes"],
                  before=before["events"], after=after["events"], peak_bytes=after["peak_bytes"])
    start, end = before["events"]["oom_kill"], after["events"]["oom_kill"]
    if type(start) is int and type(end) is int and end >= start:
        result["oom_kill_delta"] = end - start
    result["status"] = "AVAILABLE" if (result["oom_kill_delta"] != NA and result["peak_bytes"] != NA
        and before["limit_bytes"] == after["limit_bytes"] != NA) else "PARTIAL"
    if result["limit_bytes"] == result["peak_bytes"] == NA and all(
            value == NA for events in (result["before"], result["after"]) for value in events.values()):
        result["status"] = NA
    return result
