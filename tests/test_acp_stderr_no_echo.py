"""historical reference: the runtime ACP client must never echo raw child-process stderr.

The vendor ACP child process is untrusted output: a login/headless-auth
surface can dump credential-shaped material onto stderr.  The runtime
client's early-exit path used to interpolate the captured stderr tail
verbatim into a ``RuntimeError``.  These tests drive a fake ACP child that
emits synthetic credential-shaped stderr and exits (or stalls), asserting
the public exception/log/chat-error surfaces carry zero verbatim child
output while the diagnostic stays deterministic, bounded, and actionable
(class names, line/byte counts, and a truncated sha256 fingerprint only).

The credential-shaped strings are assembled at RUNTIME from inert
fragments so the public repository tree stays audit-clean.  These are
synthetic-shape behavior tests: they prove no-echo propagation, not any
vendor-policy compliance, and they assert no real credential was exposed.

Rework (Reviewer review-record / run 455): suppressing the stderr echo must
not suppress previously-eligible retry/failover.  When the early-exit
stderr carries a rate-limit or authentication signature (exit code 3 in
the pre-fix evidence), the client must still classify the attempt as
failover-eligible via a structured signal that never crosses public
surfaces as raw child text.  The failover regressions below pin that
behavior.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = (
    Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
)

# Synthetic values (never live credentials).  The shape fragments that the
# public-tree byte auditor treats as real-credential literals are assembled
# at runtime so no committed file contains a matching literal.
_SECRET_TOKEN_ASSIGNMENT = "SYNTH" + ".EARLYEXIT" + ".TOKEN" + ".VALUE" + ".AAAA"
_SECRET_BEARER = "SYNTHETICBearerValue" + "BBBB"
_BENIGN_CHATTER = "routine bootstrap chatter from the fake acp server"

_EARLY_EXIT_STDERR = (
    _BENIGN_CHATTER,
    "login surface dump: access_token=" + _SECRET_TOKEN_ASSIGNMENT,
    "Bea" + "rer " + _SECRET_BEARER,
)

_MARKERS = (_SECRET_TOKEN_ASSIGNMENT, _SECRET_BEARER, _BENIGN_CHATTER,
            "login surface dump")


def _load_client(
    monkeypatch,
    *,
    command: str,
    args: list[str],
    cwd: str,
    rate_limit_retries: int = 0,
):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(Path(cwd) / "acp-conversation-state.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(Path(cwd) / "acp-limits.json"),
    )
    registered = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)
    # Same client-side stubs the 121 stabilization suite uses so a failover
    # replay that reaches a full successful turn exercises identical wiring.
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)

    module_name = "antigravity_acp_stderr_no_echo"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.antigravity_acp.create_client(
        command=command,
        args=args,
        acp_cwd=cwd,
        rate_limit_retries=rate_limit_retries,
    )


def _write_child(tmp_path: Path, *, name: str, body: str) -> Path:
    script = tmp_path / name
    script.write_text(
        "import sys\nimport time\n"
        + f"STDERR_LINES = {_EARLY_EXIT_STDERR!r}\n"
        + body,
        encoding="utf-8",
    )
    return script


_EARLY_EXIT_BODY = """
sys.stdin.readline()  # consume the initialize request
sys.stderr.write("\\n".join(STDERR_LINES) + "\\n")
sys.stderr.flush()
sys.exit(3)
"""

_STALL_BODY = """
sys.stdin.readline()  # consume the initialize request
sys.stderr.write(STDERR_LINES[1] + "\\n")
sys.stderr.flush()
time.sleep(60)  # never answer; the client must hit its session timeout
"""


def _all_logged_text(caplog) -> str:
    return "\n".join(
        f"{record.name}:{record.getMessage()}" for record in caplog.records
    )


def test_early_exit_never_echoes_child_stderr_into_exception_or_logs(
    monkeypatch, tmp_path, caplog
) -> None:
    """RED oracle: fake ACP child writes secret-shaped stderr, exits before
    initialize completes.  The client must still raise a deterministic
    RuntimeError whose text carries zero verbatim child output."""
    script = _write_child(tmp_path, name="fake_acp_early_exit.py", body=_EARLY_EXIT_BODY)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
    )

    with caplog.at_level(logging.DEBUG):
        try:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
            )
        except RuntimeError as exc:
            diagnostic = str(exc)
        else:
            raise AssertionError("fake early-exit ACP child did not surface RuntimeError")

    logged = _all_logged_text(caplog)

    # Deterministic, actionable early-exit class survives.
    assert "Antigravity ACP process exited early" in diagnostic
    assert "server stderr suppressed" in diagnostic
    assert "credential-shape classes observed" in diagnostic
    assert re.search(r"sha256=[0-9a-f]{16}", diagnostic)
    # Class NAMES (fixed strings) may appear; values may not.
    assert "token-assignment" in diagnostic
    assert "bearer-token" in diagnostic
    # No verbatim child output anywhere in the public surfaces.
    for marker in _MARKERS:
        assert marker not in diagnostic, marker
    for line in _EARLY_EXIT_STDERR:
        assert line not in diagnostic, line
        assert line not in logged, line
    for marker in _MARKERS:
        assert marker not in logged, marker
    # The diagnostic is bounded even against a 40-line stderr tail.
    assert len(diagnostic) < 1000


def test_early_exit_diagnostic_is_deterministic_and_non_reversible(
    monkeypatch, tmp_path
) -> None:
    """Two identical early-exit sessions produce byte-identical diagnostics
    (correlation-safe), and the fingerprint never carries the payload."""
    import hashlib

    script = _write_child(
        tmp_path, name="fake_acp_deterministic.py", body=_EARLY_EXIT_BODY
    )
    diagnostics: list[str] = []
    for run in range(2):
        if run:
            # Separate cwd so state files never cross-contaminate runs.
            cwd = tmp_path / f"run-{run}"
            cwd.mkdir()
        else:
            cwd = tmp_path / "run-0"
            cwd.mkdir()
        client = _load_client(
            monkeypatch, command=sys.executable, args=[str(script)], cwd=str(cwd)
        )
        try:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
            )
        except RuntimeError as exc:
            diagnostics.append(str(exc))
        else:
            raise AssertionError("fake early-exit ACP child did not surface RuntimeError")

    assert diagnostics[0] == diagnostics[1]
    joined = "\n".join(_EARLY_EXIT_STDERR)
    # The full-payload digest must not be recoverable from the truncated one.
    assert hashlib.sha256(joined.encode()).hexdigest() not in diagnostics[0]


def test_stderr_summary_helper_echoes_nothing_and_never_reverses_secrets(
    monkeypatch, tmp_path
) -> None:
    """The runtime-local summary helper itself is bounded, deterministic and
    free of any input substring beyond fixed class names."""
    import hashlib

    _load_client(
        monkeypatch, command=sys.executable, args=["-c", "pass"], cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_stderr_no_echo.client"]
    summary = client_module._acp_stderr_diagnostic(_EARLY_EXIT_STDERR)

    for line in _EARLY_EXIT_STDERR:
        assert line not in summary, line
    for marker in _MARKERS:
        assert marker not in summary, marker
    assert "server stderr suppressed" in summary
    assert "3 line(s)" in summary
    assert "credential-shape classes observed" in summary
    assert "token-assignment" in summary and "bearer-token" in summary
    assert summary == client_module._acp_stderr_diagnostic(_EARLY_EXIT_STDERR)
    assert re.search(r"sha256=[0-9a-f]{16}", summary)
    assert len(summary) <= 400
    joined = "\n".join(_EARLY_EXIT_STDERR)
    assert hashlib.sha256(joined.encode()).hexdigest() not in summary


def test_stalled_child_timeout_error_never_echoes_child_stderr(
    monkeypatch, tmp_path
) -> None:
    """The sibling timeout path in the same request loop must also carry no
    raw child stderr."""
    script = _write_child(tmp_path, name="fake_acp_stall.py", body=_STALL_BODY)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
    )
    with pytest.raises(TimeoutError) as raised:
        client.list_models(timeout_seconds=2.0)
    message = str(raised.value)
    assert "Timed out" in message
    for marker in _MARKERS:
        assert marker not in message, marker


def test_early_exit_without_stderr_keeps_timeout_error_class(
    monkeypatch, tmp_path
) -> None:
    """Trigger-semantics pin: the pre-fix code raised TimeoutError (not
    RuntimeError) when the child exited early with no stderr text.  That
    classification boundary must survive the no-echo fix."""
    script = tmp_path / "fake_acp_silent_exit.py"
    script.write_text(
        "import sys\n"
        "sys.stdin.readline()\n"
        "sys.exit(7)\n",
        encoding="utf-8",
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
    )
    with pytest.raises(TimeoutError):
        client.list_models(timeout_seconds=5.0)


# ---------------------------------------------------------------------------
# historical reference rework (Reviewer review-record / run 455): the no-echo fix must not
# suppress previously-eligible retry/failover for rate-limit / authentication
# early-exit stderr.
# ---------------------------------------------------------------------------

# Signature phrases the client's existing failover regexes match, each
# carrying a unique synthetic nonce so even a PARTIAL echo is detectable.
# Assembled at runtime like the fragments above; nothing credential-shaped
# is committed.
_SYNTH_RL_NONCE = "SYNTH" + "RLNONCE" + "7731"
_SYNTH_AUTH_PRINCIPAL = "SYNTH" + "AUTHPRIN" + "4402"
_RATE_LIMIT_SIG_LINE = "upstream api gate: 429 too many requests; herd=" + _SYNTH_RL_NONCE
_AUTH_SIG_LINE = "login surface: authentication failed; principal=" + _SYNTH_AUTH_PRINCIPAL
_CRED_SHAPED_LINE = _EARLY_EXIT_STDERR[1]

# The structured retry signal may only ever carry these fixed names (or
# None), which is what makes the signal itself non-reversible.
_FIXED_RETRY_CLASSES = {"rate-limit", "authentication"}

_RECOVERY_ANSWER = "recovered after an early-exit failover replay"

_RETRY_CHILD_BODY = '''
import json
import sys

with open(COUNTER, "a", encoding="utf-8") as fh:
    fh.write("spawn\\n")
spawn_index = sum(1 for _ in open(COUNTER, encoding="utf-8"))


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\\n")
    sys.stdout.flush()


if RECOVER_FROM and spawn_index > 1:
    # Behave like a healthy ACP child from the second spawn on, so a
    # successful failover replay can complete a full turn.
    for line in sys.stdin:
        msg = json.loads(line)
        method, rid = msg.get("method"), msg.get("id")
        if method == "initialize":
            emit({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": 1}})
        elif method == "session/new":
            emit({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": "s-recovered"}})
        elif method == "session/prompt":
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": ANSWER_TEXT}}}})
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
else:
    sys.stdin.readline()  # consume the initialize request
    sys.stderr.write("\\n".join(STDERR_LINES) + "\\n")
    sys.stderr.flush()
    sys.exit(EXIT_CODE)
'''


def _write_retry_child(
    tmp_path: Path,
    *,
    name: str,
    stderr_lines: tuple[str, ...],
    recover_from: bool,
    exit_code: int = 3,
) -> tuple[Path, Path]:
    counter = tmp_path / f"{name}.counter"
    script = tmp_path / f"{name}.py"
    script.write_text(
        f"COUNTER = {str(counter)!r}\n"
        f"STDERR_LINES = {stderr_lines!r}\n"
        f"EXIT_CODE = {exit_code!r}\n"
        f"RECOVER_FROM = {recover_from!r}\n"
        f"ANSWER_TEXT = {_RECOVERY_ANSWER!r}\n"
        + _RETRY_CHILD_BODY,
        encoding="utf-8",
    )
    return script, counter


def _spawn_count(counter: Path) -> int:
    if not counter.exists():
        return 0
    return counter.read_text(encoding="utf-8").count("spawn")


_RETRYABLE_SIG_CASES = [
    pytest.param(_RATE_LIMIT_SIG_LINE, "rate-limit", id="rate-limit"),
    pytest.param(_AUTH_SIG_LINE, "authentication", id="authentication"),
]

_LEAK_MARKERS = (
    "login surface dump",
    "429 too many requests",
    "authentication failed",
    "herd=",
    "principal=",
)


@pytest.mark.parametrize(("sig_line", "expected_class"), _RETRYABLE_SIG_CASES)
def test_early_exit_retryable_stderr_recovers_via_failover(
    monkeypatch, tmp_path, caplog, sig_line: str, expected_class: str
) -> None:
    """Rework RED oracle: pre-historical reference, exit code 3 with rate-limit / auth
    stderr was classified retryable because the raw text sat in the
    exception; the no-echo fix must keep that failover eligibility through
    a structured signal: the second spawn completes the turn."""
    script, counter = _write_retry_child(
        tmp_path,
        name="fake_acp_retry_sig",
        stderr_lines=(sig_line, _CRED_SHAPED_LINE),
        recover_from=True,
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
        rate_limit_retries=1,
    )
    with caplog.at_level(logging.DEBUG):
        reply = client.chat.completions.create(
            model="antigravity-acp",
            messages=[{"role": "user", "content": "hello"}],
            timeout=30,
        )
    assert reply.choices[0].message.content == _RECOVERY_ANSWER
    assert _spawn_count(counter) == 2  # first failure + one failover replay
    logged = _all_logged_text(caplog)
    assert "failover attempt 1/1" in logged
    # The recovered turn's reply and every log record must be free of raw
    # child stderr from the FIRST (failed) attempt.  Both signatures are
    # asserted globally: each case's child only ever emits its own.
    for marker in (*_LEAK_MARKERS, _SYNTH_RL_NONCE, _SYNTH_AUTH_PRINCIPAL,
                   _SECRET_TOKEN_ASSIGNMENT):
        assert marker not in logged, marker
        assert marker not in reply.choices[0].message.content, marker


@pytest.mark.parametrize(("sig_line", "expected_class"), _RETRYABLE_SIG_CASES)
def test_early_exit_retryable_stderr_spends_failover_budget_then_surfaces(
    monkeypatch, tmp_path, caplog, sig_line: str, expected_class: str
) -> None:
    """With retries=1 a persistently failing child is re-spawned exactly
    once (classification preserved), then surfaces.  The raised exception
    carries the bounded no-echo summary while the fixed retry class rides a
    structured attribute — never the message text."""
    script, counter = _write_retry_child(
        tmp_path,
        name="fake_acp_retry_exhaust",
        stderr_lines=(sig_line, _CRED_SHAPED_LINE),
        recover_from=False,
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
        rate_limit_retries=1,
    )
    with caplog.at_level(logging.DEBUG):
        try:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
                timeout=30,
            )
        except RuntimeError as exc:
            surfaced = exc
        else:
            raise AssertionError("fake early-exit ACP child did not surface RuntimeError")

    assert _spawn_count(counter) == 2
    assert "failover attempt 1/1" in _all_logged_text(caplog)
    diagnostic = str(surfaced)
    assert "Antigravity ACP process exited early" in diagnostic
    assert "server stderr suppressed" in diagnostic
    # The separate structured signal carries the fixed class name.
    assert getattr(surfaced, "acp_retry_class", None) == expected_class
    logged = _all_logged_text(caplog)
    for marker in (*_LEAK_MARKERS, _SYNTH_RL_NONCE, _SYNTH_AUTH_PRINCIPAL,
                   _SECRET_TOKEN_ASSIGNMENT):
        assert marker not in diagnostic, marker
        assert marker not in repr(surfaced), marker
        assert marker not in logged, marker


def test_early_exit_without_retry_signature_is_not_failed_over(
    monkeypatch, tmp_path, caplog
) -> None:
    """Safety-side preservation: benign stderr that matched no failover
    signature pre-fix must still not trigger any failover now."""
    script, counter = _write_retry_child(
        tmp_path,
        name="fake_acp_benign_exit",
        stderr_lines=(_BENIGN_CHATTER,),
        recover_from=True,
        exit_code=5,
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
        rate_limit_retries=1,
    )
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError) as raised:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
                timeout=30,
            )
    assert _spawn_count(counter) == 1
    assert "failover attempt" not in _all_logged_text(caplog)
    assert getattr(raised.value, "acp_retry_class", None) is None
    assert "server stderr suppressed" in str(raised.value)
    assert _BENIGN_CHATTER not in str(raised.value)


def test_stderr_retry_class_helper_returns_only_fixed_class_names(
    monkeypatch, tmp_path
) -> None:
    """Helper-level pin: classification returns fixed enum names (or None)
    computed from captured stderr, and ``_is_failover_error`` consumes the
    structured signal without re-opening a raw-content string path."""
    _load_client(
        monkeypatch, command=sys.executable, args=["-c", "pass"], cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_stderr_no_echo.client"]

    assert client_module._acp_stderr_retry_class([_RATE_LIMIT_SIG_LINE]) == "rate-limit"
    assert client_module._acp_stderr_retry_class([_AUTH_SIG_LINE]) == "authentication"
    assert client_module._acp_stderr_retry_class([_BENIGN_CHATTER]) is None
    assert client_module._acp_stderr_retry_class([]) is None

    early = client_module._AcpEarlyExitError(
        "bounded summary only", acp_retry_class="rate-limit"
    )
    assert isinstance(early, RuntimeError)
    assert client_module._is_failover_error(early) is True
    unclassified = client_module._AcpEarlyExitError(
        "bounded summary only", acp_retry_class=None
    )
    assert client_module._is_failover_error(unclassified) is False
    # The string path for pre-existing (server-error) classification is
    # untouched.
    assert client_module._is_failover_error(RuntimeError("429 Too Many Requests")) is True
    assert client_module._is_failover_error(RuntimeError("routine failure")) is False
    # Signal values are fixed names; never derived from child text.
    for lines in (_EARLY_EXIT_STDERR, (_RATE_LIMIT_SIG_LINE, _AUTH_SIG_LINE)):
        result = client_module._acp_stderr_retry_class(list(lines))
        assert result is None or result in _FIXED_RETRY_CLASSES, result


# ---------------------------------------------------------------------------
# historical reference rework 2 (Reviewer review-record / run 458, reviewed head
# 3a91d47f1968bda5fefa9852f1f273326788bb44): ``_is_failover_error`` fell
# through to parsing the GENERATED no-echo diagnostic whenever the
# structured retry class was absent.  The diagnostic embeds the captured
# stderr byte count, so benign stderr of exactly 401/403/429 bytes matched
# the word-boundary auth / rate-limit signatures and became falsely
# retryable / failover-eligible solely from that byte count.  Early-exit
# classification is now EXCLUSIVELY structured: a capture-time class is
# honored, and no generated diagnostic or stderr-derived summary is ever
# re-parsed on this path.  Legacy string classification for unrelated
# (non-``_AcpEarlyExitError``) errors stays untouched.
# ---------------------------------------------------------------------------

_BENIGN_FILLER = "routine bootstrap chatter from the fake acp server padding "


def _benign_stderr_of_exact_size(nbytes: int) -> str:
    """One benign single-line stderr string of exactly ``nbytes`` bytes.

    Pure ASCII with no signature- or credential-shape words, so the only
    failover-signature-looking number in the whole early-exit surface is
    the diagnostic's own byte count.
    """
    line = _BENIGN_FILLER + "x" * (nbytes - len(_BENIGN_FILLER))
    assert len(line.encode("utf-8")) == nbytes
    return line


@pytest.mark.parametrize("byte_count", [401, 403, 429])
def test_benign_stderr_padded_to_signature_byte_counts_is_not_failed_over(
    monkeypatch, tmp_path, caplog, byte_count: int
) -> None:
    """Behavioral RED oracle: benign synthetic stderr padded to exactly
    401 / 403 / 429 bytes exits early (code 3) while a healthy second
    spawn WOULD have recovered the turn.  The early exit must surface
    immediately with zero failover — the summary byte count alone may not
    make the error retryable."""
    stderr_line = _benign_stderr_of_exact_size(byte_count)
    script, counter = _write_retry_child(
        tmp_path,
        name=f"fake_acp_pad_{byte_count}",
        stderr_lines=(stderr_line,),
        recover_from=True,
        exit_code=3,
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script)],
        cwd=str(tmp_path),
        rate_limit_retries=1,
    )
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError) as raised:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
                timeout=30,
            )
    diagnostic = str(raised.value)
    # Padding determinism pin: the diagnostic really reported the trap size.
    assert f"{byte_count} byte(s)" in diagnostic
    assert "Antigravity ACP process exited early" in diagnostic
    assert getattr(raised.value, "acp_retry_class", None) is None
    # Solely-structured classification: no failover replay was attempted.
    assert _spawn_count(counter) == 1
    assert "failover attempt" not in _all_logged_text(caplog)
    # No-echo preservation on the same path.
    assert stderr_line not in diagnostic
    assert stderr_line not in _all_logged_text(caplog)


@pytest.mark.parametrize("byte_count", [401, 403, 429])
def test_failover_classification_of_early_exit_is_exclusively_structured(
    monkeypatch, tmp_path, byte_count: int
) -> None:
    """Helper-level RED oracle for the exact reviewed boundary.

    The diagnostic text built around a benign ``byte_count``-byte stderr
    tail still trips the legacy signature regexes (trap pin, and proof the
    non-``_AcpEarlyExitError`` string path is retained verbatim).  An
    UNCLASSIFIED ``_AcpEarlyExitError`` carrying that text must refuse the
    string fallback, while a structured class remains authoritative
    regardless of the diagnostic's byte count.
    """
    _load_client(
        monkeypatch, command=sys.executable, args=["-c", "pass"], cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_stderr_no_echo.client"]
    stderr_line = _benign_stderr_of_exact_size(byte_count)
    diagnostic = (
        "Antigravity ACP process exited early (exit code 3); "
        f"{client_module._acp_stderr_diagnostic([stderr_line])}. "
        "Inspect the configured ACP command's own output manually "
        "if more detail is required."
    )
    assert f"{byte_count} byte(s)" in diagnostic
    # Trap pin: the byte count alone still matches the legacy signatures,
    # and unrelated (non-early-exit) errors keep that string classification.
    assert client_module._is_failover_error(RuntimeError(diagnostic)) is True
    # The early-exit path never consults its generated text.
    unclassified = client_module._AcpEarlyExitError(
        diagnostic, acp_retry_class=None
    )
    assert client_module._is_failover_error(unclassified) is False
    # Explicitly structured classification stays authoritative.
    structured = client_module._AcpEarlyExitError(
        diagnostic, acp_retry_class="authentication"
    )
    assert client_module._is_failover_error(structured) is True
