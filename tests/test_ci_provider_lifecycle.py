"""The common native lifecycle must actually observe deletion, never assume it."""
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import ci_provider_lifecycle as driver


@pytest.fixture
def installed(monkeypatch):
    before = dict(official_server=True, official_launcher=True, provider_registered=True, provider_executable=True)
    after = dict.fromkeys(before, False)
    status = Mock(side_effect=[before, after])
    verify, delete = Mock(), Mock()
    monkeypatch.setattr(driver.install_acp, "status", status)
    monkeypatch.setattr(driver.install_acp, "verify", verify)
    monkeypatch.setattr(driver.install_acp, "delete", delete)
    return before, after, status, verify, delete


def test_common_lifecycle_reuses_installer_and_confirms_absence(tmp_path, installed):
    before, after, status, verify, delete = installed
    home, prefix, bin_dir = (tmp_path / name for name in ("home", "prefix", "bin"))
    result = driver.verify_and_remove(home, prefix, bin_dir)
    verify.assert_called_once_with(home, prefix, bin_dir, timeout=60.0)
    delete.assert_called_once_with(home, prefix, bin_dir)
    assert status.call_count == 2
    assert result["status"] == "PASS" and result["before"] == before and result["after"] == after
    assert result["authenticated"] is False and result["prompts"] == 0


@pytest.mark.parametrize("field", ("official_server", "official_launcher", "provider_registered", "provider_executable"))
def test_surviving_managed_state_is_failure(tmp_path, installed, field):
    before, _, status, _, _ = installed
    remaining = dict.fromkeys(before, False)
    remaining[field] = True
    status.side_effect = [before, remaining]
    with pytest.raises(RuntimeError, match="survived removal"):
        driver.verify_and_remove(tmp_path, tmp_path, tmp_path)


def test_incomplete_installed_state_does_not_delete(tmp_path, installed):
    _, _, status, verify, delete = installed
    status.side_effect = [{"official_server": False}]
    with pytest.raises(RuntimeError, match="incomplete"):
        driver.verify_and_remove(tmp_path, tmp_path, tmp_path)
    verify.assert_not_called()
    delete.assert_not_called()


def test_verification_failure_is_not_converted_to_pass(tmp_path, installed):
    _, _, _, verify, delete = installed
    verify.side_effect = RuntimeError("failed pin or initialize")
    with pytest.raises(RuntimeError, match="failed pin"):
        driver.verify_and_remove(tmp_path, tmp_path, tmp_path)
    delete.assert_not_called()


def test_cli_fails_without_claiming_pass(tmp_path, installed, capsys):
    _, _, _, _, delete = installed
    delete.side_effect = OSError("private path must not be echoed")
    assert driver.main(["--hermes-home", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert '"status": "FAIL"' in output and '"status": "PASS"' not in output
    assert "private path" not in output


@pytest.mark.parametrize("phase", ("status_before", "verify", "delete", "status_after"))
def test_failure_phase_is_reported_without_raw_error(tmp_path, installed, capsys, phase):
    import errno
    import json

    before, _, status, verify, delete = installed
    failure = PermissionError(errno.EACCES, "private credential-shaped exception", str(tmp_path / "secret"))
    if phase == "status_before":
        status.side_effect = failure
    elif phase == "status_after":
        status.side_effect = [before, failure]
    else:
        (verify if phase == "verify" else delete).side_effect = failure
    assert driver.main(["--hermes-home", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    record = json.loads(out)
    assert record["status"] == "FAIL" and record["phase"] == phase
    assert record["error_class"] == "PermissionError"
    assert "private" not in out and "secret" not in out and str(tmp_path) not in out


def test_filename_is_reduced_to_official_executable_type(tmp_path):
    import errno
    exc = PermissionError(errno.EACCES, "not logged", str(tmp_path / "official/1.4.4/agy_acp_server.exe"))
    result = driver.failure_record(exc, tmp_path / "home", tmp_path / "official", tmp_path / "bin")
    assert result["path_type"] == "official_executable"
