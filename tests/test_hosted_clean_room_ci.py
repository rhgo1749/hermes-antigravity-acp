"""historical reference rework: the hosted fresh-UID clean-room CI job is a contract.

The `acp-clean-room` job on GitHub-hosted `ubuntu-24.04` is the venue the
maintainer ruling (historical reference historical reference) chose to re-instrument the
separate-OS-UID criterion that the private dev container could not satisfy.
This suite keeps that venue honest WITHOUT running it:

- the workflow job must pin the hosted runner, keep least-privilege
  permissions, create a real OS UID, scrub the child environment to the
  driver's allowlisted variable set, and contain no DinD/privileged/
  secrets/auth/catalog/inference surface;
- the driver must refuse the wrong venue (root, non-24.04, no runner home,
  readable runner-private canary, unexpected env vars) and keep the exact
  fail-closed exit-code table for the lifecycle chain;
- the historical reference redaction lineage is re-proved for the new job: credential-
  shaped material is summarized as counts/fingerprints/class names and is
  never disclosed verbatim by any driver or probe output path;
- the probe must contain no authentication code path at all;
- the evidence doc's HOSTED-* token and Actions-run citation lines keep
  their exact shapes, stay PENDING until a real green run is cited, and
  never claim acceptance while pending;
- every new artifact passes the repository's own secret scanners.

Credential-free and offline: nothing here downloads, executes, or
authenticates; fake secret material below is assembled at runtime so the
committed source of this file trips no scanner.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
EVIDENCE_DOC = ROOT / "docs" / "official-server-1.4.4-clean-room-e2e-2026-11-07.md"
DRIVER_PATH = ROOT / "scripts" / "hosted_clean_room_ci.py"
PROBE_PATH = ROOT / "scripts" / "clean_room_provider_probe.py"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = _load("hosted_clean_room_ci_contract", DRIVER_PATH)
audit = _load("audit_hosted_contract", ROOT / "scripts" / "audit_public_tree.py")
install_acp = _load("install_acp_hosted_contract", ROOT / "scripts" / "install_acp.py")

ACP_PIN = "baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a"
HERMES_COMMIT = "a9ff9799e273f525b82718cdc69fdec71b1dca5a"

# Fake credential-shaped material assembled at runtime so this committed
# file matches none of the repository's own scanners while the in-memory
# strings DO, exercising the suppression paths exactly.
FAKE_SHAPES = {
    "token-assignment": "ACCESS_TO" + "KEN=SU" + "PERsecretvalue42",
    "authorization-header": "Author" + "ization: Bearer fake" + "-header-value",
    "bearer-token": "Bearer fakeb" + "earertokenvalueabcdef",
    "google-access-token-prefix": "ya29." + "AbCdEfGhIjKlMnOpQrStUvWx",
    "google-api-key-prefix": "AI" + "zaQr6x" + "TESTKEYMATERIAL00001",
    "github-token-prefix": "gh" + "p_" + "a" * 25,
    "pem-private-key": "-----BEGIN P" + "RIVATE KEY-----",
    "cookie-header": "Coo" + "kie: sessionid" + "=abc123",
    "oauth-url": "https://accounts." + "google.com/o" + "auth?client_id=x",
}
FAKE_VALUES = (
    "SUPERsecretvalue42",
    "fake-header-value",
    "fakeb" + "earertokenvalueabcdef",
    "AbCdEfGhIjKlMnOpQrStUvWx",
    "TESTKEYMATERIAL00001",
    "a" * 25,
    "-----BEGIN PR" + "IVATE KEY-----",
    "sessionid" + "=abc123",
)


@pytest.fixture(scope="module")
def ci() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def job_block(ci: str) -> str:
    match = re.search(r"^  acp-clean-room:\n(?:.*\n)*?(?=^  \S|\Z)", ci, re.M)
    assert match, "the acp-clean-room job must exist in .github/workflows/ci.yml"
    return match.group(0)


@pytest.fixture(scope="module")
def doc() -> str:
    return EVIDENCE_DOC.read_text(encoding="utf-8")


# -- workflow invariants ------------------------------------------------


def test_job_pins_hosted_runner_and_bounded_timeout(job_block: str) -> None:
    assert "runs-on: ubuntu-24.04" in job_block
    assert re.search(r"timeout-minutes:\s+\d+", job_block)


def test_job_permissions_are_least_privilege(job_block: str) -> None:
    assert re.search(r"permissions:\s*\n\s+contents:\s+read\s*\n", job_block)
    # The whole workflow references no Actions secret expression anywhere.
    assert "${{ secrets" not in CI_WORKFLOW.read_text(encoding="utf-8")


def test_job_creates_a_dedicated_os_uid(job_block: str) -> None:
    assert re.search(r"useradd --create-home --shell /bin/bash", job_block)
    assert re.search(r"sudo -u \"\$CLEAN_ROOM_USER\" env -i", job_block)
    assert ".cr94canary" in job_block
    assert "chmod 600" in job_block
    # The driver executes from a clean-room-owned copy, not the runner's
    # workspace checkout (which stays non-traversable by design).
    assert "$CLEAN_ROOM_HOME/repo/scripts/hosted_clean_room_ci.py" in job_block
    assert "sudo cp -a" in job_block
    # The pinned uv is proven to resolve under the clean-room identity
    # itself, after the user exists and before the chain depends on it.
    create_block = job_block.split("Create dedicated clean-room OS UID", 1)[1].split(
        "- name:", 1
    )[0]
    assert "/usr/local/bin/uv --version" in create_block


def test_child_environment_is_scrubbed_to_the_driver_allowlist(job_block: str) -> None:
    env_i = job_block.split("env -i", 1)[1].split("hosted_clean_room_ci.py", 1)[0]
    names = set(re.findall(r"^\s*([A-Z][A-Z0-9_]*)=", env_i, re.M))
    assert names == set(driver.ALLOWED_ENV_KEYS)
    assert "HERMES_HOME=" in env_i and "HOME=" in env_i
    assert "CLEAN_ROOM_USER=" not in env_i  # identity travels via USER/LOGNAME


def test_job_has_no_docker_privileged_auth_or_catalog_surface(job_block: str) -> None:
    assert not re.search(r"\bdocker\b\s+(build|run|exec|pull|compose)", job_block)
    assert "--privileged" not in job_block
    # The job never authenticates: "unauthenticated" prose is allowed, a
    # real authenticate surface is not.
    assert re.search(r"(?<!un)authenticate", job_block, re.I) is None
    assert "hermes plugins install" not in job_block
    exec_block = job_block.split(
        "Execute the real-binary clean-room chain as the dedicated UID", 1
    )[1].split("- name:", 1)[0]
    assert "${{" not in exec_block  # no secrets/vars interpolated into the uid env
    assert "workflow_dispatch" not in job_block


def test_job_gates_supply_chain_and_hermes_commit(job_block: str) -> None:
    assert ACP_PIN in job_block
    assert HERMES_COMMIT in job_block
    assert "uv==0.13.5" in job_block
    # uv must live in a world-readable venv, not the runner's user-site
    # (a /home/runner install is non-traversable by the clean-room UID).
    assert "sudo python3 -m venv /opt/uv94" in job_block
    assert "chmod -R a+rX /opt/uv94" in job_block
    assert "NousResearch/hermes-agent" in job_block
    assert job_block.count("persist-credentials: false") >= 2


def test_job_scans_evidence_and_checks_runner_state(job_block: str) -> None:
    assert "--scan-file" in job_block
    assert job_block.count("if: always()") >= 2
    for state_path in (".local/opt/antigravity-acp", ".hermes", ".gemini"):
        assert state_path in job_block


def test_fake_ci_comment_no_longer_denies_a_ci_real_binary_job(ci: str) -> None:
    flat = " ".join(ci.split())
    assert "No platform has an executed real-binary install lifecycle" not in flat
    assert "acp-clean-room job below" in flat


# -- driver invariants ---------------------------------------------------


def _driver_source() -> str:
    return DRIVER_PATH.read_text(encoding="utf-8")


def test_driver_refuses_the_wrong_venue() -> None:
    source = _driver_source()
    assert "if self.uid == 0" in source  # refuses to run as root
    assert "Ubuntu 24.04" in source
    assert "/home/runner" in source
    assert ".cr94canary" in source
    assert "privilege_escalation_available" in source
    assert "raise StepFailure" in source
    assert "sudo" in source


def test_integrity_is_a_baseline_delta_not_a_static_skel_list() -> None:
    # GitHub-hosted images customize /etc/skel (nvm/rustup/cargo/dotnet/
    # ghcup/composer dot-dirs appear in fresh homes); a static allowlist
    # misflags provenance of the image. The driver instead baselines HOME
    # after workflow staging and its own decoy seeding, then fails closed
    # on anything the chain itself created beyond installer/uv-owned trees.
    assert driver.ALLOWED_CREATED_ENTRIES == frozenset({".cache", ".config", ".local"})
    source = _driver_source()
    assert "self.home_baseline = sorted(" in source
    assert "set(self.home_baseline) - ALLOWED_CREATED_ENTRIES" in source
    assert "baseline_home_entries=self.home_baseline" in source


def test_driver_step_expectation_table_is_the_fail_closed_law() -> None:
    table = driver.STEP_EXPECTATIONS
    assert table["h01-official-status-preinstall"] == 1
    assert table["h02-official-verify-preinstall"] == 2
    assert table["h03-provider-status-preinstall"] == 1
    assert table["h04-official-install-download-1"] == 0
    assert table["h10-official-uninstall"] == 0
    assert table["h11-official-status-post-uninstall"] == 1
    assert table["h12-official-verify-post-uninstall"] == 2
    assert table["h16-foreign-launcher-uninstall-refused"] == 2
    assert table["h17-foreign-launcher-install-refused"] == 2
    assert table["h19-provider-delete"] == 0
    assert table["h20-provider-status-after-delete"] == 1
    assert table["h25-hermes-unmodified"] == 0
    assert table["h26-hermes-provider-probe"] == 0
    initialize_steps = [name for name, rc in table.items() if "initialize" in name]
    assert len(initialize_steps) == 3
    assert all(table[name] == 0 for name in initialize_steps)


def test_stream_summaries_never_echo_credential_shaped_text() -> None:
    text = "\n".join(f"{name} -> {value}" for name, value in FAKE_SHAPES.items())
    record = driver._suppressed(text)
    blob = json.dumps(record, sort_keys=True)
    for value in FAKE_VALUES:
        assert value not in blob
    assert re.search(r"sha256=[0-9a-f]{16}", record["summary"])
    for name in FAKE_SHAPES:
        assert name in record["classes"]
    assert audit.scan_text(blob) == []


def test_repo_authored_disclosure_fails_closed_on_a_scan_trip() -> None:
    clean = driver._disclosure("official ACP server installed; no authentication was attempted\n")
    assert clean["disclosure"] == "published_repo_authored_text"
    assert clean["tail"] == ["official ACP server installed; no authentication was attempted"]
    dirty = driver._disclosure(FAKE_SHAPES["google-access-token-prefix"])
    assert dirty["disclosure"] == "suppressed_by_secret_scan"
    assert "AbCdEfGhIjKlMnOpQrStUvWx" not in json.dumps(dirty)


def test_evidence_events_trip_the_scanner_before_reaching_disk(tmp_path) -> None:
    evidence = driver.Evidence(tmp_path / "evidence.jsonl")
    with pytest.raises(driver.StepFailure):
        evidence.event("probe", payload=FAKE_SHAPES["github-token-prefix"])
    written = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8")
    assert "evidence_scan_trip" in written
    assert "a" * 25 not in written
    evidence.event("step", step="h04", rc=0)
    assert json.loads((tmp_path / "evidence.jsonl").read_text().splitlines()[-1])["rc"] == 0


def test_scan_file_mode_fails_closed_on_leaked_secrets(tmp_path, capsys) -> None:
    dirty = tmp_path / "evidence.jsonl"
    dirty.write_text(f'{{"event":"step"}}\n{FAKE_SHAPES["pem-private-key"]}\n', encoding="utf-8")
    assert driver.scan_file(dirty) == 1
    err = capsys.readouterr().err
    assert "rule(s) tripped" in err and "PRIVATE KEY-----" not in err
    clean = tmp_path / "clean.jsonl"
    clean.write_text('{"event":"result","status":"PASS"}\n', encoding="utf-8")
    assert driver.scan_file(clean) == 0


def test_driver_reuses_the_pr93_summary_contract() -> None:
    source = _driver_source()
    assert "_server_stderr_summary" in source  # install_acp lineage, not a copy
    assert "sha256_16" in source and "lines" in source and "bytes" in source


# -- probe invariants -----------------------------------------------------


def _probe_source() -> str:
    return PROBE_PATH.read_text(encoding="utf-8")


def test_probe_contains_no_authentication_code_path() -> None:
    source = _probe_source()
    assert '"authenticate"' not in source
    assert "'authenticate'" not in source
    assert not re.search(r"request\(\s*[\"']auth", source)
    assert "accounts.google.com" not in source
    assert "client_secret" not in source
    assert "authenticate_frames=0" in source


def test_probe_selection_expectations_match_the_plugin_source() -> None:
    plugin = (ROOT / "hermes-plugin" / "antigravity-acp" / "__init__.py").read_text()
    probe = _probe_source()
    assert 'display_name="Antigravity ACP"' in plugin
    assert 'DISPLAY_NAME = "Antigravity ACP"' in probe
    assert 'BASE_URL = "acp://antigravity"' in probe and 'base_url="acp://antigravity"' in plugin
    assert 'AUTH_TYPE = "external_process"' in probe
    assert 'auth_type="external_process"' in plugin


def test_probe_records_only_fingerprints_for_the_model_boundary() -> None:
    probe = _probe_source()
    assert "_server_stderr_summary" in probe
    assert "ids_printed=False" in probe
    assert "code=-32000" in probe and "Authentication required" in probe
    assert "fetch_models_none" in probe


# -- evidence document invariants ----------------------------------------


def _text_blocks(doc: str) -> list[str]:
    return re.findall(r"```text\n(.*?)```", doc, re.DOTALL)


def _hosted_block(doc: str) -> str:
    blocks = [b for b in _text_blocks(doc) if "HOSTED-CI-CLEAN-ROOM:" in b]
    assert blocks, "the evidence record must carry the hosted CI token block"
    return blocks[0]


def test_hosted_section_records_the_ruling_and_venue(doc: str) -> None:
    assert "## Hosted fresh-UID clean-room CI" in doc
    section = doc.split("## Hosted fresh-UID clean-room CI", 1)[1]

    assert "ubuntu-24.04" in section
    assert "useradd" in section
    assert ACP_PIN in section
    assert "NOT EXECUTED" in section  # prior container/Docker eras stay
    assert "HOSTED-AUTHENTICATED-SESSION: NOT RUN" in section
    assert "HOSTED-REAL-INFERENCE: NOT RUN / NO-GO" in section
    assert "HOSTED-CATALOG-INSTALL: OUT OF SCOPE" in section


def test_hosted_status_tokens_keep_exact_meaning(doc: str) -> None:
    block = _hosted_block(doc)
    assert re.search(r"HOSTED-CI-CLEAN-ROOM: (PENDING|PASSED)", block)
    assert re.search(r"HOSTED-FRESH-UID: (PENDING|VERIFIED)", block)
    assert re.search(r"HOSTED-REAL-INITIALIZE: (PENDING|EXECUTED)", block)
    assert "HOSTED-UNAUTHENTICATED-MODEL-DISCOVERY: NOT VERIFIED" in block
    assert "HOSTED-AUTHENTICATED-SESSION: NOT RUN" in block
    assert "HOSTED-REAL-INFERENCE: NOT RUN / NO-GO" in block
    assert "HOSTED-CATALOG-INSTALL: OUT OF SCOPE" in block


def test_hosted_run_citation_line_keeps_its_shape(doc: str) -> None:
    citation = [b for b in _text_blocks(doc) if "HOSTED-CI-RUN-ID:" in b]
    assert citation, "the evidence record must carry the Actions-run citation block"
    block = citation[0]
    run_match = re.search(r"HOSTED-CI-RUN-ID: (PENDING|\d{5,})", block)
    url_match = re.search(
        r"HOSTED-CI-RUN-URL: (PENDING|https://github\.com/"
        r"rhgo1749/hermes-antigravity-acp/actions/runs/(\d+))",
        block,
    )
    head_match = re.search(r"HOSTED-CI-RUN-HEAD: (PENDING|[0-9a-f]{40})", block)
    assert run_match and url_match and head_match
    assert "HOSTED-CI-JOB: acp-clean-room" in block
    if run_match.group(1) != "PENDING":
        assert url_match.group(2) == run_match.group(1), "run id and URL must name one run"
        assert head_match.group(1) != "PENDING", "a cited run needs its exact head sha"
    else:
        assert url_match.group(1) == "PENDING" and head_match.group(1) == "PENDING"
        # No acceptance claim while the citation is still pending.
        assert "no acceptance claim may be made" in doc


# -- new artifacts pass the repository's own scanners ---------------------


def test_new_artifacts_are_scanner_clean() -> None:
    # This test file itself is excluded from the personal-path literal
    # screen below: its own scanner rule string would self-trip. The CI
    # repository audit already covers this file's committed content.
    for path in (CI_WORKFLOW, DRIVER_PATH, PROBE_PATH, EVIDENCE_DOC):
        text = path.read_text(encoding="utf-8")
        assert audit.scan_text(text) == [], f"{path.name} trips the secret scanner"
        for name, pattern in install_acp._CREDENTIAL_SHAPES:
            tripping = [line for line in text.splitlines() if pattern.search(line)]
            if not tripping:
                continue
            if path == PROBE_PATH and name == "token-assignment":
                # Documented shape-classifier false positive: the probe's
                # own api_key create_client kwarg — the exact class the
                # driver's HERMES_HOME integrity scan tolerates inside the
                # plugin's own installed provider source.
                assert all(re.search(r"\bapi_key\s*[:=]", line) for line in tripping)
                continue
            raise AssertionError(f"{path.name} trips credential shape {name}")
        assert "/home/hermes" not in text
