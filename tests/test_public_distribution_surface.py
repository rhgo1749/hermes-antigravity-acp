"""historical reference: personal host-deploy, mux, and portfolio policy stay off the
public distribution surface.

The generalized invariant under test: the public plugin, the default install,
and CI contain and execute ONLY the vendor official ACP connection plus the
canonical 7-file Hermes provider fileset and the needed transfer/session-safety
features. One explicitly-chosen user auth environment (HOME/profile) connects
to exactly ONE official ACP server instance — no account registry, no personal
host paths, no portfolio overlay, no ``/quota`` command surface. Personal
host-deploy, finance/portfolio policy, and multi-account mux tooling belong to
non-distributed private ops; per the Issue's decision they remain in the
repository tree for existing private hosts (distribution-surface isolation,
not physical removal).
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import types
import uuid
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"
OVERLAY_SOURCE = ROOT / "private-ops" / "portfolio_policy.py"

# Independent witness of the canonical contract (kept as a literal here so a
# change to deploy_hermes_profiles.REQUIRED cannot silently redefine it).
CANONICAL_PROVIDER_FILES = {
    "plugin.yaml",
    "__init__.py",
    "client.py",
    "bridge.py",
    "conversation_state.py",
    "native_limit_state.py",
    "process_teardown.py",
    "hermes_compat.py",
    "login.py",
}

# Personal-ops tokens that must never appear on the public distribution
# surface (default installers, provider projection, CI, README, catalog
# entry). Rework-r4 (historical reference): the public provider tree is token-scanned
# TOO — client.py now carries a domain-neutral obligation-evidence contract
# with zero personal naming (the r2-era exemption rationale is retired).
PRIVATE_OPS_TOKENS = (
    "acp-accounts.json",
    "acp-mux-state.json",
    "hermes-cloudcli-agent",
    "/home/hermes",
    "antigravity-acp-mux",
    "scripts/acp_mux",
    "deploy_acp_host",
    "deploy_finance_hotfix_host",
    "deploy_portfolio_policy",
    "portfolio_policy",
    "portfolio-manager",
)

# Files whose bytes ship (or drive what ships) on the default public path.
PUBLIC_INSTALL_CLOSURE = (
    "scripts/install_acp.py",
    "scripts/install_official.py",
    "scripts/deploy_hermes_profiles.py",
    "scripts/acp_probe.py",
    "README.md",
    "docs/plugin-catalog-entry.draft.yaml",
    ".github/workflows/ci.yml",
    "antigravity_acp/registry.py",
)


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _deploy():
    return _load_script(SCRIPTS / "deploy_hermes_profiles.py", "pds_deployer")


# ---------------------------------------------------------------------------
# (a) The public provider tree is exactly the canonical 8-file contract.
# The 8th file (login.py, plugin 0.6.0) is the plugin-owned attended ACP
# login driver that satisfies Hermes' setup_status.login_command contract.
# ---------------------------------------------------------------------------

def test_canonical_fileset_witness_matches_deployer_contract() -> None:
    deploy = _deploy()
    assert set(deploy.REQUIRED) == CANONICAL_PROVIDER_FILES
    assert len(deploy.REQUIRED) == 9


_PROVIDER_PREFIX = "hermes-plugin/antigravity-acp/"


def _provider_relative_names(tracked: list[str]) -> set[str]:
    """Full relative paths under the provider root; nesting is preserved.

    Rework-r2 (historical reference): the witness compares exact relative paths, not
    basenames. A nested file whose basename is canonical (for example
    ``hermes-plugin/antigravity-acp/extra/client.py``) is a non-canonical
    provider path and must fail this witness, not hide inside it.
    """
    relatives: set[str] = set()
    for name in tracked:
        assert name.startswith(_PROVIDER_PREFIX), name
        relatives.add(name[len(_PROVIDER_PREFIX) :])
    return relatives


def test_public_provider_tree_tracks_exactly_the_canonical_files() -> None:
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "hermes-plugin/antigravity-acp"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    assert _provider_relative_names(tracked) == CANONICAL_PROVIDER_FILES
    on_disk = {
        child.relative_to(PLUGIN_DIR).as_posix()
        for child in PLUGIN_DIR.rglob("*")
        if child.is_file() and "__pycache__" not in child.relative_to(PLUGIN_DIR).parts
    }
    assert on_disk == CANONICAL_PROVIDER_FILES
    # The nested-path rule itself, witnessed against a synthetic tree: the
    # old basename matching let these through; relative matching rejects them.
    assert _provider_relative_names(
        [
            _PROVIDER_PREFIX + "client.py",
            _PROVIDER_PREFIX + "extra/client.py",
            _PROVIDER_PREFIX + "private_secrets/__init__.py",
        ]
    ) != CANONICAL_PROVIDER_FILES


# ---------------------------------------------------------------------------
# (b) Update propagation never copies unmanaged files into the candidate.
# ---------------------------------------------------------------------------

def _seed_standalone_target(home: Path) -> Path:
    target = home / "plugins" / "model-providers" / _deploy().PROVIDER
    target.mkdir(parents=True)
    for name in CANONICAL_PROVIDER_FILES:
        if name == "plugin.yaml":
            (target / name).write_text(
                "name: antigravity-acp-provider\nkind: model-provider\nversion: 0.4.0\n",
                encoding="utf-8",
            )
        else:
            (target / name).write_bytes(f"# old provider {name}\n".encode())
    (target / _deploy().INSTALL_PROVENANCE_FILE).write_text(
        json.dumps({"managed_by": _deploy().STANDALONE_MANAGED_BY}) + "\n",
        encoding="utf-8",
    )
    return target


def test_generic_deploy_refuses_before_any_write_when_a_tree_carries_overlays(tmp_path) -> None:
    """historical reference rework-r2: a generic deploy never silently strips overlays.

    Round-1 made update propagation drop unmanaged files; a redeploy then
    reported success while quietly removing a live private overlay. The
    rework turns that silent loss into a pre-mutation refusal: zero writes
    anywhere, and the unmanaged files stay live with unchanged bytes.
    """
    deploy = _deploy()
    home = tmp_path / "hermes"
    home.mkdir()
    target = _seed_standalone_target(home)
    (target / "portfolio_policy.py").write_text("# private opt-in overlay\n", encoding="utf-8")
    (target / "personal_note.txt").write_text("not installer state\n", encoding="utf-8")
    launch = {"process_command": "antigravity-acp-official", "process_args": ["--uid="]}
    (target / deploy.LAUNCH_CONFIG_FILE).write_text(json.dumps(launch) + "\n", encoding="utf-8")
    before = {child.name: child.read_bytes() for child in target.iterdir()}

    with pytest.raises(ValueError, match="unmanaged file") as excinfo:
        deploy.install(deploy.SOURCE, home, apply=True, all_profiles=False)
    message = str(excinfo.value)
    assert "no files were touched" in message
    assert "operator-managed deployment documentation" in message
    assert "--allow-unmanaged-overlays" in message

    # Nothing was mutated anywhere: the live tree is byte-identical and no
    # staging or backup roots were created.
    assert {child.name: child.read_bytes() for child in target.iterdir()} == before
    assert not (home / "plugin-backups").exists()
    assert deploy.verify(home) == []


def test_operator_override_deploy_still_never_propagates_unmanaged_files(tmp_path) -> None:
    """The explicit operator-approved override deploys but never adopts.

    Rework-r2 preserves the round-1 propagation invariant even under the
    override: only this installer's own preserved state carries into the new
    tree; unmanaged private files are dropped from the live tree (recoverable
    in the deployment backup) and never copied into the candidate.
    """
    deploy = _deploy()
    home = tmp_path / "hermes"
    home.mkdir()
    target = _seed_standalone_target(home)
    (target / "portfolio_policy.py").write_text("# private opt-in overlay\n", encoding="utf-8")
    (target / "personal_note.txt").write_text("not installer state\n", encoding="utf-8")
    launch = {"process_command": "antigravity-acp-official", "process_args": ["--uid="]}
    (target / deploy.LAUNCH_CONFIG_FILE).write_text(json.dumps(launch) + "\n", encoding="utf-8")

    reports = deploy.install(
        deploy.SOURCE, home, apply=True, all_profiles=False, allow_unmanaged_overlays=True
    )
    assert reports and reports[0].startswith("deployed:")

    # Unmanaged personal files are NOT propagated into the new tree.
    assert not (target / "portfolio_policy.py").exists()
    assert not (target / "personal_note.txt").exists()
    # The installer's own preserved state (launch settings) still carries over.
    assert json.loads((target / deploy.LAUNCH_CONFIG_FILE).read_text(encoding="utf-8")) == launch
    # Everything dropped out of the live tree remains recoverable in the backup.
    backups = list((home / "plugin-backups").glob(f"deploy-*/{deploy.homes(home)[0][0]}"))
    assert len(backups) == 1
    assert (backups[0] / "portfolio_policy.py").is_file()
    assert (backups[0] / "personal_note.txt").is_file()
    # The provenance marker pins exactly the managed set.
    marker = json.loads((target / deploy.INSTALL_PROVENANCE_FILE).read_text(encoding="utf-8"))
    assert set(marker["managed_files"]) == CANONICAL_PROVIDER_FILES
    assert deploy.verify(home) == []


# ---------------------------------------------------------------------------
# (c) Default install, CI, and catalog entry stay free of personal ops.
# ---------------------------------------------------------------------------

def test_default_install_closure_and_ci_contain_no_personal_ops_tokens() -> None:
    offenders: dict[str, list[str]] = {}
    for relative in PUBLIC_INSTALL_CLOSURE:
        text = (ROOT / relative).read_text(encoding="utf-8")
        hits = [token for token in PRIVATE_OPS_TOKENS if token in text]
        if hits:
            offenders[relative] = hits
    assert offenders == {}


def test_ci_checkouts_never_persist_credentials() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert checkout_steps_missing_persist_flag(workflow) == []
    # Witness the checker itself fails closed: a checkout step without the
    # explicit flag (GitHub's default persists a token) is reported regardless
    # of where its keys sit relative to the `uses:` line.
    assert checkout_steps_missing_persist_flag(_CHECKOUT_WITNESS_GOOD) == []
    offenders = checkout_steps_missing_persist_flag(_CHECKOUT_WITNESS_BAD)
    # One offender per bad checkout step: the flagless step (GitHub persists a
    # token) and the step that explicitly opts back in. The sibling step's
    # own legitimate flag is never borrowed to excuse them.
    assert len(offenders) == 2, offenders
    assert all("actions/checkout" in offender for offender in offenders)


def checkout_steps_missing_persist_flag(workflow_text: str) -> list[str]:
    """Structural (order-independent) gate: every actions/checkout step must
    set ``persist-credentials: false`` in its own ``with:`` mapping.

    historical reference criterion 6 hardening: the previous forward-window regex passed
    as long as the literal appeared anywhere below the ``uses:`` line, so a
    reordered step (``with:`` first), a step borrowing a sibling's flag, or an
    explicit ``persist-credentials: true`` inside the window could slip
    through. This walks the ``steps:`` list one ``-`` item at a time and
    inspects only the step's own keys.
    """
    lines = workflow_text.splitlines()
    offenders: list[str] = []
    step_start = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "steps:":
            step_start = index
            continue
        if step_start is None:
            continue
        # A step item begins with "- " (or "-" alone).
        if not re.match(r"^\s*-\s", line) and line.strip() != "-":
            continue
        item_indent = len(line) - len(line.lstrip())
        block: list[str] = [line]
        for follow in lines[index + 1 :]:
            if follow.strip() == "":
                block.append(follow)
                continue
            follow_indent = len(follow) - len(follow.lstrip())
            if follow_indent <= item_indent and (
                re.match(r"^\s*-\s", follow) or not follow.startswith(" ")
            ):
                break
            block.append(follow)
        if not any("uses: actions/checkout" in entry for entry in block):
            continue
        uses_line = next(entry for entry in block if "uses: actions/checkout" in entry)
        body = "\n".join(block)
        flag = re.search(r"^\s*persist-credentials:\s*(\S+)\s*$", body, re.MULTILINE)
        if flag is None or flag.group(1).lower() != "false":
            offenders.append(f"steps[{len(offenders)}] {uses_line.strip().lstrip('- ')}")
    return offenders


_CHECKOUT_WITNESS_GOOD = """
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: reordered step keeps the flag inside its own block
        with:
          persist-credentials: false
          repository: someone/else
        uses: actions/checkout@v4
"""

_CHECKOUT_WITNESS_BAD = """
jobs:
  a:
    steps:
      - run: echo no checkout here
        with:
          persist-credentials: false
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
"""


def test_official_server_acquisition_stays_pinned_to_google_cdn() -> None:
    registry_text = (ROOT / "antigravity_acp" / "registry.py").read_text(encoding="utf-8")
    urls = re.findall(r"https?://[^\"'\s]+", registry_text)
    assert urls, "registry must pin explicit download URLs"
    for url in urls:
        assert url.startswith("https://dl.google.com/"), url
    registry = _load_script(ROOT / "antigravity_acp" / "registry.py", "pds_registry")
    assert registry.VERSION == "1.4.4"


def test_public_tree_audit_flags_extra_provider_files_and_personal_tokens(tmp_path) -> None:
    audit = _load_script(SCRIPTS / "audit_public_tree.py", "pds_audit")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    provider = tmp_path / "hermes-plugin" / "antigravity-acp"
    provider.mkdir(parents=True)
    (provider / "plugin.yaml").write_text("name: antigravity-acp-provider\n", encoding="utf-8")
    (provider / "portfolio_policy.py").write_text("# smuggled overlay\n", encoding="utf-8")
    # Rework-r4: a CANONICAL provider path smuggles nothing either — the
    # provider tree is token-scanned like the public closure.
    (provider / "client.py").write_text(
        "# domain-neutral provider client\nportfolio_policy = None\n", encoding="utf-8"
    )
    # Rework-r2: nested paths whose BASENAME is canonical must not evade the
    # provider-tree rule (an allowed-name copy plus an importable nested
    # private package).
    (provider / "extra").mkdir()
    (provider / "extra" / "client.py").write_text("# nested provider copy\n", encoding="utf-8")
    (provider / "private_secrets").mkdir()
    (provider / "private_secrets" / "__init__.py").write_text("IMPORTABLE = True\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "run scripts/acp_mux.py with acp-accounts.json\n", encoding="utf-8"
    )
    findings = audit.scan_repository(tmp_path)
    flagged = {
        finding.relative_path
        for finding in findings
        if finding.rule == "public_provider_tree_file"
    }
    assert flagged == {
        "hermes-plugin/antigravity-acp/portfolio_policy.py",
        "hermes-plugin/antigravity-acp/extra/client.py",
        "hermes-plugin/antigravity-acp/private_secrets/__init__.py",
    }
    # Rework-r4 RED: the token scan now covers the provider tree itself.
    token_findings = {
        finding.relative_path
        for finding in findings
        if finding.rule == "personal_ops_reference"
    }
    assert "hermes-plugin/antigravity-acp/client.py" in token_findings
    assert "README.md" in token_findings
    assert audit.main(["--root", str(tmp_path)]) == 1


def test_real_provider_tree_carries_no_personal_ops_tokens() -> None:
    """Rework-r4 GREEN (R6/R7): the shipped provider tree is token-clean."""
    offenders: dict[str, list[str]] = {}
    for source in sorted(PLUGIN_DIR.iterdir()):
        if not source.is_file():
            continue
        text = source.read_text(encoding="utf-8")
        hits = [token for token in PRIVATE_OPS_TOKENS if token in text]
        if hits:
            offenders[source.name] = hits
    assert offenders == {}


# ---------------------------------------------------------------------------
# (d) Clean vanilla install: one auth environment, one official server,
#     no overlay, no registry, no /quota command surface.
# ---------------------------------------------------------------------------

def _fake_official_archive_bytes() -> bytes:
    server = b"""#!/usr/bin/env python3
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get('method') == 'initialize':
        print(json.dumps({
            'jsonrpc': '2.0',
            'id': message.get('id'),
            'result': {
                'protocolVersion': 1,
                'agentInfo': {'name': 'fake-official-acp', 'version': 'test'},
                'authMethods': [],
                'agentCapabilities': {},
            },
        }), flush=True)
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("agy_acp_server.par", date_time=(2026, 1, 1, 0, 0, 0))
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, server)
    return buffer.getvalue()


_FAKE_ARCHIVE_BYTES = _fake_official_archive_bytes()
_FAKE_ARCHIVE_SHA256 = hashlib.sha256(_FAKE_ARCHIVE_BYTES).hexdigest()


def _load_installed_provider(monkeypatch, provider_path: Path):
    registered = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    setattr(providers, "register_provider", registered.append)
    providers_base = types.ModuleType("providers.base")
    setattr(providers_base, "ProviderProfile", FakeProviderProfile)
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    name = f"installed_antigravity_provider_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(
        name,
        provider_path / "__init__.py",
        submodule_search_locations=[str(provider_path)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    assert registered == [module.antigravity_acp]
    return module


@pytest.mark.skipif(os.name == "nt", reason="fake ACP archive is a POSIX test executable")
def test_clean_single_account_install_ships_no_personal_ops_surface(monkeypatch, tmp_path) -> None:
    installer = _load_script(SCRIPTS / "install_acp.py", "pds_install_acp")
    monkeypatch.setenv("HOME", str(tmp_path))
    if os.name == "nt":
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
    launcher = tmp_path / ".local" / "bin" / installer._launcher_name()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", str(launcher))

    def fake_download(_url: str, filename: str):
        Path(filename).write_bytes(_FAKE_ARCHIVE_BYTES)
        return filename, None

    monkeypatch.setattr(
        installer.official_installer.urllib.request, "urlretrieve", fake_download
    )
    pinned = installer.official_installer.resolve_distribution()
    monkeypatch.setattr(
        installer.official_installer,
        "resolve_distribution",
        lambda *_args, **_kwargs: dataclasses.replace(pinned, sha256=_FAKE_ARCHIVE_SHA256),
    )

    home = tmp_path / ".hermes"
    prefix = tmp_path / ".local" / "opt" / "antigravity-acp"
    bin_dir = tmp_path / ".local" / "bin"
    assert installer.main(
        ["install", "--hermes-home", str(home), "--prefix", str(prefix), "--bin-dir", str(bin_dir)]
    ) == 0

    provider = home / "plugins" / "model-providers" / "antigravity-acp"
    shipped = {child.name for child in provider.iterdir() if child.is_file()}
    assert shipped == CANONICAL_PROVIDER_FILES | {"install-provenance.json"}
    assert not (provider / "portfolio_policy.py").exists()
    # Nothing personal was created in the user-chosen home.
    assert not (home / "acp-accounts.json").exists()
    assert not (home / "acp-mux-state.json").exists()

    # The provider resolves to exactly one official ACP launcher instance.
    module = _load_installed_provider(monkeypatch, provider)
    client = module.antigravity_acp.create_client()
    assert client._acp_command == str(launcher)
    assert client._acp_args == []
    client_module = sys.modules[module.__name__ + ".client"]
    # The public tree carries no portfolio overlay; the verified-clean
    # obligation-evidence path (precedence rule 4) is what makes a clean
    # install work — generic installs are never banned.
    assert client_module.policy_overlays == ()


def _declared_surface_violations(manifest_text: str) -> list[str]:
    """Fail-closed structural witness for the plugin's declared surface.

    The plugin-catalog contract (catalog rules 11-13) and historical reference criterion 3
    require this plugin to register exactly one model-provider profile and
    NOTHING else: every ``provides_*`` list, any ``commands``/``skills``
    declaration, and every ``/quota`` tool/skill reference (the personal
    usage-quota surface stays unshipped and its telemetry stays
    ``status='unavailable'``) are violations, as is a ``requires_env`` entry
    (the official ACP child authenticates through Google's own runtime; the
    plugin itself must demand zero credential environment variables).
    """
    violations: list[str] = []
    for surface in ("provides_tools", "provides_hooks", "provides_middleware", "requires_env"):
        match = re.search(rf"^{surface}:[ \t]*(.*)$", manifest_text, re.MULTILINE)
        if match is None:
            violations.append(f"{surface}: missing declaration")
            continue
        inline = match.group(1).split("#", 1)[0].strip()
        if inline not in ("[]", ""):
            violations.append(f"{surface}: non-empty inline list {inline!r}")
            continue
        if inline == "":
            # Block-style list: any "- " item line under the key is surface.
            tail = manifest_text[match.end() :]
            for line in tail.splitlines():
                if line.strip() == "" or line.lstrip().startswith("#"):
                    continue
                if re.match(r"^\s*-\s", line):
                    violations.append(f"{surface}: block-list entry {line.strip()!r}")
                else:
                    break
    if re.search(r"^(commands|skills):", manifest_text, re.MULTILINE):
        violations.append("commands/skills surface declared")
    if "/quota" in manifest_text:
        violations.append("/quota reference in manifest")
    return violations


def test_public_plugin_declares_no_command_or_quota_surface() -> None:
    manifest = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    assert _declared_surface_violations(manifest) == []
    assert "commands" not in manifest.lower()
    for source in PLUGIN_DIR.glob("*.py"):
        assert "/quota" not in source.read_text(encoding="utf-8"), source.name


@pytest.mark.parametrize(
    ("mutated_manifest", "expected_fragment"),
    [
        (
            "name: antigravity-acp-provider\nprovides_tools:\n  - name: quota\n"
            "    command: /quota\n",
            "provides_tools: block-list entry",
        ),
        (
            "name: antigravity-acp-provider\nprovides_tools: [quota-tool]\n",
            "provides_tools: non-empty inline list",
        ),
        (
            "name: antigravity-acp-provider\nprovides_middleware: []\ncommands:\n  - /quota\n",
            "commands/skills surface declared",
        ),
        (
            "name: antigravity-acp-provider\nskills:\n  - /quota\n",
            "skills",
        ),
        (
            "name: antigravity-acp-provider\nrequires_env: [GOOGLE_API_KEY]\n",
            "requires_env: non-empty inline list",
        ),
        ("name: antigravity-acp-provider\n", "missing declaration"),
    ],
)
def test_planted_quota_or_env_surface_declaration_fails_closed(
    mutated_manifest: str, expected_fragment: str
) -> None:
    """historical reference criterion 3: a planted /quota tool/skill declaration anywhere
    in the manifest surface is a violation, never a silent ship."""
    violations = _declared_surface_violations(mutated_manifest)
    assert violations, mutated_manifest
    assert any(expected_fragment in violation for violation in violations), violations


def test_shipped_package_carries_no_quota_tool_or_skill_manifest(tmp_path) -> None:
    """The projection a clean install lays down is checked with the same
    fail-closed surface witness, not just the repository-side manifest."""
    for source in sorted(PLUGIN_DIR.iterdir()):
        if source.name == "plugin.yaml":
            continue
        if source.is_file():
            target = tmp_path / source.name
            target.write_bytes(source.read_bytes())
    (tmp_path / "plugin.yaml").write_bytes((PLUGIN_DIR / "plugin.yaml").read_bytes())
    manifest_text = (tmp_path / "plugin.yaml").read_text(encoding="utf-8")
    assert _declared_surface_violations(manifest_text) == []
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in tmp_path.glob("*.py") if path.is_file()
    )
    assert "/quota" not in combined
    assert "register_tool" not in combined
    assert "register_skill" not in combined


def test_usage_telemetry_status_stays_unavailable_on_public_surface(monkeypatch, tmp_path) -> None:
    """historical reference criterion 3: /quota stays unshipped, so the provider can
    never truthfully report billable usage; the telemetry contract pins
    ``status='unavailable'`` with every request-usage bucket left None and
    nothing marked as billing usage."""
    from test_standalone_client import _load

    _, _, client_module = _load(monkeypatch)
    telemetry = client_module._build_usage_telemetry(
        model="antigravity-acp",
        session_id="synthetic-session",
        turn_id_hash=None,
        context_occupancy=None,
    )
    assert telemetry["status"] == "unavailable"
    assert all(value is None for value in telemetry["request_usage"].values())
    if telemetry["context_occupancy"] is not None:
        assert telemetry["context_occupancy"]["is_billing_usage"] is False
    assert telemetry["schema_id"] == "antigravity-acp-usage-v1"
