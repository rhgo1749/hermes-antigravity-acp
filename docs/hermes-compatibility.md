# Hermes compatibility boundary

This plugin owns the Google ACP v1 JSON-RPC transport. Its supported Hermes extension seam is the public `providers.register_provider()` plus `ProviderProfile.create_client(**kwargs)` contract. The latter must tolerate future client keyword arguments. `agent.agent_runtime_helpers.create_openai_client()` is exercised as an integration check for Hermes dispatch; it is a Core implementation detail, not the plugin's public dependency.

The independent CI job checks out `NousResearch/hermes-agent` at `main`, installs that checkout from its committed `uv.lock`, and runs the seam with strict mode. It records the tested commit/tree, Python and uv versions, lock digest, and resolved package versions. Import/setup failure is a job failure, not a skipped pass. The job does not patch Hermes Core; it asserts the plugin client is not derived from `CopilotACPClient` and verifies the upstream checkout has no tracked changes.

## Dependency classes

- **Public provider seam** — `providers.register_provider()` and `ProviderProfile.create_client(**kwargs)`. The only extension point the plugin relies on to exist across releases; imported directly in `__init__.py`.
- **Documented plugin helper symbols** — `agent.runtime_cwd:resolve_agent_cwd` and `gateway.session_context:get_session_env`. Listed per-symbol in Hermes' own plugin-public catalog (`hermes_cli/plugin_validate_private_imports.py::_PUBLIC`, harvested from the plugin docs). The plugin imports exactly these symbols; the catalog emits no Catalog Rule 9 finding for them.
- **Retained private semantic dependency** — the `session_context_engaged` latch attribute in `gateway.session_context`. `hermes_compat.py` reads it dynamically from the *already-loaded* module (`sys.modules` lookup — never an import, never a rebind) because only that module's own execution can arm the latch; it is what detects cron's per-job run cwd with empty session ids as an active Hermes task scope, and any failure while consulting it fails closed to "scope active". This is a private Core internal: **not** a public API, **not** catalog-listed, and **not** a migration this plugin has completed — the plugin stays semantically bound to it, and any removal or semantic change of the latch is a compatibility break to fail closed on and re-verify (see the `gateway.session_context` row in the [dependency register](#seven-module-dependency-register)).
- **Security-required private helpers** — `agent.file_safety`, `agent.redact`, `tools.environments.local`, `tools.skill_provenance`, plus the profile-home/subprocess policy in `hermes_constants`. No evidenced public alternative exists (see [Upstream contract proposals](#upstream-contract-proposals)); they stay isolated in `hermes_compat.py`, are never reimplemented downstream, and every consumer fails closed when one is missing or raises.
- **Forbidden** — Hermes Core monkeypatching or runtime rebinds. `hermes plugins validate`'s core-override check must report zero rebinds; a non-zero count is a release blocker.

## Seven-module dependency register

Classifications and Rule 9 outcomes below are the recorded output of `hermes plugins validate` against the official upstream checkout identified in the [verification record](#verification-record), re-confirmed unchanged on the pinned official releases in the [floor pin record](#floor-pin-record-2026-11-06) and the [official v0.23.0 release record](#official-release-verification-record--v0230-gate-b5-2026-11-08). "Observed release floor" is the earliest official release tag whose history contains the current definition of the symbol (`git log -S 'def <name>'` on the official mirror, then `git tag --contains`). It is an observation, not the declared floor: since 2026-11-06 the repository declares `requires_hermes: ">=0.21.6"` in `plugin.yaml`, CI-gated by the `catalog-floor-gate` job (see [Floor pin record](#floor-pin-record-2026-11-06)). Because pickaxe finds the first commit carrying the *current* definition text, the true first usable release can only be equal or earlier, never later.

| Upstream symbol (observed floor) | Class / Rule 9 verdict | Adapter wrapper (`hermes_compat.py`) | Runtime call sites (`client.py`) | Security consequence when missing, removed, or raising |
| --- | --- | --- | --- | --- |
| `agent.file_safety.get_nt_namespace_error` (v2026.9.21), `get_read_block_error` (v2026.4.23), `get_write_denied_error` (v2026.7.20), `is_write_approval_required` (v2026.8.13) | Security-required private; **Rule 9 warning** (4 findings) | `get_nt_namespace_error`, `get_file_read_safety`, `get_file_write_safety` | `_safe_path`, `_fs_read_text_file`, `_fs_write_text_file`, `_trusted_path_is_under_session` | Any of the four absent or raising → `PermissionError` before file bytes are touched or returned; `_trusted_path_is_under_session` returns `False` so no path receives a trusted allow. NT/UNC checks, blocked-read rules, write-denial rules, and approval requirements are never reimplemented. |
| `agent.redact.redact_sensitive_text` (v2026.3.12) | Security-required private; **Rule 9 warning** | `get_file_read_safety` | `_fs_read_text_file` | Absent or raising → `PermissionError` before content is returned; an unredacted read can never escape the failure path. |
| `tools.environments.local.hermes_subprocess_env` (v2026.7.1) | Security-required host policy; **Rule 9 warning** | `build_hermes_subprocess_env` | `_build_subprocess_env` | Call fails inside a Hermes runtime → `RuntimeError`, ACP child startup refused. Module absent → the process environment is the base instead. In **both** cases the base is then narrowed by the [ACP child minimum environment contract](#acp-child-minimum-environment-contract) before spawn — the policy result is the base, never the contract, because upstream retains Tier-2 provider credentials under `inherit_credentials=True`. No credential keys are ever guessed into the child environment. |
| `agent.runtime_cwd.resolve_agent_cwd` (v2026.6.5) | **Documented plugin symbol**; no Rule 9 finding | `resolve_agent_cwd` | `_resolve_acp_working_directory` | Unavailable or raising while any Hermes task scope is active (session key/id present, or the `session_context_engaged` latch armed — covers cron runs binding a job cwd with empty session ids) → `RuntimeError`; the provider refuses to treat process cwd as the session workspace. Outside an active Hermes task scope, the standalone launch-directory fallback remains. |
| `gateway.session_context.get_session_env` (v2026.4.13); `session_context_engaged` (v2026.7.1) | `get_session_env`: **documented plugin symbol**, no Rule 9 finding (the adapter imports exactly this symbol, no bare-module import). `session_context_engaged`: **retained private semantic dependency** — read from the already-loaded module only (arming the latch requires that module to have run, so a not-loaded module proves no scope was bound); module-internal introspection that the catalog does not list, so it emits no static finding — that silence is a dynamic lookup hiding a still-retained private dependency, **not** a public API migration | `get_runtime_session_env`, `_active_hermes_session` | `_runtime_conversation_identity`, `_capture_usage_delta` | Session identity falls back to `HERMES_SESSION_ID`/`HERMES_SESSION_KEY` process env when the module is absent (documented standalone behavior); any exception while consulting an available module is treated as "scope active" and fails closed via `resolve_agent_cwd`. |
| `tools.skill_provenance.get_current_write_origin` (v2026.5.7) | Security-required private; **Rule 9 warning** | `get_current_write_origin` | `_runtime_conversation_identity` | With a Hermes `tools` package loaded, the origin module missing or raising → `RuntimeError`; conversation affinity is never computed, so a foreground ACP session can never be reused across an unknown lane. Without any Hermes `tools` package (standalone), the `foreground` lane is used. |
| `hermes_constants.get_hermes_home` (v2026.3.28), `apply_subprocess_home_env` (v2026.6.19) | Host policy surface; catalog-listed at module level (no Rule 9 finding) but no documented plugin contract — classified and preserved as host policy, not claimed public API | `get_hermes_home`, `get_hermes_home_for_video`, `apply_subprocess_home_env` | `_build_subprocess_env`, `_native_video_cache_root` | Active profile home unresolvable in a Hermes runtime → `RuntimeError` (never the default profile); HOME/scratch policy missing or raising → `RuntimeError`, child startup refused. Only a non-Hermes standalone run may use the explicit-`HERMES_HOME`/default-home fallback. |

`hermes_cli._subprocess_compat` is **removed** as a dependency: Windows hide flags use the standard-library `subprocess.CREATE_NO_WINDOW` when present, otherwise `0`; this is UX-only.

## Verification record

Recorded 2026-11-05 on the pristine official clone made for this delivery (a fresh `git clone --filter=blob:none --single-branch --branch main` of the official origin). Any pre-existing private working copies of Hermes on the development host were *not* used for these gates; only the pristine official clone identified below produced these results, and machine-local checkout locations and branch layouts are deliberately not recorded here.

- Upstream identity: `NousResearch/hermes-agent` `main` @ `d914e2334466d8e71dfa45da43fe7e48c7675ec7`, tree `9e237262145390188a007331eb6ec9f0a0b98c9a`; working tree clean before and after every gate (`git status --porcelain` empty).
- Upstream environment: `uv sync --frozen --python 3.14 --group dev` (host `uv 0.11.16`; the CI job pins `uv==0.13.5` — resolution is `--frozen` from the committed lock in both), venv `Python 3.14.7`.
- Credential-free job parity: Python 3.14 via `uv run`, `ruff check scripts hermes-plugin tests` clean, `python scripts/audit_public_tree.py` clean, `python -m pytest -q tests --ignore=tests/test_upstream_hermes_runtime_contracts.py` → **371 passed, 5 skipped** (skips: four `test_long_context_wire.py` core-import guards and the `test_vanilla_hermes_seam.py` non-strict skip — both are the documented credential-free skips, and the seam test runs un-skipped in the strict gate below).
- Strict upstream gate (same invocation as the `upstream-hermes-compat` job): `UPSTREAM_HERMES_DIR=<checkout> HERMES_STRICT_SEAM_TEST=1 HERMES_TESTED_COMMIT=d914e233… HERMES_TESTED_TREE=9e237262… <checkout>/.venv/bin/python -m pytest -q tests/test_vanilla_hermes_seam.py tests/test_upstream_hermes_runtime_contracts.py` → **5 passed** (public create_client seam + non-Copilot derivation; session-scoped cwd with refusal on API loss; cron-scope refusal; profile-scoped child HOME/scratch with credential-leak assertions; public session-context usage deltas).
- Catalog admission: `<checkout>/.venv/bin/hermes plugins validate hermes-plugin/antigravity-acp` → **Validation passed**, `✓ no core override — no runtime rebinds of Hermes core` (**zero core overrides**), and exactly **7 Catalog Rule 9 findings**: `hermes_compat.py` imports of `tools.environments.local.hermes_subprocess_env`, `tools.skill_provenance.get_current_write_origin`, `agent.file_safety.get_nt_namespace_error`, `agent.file_safety.get_read_block_error`, `agent.file_safety.get_write_denied_error`, `agent.file_safety.is_write_approval_required`, `agent.redact.redact_sensitive_text`. The identical pre-change run emitted **8** findings; the removed eighth was the bare `from gateway import session_context` module import, replaced by importing exactly the catalog-listed `gateway.session_context.get_session_env` symbol (the engaged-latch read moved to the already-loaded module). That 8→7 reduction is static-catalog import bookkeeping only — **not** a decoupling and **not** a public API migration: the dynamically inspected `session_context_engaged` latch remains a retained private semantic dependency on `gateway.session_context` internals (dependency class and register row above) that the static scanner no longer sees precisely because it is reached through `sys.modules`. The remaining seven are the security-required private helpers of the register above; each is retained deliberately and is the subject of an upstream proposal below. The one `◇ Isolation` note (`create_client()` returns a live SDK client) is the informational marker for model-provider profiles, which Hermes' own docs state "cross the host as data + methods".
- Minimum release floor: see [Floor pin record (2026-11-06)](#floor-pin-record-2026-11-06). The per-symbol floors in the register — binding latest: `agent.file_safety.get_nt_namespace_error` at tag `v2026.9.21` — remain advisory observations; the declared floor is now a CI gate.
- Downstream identity: the head commit of the PR that carries this record; the commands above were executed against exactly that tree.

## Floor pin record (2026-11-06)

`plugin.yaml` declares `requires_hermes: ">=0.21.6"`. The value is proven, not guessed:

- **Why v0.21.6 is the floor candidate.** It is the first Hermes SemVer release (the CalVer series ends at `v2026.9.24`; `v0.21.6` is dated 2026-10-08), and it is the earliest SemVer tag whose history contains the public provider seam this plugin imports directly — `providers.register_provider`, `ProviderProfile` fields `external_process`, `process_args_env_var`, and `supports_vision_tool_messages` all resolve to `v0.21.6` under `git log -S` + `git tag --contains`. Every security-required private helper in the register has an observed CalVer-era floor (`v2026.3.12` … `v2026.9.21`), i.e. earlier than the first SemVer release, so no register symbol demands a higher SemVer floor.
- **Proof runs (2026-11-06, pristine detached worktrees of the official origin, `uv sync --frozen --python 3.14` / `--group dev`, venv Python 3.14.7, isolated `HERMES_HOME`).**

| Official Hermes ref | Commit | `hermes plugins validate hermes-plugin/antigravity-acp --install-deps` | Strict seam (`test_vanilla_hermes_seam.py` + `test_upstream_hermes_runtime_contracts.py`) |
| --- | --- | --- | --- |
| `v0.21.6` (floor) | `818c13be1` | **Validation passed** — manifest fields, `requires_hermes` spec parses, capability probe registered `antigravity-acp`, security scan safe, **no core override** | **5 passed** |
| `v0.22.7` (latest release) | `b200f5bc6` | **Validation passed** (adds the oauth check; identical outcomes) | **5 passed** |
| `main` | `95ab05005` | **Validation passed** | covered by `upstream-hermes-compat` on every push |

- **Warnings (recorded, not laundered).** At `v0.22.7` and `main` the validator reports exactly the 7 documented Catalog Rule 9 private-import findings listed in the register above (`tools.environments.local.hermes_subprocess_env`, `tools.skill_provenance.get_current_write_origin`, 4× `agent.file_safety.*`, `agent.redact.redact_sensitive_text`), plus the informational `◇ Isolation` note that `create_client()` returns a live SDK client (documented behaviour for model-provider profiles). At `v0.21.6` the same run is fully green but emits **no** Rule 9 warnings: that release's validator ships without the private-imports catalog, so the floor ref simply cannot surface them — the seven findings are a property of the current plugin surface, recorded from the v0.22.x/main runs, not something the floor run disputes. Rule 7 treats Rule 9/caution findings as reviewer-read warnings rather than admission failures; each of these seven is a deliberate, register-documented, fail-closed dependency with an [upstream contract proposal](#upstream-contract-proposals). No check reported `dangerous`; no core override; zero undeclared-capability findings.
- **CI enforcement going forward:** the `catalog-floor-gate` job pins Hermes `v0.21.6` and reruns the validate + seam pair on every change; `upstream-hermes-compat` runs the same official validate against live `main` in addition to the seam. `tests/test_plugin_manifest.py` fails if the declared floor, the empty capability declares, or the provider-only registration surface drift apart. Raising the floor requires moving all three in one change with a recorded reason.
- **Catalog entry:** `docs/plugin-catalog-entry.draft.yaml` records the submission-candidate design (name, category `models`, exact-SHA pin placeholder, capabilities matching the probe). The catalog PR to the official repository is a separate, separately approved task; nothing in this repository opens it.

## Official release verification record — v0.23.0 (Gate B.5, 2026-11-08)

This record assesses whether the ACP plugin runs on **pristine, unmodified official Hermes Core v0.23.0** — without private Core patches or operator overlays. This is a release-target regression record, not a live-inference gate. Imported symbol availability is not contract equivalence; the strict-lane results below are contract evidence, not symbol inventory.

- **Downstream identity (executed refresh, not the issue's stale audit baseline):** ACP `main@ceec8e98af43a4570988a4a1cbcda490ed6565e1` (issue opened at `56a9a50a84da356a8b3ddf2017ab99daf1d6b464`), plugin version `0.5.3`, `requires_hermes: ">=0.21.6"` unchanged (floor preserved; not raised to "simplify" this gate). The gates were then re-executed at the head of the PR that carries this record; the documentation-only delta between those two heads touches no plugin or test source other than the two Gate B.5 tests noted below.
- **Upstream identity (independently verified):** fresh `git clone --filter=blob:none` of `https://github.com/NousResearch/hermes-agent`, `git checkout --detach v0.23.0`. The annotated tag `v0.23.0` (tag object `df1774294af26285ae758c6114f3f2f60e2a602d`) peels to commit `2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`, tree `675b4cea2d2aef80460f07235b0e27e6c6922743`; the GitHub release "Hermes Agent v0.23.0 — The Hearth Release" pins the same commit. `git status --porcelain` empty before and after every gate below. No host Hermes checkout, operator mux, or personal overlay was used or consulted.
- **Upstream environment:** `uv sync --frozen --python 3.14 --group dev` (host `uv 0.11.16`), venv `Python 3.14.7`, `pytest 9.1.1`, `uv.lock` sha256 `5057a8a3cbc6d2b1f2059d66e27ffa43f447021f89779599dca416056574c064`. Both gates ran under `env -i` with an isolated disposable `HOME` and `HERMES_HOME`; zero credential variables in the environment, zero Google authentication, zero inference.

Reproducible recipe (positional placeholders; machine-local clone paths deliberately not recorded):

```bash
git clone --filter=blob:none https://github.com/NousResearch/hermes-agent <official-clone>
git -C <official-clone> checkout --detach v0.23.0
git -C <official-clone> rev-parse HEAD 'HEAD^{tree}'   # 2bd378ed1b8d… / 675b4cea2d2a…
(cd <official-clone> && uv sync --frozen --python 3.14 --group dev)

# from the reviewed ACP checkout — official catalog admission, isolated HOME/HERMES_HOME:
env -i HOME=<isolated-home> HERMES_HOME=<isolated-hermes-home> PATH=/usr/local/bin:/usr/bin:/bin \
  <official-clone>/.venv/bin/hermes plugins validate hermes-plugin/antigravity-acp --install-deps

# strict provider seam + upstream runtime contracts (0-skip gate):
env -i HOME=<isolated-home> HERMES_HOME=<isolated-hermes-home> PATH=/usr/local/bin:/usr/bin:/bin \
  UPSTREAM_HERMES_DIR=<official-clone> HERMES_STRICT_SEAM_TEST=1 \
  HERMES_TESTED_COMMIT=2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19 \
  HERMES_TESTED_TREE=675b4cea2d2aef80460f07235b0e27e6c6922743 \
  <official-clone>/.venv/bin/python -m pytest -q \
  tests/test_vanilla_hermes_seam.py tests/test_upstream_hermes_runtime_contracts.py

git -C <official-clone> status --porcelain            # must be empty
```

Results at official v0.23.0:

- **Official catalog admission:** `Validation passed` — manifest/fields/`requires_hermes`/capability probe/security scan all green, **zero core overrides** ("no runtime rebinds of Hermes core"), and exactly the **7 documented Catalog Rule 9 findings** (`tools.environments.local.hermes_subprocess_env`, `tools.skill_provenance.get_current_write_origin`, 4× `agent.file_safety.*`, `agent.redact.redact_sensitive_text`) plus the single informational `◇ Isolation` note. The seven warnings are **recorded, not laundered and not resolved**; the dynamic `session_context_engaged` latch dependency remains a retained private semantic dependency (class and register row above) whose risk this record does not retire.
- **Strict seam + runtime contracts:** at the pre-refresh head `ceec8e98` the existing pair ran **7 passed, 0 failed, 0 skipped, 0 warnings** (no false PASS from skips: `HERMES_STRICT_SEAM_TEST=1` fails closed on any import/setup loss). At the head carrying the evidence rework recorded below, the pair runs **10 passed, 0 failed, 0 skipped, 0 warnings**: the seven gates of the [Verification record](#verification-record), the two scenario tests in `tests/test_upstream_hermes_runtime_contracts.py` — `test_real_upstream_file_policy_gates_acp_bridge_reads_and_writes` (real upstream read-block/redaction/write-denial/`~/.ssh/config` approval gate/fail-closed-on-raise driving the ACP file bridge) and `test_real_upstream_lane_provenance_separates_affinity_and_fails_closed` (real `tools.skill_provenance` lane ContextVar separating ACP conversation affinity, fail-closed on lookup failure) — plus `test_core_provenance_oracle_rejects_substituted_core_modules`, the negative contract that the seam's provenance oracle rejects hand-built Core substitutes. The positive seam test exercises the real `create_openai_client` → `ProviderProfile.create_client` dispatch against official Core with **zero `sys.modules` substitution** — no stub, no rebind, no `types.ModuleType` stand-in anywhere on the positive path. The same 10-test pair ran green on pristine `v0.21.6` (`818c13be1dc4…`, tree `f36c56dd4fe0…`) and on live `main` (`110afdd60e30…`, tree `61e802ebeb6f…`), each with clean upstream status before and after — the floor promise and the moving-main gate both stay exercised with no CI workflow change.
- **Module provenance:** under the isolated environment, `providers`, `agent.file_safety`, `agent.redact`, `tools.skill_provenance`, `gateway.session_context` and `hermes_constants` all import from files inside the detached official checkout, and the seam asserts `Path(providers.__file__).is_relative_to(UPSTREAM_HERMES_DIR)` plus the tested commit/tree env pair; the plugin profile module resolves to the deployed plugin directory, never a host overlay. The genuine dispatch itself pulls `run_agent` in lazily inside `create_openai_client` and `hermes_state_pidns` through `agent.agent_runtime_helpers`' compression import; the seam asserts both immediately after dispatch: each `sys.modules` entry's `__file__` resolves inside the tested checkout and is tracked at the tested commit (`git ls-files --error-unmatch`). Provenance is file identity in the official checkout — never module type: every genuine imported module is also a `types.ModuleType` instance, so a type check neither admits fakes nor rejects real modules. The validator's core-override check reports zero rebinds; the plugin performs no `sys.modules` write to any Hermes core module (the documented latch read is lookup-only), and neither seam test writes to `sys.modules` on any positive path.
- **Evidence rework (2026-11-08, reviewer run 593):** the first Gate B.5 evidence head `3ab63df798fc…` substituted `run_agent` and `hermes_state_pidns` with hand-built `types.ModuleType` stubs in `sys.modules` inside the positive seam test, which invalidated the claimed unstubbed dispatch proof — an evidence defect, not a demonstrated runtime regression: no plugin or Core production code changed, and no production failure was observed or claimed. The `test_upstream_hermes_runtime_contracts.py` fault injections (module loss, policy raise) are a distinct, deliberate negative boundary and stay exactly where they are. Re-running the same resolved-file provenance assertions against the old seam fails RED (`sys.modules['run_agent']` had no `__file__` — a hand-built object, not the checkout module); the reworked seam runs GREEN with zero substitution on official `v0.23.0`, the `v0.21.6` floor and live `main` (counts above), and `test_core_provenance_oracle_rejects_substituted_core_modules` permanently guards the oracle against hand-built substitutes.
- **Support floor:** unchanged `">=0.21.6"`, still CI-proven by `catalog-floor-gate` (now including the two new contract tests). No register symbol's observed floor moved; every classification in the [Seven-module dependency register](#seven-module-dependency-register) re-confirmed against pristine v0.23.0 — all consulted symbols resolve with their recorded semantics, so **no new upstream contract request** is warranted: the new strict tests consume only symbols already covered by proposals 1, 2 and 4 below. No Hermes Core issue has been filed from this repository.
- **Plugin 0.6.0 rerun (2026-11-09, out-of-band login/dynamic-model hotfix, branch `fix/interactive-oauth-login` on `main@d65883d`):** the same two pristine-v0.23.0 gates were re-executed after the plugin gained the 8th managed file (`login.py`, the plugin-owned attended ACP login driver surfaced through `ProviderProfile.setup_status().login_command`) and dropped every curated model-id surface (picker fallback tuple and the single-entry `model_capabilities` map; model listing is now live-only). Fresh `git clone --filter=blob:none` of the official repository, `checkout --detach v0.23.0` → commit `2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`, tree `675b4cea2d2aef80460f07235b0e27e6c6922743` (identical to the Gate B.5 record above), `uv sync --frozen --python 3.14 --group dev`. `hermes plugins validate hermes-plugin/antigravity-acp --install-deps` under an isolated empty `HOME`/`HERMES_HOME` → **Validation passed** with exactly the same 7 recorded Catalog Rule 9 findings and the single isolation note (no new findings; `login.py` adds zero private core imports and zero core overrides). Strict pair under the isolated environment with `HERMES_STRICT_SEAM_TEST=1` and the exact commit/tree binding → **10 passed, 0 failed, 0 skipped**; upstream clone `git status --porcelain` empty after the run. Credential-free lane: `python -m pytest -q tests --ignore=tests/test_upstream_hermes_runtime_contracts.py` → **850 passed, 6 skipped**, `ruff check` and `scripts/audit_public_tree.py` clean. Zero Google credentials, zero inference in every command above.

Scenario-to-test coverage map (strict = upstream-venv lane at v0.23.0/v0.21.6/main; free = credential-free CI job):

| Issue scenario | Executed coverage |
| --- | --- |
| Session-scoped cwd; refusal when the cwd API is lost | strict: `test_agent_cwd_uses_session_scope_and_refuses_process_cwd_on_api_loss` |
| Cron job cwd with empty session ids (dynamic `session_context_engaged` latch armed by the real upstream module); API-loss refusal and resolver-crash refusal | strict: `test_cron_scope_without_session_ids_refuses_process_cwd_on_api_loss`; free: `test_hermes_compat.py::test_cron_style_scope_without_session_ids_fails_closed_on_cwd_api_loss`, `::test_runtime_cwd_call_failure_never_falls_back_to_process_cwd`, `::test_unbound_hermes_process_keeps_launch_cwd_fallback_on_cwd_api_loss` |
| Per-profile `HOME`/scratch scoping and fail-closed home policy | strict: `test_subprocess_home_and_scratch_are_profile_scoped_and_fail_closed` |
| Subprocess minimum-env allowlist and credential non-inheritance (real upstream `inherit_credentials=True` premise + a real child dumping its own environment) | strict: `test_real_upstream_credential_policy_success_is_narrowed_for_acp_child`, `test_credential_free_fake_acp_initialize_session_under_real_policy_filtering`; free: `test_runtime_safety_isolation.py` enumeration/sibling-path gates |
| Read block, forced redaction, write denial, approval gate | strict: `test_real_upstream_file_policy_gates_acp_bridge_reads_and_writes` (new); free: `test_runtime_safety_isolation.py::test_fs_read_redacts_secret_material_before_return` and the five adjacent `test_fs_read_*`/`test_fs_write_*` failure-matrix tests |
| Lane provenance (write-origin separates ACP affinity; unknown lane fails closed) | strict: `test_real_upstream_lane_provenance_separates_affinity_and_fails_closed` (new); free: `test_hermes_compat.py::test_write_origin_without_a_hermes_tools_package_uses_standalone_lane` |
| Cancellation (cancelled ACP turn never surfaces as an answer; unattended permission conflicts cancelled over JSON-RPC) | free: `test_fake_acp_e2e.py::test_fake_actual_turn_cancellation_remains_an_error`, `test_hotfix_permission_and_read.py::test_conflicting_aliases_are_cancelled_over_jsonrpc`, `test_runtime_safety_isolation.py::test_unattended_permission_without_reject_option_fails_closed_cancelled` (ACP-protocol surface — no Hermes Core symbol involved) |
| Denial (non-vetted permission requests select reject; missing reject option fails closed) | free: `test_hotfix_permission_and_read.py::test_non_vetted_permission_requests_select_reject_not_allow`, `::test_missing_reject_option_fails_closed_and_reports_protocol_limitation`, `::test_policy_denial_selects_server_reject_once_and_logs_safe_telemetry`, `test_trusted_coding_mode.py::test_chooser_blocks_outside_workspace_credentials_and_forgery` |
| Fail-closed on every consulted private seam | strict: cron/API-loss refusals, home-policy failure, new write-policy-raise and origin-raise denials; free: `test_hermes_compat.py` missing/broken-API failure matrix |

### Release-target CI gate assessment

Assessed 2026-11-08; decision: **no permanent v0.23.0 CI job — preserve this reproducible pinned evidence record plus the existing floor and live-main gates**, which the issue text explicitly permits. Cost side: each upstream-venv job re-syncs the full official dependency tree (`uv sync --frozen --group dev`, `timeout-minutes: 20` budget each) on every PR/push; a third pinned job adds one more full upstream dependency resolution per change on top of the four-job workflow's ~95-minute timeout budget, and every new Hermes release turns the pinned matrix into a freshness chore. Benefit side: upstream `v0.23.0` artifacts are immutable, so a standing job can only re-derive this same record — the only moving input is the plugin, and every plugin change already runs the identical contract file set at both ends of the support window (pinned `v0.21.6`, live `main`) including the two new scenario tests. Honest residual risk, recorded rather than hidden: a regression that reproduces **only** at the v0.23.0 mid-point (invisible at both tested ends) would not be caught by CI between pinned runs; the recipe above is the on-demand gate. Re-evaluation triggers: the release line the operator actually deploys changes; a plugin change targets v0.23.0-specific behavior; either pinned CI lane goes red on a Rule 9-adjacent contract; or the next Hermes SemVer release lands (then re-record for the new latest release).

Boundary: nothing in this record implies credentialed Google auth or inference, catalog submission, publication, or any deployment. No environment outside the disposable isolation directories was created, mutated, or consulted.

## Upstream contract proposals

For the seven remaining Rule 9 findings there is currently no evidenced public alternative. The smallest upstream changes that would retire each private import (no behavior change requested — Hermes exposes what it already enforces):

1. **File-safety policy** — catalog-list (or re-export from a documented module) the four existing pure decision functions `agent.file_safety:get_nt_namespace_error`, `:get_read_block_error`, `:get_write_denied_error`, `:is_write_approval_required` as plugin-facing, with their present "returns a denial reason or `None`" contract versioned. Consumed today by `get_nt_namespace_error`, `get_file_read_safety`, `get_file_write_safety`.
2. **Redaction** — catalog-list `agent.redact:redact_sensitive_text` with its `force=True` read-path semantics documented as plugin-facing. Consumed today by `get_file_read_safety`.
3. **Subprocess environment policy** — catalog-list `tools.environments.local:hermes_subprocess_env` (or document a `hermes_subprocess_env(inherit_credentials=True) -> dict[str, str]` sanitizer on the terminal-environment plugin page next to the already-public `BaseEnvironment`). Consumed today by `build_hermes_subprocess_env`.
4. **Write-origin / lane provenance** — expose the current lane as a public accessor (e.g. `get_write_origin()` on `gateway.session_context` beside `get_session_env`, or a `PluginContext` property) with the same "lane name string, unknown never silently defaults across lanes" contract. Consumed today by `get_current_write_origin`.
5. **Profile home / subprocess HOME-scratch policy** — `hermes_constants` is catalog-permitted at module level but the *policy* is undocumented; either document `get_hermes_home()`/`apply_subprocess_home_env(env)` as a versioned plugin-facing contract, or surface the same through `PluginContext` (e.g. `ctx.hermes_home`). Consumed today by `get_hermes_home`, `get_hermes_home_for_video`, `apply_subprocess_home_env`.

Downstream tracking: this document is the registry; the trigger to re-evaluate is any `upstream-hermes-compat` CI run against a new upstream `main` (its `hermes plugins validate`/seam results are the oracle) or upstream acknowledgment of a proposal. Until Hermes ships one, the plugin keeps the private import **and** its fail-closed contract; none of these capabilities may be replaced by a local policy copy. Proposal disposition at delivery time: documented for Hermes maintainers (the validator itself instructs "open an issue for the seam you need"); no Hermes Core issue has been filed from this repository as of the tested upstream commit, and filing upstream issues is a maintainer decision tracked from here.

## ACP child minimum environment contract

The official Google ACP child needs local runtime state only; Google
authentication is managed inside Google's own runtime and the catalog declares
an empty `requires_env` surface. Hermes' `hermes_subprocess_env(inherit_credentials=True)`
policy is consulted first and its result (or, without a Hermes runtime, the
process environment) is only the **base**: `client.py::_build_subprocess_env`
narrows either base through `_acp_child_env_filter` to an explicit enumerated
allowlist — `PATH`, `HOME`, `USER`/`LOGNAME`, `SHELL`, `LANG`/`TERM`,
`TMPDIR`/`TEMP`/`TMP`, `PYTHONUTF8`, `HERMES_REAL_HOME`, `HERMES_HOME`,
`GEMINI_HOME`, the POSIX locale categories `LC_ALL`/`LC_CTYPE`/`LC_MESSAGES`/
`LC_COLLATE`/`LC_MONETARY`/`LC_NUMERIC`/`LC_TIME`, the Windows OS/profile
roots `SYSTEMROOT`/`WINDIR`/`USERPROFILE`/`HOMEDRIVE`/`HOMEPATH`/`APPDATA`/
`LOCALAPPDATA` (Windows shells usually leave `HOME` unset, and without these
the official server has no home directory), and the four per-user XDG
Base Directory variables `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_CACHE_HOME`/
`XDG_STATE_HOME` — before adding the profile-resolved `HERMES_HOME`
(active Hermes runtime only), the resolved `HOME`, and Hermes' own
`apply_subprocess_home_env` HOME/scratch policy.

There are no wildcard prefixes: an `LC_`/`XDG_` prefix silently authorizes arbitrary
future names such as `XDG_ACCESS_TOKEN` or `LC_API_TOKEN`. Admitted XDG base
values face a second, path-level gate: they are kept only when they resolve
inside the child's own profile home, so a parent or sibling profile's path is
never copied in merely because the key name is approved; a dropped base falls
back to the XDG spec defaults under the child's own `HOME`. `XDG_RUNTIME_DIR`
(rooted in `/run/user/<uid>` by spec), the system-wide `XDG_*_DIRS` search
lists, and desktop-session identity variables are not needed by the headless
ACP child and stay off the allowlist.

This second filter is load-bearing, not belt-and-braces: real unmodified
upstream Hermes (declared floor `v0.21.6` through current `main`) **intentionally
retains** Tier-2 provider credentials such as `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, and `GEMINI_API_KEY` under `inherit_credentials=True` —
that is upstream's documented behavior for children that need provider
credentials, and the ACP child does not need them. Provider/cloud credentials,
Tier-1 gateway tokens, session identity (`HERMES_SESSION_ID`/`HERMES_SESSION_KEY`),
and operator `ACP_MUX_*` multiplexor configuration therefore never reach the
child. `_spawn` supplies only the multiplexor coordination keys it owns itself
(`ACP_MUX_AFFINITY*`, `ACP_MUX_SESSION_GC`, and a pinned `ACP_MUX_PAR` from the
per-deployment `par.txt`) after this filter; mux deployments receive such values
from the wrapper's own launch context, not from provider-env inheritance.
Host-policy failure inside an active Hermes runtime remains fail-closed
(`RuntimeError`, child startup refused).

Gates: `tests/test_runtime_safety_isolation.py` (host-policy-success and
offline-fallback paths, the `LC_*`/`XDG_*` explicit-enumeration and
sibling-profile-path gates, plus a fake ACP child that dumps its own real
environment) and `tests/test_upstream_hermes_runtime_contracts.py` (the real,
unmocked upstream policy at both hosted upstream lanes, asserting the Tier-2
retention premise and the narrowed child environment). A premise assertion that
upstream stops retaining Tier-2 keys is an intentional signal to re-investigate
this contract, not a test to delete.

## Preserved boundary

- ACP transport, resume/persistence, mux affinity/failover, tool pairing, and multimodal payload handling remain plugin-owned and do not inherit from Hermes' Copilot ACP client.
- File access still requires absolute paths, path-root containment, credential-root denial, Hermes read-block/redaction policy, and write-denial/approval checks — denial reasons come from Hermes, and a policy call that raises is itself a denial (`PermissionError`), never a fallback.
- ACP child environments remain profile-scoped and sanitized under the minimum contract above; official vendor credentials stay inside the official ACP runtime.
- An active Hermes task/session/cron scope never falls back to the broader process cwd, and an unknown write origin never reuses a foreground ACP session across lanes.
- A future Hermes update that removes a security-required helper must fail closed. It must not be "fixed" by copying Hermes policy into this plugin.

The ordinary credential-free CI job remains independent of an installed Hermes checkout and may skip its optional seam test. The separate `upstream-hermes-compat` job is the non-skipping compatibility gate.
