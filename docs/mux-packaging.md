# ACP MUX packaging (strictly opt-in)

Status: **optional preview.** The default product is **Single**:
one user-selected account/environment → unmodified official Google ACP
server (`scripts/install_acp.py`) → Hermes provider. Nothing in the default
install imports, installs, configures, or runs MUX. The optional MUX bundle
is preview code. Review applicable Google terms, authentication boundaries,
and privacy requirements before enabling it.

## Mode selection

There is no account-count auto-detection and no silent switching. The mode
is chosen per Hermes profile by the provider command it points at:

| Mode | Provider command |
| --- | --- |
| Single (default) | `antigravity-acp-official` (installed by `install_acp.py`) |
| MUX (explicit opt-in) | `<bin-dir>/antigravity-acp-mux` |

The existing `HERMES_ANTIGRAVITY_ACP_COMMAND` override remains the supported
activation lever. Installing the MUX bundle changes **nothing** about Single
installs, updates, model selection, sessions, or failure handling.

## Install (opt-in)

From a checkout of this repository:

```sh
python3 scripts/install_mux.py --bin-dir "$HOME/.local/bin" install
```

- Copies exactly three reviewed files (`acp_mux.py`, `antigravity-acp-mux.py`,
  `antigravity-acp-mux`) plus an install manifest.
- If any target path already exists and is not byte-identical to this bundle,
  the installer aborts **fail-closed with zero writes**.
- The installer never writes profiles, env files, account registries, or
  secrets, and never starts a daemon.

## Activate

Point one Hermes profile at the mux launcher and provide the mux contract
explicitly (see the environment table in `scripts/acp_mux.py`, e.g.
`ACP_MUX_ACCOUNTS`, `ACP_MUX_PAR` or `HERMES_ANTIGRAVITY_ACP_PAR`,
`ACP_MUX_DEFAULT_HOME`). The official per-account login flow stays inside
Google's official ACP runtime; the mux never reads credential files or
exchanges tokens.

## Status (doctor)

```sh
python3 scripts/install_mux.py --bin-dir "$HOME/.local/bin" status
```

Reports bundle presence/integrity, the launcher path, launcher/PAR
resolution (`ACP_MUX_PAR` → `HERMES_ANTIGRAVITY_ACP_PAR` → PATH), and the
resolved registry path + existence. Registry **contents**, credentials, and
account identifiers are never read or printed. Unresolved PAR means MUX would
fail closed; Single is unaffected.

## Rollback

```sh
python3 scripts/install_mux.py --bin-dir "$HOME/.local/bin" uninstall
```

Deletes only files recorded in the install manifest (after re-verifying their
hashes; tampered bytes abort with nothing deleted). `antigravity-acp-official`
and every non-bundle file are preserved, so the Single path survives MUX
removal byte-for-byte. After uninstall, restore the profile's provider
command to the official launcher.

## Guarantees (tested in `tests/test_mux_packaging.py`)

1. Fresh/updated Single installs are byte-identical with the MUX bundle absent;
   plugin sources never import the mux.
2. Install refuses foreign bytes fail-closed; install is idempotent.
3. Uninstall removes exactly the manifest set and preserves Single + foreign
   files; tampered bundle files abort deletion.
4. `status` never echoes registry contents or secrets.
5. No deployment, restart, real OAuth, or model inference is implied by any
   command in this document.
