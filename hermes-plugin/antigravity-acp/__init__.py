"""Hermes provider plugin for Google's official Antigravity ACP server."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, cast

from providers import register_provider
from providers.base import ProviderProfile

# Status probes and model discovery each need a live server surface.  The
# warm process pool in client.py usually serves these from a parked process,
# but the first call in a Hermes process still cold-spawns the official
# binary — through a cmd.exe wrapper on Windows, which stalled the CLI on
# every status render and every ``/model`` open.  A signed-in probe and a
# live model surface are stable within a session, so cache them in-process
# with a TTL instead of re-probing.
# A negative login probe is never cached: the sign-in wizard re-checks
# seconds after an interactive login and must re-probe immediately.
_LOGIN_TRUE_TTL_SECONDS = 300.0
_MODELS_TTL_SECONDS = 300.0

# First-call budgets for spawn + initialize + one round-trip.  On Windows
# ARM64 laptops every fresh server process is scanned by Defender before it
# answers, so a cold spawn alone can exceed 20s; the previous 20s/25s hard
# budgets turned a merely slow machine into a false "did not answer a status
# probe" / "Login failed" even right after a successful interactive login.
# The TTL caches above mean this budget is paid at most once per process, so
# generous defaults cost nothing on healthy machines.  Overridable per box.
_PROBE_TIMEOUT_SECONDS = 60.0
_DISCOVERY_TIMEOUT_SECONDS = 60.0


def _env_timeout(name: str, default: float) -> float:
    """Positive float from ``name`` or ``default``; junk falls back silently."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default

_DEFAULT_RATE_LIMIT_RETRIES = 2
_MAX_RATE_LIMIT_RETRIES = 8
# JSON-RPC code the official server returns when a session request arrives
# before Google authentication completed (the documented auth boundary).
_ACP_AUTH_REQUIRED_ERROR_CODE = -32000


def _resolve_launch_command(command: object) -> str | None:
    """Resolve a profile ``process_command`` to an executable, or None.

    Mirrors Hermes' own external-process evidence rule (PATH, then the user
    local bin): a PATH-named CLI (e.g. a launcher or mux under ``~/.local/bin``)
    is just as "installed" as an absolute path. Never touches credentials.
    """
    name = str(command or "").strip()
    if not name:
        return None
    found = shutil.which(name)
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / name
    if candidate.is_file():
        return str(candidate)
    return None


def _default_official_command() -> str:
    """Resolve the user-scoped official launcher without assuming a fixed home."""
    launcher_name = (
        "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"
    )
    launcher = Path.home() / ".local" / "bin" / launcher_name
    if launcher.is_file():
        return str(launcher)
    return "antigravity-acp-official"


def _stored_launch_config() -> tuple[str | None, tuple[str, ...]]:
    """Load a legacy launch configuration preserved by the profile installer."""
    path = Path(__file__).with_name("launch_config.json")
    if path.is_symlink():
        raise RuntimeError("Refusing a symlinked Antigravity launch configuration")
    try:
        raw_config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Antigravity launch configuration is unreadable") from exc
    if not isinstance(raw_config, dict):
        raise RuntimeError("Antigravity launch configuration must be an object")
    config = cast(dict[str, object], raw_config)
    command = config.get("process_command")
    args = config.get("process_args")
    if (
        not isinstance(command, str)
        or not command
        or not isinstance(args, list)
        or any(not isinstance(arg, str) for arg in args)
    ):
        raise RuntimeError("Antigravity launch configuration is invalid")
    return command, tuple(cast(list[str], args))


_STORED_PROCESS_COMMAND, _STORED_PROCESS_ARGS = _stored_launch_config()


def _rate_limit_retries() -> int:
    raw = os.environ.get(
        "HERMES_ANTIGRAVITY_ACP_RATE_LIMIT_RETRIES",
        str(_DEFAULT_RATE_LIMIT_RETRIES),
    )
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = _DEFAULT_RATE_LIMIT_RETRIES
    return max(0, min(value, _MAX_RATE_LIMIT_RETRIES))


class AntigravityACPProfile(ProviderProfile):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # (monotonic_deadline, value); guarded by the GIL for the simple
        # read/replace pattern used here.
        self._login_probe_cache: tuple[float, bool] | None = None
        self._models_cache: tuple[float, list[dict[str, Any]]] | None = None

    def _cached_login_probe(self) -> bool | None:
        entry = self._login_probe_cache
        if entry is not None and time.monotonic() < entry[0]:
            return entry[1]
        return None

    def _store_login_probe(self, logged_in: bool) -> None:
        # Negative answers are never cached (see module comment): the sign-in
        # wizard must re-probe the moment an interactive login completes.
        if logged_in:
            self._login_probe_cache = (
                time.monotonic() + _LOGIN_TRUE_TTL_SECONDS,
                True,
            )

    def create_client(self, **client_kwargs: Any) -> Any:
        from .client import AntigravityACPClient

        # Hermes may reconstruct runtime metadata with explicit-but-empty launch
        # fields (command=None / args=[]).  Repair only falsy launch values while
        # preserving non-empty user overrides; this provider owns the official
        # Antigravity ACP subprocess contract.
        if not client_kwargs.get("command"):
            client_kwargs["command"] = self.process_command
        if not client_kwargs.get("args"):
            client_kwargs["args"] = list(self.process_args)
        if not client_kwargs.get("base_url"):
            client_kwargs["base_url"] = self.base_url
        client_kwargs.setdefault("rate_limit_retries", _rate_limit_retries())
        return AntigravityACPClient(**client_kwargs)

    def fetch_models(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 20.0,
    ) -> list[str] | None:
        # Derive from discover_models so one cached server surface answers
        # both picker shapes; the ACP contract ignores api_key/base_url.
        rows = self.discover_models()
        if not rows:
            return None
        return [str(row.get("id") or "").strip() for row in rows if row.get("id")] or None

    def _probe_login_state(self, *, timeout_seconds: float | None = None) -> bool:
        """True when a fresh server session opens; False on the auth boundary.

        Spawns (or warm-reuses) the official server and performs only
        ``initialize`` and ``session/new`` — never authenticate, login, or a
        model prompt. Any non-auth failure raises so callers can fail closed
        instead of reporting a false "logged in". A fresh cached answer (see
        the TTL constants) is returned without spawning.
        """
        cached = self._cached_login_probe()
        if cached is not None:
            return cached
        if timeout_seconds is None:
            timeout_seconds = _env_timeout(
                "HERMES_ANTIGRAVITY_ACP_PROBE_TIMEOUT_SECONDS",
                _PROBE_TIMEOUT_SECONDS,
            )
        client = self.create_client(
            command=self.process_command,
            args=list(self.process_args),
        )
        try:
            client.list_models(timeout_seconds=timeout_seconds)
        except Exception as exc:  # noqa: BLE001 — classify the boundary only
            message = str(exc)
            if (
                f"code={_ACP_AUTH_REQUIRED_ERROR_CODE}" in message
                or "Authentication required" in message
            ):
                return False
            raise
        else:
            self._store_login_probe(True)
            return True
        finally:
            client.close()

    def _login_command(self) -> list[str]:
        return [
            sys.executable,
            str(Path(__file__).resolve().parent / "login.py"),
            "--method",
            "oauth-personal",
        ]

    def setup_status(self, **kwargs: Any) -> dict[str, Any] | None:
        """Generic plugin-flow status: official server presence + live login state.

        ``logged_in`` is probed against the real server (no credential file is
        ever read). An unusable install reports ``available=False`` with a
        fixed-text detail; nothing here invents account or plan data.
        """
        launcher = _resolve_launch_command(self.process_command)
        available = launcher is not None or str(self.base_url or "").startswith("acp+tcp://")
        detail = (
            "The official Antigravity ACP server has not been installed yet; "
            "run the hermes-antigravity-acp installer first."
            if not available
            else ""
        )
        logged_in = False
        if available:
            try:
                logged_in = self._probe_login_state()
            except Exception:
                return {
                    "available": True,
                    "logged_in": False,
                    "plan": "",
                    "detail": (
                        "The official ACP server did not answer a status probe; "
                        "inspect the server installation manually before retrying."
                    ),
                    "login_command": self._login_command(),
                }
            if not logged_in:
                detail = (
                    "Not signed in to Google through the official Antigravity ACP "
                    "server; sign in to continue"
                )
        return {
            "available": available,
            "logged_in": logged_in,
            "plan": "",
            "detail": detail,
            "login_command": self._login_command(),
        }

    def discover_models(self, **kwargs: Any) -> list[dict[str, Any]] | None:
        """The signed-in account's live model rows from both server surfaces.

        ids/labels/notes come from the server's own entries only (ids from
        ``value``/``modelId``, labels from ``name``); the curated static list
        is intentionally empty so a picker can never offer a model the
        account does not have. ``None`` (falling through to the empty floor)
        is returned on any failure, including the not-logged-in boundary.
        A fresh cached listing is returned without spawning the server.
        """
        cached = self._models_cache
        if cached is not None and time.monotonic() < cached[0]:
            return list(cached[1])
        try:
            client = self.create_client(
                command=self.process_command,
                args=list(self.process_args),
            )
        except Exception:
            return None
        try:
            config_entries, legacy_entries = client.session_model_surface(
                timeout_seconds=_env_timeout(
                    "HERMES_ANTIGRAVITY_ACP_DISCOVERY_TIMEOUT_SECONDS",
                    _DISCOVERY_TIMEOUT_SECONDS,
                )
            )
        except Exception:
            return None
        finally:
            client.close()
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()

        def _add(raw_id: Any, label: Any, note: str) -> None:
            model_id = str(raw_id or "").strip()
            if not model_id or model_id in seen:
                return
            seen.add(model_id)
            row: dict[str, Any] = {"id": model_id}
            rendered = str(label or "").strip()
            if rendered and rendered != model_id:
                row["label"] = rendered
            if note:
                row["note"] = note
            rows.append(row)

        for entry in config_entries:
            meta = entry.get("_meta") if isinstance(entry.get("_meta"), dict) else {}
            enablement = str(meta.get("copilotEnablement") or "").strip().lower()
            if enablement == "disabled":
                continue
            note = f"surface: model config ({enablement or 'enabled'})"
            _add(entry.get("value"), entry.get("name") or entry.get("label"), note)
        for entry in legacy_entries:
            meta = entry.get("_meta") if isinstance(entry.get("_meta"), dict) else {}
            enablement = str(meta.get("copilotEnablement") or "").strip().lower()
            if enablement == "disabled":
                continue
            _add(entry.get("modelId"), entry.get("name"), "surface: session models")
        if rows:
            self._models_cache = (time.monotonic() + _MODELS_TTL_SECONDS, list(rows))
        return rows or None


antigravity_acp = AntigravityACPProfile(
    name="antigravity-acp",
    aliases=(
        "antigravity-cli",
        "agy",
        "antigravity",
        "agy-acp",
        "antigravity-official-acp",
    ),
    display_name="Antigravity ACP (official)",
    description="Google Antigravity through Google's official ACP v1 stdio server",
    api_mode="chat_completions",
    env_vars=(),
    base_url="acp://antigravity",
    auth_type="external_process",
    supports_vision=True,
    supports_vision_tool_messages=True,
    # Use the official launcher directly. Host-specific muxes remain an explicit
    # command override and are not a prerequisite for a generic installation.
    process_command=_STORED_PROCESS_COMMAND or _default_official_command(),
    # The official launcher supplies platform-specific registry arguments.
    process_args=_STORED_PROCESS_ARGS,
    process_command_env_vars=("HERMES_ANTIGRAVITY_ACP_COMMAND",),
    process_args_env_var="HERMES_ANTIGRAVITY_ACP_ARGS",
    # No curated picker floor: every offered model id must come from the
    # signed-in account's live server surfaces (fetch_models/discover_models).
    # A cold or unauthenticated listing offers only the free-text input, so
    # the picker can never present a model id the account does not have.
    fallback_models=(),
)

register_provider(antigravity_acp)
