"""Narrow adapter for Hermes host integrations used by the ACP provider.

The provider's public boundary is ``ProviderProfile.create_client`` plus ACP
JSON-RPC. Hermes-only conveniences and policy hooks stay here so upstream
module moves have one compatibility surface. Security policy is never
reimplemented here: missing file-safety APIs are surfaced to the client, which
fails closed. The subprocess fallback remains an explicit environment allowlist
in ``client.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, MutableMapping


def hermes_runtime_present() -> bool:
    """Whether this process has loaded Hermes' public provider or a runtime package."""
    providers = sys.modules.get("providers")
    if providers is not None and getattr(providers, "__file__", None):
        return True
    return any(
        sys.modules.get(name) is not None
        for name in ("agent", "gateway", "tools", "hermes_constants")
    )


def _active_hermes_session() -> bool:
    """Fail closed when an active Hermes task scope cannot obtain its scoped cwd.

    Uses upstream's own signals only, and imports nothing: only a
    ``gateway.session_context`` module already loaded into this process can
    have bound a task scope, because only that module's ``set_session_vars``
    arms the session key/id and the process-wide ``session_context_engaged``
    latch. A module that was never loaded therefore proves no task scope was
    ever bound here, and the launch-directory fallback stays intact — an
    import would cross-load the very package whose absence is being asked
    about, and inherited ``HERMES_SESSION_ID``/``HERMES_SESSION_KEY`` process
    environment values are child-process residue that must not hijack an
    unbound process. Cron's ``_CronRunScope`` binds a per-job cwd with empty
    session key/id but engages the latch, so the ids alone cannot prove
    "no active workspace".
    """
    session_context = sys.modules.get("gateway.session_context")
    if session_context is None:
        return False
    try:
        get_session_env = session_context.get_session_env
        if get_session_env("HERMES_SESSION_KEY", "") or get_session_env("HERMES_SESSION_ID", ""):
            return True
        engaged = getattr(session_context, "session_context_engaged", None)
        if callable(engaged):
            return bool(engaged())
        # Older upstream without the latch: cron marks its run scope explicitly.
        return bool(get_session_env("HERMES_CRON_SESSION", ""))
    except Exception:
        return True


def get_hermes_home() -> Path:
    """Resolve the active Hermes home, with the provider's standalone fallback."""
    try:
        from hermes_constants import get_hermes_home as resolve_home
    except (ImportError, AttributeError):
        configured = os.environ.get("HERMES_HOME", "").strip()
        if configured:
            return Path(os.path.expandvars(os.path.expanduser(configured)))
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes active home cannot be resolved; refusing to use the default profile."
            )
        return Path.home() / ".hermes"
    return Path(resolve_home())


def get_hermes_home_for_video() -> Path | None:
    """Resolve a video-cache root only when the home is established safely."""
    try:
        from hermes_constants import get_hermes_home as resolve_home
    except (ImportError, AttributeError):
        configured = os.environ.get("HERMES_HOME", "").strip()
        if configured:
            return Path(os.path.expandvars(os.path.expanduser(configured)))
        base_home = os.environ.get("HOME", "").strip()
        if not base_home:
            return None
        return Path(base_home) / ".hermes"
    return Path(resolve_home())


def build_hermes_subprocess_env() -> dict[str, str] | None:
    """Ask Hermes' credential-aware environment policy; None selects the safe local allowlist.

    The returned mapping is a base, never the child contract: upstream
    ``hermes_subprocess_env(inherit_credentials=True)`` intentionally retains
    Tier-2 provider credentials for children that need them. The caller in
    ``client.py`` narrows any result through the ACP child minimum-environment
    contract before spawning.
    """
    try:
        from tools.environments.local import hermes_subprocess_env
    except ImportError:
        return None
    try:
        return hermes_subprocess_env(inherit_credentials=True)
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess environment policy failed; refusing to start the ACP child."
            ) from exc
        return None


def apply_subprocess_home_env(env: MutableMapping[str, str]) -> bool:
    """Apply Hermes HOME/scratch policy; fail closed in an active Hermes runtime."""
    try:
        from hermes_constants import apply_subprocess_home_env as apply_home_policy
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess HOME/scratch policy is unavailable; refusing to start the ACP child."
            ) from exc
        return False
    try:
        apply_home_policy(env)
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess HOME/scratch policy failed; refusing to start the ACP child."
            ) from exc
        return False
    return True


def windows_hide_flags() -> int:
    """Use Python's platform flag directly; window suppression is optional UX."""
    import subprocess

    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def get_runtime_session_env() -> tuple[str, str]:
    """Return gateway session identifiers, falling back to explicit process env."""
    try:
        from gateway.session_context import get_session_env

        session_id = str(get_session_env("HERMES_SESSION_ID", "") or "").strip()
        session_key = str(get_session_env("HERMES_SESSION_KEY", "") or "").strip()
    except Exception:
        session_id = str(os.environ.get("HERMES_SESSION_ID", "") or "").strip()
        session_key = str(os.environ.get("HERMES_SESSION_KEY", "") or "").strip()
    return session_id, session_key


def get_current_write_origin() -> str:
    """Return the Hermes lane; unknown origin is unsafe when a session identity exists."""
    try:
        from tools.skill_provenance import get_current_write_origin as resolve_origin
    except ImportError as exc:
        if "tools" not in sys.modules:
            return "foreground"
        raise RuntimeError(
            "Hermes write-origin context is unavailable; refusing to reuse an ACP session across lanes."
        ) from exc
    try:
        origin = str(resolve_origin() or "foreground").strip()
    except Exception as exc:
        raise RuntimeError(
            "Hermes write-origin lookup failed; refusing to reuse an ACP session across lanes."
        ) from exc
    return origin or "foreground"


def resolve_agent_cwd() -> Path | None:
    """Resolve Hermes' request-scoped cwd when that optional context API exists."""
    try:
        from agent.runtime_cwd import resolve_agent_cwd as resolve_cwd
    except ImportError as exc:
        if _active_hermes_session():
            raise RuntimeError(
                "Hermes session-scoped workspace is unavailable; refusing to use process cwd."
            ) from exc
        return None
    try:
        return Path(resolve_cwd())
    except Exception as exc:
        raise RuntimeError(
            "Hermes session-scoped workspace lookup failed; refusing to guess the workspace."
        ) from exc


def get_nt_namespace_error(path: str, *, verb: str) -> str | None:
    """Delegate NT/UNC namespace policy; absence is intentionally an error."""
    from agent.file_safety import get_nt_namespace_error as check_namespace

    return check_namespace(path, verb=verb)


def get_file_read_safety() -> tuple[Any, Any]:
    """Return Hermes read-block and redaction policy, without a local substitute."""
    from agent.file_safety import get_read_block_error
    from agent.redact import redact_sensitive_text

    return get_read_block_error, redact_sensitive_text


def get_file_write_safety() -> tuple[Any, Any]:
    """Return Hermes write-denial and approval policy, without a local substitute."""
    from agent.file_safety import get_write_denied_error, is_write_approval_required

    return get_write_denied_error, is_write_approval_required
