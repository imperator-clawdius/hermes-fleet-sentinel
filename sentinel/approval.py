"""Human approval gate for model-initiated recovery.

``fleet_recover`` mutates a remote machine: it can SIGTERM a gateway, delete a
``gateway.pid`` lock, or send a Wake-on-LAN packet. Its ``dry_run``/``confirm``
flags are set by the *model*, and a flag the model sets is not consent — a
prompt-injected turn could set both and act.

This module supplies the ``pre_tool_call`` hook that closes that hole. Any
``fleet_recover`` call that would actually act is escalated to Hermes's
human-approval gate; the gate fails closed in unattended runs. Dry runs,
the CLI ``--execute`` path, and user-enabled ``auto_heal`` are untouched,
because none of them originate from the model.

The hook is a pure function of ``(tool_name, args)`` so it can be unit-tested
without a plugin host.
"""

from __future__ import annotations

from typing import Any, Optional

APPROVAL_TOOL = "fleet_recover"


def recovery_needs_approval(args: Any) -> bool:
    """True when this call would act on a host rather than simulate it.

    ``dry_run`` defaults to true in the tool schema, so only the explicit
    ``False`` (the same strict check ``recover.should_execute`` makes) counts
    as a real recovery.
    """
    return isinstance(args, dict) and args.get("dry_run") is False


def _clean(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def approval_hook(*, tool_name: str = "", args: Optional[dict] = None, **_kwargs: Any) -> Optional[dict]:
    """``pre_tool_call`` callback: escalate real recoveries, ignore everything else.

    Returns ``{"action": "approve", ...}`` for a non-dry ``fleet_recover`` and
    ``None`` otherwise. Hermes treats a ``rule_key`` as the grain of its
    ``[a]lways`` allowlist, so approving one verb does not silently approve the
    others.
    """
    if tool_name != APPROVAL_TOOL:
        return None
    if not recovery_needs_approval(args):
        return None
    payload = args or {}
    action = _clean(payload.get("action"), "recover")
    host = _clean(payload.get("host"), "unknown host")
    return {
        "action": "approve",
        "message": f"fleet-sentinel: {action} on {host}",
        "rule_key": f"fleet_recover:{action}",
    }
