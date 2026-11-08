"""Tool schemas and handlers. Handlers return JSON strings and never raise."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from .recover import ACTIONS

logger = logging.getLogger(__name__)

TOOLSET = "fleet"
EMOJI = "🛰"

FLEET_STATUS_DESC = (
    "Live health of every configured remote Hermes agent host. Probes each host (tailnet, TCP, one ssh "
    "round trip) and returns a corroborated verdict per host: up (gateway alive with >=1 platform socket), "
    "deaf (gateway alive but 0 platform sockets past the grace window), down_physical (tailnet offline AND "
    "TCP failed: power/cable), degraded, or unknown (probe could not complete). Includes last_ok and a short "
    "reason. Use when asked whether the fleet, a bot, or a remote agent is up."
)
FLEET_PROBE_DESC = (
    "Full probe-ladder evidence for one fleet host: what tailscale, the TCP connect and the remote ssh probe "
    "each returned (unit state, MainPID, platform socket count, gateway_state.json and whether it is stale), "
    "and the reasoning that produced the verdict. Use to explain or debug a single host's verdict."
)
FLEET_RECOVER_DESC = (
    "Recovery action for one fleet host. restart-gateway kills the systemd unit's MainPID so Restart=always "
    "starts a fresh gateway (refused unless the unit has Restart=always); clear-lock removes a gateway.pid "
    "lock only when its pid is dead; wake sends a Wake-on-LAN packet when the host has wol_mac. Dry run by "
    "default: it only acts when dry_run is false AND confirm is true. Ask the user before acting."
)

SCHEMAS: dict[str, dict[str, Any]] = {
    "fleet_status": {
        "name": "fleet_status",
        "description": FLEET_STATUS_DESC,
        "parameters": {"type": "object", "properties": {}},
    },
    "fleet_probe": {
        "name": "fleet_probe",
        "description": FLEET_PROBE_DESC,
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Configured host name or ssh alias"}},
            "required": ["host"],
        },
    },
    "fleet_recover": {
        "name": "fleet_recover",
        "description": FLEET_RECOVER_DESC,
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Configured host name or ssh alias"},
                "action": {"type": "string", "enum": list(ACTIONS), "description": "Recovery verb"},
                "dry_run": {"type": "boolean", "description": "Default true. false (with confirm=true) acts."},
                "confirm": {"type": "boolean", "description": "Must be true, with dry_run=false, to act."},
            },
            "required": ["host", "action"],
        },
    },
}


def _safe(fn: Callable[[], Any], tool: str) -> str:
    try:
        return json.dumps(fn(), ensure_ascii=False, default=str)
    except Exception as exc:  # contract: a tool handler returns error JSON, never raises
        logger.warning("fleet-sentinel %s failed", tool, exc_info=True)
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


def make_handlers(sentinel: Any) -> dict[str, Callable[..., str]]:
    def fleet_status(args: dict | None = None, **kwargs: Any) -> str:
        return _safe(sentinel.status, "fleet_status")

    def fleet_probe(args: dict | None = None, **kwargs: Any) -> str:
        host = (args or {}).get("host")
        if not isinstance(host, str) or not host.strip():
            return json.dumps({"error": "host is required"})
        return _safe(lambda: sentinel.probe(host.strip()), "fleet_probe")

    def fleet_recover(args: dict | None = None, **kwargs: Any) -> str:
        args = args or {}
        host, action = args.get("host"), args.get("action")
        if not isinstance(host, str) or not host.strip():
            return json.dumps({"error": "host is required"})
        if not isinstance(action, str) or not action.strip():
            return json.dumps({"error": f"action is required ({', '.join(ACTIONS)})"})
        return _safe(lambda: sentinel.recover(host.strip(), action.strip(), dry_run=args.get("dry_run", True),
                                              confirm=args.get("confirm", False)), "fleet_recover")

    return {"fleet_status": fleet_status, "fleet_probe": fleet_probe, "fleet_recover": fleet_recover}
