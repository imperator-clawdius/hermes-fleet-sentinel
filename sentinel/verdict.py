"""Corroboration: turn one host's ladder evidence into a verdict. Pure, no I/O.

Rules (each one is unit-tested in ``tests/test_verdict.py``):

1. Sockets outrank the state file. A state file that says ``disconnected`` while the
   live gateway holds >=1 ESTABLISHED platform socket is stale: verdict ``up`` with
   ``state_file_stale: true``.
2. A PID mismatch between the state file and the unit's live MainPID invalidates the
   state file for verdict purposes, and the verdict says so.
3. Never ``up`` without a live socket. A live process is not enough.
4. ``down_physical`` needs two independent failures: tailnet offline AND the TCP connect
   to the SSH port failing. Either one alone is ``unknown``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional

from .probe import HostEvidence, RemoteSnapshot, parse_iso8601

UP = "up"
DEAF = "deaf"
DOWN_PHYSICAL = "down_physical"
DEGRADED = "degraded"
UNKNOWN = "unknown"
VERDICTS = (UP, DEAF, DOWN_PHYSICAL, DEGRADED, UNKNOWN)

# gateway_state.json is NOT a heartbeat: Hermes writes it when gateway state CHANGES, so a
# healthy, idle gateway can carry a very old updated_at. Live example: Skorpius's file was
# stamped 2026-10-11, 24 days old when probed, while the gateway held 2 live ESTABLISHED
# Telegram sockets. An old stamp means only "no state change recorded recently", never "the
# gateway is dead". Past this age we stop trusting the file's reported fields
# (state_file_stale); the stamp alone is never evidence of an outage. Sockets decide.
STATE_HEARTBEAT_STALE_S = 30 * 60


@dataclass(frozen=True)
class History:
    """What the store remembers about a host before this observation."""
    last_ok: Optional[int] = None
    zero_since: Optional[int] = None
    last_verdict: Optional[str] = None


@dataclass
class StateFileView:
    present: bool = False
    parse_error: str = ""
    pid: Optional[int] = None
    pid_matches: Optional[bool] = None
    reported: str = ""          # platform state the file claims: connected / disconnected / ...
    updated_at: Optional[int] = None
    age_s: Optional[int] = None
    stale: bool = False
    trusted: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    host: str
    verdict: str
    reason_code: str
    reason: str
    notes: list[str] = field(default_factory=list)
    state_file_stale: bool = False
    state_file_trusted: bool = False
    state_file: Optional[dict[str, Any]] = None
    reachable: Optional[bool] = None
    gateway_alive: Optional[bool] = None
    gateway_pid: Optional[int] = None
    sockets: Optional[int] = None
    zero_since: Optional[int] = None
    zero_for_s: Optional[int] = None
    tailnet_online: Optional[bool] = None
    tailnet_last_seen: Optional[int] = None
    uptime_s: Optional[int] = None
    observed_at: int = 0

    @property
    def is_up(self) -> bool:
        return self.verdict == UP

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fmt_minutes(seconds: Optional[int]) -> str:
    if seconds is None:
        return "?"
    minutes = max(0, int(seconds)) // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


def _platform_state(state: Mapping[str, Any], platform: str) -> str:
    platforms = state.get("platforms")
    if not isinstance(platforms, Mapping):
        return ""
    found: list[str] = []
    for key, entry in platforms.items():
        k = str(key)
        if k == platform or k.endswith(":" + platform):
            if isinstance(entry, Mapping) and isinstance(entry.get("state"), str):
                found.append(entry["state"])
    if not found:
        return ""
    return "connected" if "connected" in found else found[0]


def analyze_state_file(remote: RemoteSnapshot, platform: str, *, now: Optional[int] = None) -> StateFileView:
    """How much the remote gateway_state.json can be believed. Pure."""
    view = StateFileView()
    if remote.state is None:
        if remote.state_error:
            view.present = True
            view.parse_error = remote.state_error
            view.stale = True
            view.reasons.append(remote.state_error)
        return view
    state = remote.state
    view.present = True
    view.pid = remote.state_pid if remote.state_pid is not None else (
        state.get("pid") if isinstance(state.get("pid"), int) else None)
    view.reported = _platform_state(state, platform)
    view.updated_at = parse_iso8601(state.get("updated_at"))
    ref_now = remote.now if remote.now is not None else now
    if view.updated_at is not None and ref_now is not None:
        view.age_s = max(0, ref_now - view.updated_at)

    if remote.mainpid and remote.mainpid > 0 and view.pid is not None:
        view.pid_matches = view.pid == remote.mainpid
        if not view.pid_matches:
            view.stale = True
            view.reasons.append(
                f"state file pid {view.pid} != live MainPID {remote.mainpid}; state file ignored")
    if view.age_s is not None and view.age_s > STATE_HEARTBEAT_STALE_S:
        view.stale = True
        view.reasons.append(f"state file last written {fmt_minutes(view.age_s)} ago "
                            "(written on state changes, not a heartbeat; sockets decide)")
    sockets = remote.sockets
    if sockets is not None and view.reported:
        if sockets > 0 and view.reported != "connected":
            view.stale = True
            view.reasons.append(
                f"state file says {platform} {view.reported!r} but {sockets} ESTABLISHED platform "
                "socket(s) exist; sockets outrank the state file")
        elif sockets == 0 and view.reported == "connected":
            view.stale = True
            view.reasons.append(
                f"state file says {platform} connected but 0 ESTABLISHED platform sockets exist")
    view.trusted = view.pid_matches is True and not view.stale
    return view


def _base(ev: HostEvidence) -> dict[str, Any]:
    return {
        "host": ev.host.name,
        "observed_at": ev.probed_at,
        "tailnet_online": ev.tailnet.online if ev.tailnet.available else None,
        "tailnet_last_seen": ev.tailnet.last_seen,
    }


def _unreachable(ev: HostEvidence, notes: list[str]) -> Verdict:
    tn, tcp = ev.tailnet, ev.tcp
    base = _base(ev)
    tail_offline = tn.available and tn.online is False
    tcp_failed = tcp.attempted and tcp.reachable is False
    if tail_offline:
        notes.append("tailnet reports the peer offline" + (f" (matched by {tn.matched})" if tn.matched else ""))
    elif not tn.available:
        notes.append(f"tailnet signal unavailable: {tn.error or 'unknown error'}")
    elif tn.online is None:
        notes.append(f"tailnet signal inconclusive: {tn.error or 'online state not reported'}")
    else:
        notes.append("tailnet reports the peer online")
    if tcp_failed:
        tried = ", ".join(f"{a['target']} ({a['error']})" for a in tcp.attempts)
        notes.append(f"TCP connect to the SSH port failed: {tried}")
    elif not tcp.attempted:
        notes.append("TCP probe skipped: no tailscale_ip or lan_ip configured")
    else:
        notes.append(f"TCP connect to {tcp.target} succeeded")

    if tail_offline and tcp_failed:
        notes.append("two independent failures (tailnet + TCP): physical outage")
        return Verdict(verdict=DOWN_PHYSICAL, reason_code="offline",
                       reason="host unreachable on the tailnet and by TCP (power or cable)",
                       notes=notes, reachable=False, **base)

    remote = ev.remote
    ssh_err = remote.error if remote is not None else (ev.remote_skipped or "ssh not attempted")
    if remote is not None:
        notes.append(f"remote probe failed: {ssh_err}")
    if tcp_failed:
        code = "tcp_failed_only"
        reason = "TCP to the SSH port failed but the tailnet does not confirm an outage"
        reachable: Optional[bool] = False
    elif tail_offline:
        code = "tailnet_offline_only"
        reason = "tailnet says offline but TCP did not confirm it"
        reachable = None if not tcp.attempted else True
    else:
        code = "probe_failed"
        reason = ssh_err
        reachable = True if (tcp.attempted and tcp.reachable) else None
    notes.append("a single failed signal is not proof of a physical outage")
    return Verdict(verdict=UNKNOWN, reason_code=code, reason=reason, notes=notes,
                   reachable=reachable, **base)


def decide(ev: HostEvidence, history: History, deaf_grace_s: int, *, now: Optional[int] = None) -> Verdict:
    """Combine the ladder evidence for one host into a corroborated :class:`Verdict`."""
    now = int(now if now is not None else ev.probed_at)
    notes: list[str] = []
    remote = ev.remote
    if remote is None or not remote.ok:
        return _unreachable(ev, notes)

    base = _base(ev)
    base["observed_at"] = now
    if ev.tcp.attempted and ev.tcp.reachable is False:
        notes.append("TCP probe to the configured ssh_port failed but ssh succeeded; check ssh_port")
    if ev.tailnet.available and ev.tailnet.online is False:
        notes.append("tailnet reports offline but ssh succeeded (LAN path or stale tailnet state)")
    notes.append(f"ssh probe ok ({remote.hostname or 'unnamed host'})")

    sf = analyze_state_file(remote, ev.host.platform, now=now)
    notes.extend(sf.reasons)
    common = dict(
        state_file_stale=sf.stale, state_file_trusted=sf.trusted, state_file=asdict(sf),
        reachable=True, sockets=remote.sockets, uptime_s=remote.uptime_s, **base,
    )

    unit = remote.unit or ev.host.systemd_unit
    if remote.unit_scope not in ("system", "user"):
        if remote.unit_active == "unknown":
            reason = "systemctl is not available on the host; the gateway process cannot be identified"
        else:
            reason = f"systemd unit {unit} not found (set `unit:` for this host)"
        if remote.state_pid_alive:
            notes.append(f"a process with the state file pid {remote.state_pid} is alive but unsupervised")
        notes.append("cannot corroborate a gateway process without its unit's MainPID")
        return Verdict(verdict=DEGRADED, reason_code="unit_not_found", reason=reason, notes=notes,
                       gateway_alive=None, **common)

    alive = (remote.unit_active == "active" and (remote.mainpid or 0) > 0
             and remote.mainpid_alive is not False)
    if not alive:
        state = remote.unit_active or "unknown"
        notes.append(f"unit {unit} is {state} (MainPID {remote.mainpid or 0})")
        return Verdict(verdict=DEGRADED, reason_code="gateway_not_running",
                       reason=f"gateway unit {unit} is {state}; no live gateway process",
                       notes=notes, gateway_alive=False, gateway_pid=None, **common)

    notes.append(f"unit {unit} active, MainPID {remote.mainpid} alive")
    pid = remote.mainpid
    if remote.sockets is None:
        notes.append(f"socket count unavailable (tool: {remote.socket_tool or 'none'})")
        if sf.trusted and sf.reported:
            notes.append(f"state file (pid-verified) claims {sf.reported!r}, but a claim is not a socket")
        return Verdict(verdict=DEGRADED, reason_code="sockets_unavailable",
                       reason="gateway alive but platform sockets could not be counted",
                       notes=notes, gateway_alive=True, gateway_pid=pid, **common)

    if remote.sockets > 0:
        notes.append(f"{remote.sockets} ESTABLISHED socket(s) to {ev.host.platform_ip}")
        reason = f"gateway pid {pid} holds {remote.sockets} platform socket(s)"
        if sf.stale:
            reason += "; state file is stale"
        return Verdict(verdict=UP, reason_code="ok", reason=reason, notes=notes,
                       gateway_alive=True, gateway_pid=pid, zero_since=None, zero_for_s=0, **common)

    # Alive, zero sockets: deaf only once the zero-socket streak has outlived the grace window.
    zero_since = history.zero_since if history.zero_since is not None and history.zero_since <= now else now
    window_start = zero_since
    proc_age = remote.mainpid_age_s
    if proc_age is not None:
        window_start = max(window_start, now - proc_age)
    zero_for = max(0, now - window_start)
    notes.append(f"0 ESTABLISHED sockets to {ev.host.platform_ip} (streak {fmt_minutes(now - zero_since)},"
                 f" process age {fmt_minutes(proc_age)})")
    common.update(gateway_alive=True, gateway_pid=pid, zero_since=zero_since, zero_for_s=zero_for)

    if proc_age is not None and proc_age < deaf_grace_s:
        return Verdict(verdict=DEGRADED, reason_code="recent_restart",
                       reason=f"gateway restarted {fmt_minutes(proc_age)} ago and has no platform socket yet",
                       notes=notes, **common)
    if zero_for >= deaf_grace_s:
        notes.append(f"zero-socket window {fmt_minutes(zero_for)} >= grace {fmt_minutes(deaf_grace_s)}")
        return Verdict(verdict=DEAF, reason_code="no_platform_sockets",
                       reason=f"host up, gateway process alive, 0 platform sockets for {fmt_minutes(zero_for)}",
                       notes=notes, **common)
    return Verdict(verdict=DEGRADED, reason_code="deaf_suspected",
                   reason=(f"0 platform sockets for {fmt_minutes(zero_for)}; deaf is confirmed after "
                           f"{fmt_minutes(deaf_grace_s)}"),
                   notes=notes, **common)
