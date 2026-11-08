"""Escalation ladder and plain-text alert rendering. Pure, no I/O.

Ladder (per host, anchored in the ``alerts`` table):

* healthy and never alerted -> silent (``tick`` prints nothing at all);
* sustained non-``up`` for ``page_after_minutes`` -> first page;
* ``deaf`` pages as soon as it is confirmed: the deaf grace window already is the
  corroboration period, and deaf is the one state we can heal;
* every ``repage_hours`` after the last page -> re-page ("still ...");
* back to ``up`` after a page -> recovery message with the outage duration and diagnostics.

``down_since`` is back-dated from the evidence (tailnet ``LastSeen`` for a physical outage,
the zero-socket streak for deaf) but never earlier than the last verified ``up``, so the
first page already says how long the host has really been down.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, tzinfo
from typing import Optional

from .config import HostConfig, Thresholds
from .store import AlertState
from .verdict import DEAF, DEGRADED, DOWN_PHYSICAL, UNKNOWN, Verdict, fmt_minutes

NONE = "none"
FIRST_PAGE = "first_page"
REPAGE = "repage"
RECOVERY = "recovery"
HEAL = "heal"


@dataclass
class Decision:
    kind: str
    message: Optional[str]
    state: AlertState
    heal: bool = False


def fmt_duration(seconds: Optional[int]) -> str:
    return fmt_minutes(seconds)


def fmt_ts(ts: Optional[int], tz: Optional[tzinfo] = None) -> str:
    if ts is None:
        return "never recorded"
    return datetime.fromtimestamp(int(ts), tz).strftime("%Y-%m-%d %H:%M")


def backdate_down_since(verdict: Verdict, last_ok: Optional[int], now: int,
                        current: Optional[int] = None) -> int:
    """Earliest truthful start of this outage."""
    candidates = [now]
    if current is not None:
        candidates.append(current)
    if verdict.verdict == DOWN_PHYSICAL and verdict.tailnet_last_seen:
        candidates.append(int(verdict.tailnet_last_seen))
    if verdict.verdict in (DEAF, DEGRADED) and verdict.zero_since:
        candidates.append(int(verdict.zero_since))
    since = min(c for c in candidates if c <= now) if any(c <= now for c in candidates) else now
    if last_ok is not None and since < last_ok:
        since = min(int(last_ok), now)
    return since


def restart_hint(host: HostConfig) -> str:
    return f"Restart with: hermes fleet-sentinel recover {host.name} restart-gateway --execute"


def render_page(host: HostConfig, verdict: Verdict, *, down_for: int, last_ok: Optional[int],
                still: bool = False, healing: bool = False, tz: Optional[tzinfo] = None) -> str:
    name = host.display_name
    is_ = "is still" if still else "is"
    dur = fmt_duration(down_for)
    if verdict.verdict == DOWN_PHYSICAL:
        paths = "the tailnet and LAN" if host.lan_ip else "the tailnet and by TCP"
        if last_ok is not None:
            seen = f"Last verified up: {fmt_ts(last_ok, tz)}."
        elif verdict.tailnet_last_seen:
            seen = f"Tailnet last saw it: {fmt_ts(verdict.tailnet_last_seen, tz)}."
        else:
            seen = "Last verified up: never recorded."
        third = "Physical: check power LED, PSU, reseat ethernet."
        if host.wol_mac:
            third += f" Wake-on-LAN: hermes fleet-sentinel recover {host.name} wake --execute"
        return (f"🔴 {name} {is_} offline — down {dur}.\n"
                f"Host unreachable on {paths} (power or cable). {seen}\n{third}")
    if verdict.verdict == DEAF:
        action = "Attempting gateway restart." if healing else restart_hint(host)
        return (f"🟠 {name} {is_} deaf — host up, gateway process alive, 0 platform sockets for "
                f"{fmt_duration(verdict.zero_for_s)}.\n"
                f"Last healthy socket: {fmt_ts(last_ok, tz)}. {action}")
    if verdict.verdict == DEGRADED:
        tail = ""
        if verdict.reason_code == "gateway_not_running":
            tail = " Check the unit's logs (journalctl -u) on the host."
        return (f"🟡 {name} {is_} degraded — {verdict.reason}. Not healthy for {dur}.\n"
                f"Last verified up: {fmt_ts(last_ok, tz)}.{tail}")
    # UNKNOWN
    return (f"⚪ {name} {is_} unverifiable — {verdict.reason}. Unverified for {dur}.\n"
            f"Last verified up: {fmt_ts(last_ok, tz)}. A failed probe is not proof of an outage.")


def render_recovery(host: HostConfig, verdict: Verdict, *, down_since: Optional[int], now: int,
                    tz: Optional[tzinfo] = None) -> str:
    outage = (now - down_since) if down_since is not None else None
    lines = [f"🟢 {host.display_name} is back up — outage lasted {fmt_duration(outage)}"
             + (f" (down since {fmt_ts(down_since, tz)})." if down_since is not None else ".")]
    diag = [f"gateway pid {verdict.gateway_pid}" if verdict.gateway_pid else "gateway alive",
            f"{verdict.sockets} platform socket(s)" if verdict.sockets is not None else "sockets n/a"]
    if verdict.uptime_s is not None:
        diag.append(f"host uptime {fmt_duration(verdict.uptime_s)}")
    line = "Now: " + ", ".join(diag) + "."
    if verdict.uptime_s is not None and outage is not None and verdict.uptime_s < outage:
        line += " The host rebooted during the outage."
    if verdict.state_file_stale:
        line += " gateway_state.json is stale; live sockets were used instead."
    lines.append(line)
    return "\n".join(lines)


def decide(host: HostConfig, verdict: Verdict, alert: AlertState, *, last_ok: Optional[int],
           thresholds: Thresholds, now: int, auto_heal: bool = False,
           tz: Optional[tzinfo] = None) -> Decision:
    """Advance one host's alert state by one observation."""
    if verdict.is_up:
        fresh = AlertState(name=alert.name)
        if alert.alerted:
            msg = render_recovery(host, verdict, down_since=alert.down_since, now=now, tz=tz)
            return Decision(RECOVERY, msg, fresh)
        return Decision(NONE, None, fresh)

    down_since = backdate_down_since(verdict, last_ok, now, alert.down_since)
    state = replace(alert, streak=alert.streak + 1, down_since=down_since)
    down_for = now - down_since
    want_heal = (verdict.verdict == DEAF and auto_heal and not alert.heal_attempted)

    if not alert.alerted:
        due = down_for >= thresholds.page_after_s or verdict.verdict == DEAF
        if not due:
            return Decision(NONE, None, state)
        state = replace(state, alerted=True, last_alert=now, heal_attempted=alert.heal_attempted or want_heal)
        msg = render_page(host, verdict, down_for=down_for, last_ok=last_ok, healing=want_heal, tz=tz)
        return Decision(FIRST_PAGE, msg, state, heal=want_heal)

    if alert.last_alert is None or now - alert.last_alert >= thresholds.repage_s:
        state = replace(state, last_alert=now, heal_attempted=alert.heal_attempted or want_heal)
        msg = render_page(host, verdict, down_for=down_for, last_ok=last_ok, still=True,
                          healing=want_heal, tz=tz)
        return Decision(REPAGE, msg, state, heal=want_heal)

    if want_heal:
        # Already paged for another state (e.g. offline), now provably deaf: heal and say so once.
        state = replace(state, heal_attempted=True)
        msg = render_page(host, verdict, down_for=down_for, last_ok=last_ok, still=True,
                          healing=True, tz=tz)
        return Decision(HEAL, msg, state, heal=True)

    return Decision(NONE, None, state)


__all__ = [
    "Decision", "decide", "render_page", "render_recovery", "backdate_down_since", "fmt_duration", "fmt_ts",
    "NONE", "FIRST_PAGE", "REPAGE", "RECOVERY", "HEAL", "UNKNOWN",
]
