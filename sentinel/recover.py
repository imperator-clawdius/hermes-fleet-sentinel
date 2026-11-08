"""Recovery verbs. Every verb is a dry run unless ``dry_run is False and confirm is True``.

* ``restart-gateway``: resolve the unit's MainPID with ``systemctl show <unit> -p MainPID``
  and ``kill`` it; systemd ``Restart=always`` brings the gateway back. ``systemctl
  restart``/``stop`` are never used. The kill is refused unless the unit really has
  ``Restart=always`` (SIGTERM is a clean exit, so ``on-failure`` would leave it dead).
* ``clear-lock``: remove ``<hermes_home>/gateway.pid`` only when the PID it records is dead.
* ``wake``: Wake-on-LAN magic packet over a stdlib UDP broadcast, only for hosts with ``wol_mac``.

Each returns ``{ok, action, host, output, dry_run}``.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Callable, Optional

from .config import HostConfig
from .probe import Runner, classify_ssh_failure, run_bounded, ssh_argv

ACTIONS = ("restart-gateway", "clear-lock", "wake")

# $1 unit, $2 execute flag (1 = act, 0 = report only)
RESTART_SCRIPT = r"""
unit="$1"; execute="$2"
sc=""
for s in system user; do
  if [ "$s" = user ]; then c="systemctl --user"; else c="systemctl"; fi
  if [ "$($c show "$unit" -p LoadState --value 2>/dev/null)" = loaded ]; then sc="$c"; echo "SCOPE=$s"; break; fi
done
if [ -z "$sc" ]; then echo "ERROR=unit $unit not found"; exit 3; fi
pid=$($sc show "$unit" -p MainPID --value 2>/dev/null)
restart=$($sc show "$unit" -p Restart --value 2>/dev/null)
echo "MAINPID=$pid"
echo "RESTART=$restart"
case "$pid" in ''|*[!0-9]*) echo "ERROR=MainPID unreadable"; exit 4;; esac
if [ "$pid" -le 0 ]; then echo "ERROR=unit has no MainPID (not running); a kill cannot revive it"; exit 4; fi
if [ "$restart" != always ]; then
  echo "ERROR=unit has Restart=$restart; killing would leave the gateway down (need Restart=always)"; exit 5
fi
if [ "$execute" != 1 ]; then echo "WOULD_KILL=$pid"; exit 0; fi
if kill "$pid" 2>/dev/null; then echo "KILLED=$pid"; else echo "ERROR=kill $pid failed (permission?)"; exit 6; fi
"""

# $1 profile, $2 home override ('-' = derive from profile), $3 execute flag
CLEAR_LOCK_SCRIPT = r"""
profile="$1"; home="$2"; execute="$3"
if [ -z "$home" ] || [ "$home" = "-" ]; then
  if [ "$profile" = "default" ]; then home="$HOME/.hermes"; else home="$HOME/.hermes/profiles/$profile"; fi
fi
case "$home" in "~"*) home="$HOME${home#\~}";; esac
lf="$home/gateway.pid"
echo "LOCK=$lf"
if [ ! -e "$lf" ]; then echo "RESULT=no lock file"; exit 0; fi
pid=$(grep -o '"pid": *[0-9]*' "$lf" 2>/dev/null | head -n 1 | tr -dc '0-9')
[ -z "$pid" ] && pid=$(head -c 32 "$lf" | tr -dc '0-9')
echo "LOCK_PID=$pid"
if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
  if [ -d "/proc/$pid" ] || kill -0 "$pid" 2>/dev/null; then
    echo "ERROR=lock pid $pid is alive; refusing to remove a live gateway's lock"; exit 5
  fi
fi
if [ "$execute" != 1 ]; then echo "WOULD_REMOVE=$lf"; exit 0; fi
if rm -f "$lf"; then echo "REMOVED=$lf"; else echo "ERROR=rm failed"; exit 6; fi
"""


def _result(ok: bool, action: str, host: str, output: Any, dry_run: bool, **extra: Any) -> dict[str, Any]:
    out = {"ok": ok, "action": action, "host": host, "output": output, "dry_run": dry_run}
    out.update(extra)
    return out


def should_execute(dry_run: Any, confirm: Any) -> bool:
    """Only an explicit ``dry_run: false`` together with ``confirm: true`` acts."""
    return dry_run is False and confirm is True


def _kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if re.fullmatch(r"[A-Z_]{2,20}", k.strip()):
                out[k.strip()] = v.strip()
    return out


def _remote(host: HostConfig, script: str, args: list[str], timeout: int, runner: Runner) -> tuple[bool, dict[str, str], str]:
    argv = ssh_argv(host, timeout, args)
    res = runner(argv, float(timeout) + 8.0, script)
    fields = _kv(res.stdout)
    if res.returncode == 0:
        return True, fields, res.stdout.strip()
    if res.returncode not in (None, 255) and fields:
        return False, fields, fields.get("ERROR") or res.stdout.strip()
    return False, fields, classify_ssh_failure(res)


def restart_gateway(host: HostConfig, *, execute: bool, timeout: int, runner: Runner = run_bounded) -> dict[str, Any]:
    ok, fields, detail = _remote(host, RESTART_SCRIPT, [host.systemd_unit, "1" if execute else "0"],
                                 timeout, runner)
    unit = host.systemd_unit
    if not ok:
        return _result(False, "restart-gateway", host.name, f"{unit}: {detail}", not execute, details=fields)
    if execute:
        msg = (f"sent SIGTERM to {unit} MainPID {fields.get('KILLED')}; systemd Restart=always will start a "
               "fresh gateway within seconds")
    else:
        msg = (f"dry run: would kill {unit} MainPID {fields.get('WOULD_KILL')} (Restart=always revives it). "
               "Pass dry_run=false and confirm=true to act.")
    return _result(True, "restart-gateway", host.name, msg, not execute, details=fields)


def clear_lock(host: HostConfig, *, execute: bool, timeout: int, runner: Runner = run_bounded) -> dict[str, Any]:
    ok, fields, detail = _remote(host, CLEAR_LOCK_SCRIPT,
                                 [host.profile, host.hermes_home or "-", "1" if execute else "0"], timeout, runner)
    if not ok:
        return _result(False, "clear-lock", host.name, detail, not execute, details=fields)
    if "RESULT" in fields:
        msg = f"{fields.get('LOCK')}: {fields['RESULT']}; nothing to do"
    elif execute:
        msg = f"removed stale lock {fields.get('REMOVED')} (pid {fields.get('LOCK_PID') or '?'} was dead)"
    else:
        msg = (f"dry run: would remove stale lock {fields.get('WOULD_REMOVE')} (pid "
               f"{fields.get('LOCK_PID') or '?'} is dead). Pass dry_run=false and confirm=true to act.")
    return _result(True, "clear-lock", host.name, msg, not execute, details=fields)


def magic_packet(mac: str) -> bytes:
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(digits) != 12:
        raise ValueError(f"invalid MAC address {mac!r}")
    return b"\xff" * 6 + bytes.fromhex(digits) * 16


Sender = Callable[[bytes, str, int], None]


def _udp_broadcast(payload: bytes, address: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(2.0)
        s.sendto(payload, (address, port))


def wake(host: HostConfig, *, execute: bool, sender: Optional[Sender] = None) -> dict[str, Any]:
    if not host.wol_mac:
        return _result(False, "wake", host.name,
                       "unavailable: no wol_mac configured for this host, so Wake-on-LAN cannot be used. "
                       "Physical check needed: power LED, PSU, ethernet.", not execute)
    try:
        packet = magic_packet(host.wol_mac)
    except ValueError as exc:
        return _result(False, "wake", host.name, str(exc), not execute)
    target = host.wol_broadcast or "255.255.255.255"
    if not execute:
        return _result(True, "wake", host.name,
                       f"dry run: would broadcast a magic packet for {host.wol_mac} to {target}:9. "
                       "Pass dry_run=false and confirm=true to act.", True)
    sender = sender or _udp_broadcast
    errors = []
    for port in (9, 7):
        try:
            sender(packet, target, port)
        except OSError as exc:
            errors.append(f"udp/{port}: {exc.strerror or exc}")
    if len(errors) == 2:
        return _result(False, "wake", host.name, "magic packet not sent: " + "; ".join(errors), False)
    return _result(True, "wake", host.name,
                   f"magic packet for {host.wol_mac} broadcast to {target} (udp/9, udp/7). Sent is not woken: "
                   "it only works on the same LAN segment with WoL enabled in firmware. Re-probe in ~2 min.",
                   False)


def run_action(host: HostConfig, action: str, *, dry_run: Any = True, confirm: Any = False, timeout: int = 12,
               runner: Runner = run_bounded, sender: Optional[Sender] = None) -> dict[str, Any]:
    action = (action or "").strip().lower().replace("_", "-")
    execute = should_execute(dry_run, confirm)
    if action not in ACTIONS:
        return _result(False, action, host.name, f"unknown action; choose one of {', '.join(ACTIONS)}", not execute)
    if dry_run is False and confirm is not True:
        note = "dry_run=false requires confirm=true; ran as a dry run instead"
    else:
        note = ""
    if action == "restart-gateway":
        res = restart_gateway(host, execute=execute, timeout=timeout, runner=runner)
    elif action == "clear-lock":
        res = clear_lock(host, execute=execute, timeout=timeout, runner=runner)
    else:
        res = wake(host, execute=execute, sender=sender)
    if note:
        res["note"] = note
    return res
