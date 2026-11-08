"""``hermes fleet-sentinel ...`` argparse tree and handlers.

Subcommands:

* ``tick [--json] [--quiet]``  probe all, update the store, print ONLY alerts. Exit 0 always.
  For cron use ``scripts/fleet-sentinel-tick.sh`` (-> ``scripts/tick.py``), not this
  subcommand: Hermes skips ``register_cli_command`` in the default host isolation mode, so
  ``hermes fleet-sentinel tick`` may not exist there. Empty stdout means "send nothing".
* ``status [--json]``          live probe of every host.
* ``hosts``                    configured hosts, last cached verdict and any config problems.
* ``probe <host> [--json]``    full ladder evidence for one host.
* ``recover <host> <action> [--execute]``  recovery verb; dry run unless ``--execute``.
* ``events [host] [--limit N]`` audit trail of verdict changes and recovery actions.
* ``init [--cron]``            write a default settings block; optionally print the cron recipe.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

from .config import EXAMPLE_HOST, default_settings_block
from .recover import ACTIONS
from .runtime import Sentinel, iso

ConfigGet = Callable[[str], Any]
ConfigSet = Callable[[str, Any], None]

CRON_SCRIPT_NAME = "fleet-sentinel-tick.sh"


def setup_parser(parser: argparse.ArgumentParser) -> None:
    subs = parser.add_subparsers(dest="fleet_command", metavar="<command>")

    p = subs.add_parser("tick", help="Probe all hosts and print only alerts (cron entry point)")
    p.add_argument("--json", action="store_true", help="Emit alerts as a JSON list (nothing when healthy)")
    p.add_argument("--quiet", action="store_true", help="Do not report config problems on stderr")

    p = subs.add_parser("status", help="Live verdict for every configured host")
    p.add_argument("--json", action="store_true", help="Emit JSON")

    subs.add_parser("hosts", help="List configured hosts, last cached verdict and config problems")

    p = subs.add_parser("probe", help="Full probe-ladder evidence for one host")
    p.add_argument("host", help="Host name or ssh alias")
    p.add_argument("--json", action="store_true", help="Emit JSON (default prints a readable summary)")

    p = subs.add_parser("recover", help="Run a recovery verb (dry run unless --execute)")
    p.add_argument("host", help="Host name or ssh alias")
    p.add_argument("action", choices=list(ACTIONS), help="Recovery verb")
    p.add_argument("--execute", action="store_true", help="Actually act (default is a dry run)")

    p = subs.add_parser("events", help="Recent verdict changes and recovery actions")
    p.add_argument("host", nargs="?", help="Limit to one host")
    p.add_argument("--limit", type=int, default=20, help="Number of events (default 20)")

    p = subs.add_parser("init", help="Write a default settings block")
    p.add_argument("--cron", action="store_true", help="Also print the cron job recipe for `tick`")


def _print_json(data: Any, out: TextIO) -> None:
    out.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")


def cmd_tick(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    try:
        alerts, settings = sentinel.tick()
    except Exception as exc:  # a cron watchdog must never fail the job on its own error
        if not getattr(args, "quiet", False):
            err.write(f"fleet-sentinel tick failed: {type(exc).__name__}: {exc}\n")
        return 0
    if alerts:
        if getattr(args, "json", False):
            _print_json(alerts, out)
        else:
            out.write("\n\n".join(a["message"] for a in alerts) + "\n")
    if settings.problems and not getattr(args, "quiet", False):
        for problem in settings.problems:
            err.write(f"fleet-sentinel config: {problem}\n")
    return 0


def cmd_status(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    if getattr(args, "json", False):
        _print_json(sentinel.status(), out)
    else:
        out.write(sentinel.live_text() + "\n")
    return 0


def cmd_hosts(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    settings = sentinel.settings()
    if not settings.hosts:
        out.write("No hosts configured. Run `hermes fleet-sentinel init`, then add hosts under\n"
                  "plugins.entries.fleet-sentinel.settings.hosts in config.yaml.\n")
    for h in settings.hosts:
        row = sentinel.store.get_host(h.name)
        last = row.last_verdict if row and row.last_verdict else "never probed"
        ok = iso(row.last_ok) if row and row.last_ok else "never"
        addrs = ", ".join(a for a in (h.tailscale_ip, h.lan_ip) if a) or "no IPs (TCP rung skipped)"
        out.write(f"{h.name:<16} ssh={h.ssh_alias:<16} unit={h.systemd_unit:<28} {addrs}\n"
                  f"{'':<16} last={last}  last_ok={ok}"
                  + (f"  wol={h.wol_mac}" if h.wol_mac else "") + "\n")
    t = settings.thresholds
    out.write(f"thresholds: page_after={t.page_after_minutes}m repage={t.repage_hours}h "
              f"deaf_grace={t.deaf_grace_minutes}m ssh_timeout={t.ssh_timeout_seconds}s "
              f"auto_heal={'on' if settings.auto_heal else 'off'}\n")
    for problem in settings.problems:
        out.write(f"config problem: {problem}\n")
    return 0


def cmd_probe(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    data = sentinel.probe(args.host)
    if getattr(args, "json", False) or "error" in data:
        _print_json(data, out)
        return 0 if "error" not in data else 1
    out.write(f"{data['host']}: {data['verdict']} — {data['reason']}\n")
    for note in data.get("why") or []:
        out.write(f"  - {note}\n")
    if data.get("state_file_stale"):
        out.write("  state_file_stale: true\n")
    for problem in data.get("problems") or []:
        out.write(f"config problem: {problem}\n")
    return 0


def cmd_recover(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    execute = bool(getattr(args, "execute", False))
    res = sentinel.recover(args.host, args.action, dry_run=not execute, confirm=execute)
    _print_json(res, out)
    return 0 if res.get("ok") else 1


def cmd_events(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    rows = sentinel.store.events(getattr(args, "host", None), limit=max(1, int(args.limit or 20)))
    if not rows:
        out.write("no events recorded\n")
    for r in reversed(rows):
        out.write(f"{iso(r['ts'])}  {r['name']:<14} {r['from_state'] or '-'} -> {r['to_state']}  "
                  f"{r['detail'] or ''}\n")
    return 0


PLUGIN_DIR = Path(__file__).resolve().parent.parent


def cron_recipe(plugin_dir: Optional[Path] = None) -> str:
    """The supported cron path: scripts/fleet-sentinel-tick.sh -> scripts/tick.py.

    It does NOT go through ``hermes fleet-sentinel tick``: that subcommand is skipped in the
    default host isolation mode. Hermes only runs cron scripts that resolve inside
    ~/.hermes/scripts/ (symlinks out are refused), hence the two-line stub.
    """
    wrapper = (plugin_dir or PLUGIN_DIR) / "scripts" / CRON_SCRIPT_NAME
    return (
        "1) Install a stub in ~/.hermes/scripts/ that runs the plugin's wrapper:\n"
        f"     printf '#!/bin/sh\\nexec \"%s\" \"$@\"\\n' '{wrapper}' > ~/.hermes/scripts/{CRON_SCRIPT_NAME}\n"
        f"     chmod +x ~/.hermes/scripts/{CRON_SCRIPT_NAME}\n"
        "2) Register it as a no-agent cron job (empty stdout = no message):\n"
        f"     hermes cron create 'every 5m' --script {CRON_SCRIPT_NAME}"
        " --no-agent --name fleet-sentinel --deliver telegram\n"
    )


def cmd_init(sentinel: Sentinel, args: argparse.Namespace, out: TextIO, err: TextIO,
             get: Optional[ConfigGet] = None, put: Optional[ConfigSet] = None) -> int:
    block = default_settings_block()
    if get is None or put is None:
        out.write("Settings writer unavailable; add this under plugins.entries.fleet-sentinel.settings:\n")
        _print_json(block, out)
    else:
        written = []
        for key, value in block.items():
            if get(key) is None:
                put(key, value)
                written.append(key)
        if written:
            out.write(f"Wrote default settings: {', '.join(written)} "
                      "(plugins.entries.fleet-sentinel.settings).\n")
        else:
            out.write("Settings already present; nothing overwritten.\n")
        out.write("Add hosts under settings.hosts, for example:\n")
        _print_json([EXAMPLE_HOST], out)
    if getattr(args, "cron", False):
        out.write(cron_recipe())
    return 0


COMMANDS = {
    "tick": cmd_tick,
    "status": cmd_status,
    "hosts": cmd_hosts,
    "probe": cmd_probe,
    "recover": cmd_recover,
    "events": cmd_events,
}


def run(sentinel: Sentinel, args: argparse.Namespace, *, get: Optional[ConfigGet] = None,
        put: Optional[ConfigSet] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    command = getattr(args, "fleet_command", None)
    if command == "init":
        return cmd_init(sentinel, args, out, err, get=get, put=put)
    fn = COMMANDS.get(command or "")
    if fn is None:
        out.write("usage: hermes fleet-sentinel {tick,status,hosts,probe,recover,events,init} ...\n")
        return 0 if command is None else 2
    try:
        return fn(sentinel, args, out, err)
    except Exception as exc:
        if command == "tick":
            return 0
        err.write(f"fleet-sentinel {command} failed: {type(exc).__name__}: {exc}\n")
        return 1
