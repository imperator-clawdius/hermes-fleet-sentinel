# fleet-sentinel

Out-of-band health checks for remote Hermes agent hosts. For each host it reports a
corroborated verdict (`up`, `deaf`, `down_physical`, `degraded` or `unknown`), pages when an
outage lasts, and can restart a gateway that has gone quiet.

A host can answer ping and SSH while its Telegram poller is dead. Its `gateway_state.json`
can also be weeks out of date. fleet-sentinel never trusts a single signal: every verdict is
corroborated by at least two of these:

| Rung | Signal | Tool |
| --- | --- | --- |
| 1 | Is the peer online on the tailnet, and when was it last seen | `tailscale status --json` (local) |
| 2 | Does the SSH port accept a TCP connection (tailscale IP, then LAN IP) | `socket.create_connection` |
| 3 | Unit state, MainPID, ESTABLISHED sockets to the platform API, the state file | one `ssh` round trip |

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `up` | Host reachable, gateway process alive, and at least 1 ESTABLISHED socket to the platform API. |
| `deaf` | Host reachable and gateway alive, but **0** platform sockets for at least `deaf_grace_minutes`. An ICMP or SSH watchdog cannot see this failure. |
| `down_physical` | The tailnet says the host is offline **and** TCP to the SSH port fails. Reported as a power or cable problem, never as a gateway fault. |
| `degraded` | Reachable, but the signals disagree in a way that is not yet `deaf`: a recent restart, a stopped unit, or sockets that could not be counted. |
| `unknown` | The probe could not finish (ssh permission denied, timeout, unparseable output), or only one signal failed. |

Corroboration rules (each is unit-tested in `tests/test_verdict.py`):

1. **Sockets outrank the state file.** If `gateway_state.json` says `disconnected` while the
   live gateway holds ESTABLISHED platform sockets, the verdict is `up` and the output has
   `state_file_stale: true`.
2. **A PID mismatch invalidates the state file.** If the file's `pid` differs from the unit's
   live MainPID, the file is ignored and the verdict says so.
3. **Never `up` without a live socket.** A live process alone is not enough.
4. **`down_physical` needs two independent failures** (tailnet offline AND TCP failure). Either
   one alone gives `unknown`. A missing or stopped tailscale never produces `down_physical`.

`gateway_state.json` is **not a heartbeat**. Hermes writes it when gateway state changes, not
on a timer, so a healthy idle gateway can carry a stamp that is weeks old. A stamp older than 30
minutes makes fleet-sentinel stop trusting the file's fields (`state_file_stale: true`). It
means "no state change recorded recently", never "the gateway is dead", and it is never enough
evidence on its own. Sockets decide.

### Live evidence

Two real hosts, two different failure shapes (identifiers genericized for publication):

| Host | Verdict | Evidence |
| --- | --- | --- |
| gpu-host | `down_physical` | Tailnet reports the peer offline **and** TCP to the SSH port fails on both `<tailnet-ip>:22` and `<lan-ip>:22`. Two independent failures, so this is reported as power or cable. |
| pi-host | `up` | `gateway_state.json` says `disconnected` with a `pid` that no longer exists. The live unit MainPID differs, so the file is stale. Its stamp is 24 days old, yet the gateway holds **2 live ESTABLISHED** Telegram sockets. Sockets win: `up`, with `state_file_stale: true`. |

A ping or SSH watchdog would have called the Pi broken because of its state file. A single
failed probe would have called any blip on the GPU host an outage. Neither verdict rests on one
signal.

## Install

```bash
hermes plugins install <repo-url>
hermes plugins enable fleet-sentinel
```

Then add your hosts (see [Configuration](#configuration)) and register the cron job described
in [Alerts via cron](#alerts-via-cron).

Requires Hermes `>=0.21.5`. Python stdlib only; no Python dependencies.

Each remote host needs:

- a Host alias your local ssh client resolves, with key authentication that works non-interactively
  (`BatchMode=yes`) and a host key already in `known_hosts` (`StrictHostKeyChecking=yes`);
- a Hermes gateway running as a systemd unit (system or `--user`), `hermes-gateway` by default
  or `hermes-gateway-<profile>`;
- `ss` (iproute2) or `netstat` to count sockets.

## Configuration

Settings live under `plugins.entries.fleet-sentinel.settings` in `config.yaml`:

```yaml
plugins:
  entries:
    fleet-sentinel:
      settings:
        hosts:
          - name: pi-host
            ssh_alias: pi-host
            tailscale_ip: 100.101.1.10
            lan_ip: 192.168.1.50
          - name: gpu-host
            ssh_alias: gpu-host
            tailscale_ip: 100.101.1.11
            lan_ip: 192.168.1.51
            wol_mac: "aa:bb:cc:dd:ee:ff"     # optional: enables `wake`
        thresholds:
          page_after_minutes: 60    # first page after this much sustained non-up
          repage_hours: 24          # re-page interval while still down
          deaf_grace_minutes: 10    # 0 sockets for this long => deaf
          ssh_timeout_seconds: 12
        auto_heal: false            # true: `tick` restarts a deaf gateway once
```

Host fields: `name` and `ssh_alias` (required); `label`, `tailscale_ip`, `lan_ip`, `profile`
(default `default`), `platform` (default `telegram`), `platform_ip` (default
`149.154.166.110`), `ssh_port` (default 22), `unit`, `hermes_home`, `wol_mac`, `wol_broadcast`.

Bad or partial config never crashes the plugin. Invalid values fall back to defaults and are
listed under `problems` in the tool output and in `hermes fleet-sentinel hosts`. Identifiers
that reach the remote shell are checked against an allow-list as well as shell-quoted.

## Tools (toolset `fleet`)

| Tool | Arguments | Returns |
| --- | --- | --- |
| `fleet_status` | none | Every host with verdict, reason, detail, last_ok, `state_file_stale`. |
| `fleet_probe` | `{host}` | Full ladder evidence for one host, plus the reasoning behind the verdict. |
| `fleet_recover` | `{host, action, dry_run?, confirm?}` | `{ok, action, host, output, dry_run}` |

Recovery actions are dry runs unless the call passes **both** `dry_run: false` and `confirm: true`:

- `restart-gateway`: reads `systemctl show <unit> -p MainPID` and sends `kill <pid>`. systemd's
  `Restart=always` then starts a fresh gateway. It refuses to act unless the unit has
  `Restart=always`, and it never runs `systemctl restart` or `systemctl stop`.
- `clear-lock`: removes `<hermes_home>/gateway.pid`, but only if the PID it records is dead.
- `wake`: sends a Wake-on-LAN magic packet. Only works for hosts that set `wol_mac`, and says
  so plainly when unavailable.

## CLI

These subcommands are registered with `ctx.register_cli_command()`. Hermes **skips** that call
in the default host isolation mode (`hermes plugins validate` says so), so there they may not
exist. They work when the plugin loads outside host isolation. **Do not build cron on
`hermes fleet-sentinel tick`;** use `scripts/fleet-sentinel-tick.sh` (below), which needs no
CLI registration.

```text
hermes fleet-sentinel tick [--json] [--quiet]   probe all, update the store, print ONLY alerts (exit 0 always)
hermes fleet-sentinel status [--json]           live verdicts
hermes fleet-sentinel hosts                     configured hosts, cached verdicts, config problems
hermes fleet-sentinel probe <host> [--json]     ladder evidence for one host
hermes fleet-sentinel recover <host> <action> [--execute]
hermes fleet-sentinel events [host] [--limit N] verdict changes and recovery audit trail
hermes fleet-sentinel init [--cron]             write default settings, print the cron recipe
```

Slash command: `/sentinel` shows the cached status; `/sentinel live` probes now.

### Alerts via cron

**The supported cron path is `scripts/fleet-sentinel-tick.sh`**, a 3-line wrapper around
`scripts/tick.py`. It does not depend on `hermes fleet-sentinel` being registered, so it works in
the default host isolation mode.

```text
python3 scripts/tick.py [--json] [--quiet]
```

`tick.py` runs one tick, prints **only alerts** on stdout and **always exits 0**. When nothing
needs saying, stdout is empty, and with `--no-agent` **empty stdout = no message**. Diagnostics
(config problems, its own errors) go to stderr; Hermes discards stderr from a script that exits 0.

If `$FLEET_SENTINEL_SETTINGS` is set (non-empty), `tick.py` always reads settings from that JSON
file (`{"hosts": [...], "thresholds": {...}, "auto_heal": false}`), even when Hermes is
installed. This is the same rule as `$FLEET_SENTINEL_DB`: an explicit override beats ambient
config. A missing or malformed file is reported on stderr. It never falls back to Hermes silently.

Otherwise settings come from the same place as inside Hermes, `plugins.entries.fleet-sentinel.
settings.{hosts,thresholds,auto_heal}`, read with Hermes's own config reader (`hermes_cli.config`).
If `hermes_cli` is not importable, `tick.py` looks for a checkout at `$HERMES_AGENT_DIR`,
`$HERMES_HOME/hermes-agent`, then `~/.hermes/hermes-agent`. If neither source yields settings,
the tick reports a config error on stderr and still exits 0.

Hermes runs cron scripts only from `~/.hermes/scripts/`, and it refuses symlinks that point
outside that folder. So install a 2-line stub there that execs the plugin's wrapper. The wrapper
finds the plugin directory from its own location. Run this from the plugin directory:

```bash
printf '#!/bin/sh\nexec "%s" "$@"\n' "$PWD/scripts/fleet-sentinel-tick.sh" > ~/.hermes/scripts/fleet-sentinel-tick.sh
chmod +x ~/.hermes/scripts/fleet-sentinel-tick.sh
hermes cron create 'every 5m' --script fleet-sentinel-tick.sh --no-agent --name fleet-sentinel --deliver telegram
```

`hermes fleet-sentinel init --cron` (where the CLI is available) prints the same recipe with
the path filled in. If you copy `fleet-sentinel-tick.sh` itself into `~/.hermes/scripts/`
instead, it falls back to `$FLEET_SENTINEL_PLUGIN_DIR`, then
`${HERMES_HOME:-~/.hermes}/plugins/fleet-sentinel`. `$FLEET_SENTINEL_PYTHON` overrides the
interpreter (default `python3`).

Test it by hand before relying on it. Empty output means healthy (or still inside
`page_after_minutes`):

```bash
~/.hermes/scripts/fleet-sentinel-tick.sh; echo "exit=$?"
```

Escalation:

- first page after `page_after_minutes` of sustained non-`up`;
- `deaf` pages as soon as it is confirmed;
- re-page every `repage_hours`;
- a recovery message with the outage length once the host is back.

"Down since" is back-dated from the evidence (tailnet `LastSeen`, the zero-socket streak), so the
first page already shows the true outage length:

```text
🔴 Cerberus is offline — down 1d 3h.
Host unreachable on the tailnet and LAN (power or cable). Last verified up: 2026-11-01 16:48.
Physical: check power LED, PSU, reseat ethernet.
```

## What this plugin does on your machines (disclosure)

- **Shell commands, locally:** `tailscale status --json` and `ssh <alias> sh -s -- <args>`.
  Every subprocess runs under a hard `subprocess.run(timeout=...)`. ssh always gets
  `-o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes -o ConnectTimeout=<n>
  -o StrictHostKeyChecking=yes`.
- **Shell commands, on your hosts:** a fixed, read-only probe script sent on ssh's stdin. It reads
  `systemctl show`, `/proc`, `ps`, `ss`/`netstat`, and the gateway's `gateway_state.json` and
  `gateway.pid`. Config values reach it only as quoted positional arguments. Recovery
  verbs (`kill <MainPID>`, `rm gateway.pid`) run only on an explicit confirmed call, or from
  a tick when you set `auto_heal: true`.
- **Network:** TCP connects to each host's SSH port, ssh to your own hosts, and, for `wake` only,
  a UDP broadcast on your LAN. No third-party services, no telemetry, no self-updating.
- **Data:** a SQLite history in Hermes's plugin data dir
  (`<hermes_home>/plugin-data/fleet-sentinel/state.db`). Override it with `FLEET_SENTINEL_DB`.
  No credentials are read or stored. ssh uses your existing key setup, and the agent socket is
  explicitly disabled.
- **Background work:** none. Periodic checks run only if you register the cron job yourself
  (`scripts/fleet-sentinel-tick.sh`, a separate process that shares the same settings and store).

## Development

```bash
python -m pytest tests -q          # stdlib + pytest; no network, no real ssh
hermes plugins doctor .
hermes plugins validate .
```

`tests/fixtures/` holds probe payloads: a healthy host; the Skorpius stale-state case (state file
says `disconnected`, recorded pid 424243 vs live MainPID 424242, stamped 24 days earlier,
2 ESTABLISHED sockets); a
deaf gateway; tailscale stopped (both JSON and text forms); and garbage or truncated output.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module layout and data flow.

## License

MIT
