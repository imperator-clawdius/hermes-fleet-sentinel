# Architecture

```
__init__.py            register(ctx): 3 tools, 1 CLI tree, 1 slash command. Nothing else.
sentinel/
  config.py            raw settings -> Settings (HostConfig[], Thresholds, problems). Never raises.
  probe.py             probe ladder: bounded runner + pure parsers -> HostEvidence
  verdict.py           HostEvidence + History -> Verdict           (pure, no I/O)
  store.py             sqlite: hosts / events / alerts             (one writer, upserts)
  escalate.py          Verdict + AlertState -> Decision(message)   (pure, no I/O)
  recover.py           restart-gateway / clear-lock / wake         (dry run by default)
  runtime.py           Sentinel: wires the above for tools, CLI and slash command
  tools.py             tool schemas + JSON-string handlers (never raise)
  cli.py               argparse tree for `hermes fleet-sentinel`
scripts/
  tick.py              standalone cron entry point: Sentinel + tick(), alerts only, exit 0
  fleet-sentinel-tick.sh  3-line sh wrapper for `hermes cron ... --script` (THE cron path)
```

## Entry points

| Entry point | Registered via | Available in default host isolation? |
| --- | --- | --- |
| tools `fleet_status` / `fleet_probe` / `fleet_recover` | `ctx.register_tool` | yes |
| `/sentinel [live]` | `ctx.register_command` | yes |
| `hermes fleet-sentinel ...` | `ctx.register_cli_command` | **no**: `hermes plugins validate` reports that `register_cli_command()` is skipped in the host, because `hermes <command>` subcommands are wired into the local CLI parser |
| `scripts/fleet-sentinel-tick.sh` -> `scripts/tick.py` | nothing (plain process) | yes: **the supported cron path** |

`register_cli_command` stays in `__init__.py` because it still works outside host isolation.
Cron must not depend on it. The zero-token design (a `--no-agent` cron job whose empty stdout
sends nothing) runs through the script:

```bash
# from the plugin directory; Hermes only runs scripts inside ~/.hermes/scripts/ (no symlinks out)
printf '#!/bin/sh\nexec "%s" "$@"\n' "$PWD/scripts/fleet-sentinel-tick.sh" > ~/.hermes/scripts/fleet-sentinel-tick.sh
chmod +x ~/.hermes/scripts/fleet-sentinel-tick.sh
hermes cron create 'every 5m' --script fleet-sentinel-tick.sh --no-agent --name fleet-sentinel --deliver telegram
```

Empty stdout = no message. `tick.py` exits 0 on every path. Hermes delivers a non-zero exit
as a failure notice, and it discards stderr when the exit is 0.

`tick.py` resolves settings in this order. First, the JSON file named by
`$FLEET_SENTINEL_SETTINGS`, whenever that variable is set and non-empty. An explicit override
beats ambient config, like `$FLEET_SENTINEL_DB`, and a bad file is an error rather than a
fall-through. Second, the same lookup as `ctx.get_config`
(`plugins.entries.fleet-sentinel.settings.{hosts,thresholds,auto_heal}`, with the legacy
`config` subtree as a per-key fallback), read through `hermes_cli.config.load_config_readonly`
from the importable `hermes_cli` or from a checkout at `$HERMES_AGENT_DIR`,
`$HERMES_HOME/hermes-agent` or `~/.hermes/hermes-agent`. If neither yields settings, the tick
reports a config problem on stderr and exits 0. With Hermes on `sys.path`, the store resolves through
`plugins.plugin_storage`, the same `state.db` the in-host plugin uses, so escalation state is
shared between the tools and cron. The wrapper finds the plugin from its own location, then from
`$FLEET_SENTINEL_PLUGIN_DIR`, then from `${HERMES_HOME:-~/.hermes}/plugins/fleet-sentinel`.

## Data flow

```
settings provider (ctx.get_config in-host; tick.py: $FLEET_SENTINEL_SETTINGS > hermes_cli config reader)
        │
        ▼
 parse_settings ──► Settings ── problems surfaced in every output
        │
        ▼
 fetch_tailnet (once per run) ──► TailnetView
        │
        ▼  one thread per host (ThreadPoolExecutor, max 8)
 probe_host:  tailnet_obs_for ─► tcp_probe ─► remote_probe (ssh, skipped if 2 failures already)
        │
        ▼  sequential from here: one store writer
 store.history(name) ─► verdict.decide ─► store.record_observation
        │
        ├─► status / probe: JSON summary + evidence
        └─► tick: escalate.decide ─► (optional auto-heal) ─► store.put_alert ─► alert text
```

## Probe ladder (`probe.py`)

Every external command goes through `run_bounded`, which always calls
`subprocess.run(..., timeout=N)`. A tool's own timeout flag is never the only bound. The ssh
round trip is bounded by `ConnectTimeout` (handshake) and an external `ssh_timeout + 8s` (whole
call).

The remote probe is a constant script sent on ssh's stdin to `sh -s`. Config values
(unit, profile, platform IP, hermes home) go in only as positional parameters. They are
allow-list validated in `config.py` and `shlex.quote`d in `ssh_argv`, and are never
interpolated into the script. The script prints `KEY=value` lines ending in `PROBE_END=1`. Any
payload that is missing required keys or the end marker is rejected as not parseable or
truncated, never half-trusted.

Tailscale is optional. A missing CLI, a stopped daemon (`Tailscale is stopped.` or
`BackendState: Stopped`) or an unexpected JSON shape all give `TailnetView(available=False)`.
That only weakens the evidence; it can never turn into an "offline" signal.

## Corroboration (`verdict.py`)

`decide()` is a pure function of `HostEvidence`, the stored `History` (last_ok, zero_since)
and the grace window:

1. The remote probe failed: `_unreachable`. `down_physical` only when tailnet offline **and**
   TCP failed; otherwise `unknown`, with a reason code (`tcp_failed_only`,
   `tailnet_offline_only`, `probe_failed`).
2. Unit not found, or no systemd: `degraded`.
3. Unit inactive or MainPID dead: `degraded` (`gateway_not_running`).
4. Socket count unavailable: `degraded`. A state-file claim is not a socket.
5. Sockets > 0: `up`. `analyze_state_file` decides `state_file_stale`: PID mismatch, an
   `updated_at` older than 30 minutes, or a claim that contradicts the sockets.
6. Sockets == 0: the zero-socket window starts at the later of the stored `zero_since` and the
   process start time. Process younger than the grace window: `degraded` (`recent_restart`).
   Window >= grace: `deaf`. Otherwise `degraded` (`deaf_suspected`).

**The state-file age is not a liveness signal.** `gateway_state.json` is written when gateway
state *changes*, not as a heartbeat, so a healthy idle gateway can carry a very old
`updated_at`. Past `STATE_HEARTBEAT_STALE_S` (30 min) the file's fields are no longer trusted
(`state_file_stale`), which only withholds trust. An old stamp means "no state change recorded
recently", never "the gateway is dead", and no verdict rests on it alone. Sockets decide.

### Live evidence

- **gpu-host -> `down_physical`.** The tailnet reports the peer offline, **and** TCP to the SSH
  port fails on `100.101.1.11:22` (tailscale) and on `192.168.1.51:22` (LAN). That is two
  independent failures (rule 1), so it is reported as power or cable, not a gateway fault.
- **pi-host -> `up`.** `gateway_state.json` records pid `424243`, which is stale: the live unit
  MainPID is `424242`. The file says `disconnected`, and its stamp is 24 days old (2026-10-11).
  The gateway holds **2 live ESTABLISHED** Telegram sockets. Rule 5: `up`, `state_file_stale: true`.
  This case is pinned in `tests/fixtures/remote_pi-host_stale_state.txt`.

## Store (`store.py`)

Location, first match wins: `FLEET_SENTINEL_DB`, then `plugins.plugin_storage.plugin_db("fleet-sentinel",
"state.db")` (module function; follows the active profile, survives plugin updates), then
`<hermes_home>/fleet-sentinel/state.db` outside Hermes. WAL mode, `PRAGMA user_version = 1`.

- `hosts(name PK, first_seen, last_ok, last_verdict, last_change, zero_since, last_reason, last_probe)`
- `events(id, name, ts, from_state, to_state, detail)`: appended only on a verdict change or a
  recovery action.
- `alerts(name PK, alerted, down_since, last_alert, streak, heal_attempted)`: the escalation anchor.

Every write is an upsert keyed by host name, so replaying an observation is harmless.

## Escalation (`escalate.py`)

A per-host state machine over `AlertState`:

| State | Event | Result |
| --- | --- | --- |
| not alerted | `up` | silent, state reset |
| not alerted | non-up, `down_for < page_after` (not deaf) | silent, streak += 1 |
| not alerted | non-up, `down_for >= page_after`, or confirmed `deaf` | **first page** |
| alerted | non-up, `now - last_alert >= repage` | **re-page** ("is still ...") |
| alerted | non-up, newly deaf with auto_heal and no heal yet | **heal** notice + restart |
| alerted | `up` | **recovery** message (outage length, pid, sockets, reboot note) |

`down_since` is back-dated to the earliest truthful start: the tailnet `LastSeen` for a physical
outage, `zero_since` for deaf. It is clamped so it is never earlier than the last verified `up`.

Rendering is plain text; the gateway does its own Markdown formatting.

## Recovery (`recover.py`)

`should_execute(dry_run, confirm)` returns true only for `dry_run is False and confirm is True`.
Recovery scripts are constants sent on stdin, like the probe. `restart-gateway` kills the
MainPID (never `systemctl restart`/`stop`) and refuses unless `Restart=always`, because a
SIGTERM is a clean exit and `on-failure` would leave the gateway down. `wake` builds the magic
packet with stdlib sockets and reports plainly that "sent" does not mean "woken".

## Failure containment

- Tool handlers wrap everything with `_safe` and return `{"error": ...}` JSON. They never raise.
- `tick` (both `scripts/tick.py` and the CLI subcommand) returns exit code 0 on every path,
  including its own import, settings and internal errors, because a cron
  watchdog must not fail on a down host. Config problems go to stderr, never stdout, so they
  never become a message.
- A settings provider that raises degrades to defaults and reports the problem.
