"""Probe ladder: pure parsers plus a bounded subprocess runner.

Rungs, cheapest first:

1. ``tailscale status --json``: is the peer online on the tailnet, when was it last seen.
2. TCP connect to the SSH port (tailscale IP, then LAN IP).
3. One ``ssh <alias> sh -s -- <args>`` round trip running :data:`REMOTE_PROBE_SCRIPT`,
   which prints ``KEY=value`` lines.

Every subprocess call goes through :func:`run_bounded`, which always passes an
external ``timeout=`` to :func:`subprocess.run`; a tool's own timeout flag is
never the only bound. The parsers are pure so they can be tested against
captured payloads in ``tests/fixtures``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

from .config import HostConfig

PROBE_VERSION = 1

SSH_BASE_OPTIONS: tuple[str, ...] = (
    "-o", "BatchMode=yes",
    # Mandatory: without it the macOS launchd ssh-agent socket can stall the client.
    "-o", "IdentityAgent=none",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
)

_TAILSCALE_FALLBACKS = (
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/usr/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
)

# The remote probe. Constant text sent on ssh's stdin to ``sh -s``; user data only ever
# arrives as positional parameters ($1..$4), never by string interpolation into the script.
REMOTE_PROBE_SCRIPT = r"""
unit="$1"; profile="$2"; pip="$3"; home="$4"
if [ -z "$home" ] || [ "$home" = "-" ]; then
  if [ "$profile" = "default" ]; then home="$HOME/.hermes"; else home="$HOME/.hermes/profiles/$profile"; fi
fi
case "$home" in "~"*) home="$HOME${home#\~}";; esac
alive() {
  case "$1" in ''|*[!0-9]*) return 1;; esac
  [ "$1" -gt 0 ] || return 1
  [ -d "/proc/$1" ] && return 0
  kill -0 "$1" 2>/dev/null
}
pid_of() { grep -o '"pid": *[0-9]*' "$1" 2>/dev/null | head -n 1 | tr -dc '0-9'; }
mtime_of() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }
echo "PROBE_VERSION=1"
echo "HOSTNAME=$(hostname 2>/dev/null)"
echo "NOW=$(date +%s)"
up=""; [ -r /proc/uptime ] && up=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)
echo "UPTIME_S=$up"
bt=""; [ -r /proc/stat ] && bt=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)
echo "BOOTED=$bt"
scope=none; active=not-found; mpid=0; restart=""
if command -v systemctl >/dev/null 2>&1; then
  for s in system user; do
    if [ "$s" = user ]; then sc="systemctl --user"; else sc="systemctl"; fi
    ls=$($sc show "$unit" -p LoadState --value 2>/dev/null)
    if [ "$ls" = loaded ]; then
      scope=$s
      active=$($sc show "$unit" -p ActiveState --value 2>/dev/null)
      mpid=$($sc show "$unit" -p MainPID --value 2>/dev/null)
      restart=$($sc show "$unit" -p Restart --value 2>/dev/null)
      break
    fi
  done
else
  active=unknown
fi
echo "UNIT=$unit"
echo "UNIT_SCOPE=$scope"
echo "UNIT_ACTIVE=$active"
echo "UNIT_RESTART=$restart"
echo "MAINPID=$mpid"
if alive "$mpid"; then
  echo "MAINPID_ALIVE=1"
  echo "MAINPID_AGE_S=$(ps -o etimes= -p "$mpid" 2>/dev/null | tr -dc '0-9')"
else
  echo "MAINPID_ALIVE=0"
  echo "MAINPID_AGE_S="
fi
echo "HERMES_HOME=$home"
sf="$home/gateway_state.json"
if [ -r "$sf" ]; then
  echo "STATE_MTIME=$(mtime_of "$sf")"
  echo "STATE_JSON=b64:$(head -c 65536 "$sf" | base64 | tr -d '\n')"
  sp=$(pid_of "$sf")
  echo "STATE_PID=$sp"
  if alive "$sp"; then echo "STATE_PID_ALIVE=1"; else echo "STATE_PID_ALIVE=0"; fi
else
  echo "STATE_MTIME="
  echo "STATE_JSON="
fi
lf="$home/gateway.pid"
if [ -r "$lf" ]; then
  lp=$(pid_of "$lf")
  echo "LOCK_PID=$lp"
  if alive "$lp"; then echo "LOCK_PID_ALIVE=1"; else echo "LOCK_PID_ALIVE=0"; fi
fi
if command -v ss >/dev/null 2>&1; then
  n=$(ss -Htn state established dst "$pip" 2>/dev/null | wc -l | tr -dc '0-9')
  echo "SOCKET_TOOL=ss"
  echo "SOCKETS=$n"
elif command -v netstat >/dev/null 2>&1; then
  n=$(netstat -tn 2>/dev/null | awk -v ip="$pip" '$6=="ESTABLISHED" && index($5, ip ":")==1 {c++} END {print c+0}')
  echo "SOCKET_TOOL=netstat"
  echo "SOCKETS=$n"
else
  echo "SOCKET_TOOL=none"
  echo "SOCKETS="
fi
echo "PROBE_END=1"
"""


# --------------------------------------------------------------------------------------
# Bounded runner
# --------------------------------------------------------------------------------------

@dataclass
class CommandResult:
    argv: list[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing


Runner = Callable[[Sequence[str], float, Optional[str]], CommandResult]

# ssh only needs PATH, HOME (for ~/.ssh and ~/.ssh/config) and LANG. Passing the
# full agent environment to a subprocess that talks to another machine is needless
# exposure, so children get this allowlist and nothing else.
_CHILD_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")


def child_env() -> dict[str, str]:
    """Minimal, explicit environment for ``ssh``/``tailscale`` subprocesses."""
    env = {key: os.environ[key] for key in _CHILD_ENV_KEYS if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    return env


def run_bounded(argv: Sequence[str], timeout: float, input_text: Optional[str] = None) -> CommandResult:
    """Run ``argv`` with a hard wall-clock ``timeout``. Never raises."""
    argv = [str(a) for a in argv]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv, input=input_text, capture_output=True, text=True, timeout=timeout,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            errors="replace", env=child_env(),
        )
    except subprocess.TimeoutExpired as exc:
        def _s(v: Any) -> str:
            if isinstance(v, bytes):
                return v.decode("utf-8", "replace")
            return v or ""
        return CommandResult(argv, None, _s(exc.stdout), _s(exc.stderr), timed_out=True,
                             duration_s=time.monotonic() - start)
    except FileNotFoundError as exc:
        return CommandResult(argv, None, "", str(exc), missing=True, duration_s=time.monotonic() - start)
    except OSError as exc:
        return CommandResult(argv, None, "", f"{type(exc).__name__}: {exc}",
                             duration_s=time.monotonic() - start)
    return CommandResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "",
                         duration_s=time.monotonic() - start)


# --------------------------------------------------------------------------------------
# Rung 1: tailscale
# --------------------------------------------------------------------------------------

@dataclass
class TailnetPeer:
    hostname: str
    dns_name: str
    ips: tuple[str, ...]
    online: Optional[bool]
    last_seen: Optional[int]


@dataclass
class TailnetView:
    available: bool
    error: str = ""
    backend_state: str = ""
    peers: list[TailnetPeer] = field(default_factory=list)


@dataclass
class TailnetObs:
    available: bool
    online: Optional[bool] = None
    last_seen: Optional[int] = None
    matched: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_iso8601(value: Any) -> Optional[int]:
    """Epoch seconds for an ISO-8601 timestamp; ``None`` for Go's zero time or garbage."""
    if not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    year = int(m.group(1))
    if year <= 1:  # Go zero time "0001-01-01T00:00:00Z" = "currently connected / never"
        return None
    tz = m.group(8) or "Z"
    if tz == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        from datetime import timedelta
        tzinfo = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        dt = datetime(year, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                      int(m.group(6)), tzinfo=tzinfo)
    except ValueError:
        return None
    return int(dt.timestamp())


def parse_tailscale_status(stdout: str, returncode: Optional[int] = 0, stderr: str = "") -> TailnetView:
    """Parse ``tailscale status --json``. Tolerates a stopped daemon and shape drift."""
    text = (stdout or "").strip()
    if not text:
        msg = (stderr or "").strip() or "empty output"
        return TailnetView(False, error=f"tailscale status returned nothing ({msg[:200]})")
    try:
        data = json.loads(text)
    except ValueError:
        first = text.splitlines()[0][:200]
        return TailnetView(False, error=f"tailscale status is not JSON: {first}")
    if not isinstance(data, Mapping):
        return TailnetView(False, error="tailscale status JSON is not an object")
    backend = str(data.get("BackendState") or "")
    if backend and backend != "Running":
        return TailnetView(False, error=f"tailscale backend is {backend}", backend_state=backend)
    raw_peers = data.get("Peer")
    if raw_peers is None:
        raw_peers = {}
    if isinstance(raw_peers, Mapping):
        peer_iter = list(raw_peers.values())
    elif isinstance(raw_peers, list):
        peer_iter = raw_peers
    else:
        return TailnetView(False, error="tailscale status has an unrecognised Peer shape", backend_state=backend)
    peers: list[TailnetPeer] = []
    for p in peer_iter:
        if not isinstance(p, Mapping):
            continue
        ips = p.get("TailscaleIPs") or []
        online = p.get("Online")
        peers.append(TailnetPeer(
            hostname=str(p.get("HostName") or ""),
            dns_name=str(p.get("DNSName") or ""),
            ips=tuple(str(i) for i in ips if isinstance(i, str)),
            online=online if isinstance(online, bool) else None,
            last_seen=parse_iso8601(p.get("LastSeen")),
        ))
    return TailnetView(True, backend_state=backend or "Running", peers=peers)


def tailnet_obs_for(host: HostConfig, view: TailnetView) -> TailnetObs:
    """Find ``host`` in the tailnet view: by tailscale IP first, then by host/DNS name."""
    if not view.available:
        return TailnetObs(False, error=view.error)
    peer = None
    matched = ""
    if host.tailscale_ip:
        for p in view.peers:
            if host.tailscale_ip in p.ips:
                peer, matched = p, f"ip {host.tailscale_ip}"
                break
    if peer is None:
        wanted = {host.name.lower(), host.ssh_alias.lower()}
        for p in view.peers:
            short = p.dns_name.split(".", 1)[0].lower()
            if p.hostname.lower() in wanted or (short and short in wanted):
                peer, matched = p, f"name {p.hostname or short}"
                break
    if peer is None:
        return TailnetObs(True, online=None, error="host not found in tailnet peers")
    return TailnetObs(True, online=peer.online, last_seen=peer.last_seen, matched=matched)


def tailscale_binary() -> Optional[str]:
    found = shutil.which("tailscale")
    if found:
        return found
    for candidate in _TAILSCALE_FALLBACKS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def fetch_tailnet(runner: Runner = run_bounded, timeout: float = 8.0) -> TailnetView:
    binary = tailscale_binary()
    if binary is None:
        return TailnetView(False, error="tailscale CLI not installed")
    res = runner([binary, "status", "--json"], timeout, None)
    if res.missing:
        return TailnetView(False, error="tailscale CLI not installed")
    if res.timed_out:
        return TailnetView(False, error=f"tailscale status timed out after {timeout:.0f}s")
    return parse_tailscale_status(res.stdout, res.returncode, res.stderr)


# --------------------------------------------------------------------------------------
# Rung 2: TCP
# --------------------------------------------------------------------------------------

@dataclass
class TcpObs:
    attempted: bool
    reachable: Optional[bool] = None
    target: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Connector = Callable[[str, int, float], Optional[str]]


def _connect(ip: str, port: int, timeout: float) -> Optional[str]:
    """Return ``None`` on success, else a short error string."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return None
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return exc.strerror or type(exc).__name__


def tcp_probe(host: HostConfig, timeout: float, connect: Connector = _connect) -> TcpObs:
    targets = [ip for ip in (host.tailscale_ip, host.lan_ip) if ip]
    if not targets:
        return TcpObs(False)
    attempts = []
    for ip in targets:
        err = connect(ip, host.ssh_port, timeout)
        attempts.append({"target": f"{ip}:{host.ssh_port}", "ok": err is None, "error": err or ""})
        if err is None:
            return TcpObs(True, True, f"{ip}:{host.ssh_port}", attempts)
    return TcpObs(True, False, "", attempts)


# --------------------------------------------------------------------------------------
# Rung 3: ssh remote probe
# --------------------------------------------------------------------------------------

@dataclass
class RemoteSnapshot:
    ok: bool
    error: str = ""
    hostname: str = ""
    now: Optional[int] = None
    uptime_s: Optional[int] = None
    booted: Optional[int] = None
    unit: str = ""
    unit_scope: str = ""
    unit_active: str = ""
    unit_restart: str = ""
    mainpid: Optional[int] = None
    mainpid_alive: Optional[bool] = None
    mainpid_age_s: Optional[int] = None
    hermes_home: str = ""
    state: Optional[dict[str, Any]] = None
    state_error: str = ""
    state_mtime: Optional[int] = None
    state_pid: Optional[int] = None
    state_pid_alive: Optional[bool] = None
    lock_pid: Optional[int] = None
    lock_pid_alive: Optional[bool] = None
    socket_tool: str = ""
    sockets: Optional[int] = None
    raw_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_REQUIRED_KEYS = ("HOSTNAME", "UNIT_ACTIVE", "MAINPID", "SOCKETS")


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    value = value.strip()
    if not value or not re.fullmatch(r"-?\d{1,19}", value):
        return None
    return int(value)


def _bool_flag(value: Optional[str]) -> Optional[bool]:
    if value is None or value.strip() == "":
        return None
    return value.strip() == "1"


def decode_state_json(value: str) -> tuple[Optional[dict[str, Any]], str]:
    """Decode ``STATE_JSON``: ``b64:<base64>``, bare base64, or a compact JSON line."""
    value = (value or "").strip()
    if not value:
        return None, ""
    candidates: list[str] = []
    if value.startswith("b64:"):
        value = value[4:]
    if value.startswith("{"):
        candidates.append(value)
    else:
        try:
            candidates.append(base64.b64decode(value, validate=True).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            return None, "state file payload is neither JSON nor base64"
    for text in candidates:
        try:
            data = json.loads(text)
        except ValueError:
            return None, "state file is not valid JSON (truncated or corrupt)"
        if not isinstance(data, dict):
            return None, "state file JSON is not an object"
        return data, ""
    return None, "state file payload is empty"


def parse_remote_payload(text: str) -> RemoteSnapshot:
    """Parse the ``KEY=value`` lines printed by :data:`REMOTE_PROBE_SCRIPT`. Never raises."""
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.rstrip("\r")
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,40}", key):
            fields.setdefault(key, value)
    missing = [k for k in _REQUIRED_KEYS if k not in fields]
    if missing:
        snippet = (text or "").strip().splitlines()[:1]
        why = f"remote probe output is not parseable (missing {', '.join(missing)})"
        if snippet:
            why += f"; first line: {snippet[0][:120]!r}"
        return RemoteSnapshot(False, error=why, raw_keys=sorted(fields))
    if "PROBE_END" not in fields:
        return RemoteSnapshot(False, error="remote probe output was truncated (no PROBE_END)",
                              raw_keys=sorted(fields))

    state, state_error = decode_state_json(fields.get("STATE_JSON", ""))
    mainpid = _int_or_none(fields.get("MAINPID"))
    state_pid = _int_or_none(fields.get("STATE_PID"))
    if state is not None and state_pid is None and isinstance(state.get("pid"), int):
        state_pid = state["pid"]
    return RemoteSnapshot(
        ok=True,
        hostname=fields.get("HOSTNAME", "").strip(),
        now=_int_or_none(fields.get("NOW")),
        uptime_s=_int_or_none(fields.get("UPTIME_S")),
        booted=_int_or_none(fields.get("BOOTED")),
        unit=fields.get("UNIT", "").strip(),
        unit_scope=fields.get("UNIT_SCOPE", "").strip(),
        unit_active=fields.get("UNIT_ACTIVE", "").strip() or "unknown",
        unit_restart=fields.get("UNIT_RESTART", "").strip(),
        mainpid=mainpid,
        mainpid_alive=_bool_flag(fields.get("MAINPID_ALIVE")),
        mainpid_age_s=_int_or_none(fields.get("MAINPID_AGE_S")),
        hermes_home=fields.get("HERMES_HOME", "").strip(),
        state=state,
        state_error=state_error,
        state_mtime=_int_or_none(fields.get("STATE_MTIME")),
        state_pid=state_pid,
        state_pid_alive=_bool_flag(fields.get("STATE_PID_ALIVE")),
        lock_pid=_int_or_none(fields.get("LOCK_PID")),
        lock_pid_alive=_bool_flag(fields.get("LOCK_PID_ALIVE")),
        socket_tool=fields.get("SOCKET_TOOL", "").strip(),
        sockets=_int_or_none(fields.get("SOCKETS")),
        raw_keys=sorted(fields),
    )


def ssh_argv(host: HostConfig, connect_timeout: int, remote_args: Sequence[str]) -> list[str]:
    """``ssh`` argv running ``sh -s -- <args>``; the script itself goes on stdin.

    Every argument is allow-list validated by :mod:`config` and shell-quoted here, because
    ssh joins the remote command into one string for the remote login shell.
    """
    quoted = " ".join(shlex.quote(str(a)) for a in remote_args)
    remote = "sh -s --" + (f" {quoted}" if quoted else "")
    return ["ssh", *SSH_BASE_OPTIONS, "-o", f"ConnectTimeout={int(connect_timeout)}", "-T",
            "--", host.ssh_alias, remote]


def probe_args(host: HostConfig) -> list[str]:
    return [host.systemd_unit, host.profile, host.platform_ip, host.hermes_home or "-"]


def classify_ssh_failure(res: CommandResult) -> str:
    if res.missing:
        return "ssh client not installed"
    if res.timed_out:
        return "ssh timed out"
    err = (res.stderr or "").strip()
    low = err.lower()
    if "permission denied" in low:
        return "ssh permission denied (key not accepted)"
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return "ssh host key verification failed"
    if "could not resolve hostname" in low:
        return "ssh alias does not resolve"
    if "connection timed out" in low or "operation timed out" in low:
        return "ssh connect timed out"
    if "connection refused" in low:
        return "ssh connection refused"
    if "no route to host" in low or "network is unreachable" in low:
        return "no route to host"
    last = err.splitlines()[-1][:160] if err else f"exit {res.returncode}"
    return f"ssh failed: {last}"


def remote_probe(host: HostConfig, ssh_timeout: int, runner: Runner = run_bounded) -> tuple[RemoteSnapshot, CommandResult]:
    argv = ssh_argv(host, ssh_timeout, probe_args(host))
    # External bound: ConnectTimeout covers the handshake; this covers the whole round trip.
    res = runner(argv, float(ssh_timeout) + 8.0, REMOTE_PROBE_SCRIPT)
    if res.ok:
        return parse_remote_payload(res.stdout), res
    # ssh exits 255 on its own failures; any other status is the remote sh's. A payload that
    # reached PROBE_END is complete and usable whatever the final status was.
    if res.returncode not in (None, 255) and "PROBE_END=1" in (res.stdout or ""):
        return parse_remote_payload(res.stdout), res
    return RemoteSnapshot(False, error=classify_ssh_failure(res)), res


# --------------------------------------------------------------------------------------
# Whole ladder for one host
# --------------------------------------------------------------------------------------

@dataclass
class HostEvidence:
    host: HostConfig
    probed_at: int
    tailnet: TailnetObs
    tcp: TcpObs
    remote: Optional[RemoteSnapshot]
    remote_skipped: str = ""
    ssh_stderr: str = ""
    ssh_duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host.to_dict(),
            "probed_at": self.probed_at,
            "tailnet": self.tailnet.to_dict(),
            "tcp": self.tcp.to_dict(),
            "remote": self.remote.to_dict() if self.remote else None,
            "remote_skipped": self.remote_skipped,
            "ssh_stderr": self.ssh_stderr[-400:],
            "ssh_duration_s": round(self.ssh_duration_s, 2),
        }


def probe_host(
    host: HostConfig,
    view: TailnetView,
    ssh_timeout: int,
    *,
    runner: Runner = run_bounded,
    connect: Connector = _connect,
    clock: Callable[[], float] = time.time,
) -> HostEvidence:
    tailnet = tailnet_obs_for(host, view)
    tcp = tcp_probe(host, min(5.0, float(ssh_timeout)), connect)
    ev = HostEvidence(host=host, probed_at=int(clock()), tailnet=tailnet, tcp=tcp, remote=None)
    if tailnet.available and tailnet.online is False and tcp.attempted and tcp.reachable is False:
        # Two independent failures already; an ssh attempt would only burn the timeout.
        ev.remote_skipped = "tailnet offline and TCP connect failed"
        return ev
    snap, res = remote_probe(host, ssh_timeout, runner)
    ev.remote = snap
    ev.ssh_stderr = res.stderr or ""
    ev.ssh_duration_s = res.duration_s
    return ev
