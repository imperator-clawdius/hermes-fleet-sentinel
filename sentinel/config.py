"""Settings: defaults, merge, and schema validation.

Settings live under ``plugins.entries.fleet-sentinel.settings`` in Hermes's
``config.yaml``. This module never raises on bad input: every malformed value
is replaced by its default and described in ``Settings.problems`` so the
probe output can surface it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

DEFAULT_PLATFORM = "telegram"
DEFAULT_PLATFORM_IP = "149.154.166.110"  # api.telegram.org
DEFAULT_PROFILE = "default"
DEFAULT_SSH_PORT = 22

DEFAULT_THRESHOLDS: dict[str, int] = {
    "page_after_minutes": 60,
    "repage_hours": 24,
    "deaf_grace_minutes": 10,
    "ssh_timeout_seconds": 12,
}

# Inclusive sanity bounds; values outside are reported and replaced by the default.
_THRESHOLD_BOUNDS: dict[str, tuple[int, int]] = {
    "page_after_minutes": (0, 7 * 24 * 60),
    "repage_hours": (1, 24 * 30),
    "deaf_grace_minutes": (1, 24 * 60),
    "ssh_timeout_seconds": (2, 120),
}

# JSON-schema view of the settings (mirrors plugin.yaml's config_schema items/properties).
HOST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "ssh_alias"],
    "properties": {
        "name": {"type": "string"},
        "ssh_alias": {"type": "string"},
        "label": {"type": "string"},
        "tailscale_ip": {"type": "string"},
        "lan_ip": {"type": "string"},
        "profile": {"type": "string", "default": DEFAULT_PROFILE},
        "platform": {"type": "string", "default": DEFAULT_PLATFORM},
        "platform_ip": {"type": "string", "default": DEFAULT_PLATFORM_IP},
        "ssh_port": {"type": "integer", "default": DEFAULT_SSH_PORT},
        "unit": {"type": "string"},
        "hermes_home": {"type": "string"},
        "wol_mac": {"type": "string"},
        "wol_broadcast": {"type": "string", "default": "255.255.255.255"},
    },
}

# Identifiers that end up as arguments of a remote ``sh -s`` call. They are shell-quoted
# as well, but a strict allow-list means a hostile config cannot even reach the quoting.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,252}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{0,200}$")
_HOME_RE = re.compile(r"^(~|/)[A-Za-z0-9/._-]{0,511}$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$")


@dataclass(frozen=True)
class HostConfig:
    name: str
    ssh_alias: str
    label: str = ""
    tailscale_ip: str = ""
    lan_ip: str = ""
    profile: str = DEFAULT_PROFILE
    platform: str = DEFAULT_PLATFORM
    platform_ip: str = DEFAULT_PLATFORM_IP
    ssh_port: int = DEFAULT_SSH_PORT
    unit: str = ""
    hermes_home: str = ""
    wol_mac: str = ""
    wol_broadcast: str = "255.255.255.255"

    @property
    def display_name(self) -> str:
        if self.label:
            return self.label
        return self.name[:1].upper() + self.name[1:]

    @property
    def systemd_unit(self) -> str:
        """Explicit ``unit`` or Hermes's naming: ``hermes-gateway[-<profile>]``."""
        if self.unit:
            return self.unit
        if self.profile == DEFAULT_PROFILE:
            return "hermes-gateway"
        return f"hermes-gateway-{self.profile}"

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["unit"] = self.systemd_unit
        return out


@dataclass(frozen=True)
class Thresholds:
    page_after_minutes: int = DEFAULT_THRESHOLDS["page_after_minutes"]
    repage_hours: int = DEFAULT_THRESHOLDS["repage_hours"]
    deaf_grace_minutes: int = DEFAULT_THRESHOLDS["deaf_grace_minutes"]
    ssh_timeout_seconds: int = DEFAULT_THRESHOLDS["ssh_timeout_seconds"]

    @property
    def page_after_s(self) -> int:
        return self.page_after_minutes * 60

    @property
    def repage_s(self) -> int:
        return self.repage_hours * 3600

    @property
    def deaf_grace_s(self) -> int:
        return self.deaf_grace_minutes * 60


@dataclass(frozen=True)
class Settings:
    hosts: tuple[HostConfig, ...] = ()
    thresholds: Thresholds = field(default_factory=Thresholds)
    auto_heal: bool = False
    problems: tuple[str, ...] = ()

    def host(self, name: str) -> Optional[HostConfig]:
        wanted = (name or "").strip().lower()
        for h in self.hosts:
            if h.name.lower() == wanted or h.ssh_alias.lower() == wanted:
                return h
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": [h.to_dict() for h in self.hosts],
            "thresholds": asdict(self.thresholds),
            "auto_heal": self.auto_heal,
            "problems": list(self.problems),
        }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _parse_thresholds(raw: Any, problems: list[str]) -> Thresholds:
    if raw is None:
        return Thresholds()
    if not isinstance(raw, Mapping):
        problems.append(f"thresholds should be an object (got {type(raw).__name__}); using defaults")
        return Thresholds()
    values = dict(DEFAULT_THRESHOLDS)
    for key, value in raw.items():
        if key not in DEFAULT_THRESHOLDS:
            problems.append(f"thresholds.{key} is not a known threshold; ignored")
            continue
        if value is None:
            continue
        if not _is_int(value):
            problems.append(
                f"thresholds.{key} should be an integer (got {type(value).__name__}); "
                f"using default {DEFAULT_THRESHOLDS[key]}"
            )
            continue
        lo, hi = _THRESHOLD_BOUNDS[key]
        if not lo <= value <= hi:
            problems.append(
                f"thresholds.{key}={value} is outside {lo}..{hi}; using default {DEFAULT_THRESHOLDS[key]}"
            )
            continue
        values[key] = value
    return Thresholds(**values)


def _parse_host(index: int, raw: Any, problems: list[str]) -> Optional[HostConfig]:
    where = f"hosts[{index}]"
    if not isinstance(raw, Mapping):
        problems.append(f"{where} should be an object (got {type(raw).__name__}); skipped")
        return None
    name = raw.get("name")
    alias = raw.get("ssh_alias")
    if not isinstance(name, str) or not _NAME_RE.match(name.strip()):
        problems.append(f"{where}.name is required and must match {_NAME_RE.pattern}; host skipped")
        return None
    name = name.strip()
    where = f"hosts[{name}]"
    if not isinstance(alias, str) or not _ALIAS_RE.match(alias.strip()):
        problems.append(f"{where}.ssh_alias is required and must be a plain ssh alias; host skipped")
        return None
    kwargs: dict[str, Any] = {"name": name, "ssh_alias": alias.strip()}

    def text(key: str, check=None, why: str = "") -> None:
        value = raw.get(key)
        if value is None or value == "":
            return
        if not isinstance(value, str):
            problems.append(f"{where}.{key} should be a string (got {type(value).__name__}); ignored")
            return
        value = value.strip()
        if check is not None and not check(value):
            problems.append(f"{where}.{key}={value!r} is invalid{why}; ignored")
            return
        kwargs[key] = value

    text("label")
    text("tailscale_ip", _valid_ip, " (not an IP address)")
    text("lan_ip", _valid_ip, " (not an IP address)")
    text("profile", lambda v: bool(_NAME_RE.match(v)), " (profile names are [A-Za-z0-9._-])")
    text("platform", lambda v: bool(_NAME_RE.match(v)))
    text("platform_ip", _valid_ip, " (not an IP address)")
    text("unit", lambda v: bool(_UNIT_RE.match(v)), " (not a systemd unit name)")
    text("hermes_home", lambda v: bool(_HOME_RE.match(v)) and ".." not in v,
         " (must be an absolute or ~ path without spaces or '..')")
    text("wol_mac", lambda v: bool(_MAC_RE.match(v)), " (expected aa:bb:cc:dd:ee:ff)")
    text("wol_broadcast", _valid_ip, " (not an IP address)")

    port = raw.get("ssh_port")
    if port is not None:
        if _is_int(port) and 1 <= port <= 65535:
            kwargs["ssh_port"] = port
        else:
            problems.append(f"{where}.ssh_port should be an integer 1..65535 (got {port!r}); using 22")

    known = set(HOST_SCHEMA["properties"])
    for key in raw:
        if key not in known:
            problems.append(f"{where}.{key} is not a known host field; ignored")
    return HostConfig(**kwargs)


def parse_settings(raw: Any) -> Settings:
    """Merge raw settings over defaults. Never raises."""
    problems: list[str] = []
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        problems.append(f"settings should be an object (got {type(raw).__name__}); using defaults")
        raw = {}

    hosts: list[HostConfig] = []
    raw_hosts = raw.get("hosts")
    if raw_hosts is None:
        raw_hosts = []
    if not isinstance(raw_hosts, list):
        problems.append(f"hosts should be a list (got {type(raw_hosts).__name__}); no hosts configured")
        raw_hosts = []
    seen: set[str] = set()
    for i, item in enumerate(raw_hosts):
        host = _parse_host(i, item, problems)
        if host is None:
            continue
        if host.name.lower() in seen:
            problems.append(f"hosts[{host.name}] is a duplicate name; later entry skipped")
            continue
        seen.add(host.name.lower())
        hosts.append(host)

    auto_heal = raw.get("auto_heal", False)
    if not isinstance(auto_heal, bool):
        problems.append(f"auto_heal should be a boolean (got {type(auto_heal).__name__}); using false")
        auto_heal = False

    return Settings(
        hosts=tuple(hosts),
        thresholds=_parse_thresholds(raw.get("thresholds"), problems),
        auto_heal=auto_heal,
        problems=tuple(problems),
    )


def load_settings_file(path: str | os.PathLike[str]) -> tuple[Any, Optional[str]]:
    """Read a JSON (or YAML, when a YAML parser is importable) settings file.

    Returns ``(raw, error)``; never raises.
    """
    p = Path(path).expanduser()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"cannot read settings file {p}: {exc.strerror or exc}"
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            return None, f"{p} is YAML but no YAML parser is importable; use JSON"
        try:
            data = yaml.safe_load(text)
        except Exception as exc:  # yaml.YAMLError and friends
            return None, f"{p} is not valid YAML: {exc}"
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            return None, f"{p} is not valid JSON: {exc}"
    # Accept either the bare settings block or a full plugins.entries.<id>.settings tree.
    if isinstance(data, Mapping):
        entry = (((data.get("plugins") or {}).get("entries") or {}).get("fleet-sentinel") or {})
        if isinstance(entry, Mapping) and isinstance(entry.get("settings"), Mapping):
            data = entry["settings"]
    return data, None


def default_settings_block() -> dict[str, Any]:
    """The block ``hermes fleet-sentinel init`` writes when nothing is configured."""
    return {
        "hosts": [],
        "thresholds": dict(DEFAULT_THRESHOLDS),
        "auto_heal": False,
    }


EXAMPLE_HOST: dict[str, Any] = {
    "name": "pi-host",
    "ssh_alias": "pi-host",
    "tailscale_ip": "100.64.0.10",
    "lan_ip": "192.168.1.50",
    "profile": "default",
    "ssh_port": 22,
}
