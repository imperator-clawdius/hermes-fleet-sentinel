#!/usr/bin/env python3
"""Standalone cron entry point: ``python3 scripts/tick.py [--json] [--quiet]``.

This is THE supported cron path. ``hermes fleet-sentinel tick`` only exists when the plugin's
``register_cli_command`` runs in the local CLI parser, which Hermes skips in the default host
isolation mode; this script needs no CLI registration at all.

It builds a :class:`sentinel.runtime.Sentinel`, runs one ``tick()``, prints ONLY alerts on
stdout and always exits 0, so a ``hermes cron create ... --script ... --no-agent`` job sends a
message only when there is something to say (empty stdout = no message). Diagnostics go to
stderr, which Hermes discards for a script that exits 0.

Settings resolution (an explicit override beats ambient config, same precedence as the
store's ``$FLEET_SENTINEL_DB``):

1. ``$FLEET_SENTINEL_SETTINGS``, when set and non-empty: path to a JSON file holding
   ``{"hosts": [...], "thresholds": {...}, "auto_heal": false}`` (a full
   ``plugins.entries.fleet-sentinel.settings`` tree is accepted too). It is used ALWAYS, even
   when Hermes is importable; an unreadable or malformed file is an error, never a silent
   fall-through to Hermes's config.
2. Otherwise Hermes's own config reader (``hermes_cli.config.load_config_readonly``), reading
   the same keys ``ctx.get_config`` does: ``plugins.entries.fleet-sentinel.settings.{hosts,
   thresholds,auto_heal}`` (with the legacy ``config`` subtree as per-key fallback). If
   ``hermes_cli`` is not importable as-is, the Hermes checkout is looked up at
   ``$HERMES_AGENT_DIR``, ``$HERMES_HOME/hermes-agent`` and ``~/.hermes/hermes-agent``.
3. Otherwise (no Hermes, or no fleet-sentinel block in its config) a clear error is raised.
   The Sentinel turns it into a config problem that ``main`` reports on stderr; exit stays 0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

PLUGIN_ID = "fleet-sentinel"
SETTING_KEYS = ("hosts", "thresholds", "auto_heal")
SETTINGS_ENV = "FLEET_SENTINEL_SETTINGS"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))


def _hermes_checkouts() -> list[Path]:
    home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()
    out = []
    if os.environ.get("HERMES_AGENT_DIR"):
        out.append(Path(os.environ["HERMES_AGENT_DIR"]).expanduser())
    out += [home / "hermes-agent", Path.home() / ".hermes" / "hermes-agent"]
    return out


def _import_hermes_config_reader() -> Callable[[], Any]:
    """``load_config_readonly`` from Hermes; raises ImportError when Hermes is not available."""
    try:
        from hermes_cli.config import load_config_readonly
        return load_config_readonly
    except ImportError:
        pass
    for checkout in _hermes_checkouts():
        if (checkout / "hermes_cli" / "config.py").is_file():
            if str(checkout) not in sys.path:
                sys.path.append(str(checkout))  # appended: our own `sentinel` package stays first
            try:
                from hermes_cli.config import load_config_readonly
                return load_config_readonly
            except ImportError:
                continue
    raise ImportError("hermes_cli.config is not importable")


def _walk(root: Any, *segments: str) -> Any:
    current = root
    for segment in segments:
        if not isinstance(current, Mapping) or segment not in current:
            return None
        current = current[segment]
    return current


def settings_from_hermes_config(config: Any) -> dict[str, Any]:
    """Same lookup as ``PluginContext.get_config`` for each of :data:`SETTING_KEYS`."""
    if not isinstance(config, Mapping):
        # load_config can hand back a FailedConfigRead marker instead of a dict.
        raise RuntimeError(f"Hermes config could not be read: {config!r}")
    entry = _walk(config, "plugins", "entries", PLUGIN_ID)
    if not isinstance(entry, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key in SETTING_KEYS:
        settings = entry.get("settings")
        if isinstance(settings, Mapping) and key in settings:
            value = settings[key]
        else:
            value = _walk(entry.get("config"), key)
        if value is not None:
            out[key] = value
    return out


def settings_env_path() -> Optional[str]:
    """The ``$FLEET_SENTINEL_SETTINGS`` override, or None when unset/blank."""
    path = os.environ.get(SETTINGS_ENV, "").strip()
    return path or None


def settings_from_env_file(path: Optional[str] = None) -> dict[str, Any]:
    """Read the ``$FLEET_SENTINEL_SETTINGS`` JSON file; raises RuntimeError with a clear message."""
    path = path or settings_env_path()
    if not path:
        raise RuntimeError(f"${SETTINGS_ENV} is not set")
    from sentinel.config import load_settings_file
    data, error = load_settings_file(path)
    if error:
        raise RuntimeError(f"${SETTINGS_ENV}: {error}")
    if not isinstance(data, Mapping):
        raise RuntimeError(f"${SETTINGS_ENV} ({path}) must hold a JSON object, "
                           f"got {type(data).__name__}")
    return {k: data[k] for k in SETTING_KEYS if data.get(k) is not None}


def load_settings(reader_factory: Callable[[], Callable[[], Any]] = _import_hermes_config_reader
                  ) -> dict[str, Any]:
    """Settings provider for the Sentinel; re-read on every call, like ``ctx.get_config``.

    Precedence: ``$FLEET_SENTINEL_SETTINGS`` (always, when set) > Hermes config reader > error.
    """
    env_path = settings_env_path()
    if env_path:
        return settings_from_env_file(env_path)
    try:
        reader = reader_factory()
    except ImportError as exc:  # (a broken-but-present Hermes raises something else and is reported)
        raise RuntimeError(f"no settings source: ${SETTINGS_ENV} is not set and the Hermes "
                           f"config reader is unavailable ({exc})") from None
    settings = settings_from_hermes_config(reader())
    if not settings:
        raise RuntimeError(f"no settings source: ${SETTINGS_ENV} is not set and Hermes config has "
                           f"no plugins.entries.{PLUGIN_ID}.settings block "
                           f"(run `hermes {PLUGIN_ID} init` or set ${SETTINGS_ENV})")
    return settings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tick.py", description="fleet-sentinel cron tick: prints only alerts.")
    p.add_argument("--json", action="store_true", help="Emit alerts as a JSON list (nothing when healthy)")
    p.add_argument("--quiet", action="store_true", help="Do not report config problems on stderr")
    return p


def main(argv: Optional[list[str]] = None, *, sentinel_factory: Optional[Callable[[], Any]] = None,
         out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args, _unknown = build_parser().parse_known_args(argv)
    except SystemExit:  # argparse --help / bad usage: never fail the cron job
        return 0
    args.fleet_command = "tick"
    sentinel = None
    if sentinel_factory is None:
        try:
            # Put Hermes on sys.path up front (when present) so the store resolves to the same
            # plugin data dir (plugins.plugin_storage) the in-host plugin uses.
            _import_hermes_config_reader()
        except Exception:
            pass
    try:
        from sentinel import cli
        from sentinel.runtime import Sentinel
        sentinel = sentinel_factory() if sentinel_factory else Sentinel(load_settings)
        cli.cmd_tick(sentinel, args, out, err)
        return 0
    except Exception as exc:  # import or construction failure: report, still exit 0
        if not args.quiet:
            err.write(f"fleet-sentinel tick failed: {type(exc).__name__}: {exc}\n")
        return 0
    finally:
        if sentinel is not None:
            try:
                sentinel.close()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(0)
