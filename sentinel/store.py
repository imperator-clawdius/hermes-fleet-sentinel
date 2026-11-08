"""SQLite history and alert-anchor store.

Location, first match wins:

1. ``FLEET_SENTINEL_DB`` environment variable (explicit path; tests use this).
2. Hermes's per-plugin data root via ``plugins.plugin_storage.plugin_db`` (survives
   ``hermes plugins update``/``remove`` and follows the active profile).
3. ``<hermes_home>/fleet-sentinel/state.db`` when running outside Hermes.

Every write is an upsert keyed by host name, so replaying an observation is harmless.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from .verdict import UP, History

PLUGIN_NAME = "fleet-sentinel"
DB_FILENAME = "state.db"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    name          TEXT PRIMARY KEY,
    first_seen    INTEGER NOT NULL,
    last_ok       INTEGER,
    last_verdict  TEXT,
    last_change   INTEGER,
    zero_since    INTEGER,
    last_reason   TEXT,
    last_probe    INTEGER
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    from_state TEXT,
    to_state   TEXT NOT NULL,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS events_name_ts ON events(name, ts);
CREATE TABLE IF NOT EXISTS alerts (
    name           TEXT PRIMARY KEY,
    alerted        INTEGER NOT NULL DEFAULT 0,
    down_since     INTEGER,
    last_alert     INTEGER,
    streak         INTEGER NOT NULL DEFAULT 0,
    heal_attempted INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class HostRow:
    name: str
    first_seen: int
    last_ok: Optional[int]
    last_verdict: Optional[str]
    last_change: Optional[int]
    zero_since: Optional[int]
    last_reason: Optional[str]
    last_probe: Optional[int]

    def history(self) -> History:
        return History(last_ok=self.last_ok, zero_since=self.zero_since, last_verdict=self.last_verdict)


@dataclass
class AlertState:
    name: str
    alerted: bool = False
    down_since: Optional[int] = None
    last_alert: Optional[int] = None
    streak: int = 0
    heal_attempted: bool = False


def hermes_home() -> Path:
    """Standalone fallback only; inside Hermes ``plugin_db`` resolves the profile's home."""
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".hermes"


def _connect_default() -> tuple[sqlite3.Connection, str]:
    override = os.environ.get("FLEET_SENTINEL_DB")
    if override:
        path = Path(override).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(str(path), check_same_thread=False, timeout=10), str(path)
    try:
        from plugins.plugin_storage import plugin_data_dir, plugin_db
    except Exception:
        plugin_db = None  # type: ignore[assignment]
    if plugin_db is not None:
        try:
            conn = plugin_db(PLUGIN_NAME, DB_FILENAME)
            return conn, str(plugin_data_dir(PLUGIN_NAME) / DB_FILENAME)
        except Exception:
            pass  # fall through to the standalone location
    path = hermes_home() / PLUGIN_NAME / DB_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(path), check_same_thread=False, timeout=10), str(path)


class Store:
    """Thread-safe wrapper; one connection, serialized by a lock."""

    def __init__(self, conn: sqlite3.Connection, path: str = ":memory:"):
        self.conn = conn
        self.path = path
        self._lock = threading.RLock()
        self.conn.row_factory = None
        self._init_schema()

    @classmethod
    def open(cls, path: Optional[str] = None) -> "Store":
        if path:
            p = Path(path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            return cls(sqlite3.connect(str(p), check_same_thread=False, timeout=10), str(p))
        conn, where = _connect_default()
        return cls(conn, where)

    @classmethod
    def memory(cls) -> "Store":
        return cls(sqlite3.connect(":memory:", check_same_thread=False), ":memory:")

    def _init_schema(self) -> None:
        with self._lock:
            self.conn.execute("PRAGMA busy_timeout = 10000")
            if self.path != ":memory:":
                mode = self.conn.execute("PRAGMA journal_mode").fetchone()
                if not mode or str(mode[0]).lower() != "wal":
                    try:
                        self.conn.execute("PRAGMA journal_mode = WAL")
                    except sqlite3.DatabaseError:
                        pass  # e.g. network filesystem: stay in the default journal mode
            version = self.conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"fleet-sentinel state db {self.path} has schema v{version}, newer than v{SCHEMA_VERSION}")
            self.conn.executescript(_SCHEMA)
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- hosts -------------------------------------------------------------------------

    def get_host(self, name: str) -> Optional[HostRow]:
        with self._lock:
            row = self.conn.execute(
                "SELECT name, first_seen, last_ok, last_verdict, last_change, zero_since, last_reason,"
                " last_probe FROM hosts WHERE name = ?", (name,)).fetchone()
        return HostRow(*row) if row else None

    def all_hosts(self) -> list[HostRow]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT name, first_seen, last_ok, last_verdict, last_change, zero_since, last_reason,"
                " last_probe FROM hosts ORDER BY name").fetchall()
        return [HostRow(*r) for r in rows]

    def history(self, name: str) -> History:
        row = self.get_host(name)
        return row.history() if row else History()

    def record_observation(self, name: str, verdict: str, ts: int, *, reason: str = "",
                           zero_since: Optional[int] = None, detail: str = "") -> HostRow:
        """Upsert one observation; append an event only when the verdict changed."""
        with self._lock:
            prev = self.get_host(name)
            prev_verdict = prev.last_verdict if prev else None
            changed = prev_verdict != verdict
            last_ok = ts if verdict == UP else (prev.last_ok if prev else None)
            last_change = ts if changed else (prev.last_change if prev else ts)
            self.conn.execute(
                """INSERT INTO hosts (name, first_seen, last_ok, last_verdict, last_change, zero_since,
                                      last_reason, last_probe)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       last_ok = excluded.last_ok,
                       last_verdict = excluded.last_verdict,
                       last_change = excluded.last_change,
                       zero_since = excluded.zero_since,
                       last_reason = excluded.last_reason,
                       last_probe = excluded.last_probe""",
                (name, ts, last_ok, verdict, last_change, zero_since, reason, ts),
            )
            if changed:
                self.conn.execute(
                    "INSERT INTO events (name, ts, from_state, to_state, detail) VALUES (?, ?, ?, ?, ?)",
                    (name, ts, prev_verdict, verdict, detail or reason))
            self.conn.commit()
            row = self.get_host(name)
        assert row is not None
        return row

    def record_event(self, name: str, ts: int, kind: str, detail: str = "") -> None:
        """Append a non-verdict event (e.g. a recovery action) to the audit trail."""
        with self._lock:
            prev = self.get_host(name)
            current = prev.last_verdict if prev else None
            self.conn.execute(
                "INSERT INTO events (name, ts, from_state, to_state, detail) VALUES (?, ?, ?, ?, ?)",
                (name, ts, current, kind, detail[:2000]))
            self.conn.commit()

    def events(self, name: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            if name:
                rows = self.conn.execute(
                    "SELECT id, name, ts, from_state, to_state, detail FROM events WHERE name = ?"
                    " ORDER BY id DESC LIMIT ?", (name, limit)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT id, name, ts, from_state, to_state, detail FROM events ORDER BY id DESC LIMIT ?",
                    (limit,)).fetchall()
        keys = ("id", "name", "ts", "from_state", "to_state", "detail")
        return [dict(zip(keys, r)) for r in rows]

    # -- alerts ------------------------------------------------------------------------

    def get_alert(self, name: str) -> AlertState:
        with self._lock:
            row = self.conn.execute(
                "SELECT name, alerted, down_since, last_alert, streak, heal_attempted FROM alerts"
                " WHERE name = ?", (name,)).fetchone()
        if not row:
            return AlertState(name=name)
        return AlertState(name=row[0], alerted=bool(row[1]), down_since=row[2], last_alert=row[3],
                          streak=int(row[4] or 0), heal_attempted=bool(row[5]))

    def put_alert(self, state: AlertState) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO alerts (name, alerted, down_since, last_alert, streak, heal_attempted)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       alerted = excluded.alerted, down_since = excluded.down_since,
                       last_alert = excluded.last_alert, streak = excluded.streak,
                       heal_attempted = excluded.heal_attempted""",
                (state.name, int(state.alerted), state.down_since, state.last_alert, int(state.streak),
                 int(state.heal_attempted)))
            self.conn.commit()

    def iter_alerts(self) -> Iterator[AlertState]:
        with self._lock:
            names = [r[0] for r in self.conn.execute("SELECT name FROM alerts ORDER BY name").fetchall()]
        for n in names:
            yield self.get_alert(n)
