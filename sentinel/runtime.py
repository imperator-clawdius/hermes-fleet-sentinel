"""Orchestration shared by the tools, the CLI and the slash command.

Probes run in parallel (one thread per host, each bounded by its own timeouts); verdicts,
store writes and escalation run sequentially afterwards so the store sees one writer.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import Any, Callable, Optional

from . import escalate, recover
from .config import HostConfig, Settings, parse_settings
from .probe import (Connector, HostEvidence, Runner, TailnetView, _connect, fetch_tailnet, probe_host,
                    run_bounded)
from .store import Store
from .verdict import UP, Verdict, decide, fmt_minutes

SettingsProvider = Callable[[], Any]


@dataclass
class Observation:
    host: HostConfig
    evidence: HostEvidence
    verdict: Verdict
    last_ok: Optional[int]


def iso(ts: Optional[int], tz: Optional[tzinfo] = None) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), tz).astimezone().isoformat(timespec="seconds")


class Sentinel:
    def __init__(
        self,
        settings_provider: SettingsProvider,
        *,
        store_factory: Callable[[], Store] = Store.open,
        runner: Runner = run_bounded,
        connect: Connector = _connect,
        clock: Callable[[], float] = time.time,
        tailnet_fetch: Optional[Callable[[], TailnetView]] = None,
    ):
        self._settings_provider = settings_provider
        self._store_factory = store_factory
        self._store: Optional[Store] = None
        self._store_lock = threading.Lock()
        self._run_lock = threading.Lock()
        self.runner = runner
        self.connect = connect
        self.clock = clock
        self._tailnet_fetch = tailnet_fetch

    # -- plumbing ----------------------------------------------------------------------

    def settings(self) -> Settings:
        try:
            raw = self._settings_provider()
        except Exception as exc:  # a broken provider must not take the tool down
            s = parse_settings({})
            return Settings(hosts=s.hosts, thresholds=s.thresholds, auto_heal=False,
                            problems=(f"could not read settings: {exc}",))
        if isinstance(raw, Settings):
            return raw
        return parse_settings(raw)

    @property
    def store(self) -> Store:
        with self._store_lock:
            if self._store is None:
                self._store = self._store_factory()
            return self._store

    def close(self) -> None:
        with self._store_lock:
            if self._store is not None:
                try:
                    self._store.close()
                finally:
                    self._store = None

    def _tailnet(self, settings: Settings) -> TailnetView:
        if self._tailnet_fetch is not None:
            return self._tailnet_fetch()
        return fetch_tailnet(self.runner, timeout=min(10.0, float(settings.thresholds.ssh_timeout_seconds)))

    # -- probing -----------------------------------------------------------------------

    def observe(self, hosts: list[HostConfig], settings: Settings) -> list[Observation]:
        if not hosts:
            return []
        view = self._tailnet(settings)
        timeout = settings.thresholds.ssh_timeout_seconds

        def one(h: HostConfig) -> HostEvidence:
            return probe_host(h, view, timeout, runner=self.runner, connect=self.connect, clock=self.clock)

        with ThreadPoolExecutor(max_workers=min(8, len(hosts)), thread_name_prefix="fleet-sentinel") as pool:
            evidence = list(pool.map(one, hosts))

        out: list[Observation] = []
        store = self.store
        for host, ev in zip(hosts, evidence):
            history = store.history(host.name)
            v = decide(ev, history, settings.thresholds.deaf_grace_s, now=ev.probed_at)
            row = store.record_observation(host.name, v.verdict, v.observed_at, reason=v.reason,
                                           zero_since=v.zero_since, detail=f"{v.reason_code}: {v.reason}")
            out.append(Observation(host, ev, v, row.last_ok))
        return out

    @staticmethod
    def summary(obs: Observation) -> dict[str, Any]:
        v = obs.verdict
        return {
            "host": obs.host.name,
            "verdict": v.verdict,
            "reason": v.reason,
            "reason_code": v.reason_code,
            "detail": v.notes,
            "last_ok": iso(obs.last_ok),
            "state_file_stale": v.state_file_stale,
            "sockets": v.sockets,
            "gateway_pid": v.gateway_pid,
            "observed_at": iso(v.observed_at),
        }

    def status(self) -> dict[str, Any]:
        settings = self.settings()
        with self._run_lock:
            observations = self.observe(list(settings.hosts), settings)
        hosts = [self.summary(o) for o in observations]
        counts: dict[str, int] = {}
        for h in hosts:
            counts[h["verdict"]] = counts.get(h["verdict"], 0) + 1
        out: dict[str, Any] = {"hosts": hosts, "counts": counts, "problems": list(settings.problems)}
        if not settings.hosts:
            out["hint"] = ("no hosts configured: add them under plugins.entries.fleet-sentinel.settings.hosts "
                           "(see `hermes fleet-sentinel init`)")
        return out

    def probe(self, name: str) -> dict[str, Any]:
        settings = self.settings()
        host = settings.host(name)
        if host is None:
            return {"error": f"unknown host {name!r}", "known_hosts": [h.name for h in settings.hosts],
                    "problems": list(settings.problems)}
        with self._run_lock:
            obs = self.observe([host], settings)[0]
        v = obs.verdict
        return {
            **self.summary(obs),
            "why": v.notes,
            "verdict_detail": v.to_dict(),
            "evidence": obs.evidence.to_dict(),
            "thresholds": {"deaf_grace_minutes": settings.thresholds.deaf_grace_minutes,
                           "ssh_timeout_seconds": settings.thresholds.ssh_timeout_seconds},
            "problems": list(settings.problems),
        }

    def recover(self, name: str, action: str, dry_run: Any = True, confirm: Any = False) -> dict[str, Any]:
        settings = self.settings()
        host = settings.host(name)
        if host is None:
            return {"ok": False, "action": action, "host": name, "output": f"unknown host {name!r}",
                    "dry_run": True}
        res = recover.run_action(host, action, dry_run=dry_run, confirm=confirm,
                                 timeout=settings.thresholds.ssh_timeout_seconds, runner=self.runner)
        if not res.get("dry_run"):
            self.store.record_event(host.name, int(self.clock()), f"recover:{res['action']}",
                                    f"ok={res['ok']} {res['output']}")
        return res

    # -- escalation --------------------------------------------------------------------

    def tick(self, *, tz: Optional[tzinfo] = None) -> tuple[list[dict[str, Any]], Settings]:
        """Probe everything, advance the ladder; return only the alerts that must be sent."""
        settings = self.settings()
        with self._run_lock:
            observations = self.observe(list(settings.hosts), settings)
            alerts: list[dict[str, Any]] = []
            store = self.store
            for obs in observations:
                state = store.get_alert(obs.host.name)
                d = escalate.decide(obs.host, obs.verdict, state, last_ok=obs.last_ok,
                                    thresholds=settings.thresholds, now=obs.verdict.observed_at,
                                    auto_heal=settings.auto_heal, tz=tz)
                message = d.message
                heal_result = None
                if d.heal:
                    heal_result = recover.restart_gateway(obs.host, execute=True,
                                                          timeout=settings.thresholds.ssh_timeout_seconds,
                                                          runner=self.runner)
                    store.record_event(obs.host.name, obs.verdict.observed_at, "recover:restart-gateway",
                                       f"auto-heal ok={heal_result['ok']} {heal_result['output']}")
                    if message:
                        prefix = "Restart sent" if heal_result["ok"] else "Restart FAILED"
                        message += f"\n{prefix}: {heal_result['output']}"
                store.put_alert(d.state)
                if message:
                    alerts.append({"host": obs.host.name, "kind": d.kind, "verdict": obs.verdict.verdict,
                                   "message": message, "heal": heal_result})
        return alerts, settings

    # -- cached view -------------------------------------------------------------------

    def cached_text(self) -> str:
        settings = self.settings()
        if not settings.hosts:
            return "fleet-sentinel: no hosts configured (run `hermes fleet-sentinel init`)."
        now = int(self.clock())
        lines = []
        icons = {"up": "🟢", "deaf": "🟠", "down_physical": "🔴", "degraded": "🟡", "unknown": "⚪"}
        for h in settings.hosts:
            row = self.store.get_host(h.name)
            if row is None or row.last_verdict is None:
                lines.append(f"⚫ {h.display_name}: never probed")
                continue
            age = fmt_minutes(now - (row.last_probe or now))
            line = f"{icons.get(row.last_verdict, '•')} {h.display_name}: {row.last_verdict}"
            if row.last_verdict != UP and row.last_reason:
                line += f" — {row.last_reason}"
            line += f" (probed {age} ago)"
            lines.append(line)
        if settings.problems:
            lines.append(f"config: {len(settings.problems)} problem(s); see `hermes fleet-sentinel hosts`")
        return "\n".join(lines)

    def live_text(self) -> str:
        data = self.status()
        if not data["hosts"]:
            return data.get("hint", "no hosts configured")
        icons = {"up": "🟢", "deaf": "🟠", "down_physical": "🔴", "degraded": "🟡", "unknown": "⚪"}
        lines = []
        for h in data["hosts"]:
            line = f"{icons.get(h['verdict'], '•')} {h['host']}: {h['verdict']} — {h['reason']}"
            lines.append(line)
        return "\n".join(lines)
