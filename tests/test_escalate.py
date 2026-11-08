"""Escalation ladder, message rendering, and the silent-when-healthy ``tick`` contract."""

from __future__ import annotations

import argparse
import io
from datetime import timezone

from conftest import FIXTURE_NOW, FakeRunner, fixture_text
from sentinel import cli
from sentinel.config import HostConfig, Thresholds, parse_settings
from sentinel.escalate import (FIRST_PAGE, HEAL, NONE, RECOVERY, REPAGE, backdate_down_since, decide,
                               render_recovery)
from sentinel.probe import TailnetView, parse_tailscale_status
from sentinel.runtime import Sentinel
from sentinel.store import AlertState, Store
from sentinel.verdict import DEAF, DOWN_PHYSICAL, UP, Verdict

UTC = timezone.utc
NOW = FIXTURE_NOW                       # 2026-11-05 04:12 UTC
LAST_OK_GPU_HOST = 1793551680           # 2026-11-01 16:48 UTC
LAST_OK_PI_HOST = 1793833320           # 2026-11-04 23:02 UTC
T = Thresholds()

GPU_HOST = HostConfig(name="gpu-host", ssh_alias="gpu-host", tailscale_ip="100.101.1.11", lan_ip="192.168.1.51")
PI_HOST = HostConfig(name="pi-host", ssh_alias="pi-host", tailscale_ip="100.101.1.10")


def offline(down_for: int) -> Verdict:
    return Verdict(host="gpu-host", verdict=DOWN_PHYSICAL, reason_code="offline",
                   reason="host unreachable on the tailnet and by TCP (power or cable)",
                   tailnet_online=False, tailnet_last_seen=NOW - down_for, observed_at=NOW, reachable=False)


def deaf(zero_for: int) -> Verdict:
    return Verdict(host="pi-host", verdict=DEAF, reason_code="no_platform_sockets",
                   reason="host up, gateway process alive, 0 platform sockets", gateway_alive=True,
                   gateway_pid=424242, sockets=0, zero_since=NOW - zero_for, zero_for_s=zero_for,
                   observed_at=NOW, reachable=True)


def up() -> Verdict:
    return Verdict(host="pi-host", verdict=UP, reason_code="ok", reason="ok", gateway_alive=True,
                   gateway_pid=424242, sockets=2, uptime_s=26 * 86400, observed_at=NOW, reachable=True,
                   state_file_stale=True)


# -- first page -------------------------------------------------------------------------

def test_first_page_exact_text_and_backdated_down_since():
    d = decide(GPU_HOST, offline(27 * 3600), AlertState("gpu-host"), last_ok=LAST_OK_GPU_HOST,
               thresholds=T, now=NOW, tz=UTC)
    assert d.kind == FIRST_PAGE
    assert d.message == (
        "🔴 Gpu-host is offline — down 1d 3h.\n"
        "Host unreachable on the tailnet and LAN (power or cable). Last verified up: 2026-11-01 16:48.\n"
        "Physical: check power LED, PSU, reseat ethernet."
    )
    assert d.state.alerted is True and d.state.last_alert == NOW
    assert d.state.down_since == NOW - 27 * 3600  # back-dated on the very first page
    assert d.state.streak == 1


def test_not_paged_before_page_after_minutes():
    d = decide(GPU_HOST, offline(30 * 60), AlertState("gpu-host"), last_ok=NOW - 30 * 60,
               thresholds=T, now=NOW, tz=UTC)
    assert d.kind == NONE and d.message is None
    assert d.state.alerted is False and d.state.streak == 1 and d.state.down_since == NOW - 30 * 60


def test_deaf_page_exact_text_with_auto_heal():
    d = decide(PI_HOST, deaf(14 * 60), AlertState("pi-host"), last_ok=LAST_OK_PI_HOST,
               thresholds=T, now=NOW, auto_heal=True, tz=UTC)
    assert d.kind == FIRST_PAGE and d.heal is True
    assert d.message == (
        "🟠 Pi-host is deaf — host up, gateway process alive, 0 platform sockets for 14m.\n"
        "Last healthy socket: 2026-11-04 23:02. Attempting gateway restart."
    )
    assert d.state.heal_attempted is True


def test_deaf_page_without_auto_heal_gives_restart_hint():
    d = decide(PI_HOST, deaf(14 * 60), AlertState("pi-host"), last_ok=LAST_OK_PI_HOST,
               thresholds=T, now=NOW, tz=UTC)
    assert d.heal is False
    assert d.message.endswith("hermes fleet-sentinel recover pi-host restart-gateway --execute")


def test_auto_heal_only_once():
    state = AlertState("pi-host", alerted=True, down_since=NOW - 900, last_alert=NOW - 600, streak=3,
                       heal_attempted=True)
    d = decide(PI_HOST, deaf(15 * 60), state, last_ok=LAST_OK_PI_HOST, thresholds=T, now=NOW,
               auto_heal=True, tz=UTC)
    assert d.kind == NONE and d.heal is False


def test_heal_after_offline_page_when_host_turns_deaf():
    state = AlertState("pi-host", alerted=True, down_since=NOW - 7200, last_alert=NOW - 3600, streak=10)
    d = decide(PI_HOST, deaf(15 * 60), state, last_ok=LAST_OK_PI_HOST, thresholds=T, now=NOW,
               auto_heal=True, tz=UTC)
    assert d.kind == HEAL and d.heal is True and "is still deaf" in d.message


# -- silence and re-page ----------------------------------------------------------------

def test_silent_while_recently_paged():
    state = AlertState("gpu-host", alerted=True, down_since=NOW - 30 * 3600, last_alert=NOW - 2 * 3600, streak=40)
    d = decide(GPU_HOST, offline(30 * 3600), state, last_ok=LAST_OK_GPU_HOST, thresholds=T, now=NOW, tz=UTC)
    assert d.kind == NONE and d.message is None
    assert d.state.last_alert == NOW - 2 * 3600 and d.state.streak == 41


def test_repage_after_24h():
    state = AlertState("gpu-host", alerted=True, down_since=NOW - 51 * 3600, last_alert=NOW - 24 * 3600, streak=300)
    d = decide(GPU_HOST, offline(51 * 3600), state, last_ok=LAST_OK_GPU_HOST, thresholds=T, now=NOW, tz=UTC)
    assert d.kind == REPAGE
    assert d.message.startswith("🔴 Gpu-host is still offline — down 2d 3h.")
    assert d.state.last_alert == NOW


def test_repage_every_repage_hours_after():
    state = AlertState("gpu-host", alerted=True, down_since=NOW - 75 * 3600, last_alert=NOW - 23 * 3600)
    assert decide(GPU_HOST, offline(75 * 3600), state, last_ok=None, thresholds=T, now=NOW).kind == NONE
    state.last_alert = NOW - 48 * 3600
    assert decide(GPU_HOST, offline(75 * 3600), state, last_ok=None, thresholds=T, now=NOW).kind == REPAGE


# -- recovery ---------------------------------------------------------------------------

def test_recovery_message_has_outage_duration_and_diagnostics():
    state = AlertState("gpu-host", alerted=True, down_since=NOW - (27 * 3600 + 300), last_alert=NOW - 3600)
    d = decide(GPU_HOST, up(), state, last_ok=LAST_OK_GPU_HOST, thresholds=T, now=NOW, tz=UTC)
    assert d.kind == RECOVERY
    first, second = d.message.split("\n")
    assert first == "🟢 Gpu-host is back up — outage lasted 1d 3h (down since 2026-11-04 01:07)."
    assert "gateway pid 424242" in second and "2 platform socket(s)" in second
    assert "gateway_state.json is stale" in second
    assert d.state == AlertState("gpu-host")  # ladder reset


def test_recovery_notes_reboot_during_outage():
    v = up()
    v.uptime_s = 600
    msg = render_recovery(GPU_HOST, v, down_since=NOW - 7200, now=NOW, tz=UTC)
    assert "The host rebooted during the outage." in msg


def test_up_without_prior_page_is_silent():
    state = AlertState("pi-host", alerted=False, down_since=NOW - 600, streak=2)
    d = decide(PI_HOST, up(), state, last_ok=NOW, thresholds=T, now=NOW)
    assert d.kind == NONE and d.message is None and d.state.streak == 0


# -- back-dating ------------------------------------------------------------------------

def test_backdate_never_earlier_than_last_ok():
    assert backdate_down_since(offline(5 * 86400), last_ok=NOW - 3600, now=NOW) == NOW - 3600


def test_backdate_uses_zero_socket_streak_for_deaf():
    assert backdate_down_since(deaf(14 * 60), last_ok=None, now=NOW) == NOW - 14 * 60


def test_backdate_keeps_existing_anchor():
    assert backdate_down_since(offline(60), last_ok=None, now=NOW, current=NOW - 9000) == NOW - 9000


# -- tick end to end: empty output when healthy -----------------------------------------

def _sentinel(responses: dict, view: TailnetView, hosts: list[dict], connect=lambda *a: None) -> Sentinel:
    store = Store.memory()
    return Sentinel(lambda: {"hosts": hosts}, store_factory=lambda: store, runner=FakeRunner(responses),
                    connect=connect, clock=lambda: NOW, tailnet_fetch=lambda: view)


def _tick_args(**kw) -> argparse.Namespace:
    return argparse.Namespace(fleet_command="tick", json=kw.get("json", False), quiet=kw.get("quiet", False))


def test_tick_prints_nothing_when_everything_is_healthy():
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    s = _sentinel({"pi-host": (0, fixture_text("remote_pi_host_stale_state.txt"), ""),
                   "orion": (0, fixture_text("remote_healthy.txt"), "")}, view,
                  [{"name": "pi-host", "ssh_alias": "pi-host", "tailscale_ip": "100.101.1.10"},
                   {"name": "orion", "ssh_alias": "orion", "tailscale_ip": "100.101.1.12"}])
    for as_json in (False, True):
        out, err = io.StringIO(), io.StringIO()
        assert cli.run(s, _tick_args(json=as_json), out=out, err=err) == 0
        assert out.getvalue() == ""
        assert err.getvalue() == ""


def test_tick_with_no_hosts_prints_nothing():
    s = _sentinel({}, TailnetView(False, error="x"), [])
    out = io.StringIO()
    assert cli.run(s, _tick_args(), out=out, err=io.StringIO()) == 0
    assert out.getvalue() == ""


def test_tick_pages_offline_host_and_exits_zero():
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    store = Store.memory()
    # Seed: gpu-host was last verified up 2026-11-01 16:48 and has been failing since.
    store.record_observation("gpu-host", UP, LAST_OK_GPU_HOST)
    s = Sentinel(lambda: {"hosts": [{"name": "gpu-host", "ssh_alias": "gpu-host", "tailscale_ip": "100.101.1.11",
                                     "lan_ip": "192.168.1.51"}]},
                 store_factory=lambda: store, runner=FakeRunner(), connect=lambda *a: "timeout",
                 clock=lambda: NOW, tailnet_fetch=lambda: view)
    out = io.StringIO()
    assert cli.run(s, _tick_args(), out=out, err=io.StringIO()) == 0
    text = out.getvalue()
    assert text.startswith("🔴 Gpu-host is offline — down 1d 3h.")
    assert "(power or cable)" in text

    # Second tick five minutes later: already paged, so silent.
    s.clock = lambda: NOW + 300
    out2 = io.StringIO()
    assert cli.run(s, _tick_args(), out=out2, err=io.StringIO()) == 0
    assert out2.getvalue() == ""


def test_tick_never_fails_on_internal_error():
    def broken_store():
        raise RuntimeError("disk full")
    s = Sentinel(lambda: {"hosts": [{"name": "a", "ssh_alias": "a"}]}, store_factory=broken_store,
                 runner=FakeRunner(), connect=lambda *a: None, clock=lambda: NOW,
                 tailnet_fetch=lambda: TailnetView(False, error="x"))
    out, err = io.StringIO(), io.StringIO()
    assert cli.run(s, _tick_args(), out=out, err=err) == 0
    assert out.getvalue() == "" and "disk full" in err.getvalue()
    assert cli.run(s, _tick_args(quiet=True), out=io.StringIO(), err=(e2 := io.StringIO())) == 0
    assert e2.getvalue() == ""


def test_tick_reports_config_problems_on_stderr_only():
    s = _sentinel({}, TailnetView(False, error="x"), [{"name": "bad host!", "ssh_alias": "x"}])
    out, err = io.StringIO(), io.StringIO()
    cli.run(s, _tick_args(), out=out, err=err)
    assert out.getvalue() == ""
    assert "hosts[0].name" in err.getvalue()


def test_settings_problems_survive_into_status():
    settings = parse_settings({"hosts": "nope"})
    s = _sentinel({}, TailnetView(False, error="x"), [])
    s._settings_provider = lambda: settings
    data = s.status()
    assert data["hosts"] == [] and "hosts should be a list" in data["problems"][0]
