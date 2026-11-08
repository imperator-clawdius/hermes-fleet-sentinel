"""scripts/tick.py: the standalone cron entry point (no CLI registration needed)."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from conftest import FIXTURE_NOW, ROOT, FakeRunner, fixture_text
from sentinel import cli
from sentinel.probe import TailnetView, parse_tailscale_status
from sentinel.runtime import Sentinel
from sentinel.store import Store
from sentinel.verdict import UP

SCRIPTS = ROOT / "scripts"
NOW = FIXTURE_NOW
LAST_OK_GPU_HOST = NOW - (27 * 3600 + 24 * 60)

_spec = importlib.util.spec_from_file_location("fleet_sentinel_tick", SCRIPTS / "tick.py")
tick = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tick)

HOSTS = [{"name": "gpu-host", "ssh_alias": "gpu-host"}]


def _no_hermes():
    raise ImportError("hermes_cli.config is not importable")


# -- settings resolution ---------------------------------------------------------------

def test_reads_the_same_keys_as_ctx_get_config():
    config = {"plugins": {"entries": {"fleet-sentinel": {"settings": {
        "hosts": HOSTS, "thresholds": {"page_after_minutes": 30}, "auto_heal": True, "other": 1}}}}}
    assert tick.settings_from_hermes_config(config) == {
        "hosts": HOSTS, "thresholds": {"page_after_minutes": 30}, "auto_heal": True}


def test_legacy_config_subtree_is_a_per_key_fallback():
    config = {"plugins": {"entries": {"fleet-sentinel": {
        "settings": {"hosts": HOSTS}, "config": {"hosts": [], "auto_heal": True}}}}}
    assert tick.settings_from_hermes_config(config) == {"hosts": HOSTS, "auto_heal": True}


def test_missing_plugin_entry_means_no_settings():
    assert tick.settings_from_hermes_config({"plugins": {"entries": {}}}) == {}
    assert tick.settings_from_hermes_config({}) == {}


def test_unreadable_hermes_config_raises():
    with pytest.raises(RuntimeError):
        tick.settings_from_hermes_config(object())


def _reader_returning(config):
    """A reader_factory standing in for an importable Hermes (no real hermes_cli import)."""
    calls = []

    def factory():
        calls.append("factory")
        return lambda: config
    factory.calls = calls
    return factory


TWO_HOSTS = [{"name": "alpha", "ssh_alias": "alpha"}, {"name": "beta", "ssh_alias": "beta"}]


def test_env_override_beats_an_available_hermes_reader_with_empty_config(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Regression: an importable Hermes whose config has no fleet-sentinel block used to win,
    # returning {} and silently ignoring $FLEET_SENTINEL_SETTINGS (tick probed nothing).
    env_file = tmp_path / "fleet_settings.json"
    env_file.write_text(json.dumps({"hosts": TWO_HOSTS}))
    monkeypatch.setenv(tick.SETTINGS_ENV, str(env_file))
    reader = _reader_returning({})
    assert tick.load_settings(reader) == {"hosts": TWO_HOSTS}
    assert reader.calls == []  # the override is used without consulting Hermes at all


def test_env_override_beats_a_configured_hermes_reader(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch):
    env_file = tmp_path / "s.json"
    env_file.write_text(json.dumps({"hosts": TWO_HOSTS, "auto_heal": False, "ignored": 1}))
    monkeypatch.setenv(tick.SETTINGS_ENV, str(env_file))
    config = {"plugins": {"entries": {"fleet-sentinel": {"settings": {"hosts": HOSTS}}}}}
    assert tick.load_settings(_reader_returning(config)) == {"hosts": TWO_HOSTS, "auto_heal": False}


def test_env_override_used_without_hermes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env_file = tmp_path / "s.json"
    env_file.write_text(json.dumps({"hosts": HOSTS, "auto_heal": False, "ignored": 1}))
    monkeypatch.setenv(tick.SETTINGS_ENV, str(env_file))
    assert tick.load_settings(_no_hermes) == {"hosts": HOSTS, "auto_heal": False}


@pytest.mark.parametrize("value", [None, "", "   "])
def test_no_env_override_falls_back_to_the_hermes_reader(value, monkeypatch: pytest.MonkeyPatch):
    if value is None:
        monkeypatch.delenv(tick.SETTINGS_ENV, raising=False)
    else:
        monkeypatch.setenv(tick.SETTINGS_ENV, value)
    config = {"plugins": {"entries": {"fleet-sentinel": {"settings": {
        "hosts": HOSTS, "thresholds": {"page_after_minutes": 30}}}}}}
    assert tick.load_settings(_reader_returning(config)) == {
        "hosts": HOSTS, "thresholds": {"page_after_minutes": 30}}


def test_no_env_and_no_plugin_block_is_a_clear_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(tick.SETTINGS_ENV, raising=False)
    with pytest.raises(RuntimeError, match=r"FLEET_SENTINEL_SETTINGS.*plugins\.entries\.fleet-sentinel"):
        tick.load_settings(_reader_returning({}))


def test_malformed_env_json_is_a_clear_error_not_a_fallback(tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setenv(tick.SETTINGS_ENV, str(bad))
    config = {"plugins": {"entries": {"fleet-sentinel": {"settings": {"hosts": HOSTS}}}}}
    with pytest.raises(RuntimeError, match=r"FLEET_SENTINEL_SETTINGS.*not valid JSON"):
        tick.load_settings(_reader_returning(config))


def test_missing_or_non_object_env_file_is_a_clear_error(tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(tick.SETTINGS_ENV, str(tmp_path / "nope.json"))
    with pytest.raises(RuntimeError, match="cannot read settings file"):
        tick.load_settings(_no_hermes)
    listy = tmp_path / "list.json"
    listy.write_text("[1, 2]")
    monkeypatch.setenv(tick.SETTINGS_ENV, str(listy))
    with pytest.raises(RuntimeError, match="must hold a JSON object"):
        tick.load_settings(_no_hermes)


def test_main_with_malformed_env_json_reports_on_stderr_and_exits_zero(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_db: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setenv(tick.SETTINGS_ENV, str(bad))
    s = Sentinel(lambda: tick.load_settings(_reader_returning({})), runner=FakeRunner(),
                 connect=lambda *a: None, clock=lambda: NOW,
                 tailnet_fetch=lambda: TailnetView(False, error="x"))
    out, err = io.StringIO(), io.StringIO()
    assert tick.main([], sentinel_factory=lambda: s, out=out, err=err) == 0
    assert out.getvalue() == ""
    assert "FLEET_SENTINEL_SETTINGS" in err.getvalue() and "not valid JSON" in err.getvalue()


def test_help_exits_zero(capsys: pytest.CaptureFixture):
    assert tick.main(["--help"]) == 0
    assert "usage: tick.py" in capsys.readouterr().out


def test_no_reader_and_no_env_is_a_reported_problem_not_a_crash(monkeypatch: pytest.MonkeyPatch,
                                                                isolated_db: Path):
    monkeypatch.delenv(tick.SETTINGS_ENV, raising=False)
    s = Sentinel(lambda: tick.load_settings(_no_hermes))
    settings = s.settings()
    assert settings.hosts == () or list(settings.hosts) == []
    assert any(tick.SETTINGS_ENV in p for p in settings.problems)
    s.close()


# -- main(): prints only alerts, exits 0 always ----------------------------------------

def _offline_sentinel() -> Sentinel:
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    store = Store.memory()
    store.record_observation("gpu-host", UP, LAST_OK_GPU_HOST)
    return Sentinel(lambda: {"hosts": [{"name": "gpu-host", "ssh_alias": "gpu-host",
                                        "tailscale_ip": "100.101.1.11", "lan_ip": "192.168.1.51"}]},
                    store_factory=lambda: store, runner=FakeRunner(), connect=lambda *a: "timeout",
                    clock=lambda: NOW, tailnet_fetch=lambda: view)


def test_main_prints_the_page_and_exits_zero():
    out, err = io.StringIO(), io.StringIO()
    assert tick.main([], sentinel_factory=_offline_sentinel, out=out, err=err) == 0
    assert out.getvalue().startswith("🔴 Gpu-host is offline — down 1d 3h.")


def test_main_json_emits_a_list_of_alerts():
    out = io.StringIO()
    assert tick.main(["--json"], sentinel_factory=_offline_sentinel, out=out, err=io.StringIO()) == 0
    alerts = json.loads(out.getvalue())
    assert [a["host"] for a in alerts] == ["gpu-host"]


def test_main_healthy_or_empty_fleet_prints_nothing():
    s = Sentinel(lambda: {"hosts": []}, store_factory=Store.memory, runner=FakeRunner(),
                 connect=lambda *a: None, clock=lambda: NOW,
                 tailnet_fetch=lambda: TailnetView(False, error="x"))
    out = io.StringIO()
    assert tick.main(["--quiet"], sentinel_factory=lambda: s, out=out, err=io.StringIO()) == 0
    assert out.getvalue() == ""


def test_main_survives_construction_failure_with_empty_stdout():
    def boom():
        raise RuntimeError("no store")
    out, err = io.StringIO(), io.StringIO()
    assert tick.main([], sentinel_factory=boom, out=out, err=err) == 0
    assert out.getvalue() == ""
    assert "no store" in err.getvalue()
    err_quiet = io.StringIO()
    assert tick.main(["--quiet"], sentinel_factory=boom, out=io.StringIO(), err=err_quiet) == 0
    assert err_quiet.getvalue() == ""


def test_main_ignores_bad_arguments():
    assert tick.main(["--bogus"], sentinel_factory=_offline_sentinel, out=io.StringIO(),
                     err=io.StringIO()) == 0
    assert tick.main(["--help"], out=io.StringIO(), err=io.StringIO()) == 0


# -- the shell wrapper and the documented recipe ---------------------------------------

def test_wrapper_is_three_line_executable_sh():
    wrapper = SCRIPTS / "fleet-sentinel-tick.sh"
    lines = wrapper.read_text().splitlines()
    assert len(lines) == 3 and lines[0] == "#!/bin/sh"
    assert "scripts/tick.py" in lines[2]
    assert os.access(wrapper, os.X_OK) and os.access(SCRIPTS / "tick.py", os.X_OK)


def test_cron_recipe_uses_the_script_not_the_cli_subcommand():
    recipe = cli.cron_recipe(Path("/opt/fleet-sentinel"))
    assert "/opt/fleet-sentinel/scripts/fleet-sentinel-tick.sh" in recipe
    assert "hermes fleet-sentinel tick" not in recipe
    assert "--script fleet-sentinel-tick.sh --no-agent" in recipe
    assert "empty stdout = no message" in recipe
