"""Settings: defaults, partial settings, bad types. parse_settings must never raise."""

from __future__ import annotations

import json
import re

import pytest

from conftest import ROOT
from sentinel.config import (DEFAULT_PLATFORM_IP, DEFAULT_THRESHOLDS, HOST_SCHEMA, HostConfig, Settings,
                             Thresholds, default_settings_block, load_settings_file, parse_settings)


# -- defaults ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [None, {}, {"hosts": None, "thresholds": None}])
def test_empty_settings_give_defaults(raw):
    s = parse_settings(raw)
    assert s.hosts == ()
    assert s.thresholds == Thresholds()
    assert s.auto_heal is False
    assert s.problems == ()


def test_default_threshold_values_match_spec():
    t = Thresholds()
    assert (t.page_after_minutes, t.repage_hours, t.deaf_grace_minutes, t.ssh_timeout_seconds) == (60, 24, 10, 12)
    assert (t.page_after_s, t.repage_s, t.deaf_grace_s) == (3600, 86400, 600)


def test_host_defaults():
    s = parse_settings({"hosts": [{"name": "pi-host", "ssh_alias": "pi-host"}]})
    h = s.hosts[0]
    assert h.profile == "default" and h.platform == "telegram"
    assert h.platform_ip == DEFAULT_PLATFORM_IP == "149.154.166.110"
    assert h.ssh_port == 22
    assert h.systemd_unit == "hermes-gateway"
    assert h.display_name == "Pi-host"
    assert s.problems == ()


def test_profile_unit_naming_and_explicit_unit():
    assert HostConfig(name="a", ssh_alias="a", profile="ops").systemd_unit == "hermes-gateway-ops"
    assert HostConfig(name="a", ssh_alias="a", unit="my-gw.service").systemd_unit == "my-gw.service"
    assert HostConfig(name="a", ssh_alias="a", label="Hydra 2").display_name == "Hydra 2"


# -- partial settings -------------------------------------------------------------------

def test_partial_thresholds_merge_over_defaults():
    s = parse_settings({"thresholds": {"deaf_grace_minutes": 5}})
    assert s.thresholds.deaf_grace_minutes == 5
    assert s.thresholds.page_after_minutes == 60 and s.thresholds.repage_hours == 24
    assert s.problems == ()


def test_full_host_entry():
    raw = {"name": "gpu-host", "ssh_alias": "gpu-host-ts", "label": "Gpu-host", "tailscale_ip": "100.101.1.11",
           "lan_ip": "192.168.1.51", "profile": "ops", "platform": "telegram", "platform_ip": "149.154.167.220",
           "ssh_port": 2222, "unit": "hermes-gateway-ops", "hermes_home": "~/.hermes/profiles/ops",
           "wol_mac": "aa:bb:cc:dd:ee:ff", "wol_broadcast": "192.168.1.255"}
    s = parse_settings({"hosts": [raw], "auto_heal": True})
    assert s.problems == ()
    h = s.hosts[0]
    assert h.ssh_port == 2222 and h.wol_mac == "aa:bb:cc:dd:ee:ff" and h.hermes_home == "~/.hermes/profiles/ops"
    assert s.auto_heal is True
    assert h.to_dict()["unit"] == "hermes-gateway-ops"


def test_host_lookup_by_name_or_alias_case_insensitive():
    s = parse_settings({"hosts": [{"name": "gpu-host", "ssh_alias": "gpu-host-ts"}]})
    assert s.host("gpu-host") is s.hosts[0]
    assert s.host(" gpu-host-ts ") is s.hosts[0]
    assert s.host("hydra") is None


# -- bad types: degrade to defaults and report ------------------------------------------

@pytest.mark.parametrize("raw, needle", [
    ("hosts: []", "settings should be an object"),
    ([1, 2], "settings should be an object"),
    ({"hosts": {"name": "x"}}, "hosts should be a list"),
    ({"thresholds": [1]}, "thresholds should be an object"),
    ({"auto_heal": "yes"}, "auto_heal should be a boolean"),
])
def test_bad_top_level_types(raw, needle):
    s = parse_settings(raw)
    assert s.hosts == () and s.thresholds == Thresholds() and s.auto_heal is False
    assert any(needle in p for p in s.problems)


@pytest.mark.parametrize("key, value, needle", [
    ("page_after_minutes", "60", "should be an integer (got str); using default 60"),
    ("repage_hours", True, "should be an integer (got bool); using default 24"),
    ("deaf_grace_minutes", 2.5, "should be an integer (got float)"),
    ("ssh_timeout_seconds", 0, "is outside 2..120; using default 12"),
    ("ssh_timeout_seconds", 10_000, "is outside 2..120"),
])
def test_bad_threshold_values_fall_back(key, value, needle):
    s = parse_settings({"thresholds": {key: value}})
    assert getattr(s.thresholds, key) == DEFAULT_THRESHOLDS[key]
    assert any(needle in p for p in s.problems), s.problems


def test_unknown_threshold_is_ignored_and_reported():
    s = parse_settings({"thresholds": {"page_after": 5}})
    assert s.thresholds == Thresholds()
    assert s.problems == ("thresholds.page_after is not a known threshold; ignored",)


@pytest.mark.parametrize("host, needle", [
    ("pi-host", "hosts[0] should be an object (got str); skipped"),
    ({"ssh_alias": "x"}, "hosts[0].name is required"),
    ({"name": "x"}, "hosts[x].ssh_alias is required"),
    ({"name": "x; rm -rf /", "ssh_alias": "x"}, "hosts[0].name is required"),
    ({"name": "x", "ssh_alias": "-oProxyCommand=evil"}, "ssh_alias is required and must be a plain ssh alias"),
    ({"name": "x", "ssh_alias": 42}, "ssh_alias is required"),
])
def test_invalid_hosts_are_skipped(host, needle):
    s = parse_settings({"hosts": [host, {"name": "ok", "ssh_alias": "ok"}]})
    assert [h.name for h in s.hosts] == ["ok"]
    assert any(needle in p for p in s.problems), s.problems


@pytest.mark.parametrize("field, value, needle", [
    ("tailscale_ip", "not-an-ip", "not an IP address"),
    ("lan_ip", 192, "should be a string (got int)"),
    ("platform_ip", "149.154.166", "not an IP address"),
    ("profile", "../etc", "profile names are"),
    ("unit", "gw; reboot", "not a systemd unit name"),
    ("hermes_home", "/home/x/../../root", "without spaces or '..'"),
    ("hermes_home", "relative/path", "must be an absolute"),
    ("wol_mac", "zz:zz:zz:zz:zz:zz", "expected aa:bb:cc:dd:ee:ff"),
])
def test_invalid_optional_host_fields_are_ignored(field, value, needle):
    s = parse_settings({"hosts": [{"name": "x", "ssh_alias": "x", field: value}]})
    h = s.hosts[0]
    assert getattr(h, field) == getattr(HostConfig(name="x", ssh_alias="x"), field)
    assert any(needle in p for p in s.problems), s.problems


@pytest.mark.parametrize("port", ["22", 0, 70000, True, 22.0])
def test_bad_ssh_port_uses_22(port):
    s = parse_settings({"hosts": [{"name": "x", "ssh_alias": "x", "ssh_port": port}]})
    assert s.hosts[0].ssh_port == 22
    assert any("ssh_port should be an integer 1..65535" in p for p in s.problems)


def test_unknown_host_field_and_duplicates_reported():
    s = parse_settings({"hosts": [{"name": "x", "ssh_alias": "x", "colour": "red"},
                                  {"name": "X", "ssh_alias": "y"}]})
    assert len(s.hosts) == 1
    assert "hosts[x].colour is not a known host field; ignored" in s.problems
    assert "hosts[X] is a duplicate name; later entry skipped" in s.problems


def test_parse_settings_never_raises_on_hostile_input():
    for raw in (object(), 3.14, {"hosts": [None, [], 1, {"name": None}]}, {"thresholds": {"x": object()}},
                {"hosts": [{"name": "a" * 500, "ssh_alias": "a"}]}):
        assert isinstance(parse_settings(raw), Settings)


def test_to_dict_round_trips_through_json():
    s = parse_settings({"hosts": [{"name": "x", "ssh_alias": "x"}], "thresholds": {"repage_hours": 12}})
    data = json.loads(json.dumps(s.to_dict()))
    assert data["thresholds"]["repage_hours"] == 12 and data["hosts"][0]["unit"] == "hermes-gateway"
    assert parse_settings({"hosts": data["hosts"], "thresholds": data["thresholds"]}).problems == ()


# -- settings files ---------------------------------------------------------------------

def test_load_settings_file_full_tree(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"plugins": {"entries": {"fleet-sentinel": {"settings": {
        "hosts": [{"name": "x", "ssh_alias": "x"}]}}}}}))
    raw, err = load_settings_file(p)
    assert err is None and raw == {"hosts": [{"name": "x", "ssh_alias": "x"}]}


def test_load_settings_file_errors(tmp_path):
    raw, err = load_settings_file(tmp_path / "missing.json")
    assert raw is None and "cannot read settings file" in err
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    raw, err = load_settings_file(bad)
    assert raw is None and "is not valid JSON" in err


def test_default_settings_block_parses_cleanly():
    s = parse_settings(default_settings_block())
    assert s.problems == () and s.thresholds == Thresholds()


# -- manifest consistency (text-level; stdlib only) -------------------------------------

def test_manifest_declares_schema_keys_and_defaults():
    text = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    assert re.search(r"^name: fleet-sentinel$", text, re.M)
    assert re.search(r'^requires_hermes: ">=0\.21\.5"$', text, re.M)
    assert re.search(r"^provides_tools: \[fleet_status, fleet_probe, fleet_recover\]$", text, re.M)
    assert not re.search(r"^(capabilities|requires_env|python_dependencies):", text, re.M)
    for key in HOST_SCHEMA["properties"]:
        assert re.search(rf"^\s+{key}: \{{type: ", text, re.M), key
    for key, value in DEFAULT_THRESHOLDS.items():
        assert re.search(rf"^\s+{key}: \{{type: integer, default: {value}\}}$", text, re.M), key
