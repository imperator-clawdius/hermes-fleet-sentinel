"""Probe ladder parsers against captured payloads in tests/fixtures (no network, no ssh)."""

from __future__ import annotations

import base64
import json
import subprocess

import pytest

from conftest import FIXTURE_NOW, FakeRunner, fixture_text
from sentinel import probe
from sentinel.config import HostConfig
from sentinel.probe import (CommandResult, TailnetView, classify_ssh_failure, decode_state_json,
                            parse_iso8601, parse_remote_payload, parse_tailscale_status, probe_host,
                            remote_probe, ssh_argv, tailnet_obs_for, tcp_probe)

PI_HOST = HostConfig(name="pi-host", ssh_alias="pi-host", tailscale_ip="100.101.1.10", lan_ip="192.168.1.50")
GPU_HOST = HostConfig(name="gpu-host", ssh_alias="gpu-host", tailscale_ip="100.101.1.11", lan_ip="192.168.1.51")


# -- (a) healthy host -------------------------------------------------------------------

def test_healthy_payload_parses_every_field():
    snap = parse_remote_payload(fixture_text("remote_healthy.txt"))
    assert snap.ok and snap.error == ""
    assert snap.hostname == "orion"
    assert snap.now == FIXTURE_NOW
    assert snap.unit == "hermes-gateway" and snap.unit_scope == "system"
    assert snap.unit_active == "active" and snap.unit_restart == "always"
    assert snap.mainpid == 412233 and snap.mainpid_alive is True and snap.mainpid_age_s == 86400
    assert snap.sockets == 1 and snap.socket_tool == "ss"
    assert snap.state is not None and snap.state["platforms"]["telegram"]["state"] == "connected"
    assert snap.state_pid == 412233 and snap.state_pid_alive is True
    assert snap.lock_pid == 412233 and snap.lock_pid_alive is True
    assert snap.uptime_s == 1209600


# -- (b) Pi-host stale state file ------------------------------------------------------

def test_pi_host_stale_state_payload():
    snap = parse_remote_payload(fixture_text("remote_pi_host_stale_state.txt"))
    assert snap.ok
    assert snap.hostname == "pi-host"
    assert snap.mainpid == 424242 and snap.mainpid_alive is True
    assert snap.sockets == 2
    # The state file is from 2026-10-11 and records the previous gateway's pid.
    assert snap.state_pid == 424243 and snap.state_pid_alive is False
    assert snap.state["platforms"]["telegram"]["state"] == "disconnected"
    assert parse_iso8601(snap.state["updated_at"]) == parse_iso8601("2026-10-11T14:03:27Z")
    assert snap.lock_pid == 424243 and snap.lock_pid_alive is False


def test_pi_host_state_file_fixture_matches_payload():
    snap = parse_remote_payload(fixture_text("remote_pi_host_stale_state.txt"))
    on_disk = json.loads(fixture_text("pi_host_gateway_state.json"))
    assert snap.state == on_disk


# -- (c) tailscale stopped / missing / shape drift --------------------------------------

def test_tailscale_stopped_plain_text():
    view = parse_tailscale_status(fixture_text("tailscale_stopped.txt"), 1, "")
    assert view.available is False
    assert "not JSON" in view.error and "Tailscale is stopped." in view.error


def test_tailscale_stopped_json_backend_state():
    view = parse_tailscale_status(fixture_text("tailscale_stopped.json"))
    assert view.available is False
    assert view.backend_state == "Stopped"
    assert view.error == "tailscale backend is Stopped"


def test_tailscale_stopped_never_yields_offline_peer():
    view = parse_tailscale_status(fixture_text("tailscale_stopped.json"))
    obs = tailnet_obs_for(GPU_HOST, view)
    assert obs.available is False and obs.online is None


def test_tailscale_running_peers():
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    assert view.available and view.backend_state == "Running"
    by_name = {p.hostname: p for p in view.peers}
    assert by_name["pi-host"].online is True
    assert by_name["pi-host"].last_seen is None  # Go zero time
    assert by_name["gpu-host"].online is False
    assert by_name["gpu-host"].last_seen == parse_iso8601("2026-11-04T01:09:41Z")


def test_tailnet_match_by_ip_then_name():
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    by_ip = tailnet_obs_for(GPU_HOST, view)
    assert by_ip.online is False and by_ip.matched == "ip 100.101.1.11"
    by_name = tailnet_obs_for(HostConfig(name="pi-host", ssh_alias="sk"), view)
    assert by_name.online is True and by_name.matched.startswith("name ")
    missing = tailnet_obs_for(HostConfig(name="hydra", ssh_alias="hydra"), view)
    assert missing.available is True and missing.online is None and "not found" in missing.error


@pytest.mark.parametrize("stdout, needle", [
    ("", "returned nothing"),
    ("[1, 2]", "not an object"),
    ('{"BackendState": "Running", "Peer": "oops"}', "unrecognised Peer shape"),
])
def test_tailscale_shape_drift_is_unavailable_not_offline(stdout, needle):
    view = parse_tailscale_status(stdout)
    assert view.available is False and needle in view.error


def test_tailscale_peer_list_shape_and_missing_online():
    data = {"BackendState": "Running", "Peer": [{"HostName": "pi-host", "TailscaleIPs": ["100.101.1.10"]}]}
    view = parse_tailscale_status(json.dumps(data))
    assert view.available and view.peers[0].online is None


def test_fetch_tailnet_cli_missing(monkeypatch):
    monkeypatch.setattr(probe, "tailscale_binary", lambda: None)
    view = probe.fetch_tailnet(FakeRunner())
    assert view.available is False and view.error == "tailscale CLI not installed"


def test_fetch_tailnet_timeout(monkeypatch):
    monkeypatch.setattr(probe, "tailscale_binary", lambda: "/usr/bin/tailscale")
    runner = FakeRunner({"/usr/bin/tailscale": CommandResult(["tailscale"], None, "", "", timed_out=True)})
    view = probe.fetch_tailnet(runner, timeout=8)
    assert view.available is False and "timed out" in view.error
    assert runner.calls[0][0] == ["/usr/bin/tailscale", "status", "--json"]
    assert runner.calls[0][1] == 8


# -- (d) garbage / partial output -------------------------------------------------------

def test_garbage_output_is_not_ok():
    snap = parse_remote_payload(fixture_text("remote_garbage.txt"))
    assert snap.ok is False
    assert "not parseable" in snap.error
    assert "Welcome to Ubuntu" in snap.error


def test_truncated_output_missing_required_keys():
    snap = parse_remote_payload(fixture_text("remote_truncated.txt"))
    assert snap.ok is False and "missing SOCKETS" in snap.error


def test_output_without_probe_end_is_truncated():
    text = fixture_text("remote_pi_host_stale_state.txt").replace("PROBE_END=1\n", "")
    snap = parse_remote_payload(text)
    assert snap.ok is False and snap.error == "remote probe output was truncated (no PROBE_END)"


def test_corrupt_state_json_is_reported_not_fatal():
    snap = parse_remote_payload(fixture_text("remote_corrupt_state.txt"))
    assert snap.ok is True and snap.state is None
    assert snap.state_error == "state file is not valid JSON (truncated or corrupt)"
    assert snap.sockets == 1


def test_empty_values_become_none():
    text = fixture_text("remote_healthy.txt").replace("SOCKETS=1", "SOCKETS=").replace(
        "MAINPID_AGE_S=86400", "MAINPID_AGE_S=abc")
    snap = parse_remote_payload(text)
    assert snap.ok and snap.sockets is None and snap.mainpid_age_s is None


def test_crlf_and_banner_lines_tolerated():
    text = "Last login: Tue Nov  4 21:00:01 2026\r\n" + fixture_text("remote_healthy.txt").replace("\n", "\r\n")
    snap = parse_remote_payload(text)
    assert snap.ok and snap.hostname == "orion" and snap.sockets == 1


def test_parse_never_raises_on_binary_noise():
    for blob in ("\x00\xff=\n" * 50, "=" * 1000, "A=B\n" * 10000, "HOSTNAME\nSOCKETS"):
        assert parse_remote_payload(blob).ok is False


@pytest.mark.parametrize("value, ok, err", [
    ("", False, ""),
    ('{"pid": 7}', True, ""),
    ("b64:" + base64.b64encode(b'{"pid": 7}').decode(), True, ""),
    (base64.b64encode(b'{"pid": 7}').decode(), True, ""),
    ("b64:!!!not-base64!!!", False, "neither JSON nor base64"),
    ("b64:" + base64.b64encode(b"[1,2]").decode(), False, "not an object"),
])
def test_decode_state_json(value, ok, err):
    data, error = decode_state_json(value)
    assert (data is not None) is ok
    assert err in error


@pytest.mark.parametrize("value, expected", [
    ("0001-01-01T00:00:00Z", None),
    ("2026-11-04T01:09:41Z", 1793754581),
    ("2026-11-04T01:09:41.123456+00:00", 1793754581),
    ("2026-11-04T03:09:41+0200", 1793754581),
    ("yesterday", None),
    (None, None),
])
def test_parse_iso8601(value, expected):
    assert parse_iso8601(value) == expected


# -- ssh command construction and the bounded runner ------------------------------------

def test_ssh_argv_has_mandatory_options_and_no_interpolation():
    argv = ssh_argv(PI_HOST, 12, probe.probe_args(PI_HOST))
    joined = " ".join(argv)
    for opt in ("BatchMode=yes", "IdentityAgent=none", "IdentitiesOnly=yes", "ConnectTimeout=12",
                "StrictHostKeyChecking=yes"):
        assert opt in joined
    assert argv[argv.index("--") + 1] == "pi-host"
    assert argv[-1] == "sh -s -- hermes-gateway default 149.154.166.110 -"
    assert probe.REMOTE_PROBE_SCRIPT not in joined  # the script travels on stdin


def test_ssh_argv_quotes_arguments():
    argv = ssh_argv(PI_HOST, 5, ["a b", "$(id)"])
    assert argv[-1] == "sh -s -- 'a b' '$(id)'"


def test_run_bounded_always_passes_timeout(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = probe.run_bounded(["echo", "hi"], 3.5)
    assert res.ok and res.stdout == "out"
    assert seen["timeout"] == 3.5
    assert seen["stdin"] is subprocess.DEVNULL


def test_run_bounded_timeout_and_missing(monkeypatch):
    def timeout_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"partial", stderr=None)

    monkeypatch.setattr(subprocess, "run", timeout_run)
    res = probe.run_bounded(["ssh", "x"], 1)
    assert res.timed_out and not res.ok and res.stdout == "partial"

    def missing_run(argv, **kwargs):
        raise FileNotFoundError(2, "No such file", argv[0])

    monkeypatch.setattr(subprocess, "run", missing_run)
    res = probe.run_bounded(["nope"], 1)
    assert res.missing and not res.ok


@pytest.mark.parametrize("stderr, expected", [
    ("pi-host: Permission denied (publickey).", "ssh permission denied (key not accepted)"),
    ("Host key verification failed.", "ssh host key verification failed"),
    ("ssh: Could not resolve hostname pi-host: nodename nor servname", "ssh alias does not resolve"),
    ("ssh: connect to host 100.101.1.11 port 22: Operation timed out", "ssh connect timed out"),
    ("ssh: connect to host x port 22: Connection refused", "ssh connection refused"),
    ("ssh: connect to host x port 22: No route to host", "no route to host"),
    ("kex_exchange_identification: read: Connection reset by peer", "ssh failed: kex_exchange_identification"),
])
def test_classify_ssh_failure(stderr, expected):
    assert classify_ssh_failure(CommandResult(["ssh"], 255, "", stderr)).startswith(expected)


def test_classify_ssh_timeout_and_missing():
    assert classify_ssh_failure(CommandResult(["ssh"], None, "", "", timed_out=True)) == "ssh timed out"
    assert classify_ssh_failure(CommandResult(["ssh"], None, "", "", missing=True)) == "ssh client not installed"


def test_remote_probe_uses_external_timeout_and_stdin_script():
    runner = FakeRunner({"pi-host": (0, fixture_text("remote_pi_host_stale_state.txt"), "")})
    snap, res = remote_probe(PI_HOST, 12, runner)
    assert snap.ok and snap.sockets == 2
    argv, timeout, stdin = runner.calls[0]
    assert timeout == 20.0  # ConnectTimeout + round-trip allowance, enforced by subprocess
    assert stdin == probe.REMOTE_PROBE_SCRIPT


def test_remote_probe_complete_payload_with_nonzero_exit_is_used():
    runner = FakeRunner({"pi-host": (1, fixture_text("remote_healthy.txt"), "")})
    snap, _ = remote_probe(PI_HOST, 12, runner)
    assert snap.ok


def test_remote_probe_permission_denied():
    runner = FakeRunner({"pi-host": (255, "", "pi-host: Permission denied (publickey).")})
    snap, _ = remote_probe(PI_HOST, 12, runner)
    assert snap.ok is False and "permission denied" in snap.error


def test_tcp_probe_falls_back_to_lan():
    tried = []

    def connect(ip, port, timeout):
        tried.append(ip)
        return "timeout" if ip.startswith("100.") else None

    obs = tcp_probe(PI_HOST, 5, connect)
    assert obs.attempted and obs.reachable is True and obs.target == "192.168.1.50:22"
    assert tried == ["100.101.1.10", "192.168.1.50"]


def test_tcp_probe_skipped_without_ips():
    obs = tcp_probe(HostConfig(name="x", ssh_alias="x"), 5, lambda *a: None)
    assert obs.attempted is False and obs.reachable is None


def test_probe_host_skips_ssh_after_two_independent_failures():
    view = parse_tailscale_status(fixture_text("tailscale_running.json"))
    runner = FakeRunner()
    ev = probe_host(GPU_HOST, view, 12, runner=runner, connect=lambda *a: "timeout", clock=lambda: FIXTURE_NOW)
    assert ev.remote is None and ev.remote_skipped == "tailnet offline and TCP connect failed"
    assert runner.calls == []


def test_probe_host_tailscale_stopped_still_runs_ssh():
    view = TailnetView(False, error="tailscale backend is Stopped")
    runner = FakeRunner({"pi-host": (0, fixture_text("remote_pi_host_stale_state.txt"), "")})
    ev = probe_host(PI_HOST, view, 12, runner=runner, connect=lambda *a: None, clock=lambda: FIXTURE_NOW)
    assert ev.remote is not None and ev.remote.ok
    assert ev.tailnet.available is False
    assert ev.to_dict()["remote"]["sockets"] == 2
