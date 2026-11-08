"""Every corroboration rule in sentinel/verdict.py, against captured payloads."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from conftest import FIXTURE_NOW, fixture_text
from sentinel.config import HostConfig
from sentinel.probe import HostEvidence, RemoteSnapshot, TailnetObs, TcpObs, parse_remote_payload
from sentinel.verdict import (DEAF, DEGRADED, DOWN_PHYSICAL, STATE_HEARTBEAT_STALE_S, UNKNOWN, UP, History,
                              analyze_state_file, decide, fmt_minutes)

GRACE = 10 * 60
PI_HOST = HostConfig(name="pi-host", ssh_alias="pi-host", tailscale_ip="100.101.1.10")
GPU_HOST = HostConfig(name="gpu-host", ssh_alias="gpu-host", tailscale_ip="100.101.1.11", lan_ip="192.168.1.51")

TAIL_ONLINE = TailnetObs(True, online=True, matched="ip 100.101.1.10")
TAIL_OFFLINE = TailnetObs(True, online=False, last_seen=FIXTURE_NOW - 27 * 3600, matched="ip 100.101.1.11")
TAIL_MISSING = TailnetObs(False, error="tailscale CLI not installed")
TAIL_STOPPED = TailnetObs(False, error="tailscale backend is Stopped")
TCP_OK = TcpObs(True, True, "100.101.1.10:22", [{"target": "100.101.1.10:22", "ok": True, "error": ""}])
TCP_FAIL = TcpObs(True, False, "", [{"target": "100.101.1.11:22", "ok": False, "error": "timeout"},
                                    {"target": "192.168.1.51:22", "ok": False, "error": "timeout"}])


def snap(name: str) -> RemoteSnapshot:
    return parse_remote_payload(fixture_text(name))


def evidence(remote, host=PI_HOST, tailnet=TAIL_ONLINE, tcp=TCP_OK, skipped="") -> HostEvidence:
    return HostEvidence(host=host, probed_at=FIXTURE_NOW, tailnet=tailnet, tcp=tcp, remote=remote,
                        remote_skipped=skipped)


def with_state(remote: RemoteSnapshot, *, pid=None, tg_state=None, updated_at=None) -> RemoteSnapshot:
    state = copy.deepcopy(remote.state)
    if pid is not None:
        state["pid"] = pid
    if tg_state is not None:
        state["platforms"]["telegram"]["state"] = tg_state
    if updated_at is not None:
        state["updated_at"] = updated_at
    return replace(remote, state=state, state_pid=state["pid"])


# -- Rule 1: sockets outrank the state file ---------------------------------------------

def test_pi_host_stale_state_file_with_live_sockets_is_up():
    v = decide(evidence(snap("remote_pi_host_stale_state.txt")), History(), GRACE)
    assert v.verdict == UP
    assert v.state_file_stale is True
    assert v.state_file_trusted is False
    assert v.sockets == 2 and v.gateway_pid == 424242
    assert v.reason == "gateway pid 424242 holds 2 platform socket(s); state file is stale"
    joined = "\n".join(v.notes)
    assert "sockets outrank the state file" in joined
    assert "'disconnected' but 2 ESTABLISHED platform socket(s) exist" in joined


def test_state_says_disconnected_pid_matches_sockets_present_is_up_and_stale():
    remote = with_state(snap("remote_healthy.txt"), tg_state="disconnected")
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict == UP
    assert v.state_file_stale is True
    assert v.state_file["pid_matches"] is True


def test_healthy_host_is_up_with_trusted_state_file():
    v = decide(evidence(snap("remote_healthy.txt")), History(), GRACE)
    assert v.verdict == UP and v.reason_code == "ok"
    assert v.state_file_stale is False and v.state_file_trusted is True
    assert v.zero_for_s == 0 and v.zero_since is None


# -- Rule 2: a PID mismatch invalidates the state file ----------------------------------

def test_pid_mismatch_is_stated_and_invalidates_state_file():
    remote = snap("remote_pi_host_stale_state.txt")
    sf = analyze_state_file(remote, "telegram")
    assert sf.pid == 424243 and sf.pid_matches is False
    assert sf.stale is True and sf.trusted is False
    assert "state file pid 424243 != live MainPID 424242; state file ignored" in sf.reasons


def test_pid_mismatch_with_connected_claim_and_zero_sockets_is_not_up():
    remote = with_state(snap("remote_deaf.txt"), pid=424243, tg_state="connected")
    v = decide(evidence(remote), History(zero_since=FIXTURE_NOW - 20 * 60), GRACE)
    assert v.verdict == DEAF
    assert v.state_file_stale is True and v.state_file_trusted is False
    assert any("state file ignored" in n for n in v.notes)


def test_old_heartbeat_marks_state_file_stale_even_with_matching_pid():
    remote = with_state(snap("remote_healthy.txt"), updated_at="2026-10-11T14:03:27+00:00")
    sf = analyze_state_file(remote, "telegram")
    assert sf.pid_matches is True and sf.stale is True and sf.trusted is False
    assert sf.age_s > STATE_HEARTBEAT_STALE_S


def test_corrupt_state_file_is_stale_but_sockets_still_decide():
    v = decide(evidence(snap("remote_corrupt_state.txt")), History(), GRACE)
    assert v.verdict == UP
    assert v.state_file_stale is True
    assert any("not valid JSON" in n for n in v.notes)


# -- Rule 3: never up without a live socket ---------------------------------------------

def test_alive_process_with_zero_sockets_and_connected_claim_is_never_up():
    remote = snap("remote_deaf.txt")
    assert remote.state["platforms"]["telegram"]["state"] == "connected"
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict != UP
    assert v.state_file_stale is True  # it claims connected with 0 sockets


def test_socket_count_unavailable_is_degraded_not_up():
    remote = replace(snap("remote_healthy.txt"), sockets=None, socket_tool="none")
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict == DEGRADED and v.reason_code == "sockets_unavailable"
    assert any("a claim is not a socket" in n for n in v.notes)


def test_unit_failed_is_degraded_gateway_not_running():
    v = decide(evidence(snap("remote_unit_failed.txt")), History(), GRACE)
    assert v.verdict == DEGRADED and v.reason_code == "gateway_not_running"
    assert v.gateway_alive is False


def test_unit_not_found_is_degraded():
    remote = replace(snap("remote_healthy.txt"), unit_scope="none", unit_active="not-found", mainpid=0)
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict == DEGRADED and v.reason_code == "unit_not_found"
    assert "set `unit:`" in v.reason


def test_dead_mainpid_reported_active_is_not_alive():
    remote = replace(snap("remote_healthy.txt"), mainpid_alive=False)
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict == DEGRADED and v.gateway_alive is False


# -- Deaf: alive + 0 sockets for >= grace -----------------------------------------------

def test_zero_sockets_first_observation_is_degraded_not_deaf():
    v = decide(evidence(snap("remote_deaf.txt")), History(), GRACE)
    assert v.verdict == DEGRADED and v.reason_code == "deaf_suspected"
    assert v.zero_since == FIXTURE_NOW


def test_zero_sockets_past_grace_is_deaf():
    v = decide(evidence(snap("remote_deaf.txt")), History(zero_since=FIXTURE_NOW - 14 * 60), GRACE)
    assert v.verdict == DEAF and v.reason_code == "no_platform_sockets"
    assert v.zero_for_s == 14 * 60
    assert v.reason == "host up, gateway process alive, 0 platform sockets for 14m"


def test_zero_sockets_exactly_at_grace_is_deaf():
    v = decide(evidence(snap("remote_deaf.txt")), History(zero_since=FIXTURE_NOW - GRACE), GRACE)
    assert v.verdict == DEAF


def test_recent_restart_with_zero_sockets_is_degraded():
    remote = replace(snap("remote_deaf.txt"), mainpid_age_s=120)
    v = decide(evidence(remote), History(zero_since=FIXTURE_NOW - 3600), GRACE)
    assert v.verdict == DEGRADED and v.reason_code == "recent_restart"


def test_zero_window_is_clamped_to_process_age():
    # Streak is 2h old but the process only lived 11m: the window is 11m (>= 10m grace).
    remote = replace(snap("remote_deaf.txt"), mainpid_age_s=11 * 60)
    v = decide(evidence(remote), History(zero_since=FIXTURE_NOW - 7200), GRACE)
    assert v.verdict == DEAF and v.zero_for_s == 11 * 60


def test_future_zero_since_is_ignored():
    v = decide(evidence(snap("remote_deaf.txt")), History(zero_since=FIXTURE_NOW + 999), GRACE)
    assert v.zero_since == FIXTURE_NOW and v.verdict == DEGRADED


# -- Rule 4: down_physical needs two independent failures --------------------------------

def test_tailnet_offline_and_tcp_failed_is_down_physical():
    ev = evidence(None, host=GPU_HOST, tailnet=TAIL_OFFLINE, tcp=TCP_FAIL,
                  skipped="tailnet offline and TCP connect failed")
    v = decide(ev, History(last_ok=FIXTURE_NOW - 30 * 3600), GRACE)
    assert v.verdict == DOWN_PHYSICAL and v.reason_code == "offline"
    assert "power or cable" in v.reason
    assert v.tailnet_last_seen == FIXTURE_NOW - 27 * 3600
    assert v.reachable is False


def test_tailnet_offline_alone_is_unknown():
    ev = evidence(RemoteSnapshot(False, error="ssh timed out"), host=GPU_HOST, tailnet=TAIL_OFFLINE, tcp=TCP_OK)
    v = decide(ev, History(), GRACE)
    assert v.verdict == UNKNOWN and v.reason_code == "tailnet_offline_only"


def test_tcp_failure_alone_is_unknown():
    ev = evidence(RemoteSnapshot(False, error="ssh connect timed out"), host=GPU_HOST,
                  tailnet=TailnetObs(True, online=True), tcp=TCP_FAIL)
    v = decide(ev, History(), GRACE)
    assert v.verdict == UNKNOWN and v.reason_code == "tcp_failed_only"
    assert "a single failed signal is not proof of a physical outage" in v.notes


@pytest.mark.parametrize("tailnet", [TAIL_MISSING, TAIL_STOPPED])
def test_missing_or_stopped_tailscale_never_yields_down_physical(tailnet):
    ev = evidence(RemoteSnapshot(False, error="ssh connect timed out"), host=GPU_HOST, tailnet=tailnet, tcp=TCP_FAIL)
    v = decide(ev, History(), GRACE)
    assert v.verdict == UNKNOWN
    assert v.tailnet_online is None
    assert any("tailnet signal unavailable" in n for n in v.notes)


def test_tailnet_offline_without_tcp_targets_is_unknown():
    host = HostConfig(name="gpu-host", ssh_alias="gpu-host")
    ev = evidence(RemoteSnapshot(False, error="ssh timed out"), host=host, tailnet=TAIL_OFFLINE, tcp=TcpObs(False))
    v = decide(ev, History(), GRACE)
    assert v.verdict == UNKNOWN
    assert any("TCP probe skipped" in n for n in v.notes)


def test_ssh_ok_overrides_stale_tailnet_offline():
    v = decide(evidence(snap("remote_healthy.txt"), tailnet=TAIL_OFFLINE), History(), GRACE)
    assert v.verdict == UP
    assert any("tailnet reports offline but ssh succeeded" in n for n in v.notes)


# -- Unknown paths ----------------------------------------------------------------------

def test_permission_denied_is_unknown():
    remote = RemoteSnapshot(False, error="ssh permission denied (key not accepted)")
    v = decide(evidence(remote), History(), GRACE)
    assert v.verdict == UNKNOWN and v.reason_code == "probe_failed"
    assert v.reason == "ssh permission denied (key not accepted)"
    assert v.reachable is True


def test_garbage_payload_is_unknown():
    v = decide(evidence(snap("remote_garbage.txt")), History(), GRACE)
    assert v.verdict == UNKNOWN
    assert "not parseable" in v.reason


def test_ssh_timeout_with_tailscale_stopped_is_unknown():
    v = decide(evidence(RemoteSnapshot(False, error="ssh timed out"), tailnet=TAIL_STOPPED), History(), GRACE)
    assert v.verdict == UNKNOWN and v.reason == "ssh timed out"


def test_verdict_to_dict_is_json_ready():
    import json
    v = decide(evidence(snap("remote_pi_host_stale_state.txt")), History(), GRACE)
    data = json.loads(json.dumps(v.to_dict()))
    assert data["verdict"] == "up" and data["state_file_stale"] is True


@pytest.mark.parametrize("seconds, text", [
    (None, "?"), (0, "0m"), (59, "0m"), (14 * 60, "14m"), (3600, "1h"), (3660, "1h 1m"),
    (27 * 3600, "1d 3h"), (48 * 3600, "2d"), (-5, "0m"),
])
def test_fmt_minutes(seconds, text):
    assert fmt_minutes(seconds) == text
