"""pre_tool_call approval gate: a flag the model sets is not consent."""

from __future__ import annotations

from pathlib import Path

from sentinel.approval import approval_hook, recovery_needs_approval

ROOT = Path(__file__).resolve().parent.parent


def _call(**args):
    return approval_hook(tool_name="fleet_recover", args=args)


def test_dry_run_default_does_not_ask() -> None:
    # dry_run defaults to true in the schema; an omitted flag is a simulation.
    assert _call(host="gpu-host", action="restart-gateway") is None


def test_explicit_dry_run_true_does_not_ask() -> None:
    assert _call(host="gpu-host", action="wake", dry_run=True) is None


def test_dry_run_false_escalates_with_host_and_action() -> None:
    assert _call(host="gpu-host", action="restart-gateway", dry_run=False) == {
        "action": "approve",
        "message": "fleet-sentinel: restart-gateway on gpu-host",
        "rule_key": "fleet_recover:restart-gateway",
    }


def test_each_verb_gets_its_own_rule_key() -> None:
    rule_keys = {
        _call(host="h", action=verb, dry_run=False)["rule_key"]
        for verb in ("restart-gateway", "clear-lock", "wake")
    }
    assert len(rule_keys) == 3


def test_other_tools_are_untouched() -> None:
    assert approval_hook(tool_name="fleet_status", args={}) is None
    assert approval_hook(tool_name="fleet_probe", args={"host": "h"}) is None
    assert approval_hook(tool_name="terminal", args={"dry_run": False}) is None


def test_missing_fields_still_escalate_and_are_labelled() -> None:
    assert _call(action="wake", dry_run=False) == {
        "action": "approve",
        "message": "fleet-sentinel: wake on unknown host",
        "rule_key": "fleet_recover:wake",
    }
    assert _call(host="h", dry_run=False)["rule_key"] == "fleet_recover:recover"


def test_non_mapping_args_are_safe() -> None:
    from typing import Any

    weird: Any = None
    assert approval_hook(tool_name="fleet_recover", args=weird) is None
    weird = "nonsense"
    assert approval_hook(tool_name="fleet_recover", args=weird) is None
    weird = []
    assert approval_hook(tool_name="fleet_recover", args=weird) is None


def test_truthy_strings_are_not_execution() -> None:
    # Only the JSON boolean false acts; a string "false" must stay a simulation.
    assert recovery_needs_approval({"dry_run": "false"}) is False
    assert recovery_needs_approval({"dry_run": 0}) is False
    assert recovery_needs_approval({"dry_run": False}) is True


def test_extra_hook_kwargs_are_ignored() -> None:
    got = approval_hook(
        tool_name="fleet_recover",
        args={"host": "h", "action": "wake", "dry_run": False},
        task_id="t-1", session_id="s-1", tool_call_id="c-1", turn_id="u-1",
        api_request_id="r-1", middleware_trace=[],
    )
    assert got is not None and got["action"] == "approve"


def test_manifest_declares_the_hook() -> None:
    """The catalog validates declared hooks against registrations; keep the two in sync."""
    manifest = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    assert "provides_hooks: [pre_tool_call]" in manifest
    assert "version: 1.0.1" in manifest
