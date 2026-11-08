"""Shared helpers. No network, no real ssh: every probe goes through fakes."""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Epoch the fixtures were captured at (NOW= line in every remote_*.txt): 2026-11-05 04:12:00 UTC.
FIXTURE_NOW = 1793851920


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if any test reaches for a real socket or subprocess."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"test attempted real I/O: {args[:1]!r}")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "state.db"
    monkeypatch.setenv("FLEET_SENTINEL_DB", str(path))
    return path


class FakeRunner:
    """Stands in for ``probe.run_bounded``; answers by argv[0] / ssh alias."""

    def __init__(self, responses: Optional[dict] = None):
        from sentinel.probe import CommandResult
        self.CommandResult = CommandResult
        self.responses = responses or {}
        self.calls: list[tuple[list[str], float, Optional[str]]] = []

    def __call__(self, argv, timeout, input_text=None):
        argv = list(argv)
        self.calls.append((argv, timeout, input_text))
        key = argv[-2] if argv and argv[0] == "ssh" else argv[0]
        resp = self.responses.get(key)
        if resp is None:
            return self.CommandResult(argv, 255, "", "ssh: connect to host: Connection timed out")
        if isinstance(resp, self.CommandResult):
            return resp
        rc, out, err = resp
        return self.CommandResult(argv, rc, out, err)
