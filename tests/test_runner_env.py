"""Subprocess environment is an allowlist; the home resolver honours Hermes."""

from __future__ import annotations

from pathlib import Path

from sentinel import store
from sentinel.probe import child_env


def test_child_env_is_an_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/tester")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "000:not-a-real-token")
    env = child_env()
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/tester"
    # A subprocess that talks to another machine has no business holding these.
    assert "ANTHROPIC_API_KEY" not in env
    assert "TELEGRAM_BOT_TOKEN" not in env


def test_child_env_always_provides_a_path(monkeypatch) -> None:
    monkeypatch.delenv("PATH", raising=False)
    assert child_env()["PATH"].startswith("/")


def test_home_env_override_wins(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    assert store.hermes_home() == tmp_path


def test_home_resolver_is_absolute_without_env(monkeypatch) -> None:
    monkeypatch.delenv("HERMES_HOME", raising=False)
    home = store.hermes_home()
    assert home.is_absolute() and home.name
