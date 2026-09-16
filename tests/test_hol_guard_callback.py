from types import SimpleNamespace

import pytest

from minion_agent.callbacks.hol_guard import HolGuardBlocked, HolGuardCallback


def _context():
    return SimpleNamespace(shared={})


def test_hol_guard_allows_explicitly_benign_command(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    monkeypatch.setattr("minion_agent.callbacks.hol_guard.shutil.which", lambda _: "/usr/bin/hol-guard")
    monkeypatch.setattr(
        "minion_agent.callbacks.hol_guard.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"classification":{"explicitly_benign":true},"minimum_action":"allow"}',
        ),
    )

    assert callback.before_tool_execution(context, command="git status") is context


def test_hol_guard_blocks_review_or_unknown_command(monkeypatch):
    callback = HolGuardCallback()
    monkeypatch.setattr("minion_agent.callbacks.hol_guard.shutil.which", lambda _: "/usr/bin/hol-guard")
    monkeypatch.setattr(
        "minion_agent.callbacks.hol_guard.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"classification":{"explicitly_benign":false},"minimum_action":"review"}',
        ),
    )

    with pytest.raises(HolGuardBlocked):
        callback.before_tool_execution(_context(), command="curl secret.example")


def test_hol_guard_fails_closed_when_cli_is_missing(monkeypatch):
    callback = HolGuardCallback()
    monkeypatch.setattr("minion_agent.callbacks.hol_guard.shutil.which", lambda _: None)

    with pytest.raises(HolGuardBlocked):
        callback.before_tool_execution(_context(), cmd="rm important-file")


def test_hol_guard_leaves_non_command_tools_unchanged(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    called = False

    def which(_):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr("minion_agent.callbacks.hol_guard.shutil.which", which)

    assert callback.before_tool_execution(context, path="README.md") is context
    assert called is False
