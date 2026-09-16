from types import SimpleNamespace

import pytest

from minion_agent.callbacks.hol_guard import HolGuardBlocked, HolGuardCallback


def _context():
    return SimpleNamespace(shared={})


def _allow_guard(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "minion_agent.callbacks.hol_guard.shutil.which",
        lambda _: "/usr/bin/hol-guard",
    )

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout='{"classification":{"explicitly_benign":true},"minimum_action":"allow"}',
        )

    monkeypatch.setattr("minion_agent.callbacks.hol_guard.subprocess.run", run)
    return calls


def test_hol_guard_allows_explicitly_benign_command(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    calls = _allow_guard(monkeypatch)

    assert callback.before_tool_execution(context, command="git status") is context
    assert calls == [
        (
            ["/usr/bin/hol-guard", "command", "test", "git status", "--json"],
            {
                "capture_output": True,
                "text": True,
                "timeout": 10.0,
                "check": False,
            },
        )
    ]


def test_hol_guard_reads_tinyagent_positional_payload(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    calls = _allow_guard(monkeypatch)
    request = {"name": "shell", "arguments": {"command": "git status"}}

    assert callback.before_tool_execution(context, request) is context
    assert calls[0][0][3] == "git status"


def test_hol_guard_reads_object_arguments(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    calls = _allow_guard(monkeypatch)
    function_call = SimpleNamespace(arguments={"cmd": "pwd"})

    assert callback.before_tool_execution(context, function_call) is context
    assert calls[0][0][3] == "pwd"


def test_hol_guard_blocks_multiple_distinct_command_aliases(monkeypatch):
    callback = HolGuardCallback()
    monkeypatch.setattr(
        "minion_agent.callbacks.hol_guard.shutil.which",
        lambda _: "/usr/bin/hol-guard",
    )

    with pytest.raises(HolGuardBlocked, match="Multiple command values"):
        callback.before_tool_execution(
            _context(),
            command="echo safe",
            cmd="rm important-file",
        )


def test_hol_guard_deduplicates_identical_command_aliases(monkeypatch):
    callback = HolGuardCallback()
    context = _context()
    calls = _allow_guard(monkeypatch)

    assert (
        callback.before_tool_execution(
            context,
            command="git status",
            cmd="git status",
        )
        is context
    )
    assert len(calls) == 1


def test_hol_guard_blocks_review_or_unknown_command(monkeypatch):
    callback = HolGuardCallback()
    monkeypatch.setattr(
        "minion_agent.callbacks.hol_guard.shutil.which",
        lambda _: "/usr/bin/hol-guard",
    )
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
