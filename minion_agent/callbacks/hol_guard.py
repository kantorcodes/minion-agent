from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .base import Callback

if TYPE_CHECKING:
    from .context import Context


class HolGuardBlocked(RuntimeError):
    """Raised when HOL Guard does not explicitly allow a command."""


class HolGuardCallback(Callback):
    """Fail-closed HOL Guard inspection for command-bearing tool calls.

    The callback is intentionally narrow: tools without one of ``command_fields``
    are left unchanged. For command-bearing calls, the command is inspected with
    ``hol-guard command test ... --json`` before the wrapped tool executes.
    """

    def __init__(
        self,
        command_fields: Sequence[str] = ("command", "cmd"),
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.command_fields = tuple(command_fields)
        self.timeout_seconds = timeout_seconds

    def _extract_commands(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[str]:
        commands: list[str] = []
        seen_containers: set[int] = set()

        def visit(value: Any, depth: int = 0) -> None:
            if depth > 2:
                return

            if isinstance(value, Mapping):
                identity = id(value)
                if identity in seen_containers:
                    return
                seen_containers.add(identity)

                for field in self.command_fields:
                    candidate = value.get(field)
                    if isinstance(candidate, str) and candidate.strip():
                        commands.append(candidate.strip())

                for key in ("arguments", "args", "kwargs", "input"):
                    nested = value.get(key)
                    if isinstance(nested, Mapping):
                        visit(nested, depth + 1)
                return

            for attribute in ("arguments", "args", "kwargs", "input"):
                nested = getattr(value, attribute, None)
                if isinstance(nested, Mapping):
                    visit(nested, depth + 1)

        visit(kwargs)
        for arg in args:
            visit(arg)

        return list(dict.fromkeys(commands))

    def _extract_command(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
        commands = self._extract_commands(args, kwargs)
        if not commands:
            return None
        if len(commands) > 1:
            raise HolGuardBlocked("Multiple command values cannot be evaluated safely")
        return commands[0]

    def _evaluate_command(self, command: str) -> None:
        executable = shutil.which("hol-guard")
        if executable is None:
            raise HolGuardBlocked("HOL Guard is not installed")

        try:
            completed = subprocess.run(
                [executable, "command", "test", command, "--json"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HolGuardBlocked("HOL Guard evaluation failed") from exc

        if completed.returncode != 0:
            raise HolGuardBlocked("HOL Guard evaluation failed")

        try:
            verdict = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise HolGuardBlocked("HOL Guard returned malformed output") from exc

        classification = verdict.get("classification") if isinstance(verdict, dict) else None
        if (
            isinstance(classification, dict)
            and classification.get("explicitly_benign") is True
            and verdict.get("minimum_action") == "allow"
        ):
            return

        raise HolGuardBlocked("HOL Guard did not explicitly allow the command")

    def before_tool_execution(self, context: Context, *args, **kwargs) -> Context:
        command = self._extract_command(args, kwargs)
        if command is None:
            return context
        self._evaluate_command(command)
        return context

    async def before_tool_execution_async(
        self, context: Context, *args, **kwargs
    ) -> Context:
        command = self._extract_command(args, kwargs)
        if command is None:
            return context
        await asyncio.to_thread(self._evaluate_command, command)
        return context
