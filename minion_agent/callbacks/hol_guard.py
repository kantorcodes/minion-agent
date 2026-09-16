from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from typing import TYPE_CHECKING

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

    def before_tool_execution(self, context: Context, *args, **kwargs) -> Context:
        del args
        command = next(
            (
                kwargs[field]
                for field in self.command_fields
                if isinstance(kwargs.get(field), str) and kwargs[field].strip()
            ),
            None,
        )
        if command is None:
            return context

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
            return context

        raise HolGuardBlocked("HOL Guard did not explicitly allow the command")
