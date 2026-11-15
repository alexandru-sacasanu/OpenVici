"""The shell tool: a thin wrapper over Executor, which owns approval,
credential scoping, the sandbox and the audit trail."""

from __future__ import annotations

from ..executor import Executor
from .base import Tool, ToolError


def shell_tool(executor: Executor) -> Tool:
    def handler(args: dict) -> str:
        outcome = executor.run_shell("shell", args["command"])
        if not outcome.ran:
            raise ToolError(outcome.message)
        result = outcome.result
        parts = [f"exit code: {result.exit_code}" + (" (timed out)" if result.timed_out else "")]
        if result.stdout:
            parts.append(f"stdout:\n{result.stdout}")
        if result.stderr:
            parts.append(f"stderr:\n{result.stderr}")
        return "\n".join(parts)

    return Tool(
        "shell",
        "Run a shell command in the isolated container. The project folder is at /workspace. "
        "There is no network access. Some commands need the user's approval.",
        {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        handler)
