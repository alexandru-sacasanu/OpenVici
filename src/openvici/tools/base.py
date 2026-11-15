"""Tool registry and dispatch.

A tool call from the model is untrusted input: the name must be registered
and the arguments must match the tool's declared schema exactly (no missing
required keys, no extra keys, right types) before the handler runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..credentials import CredentialError
from ..messages import ToolCall, ToolSpec
from ..sandbox import SandboxError

Confirm = Callable[[str, str], bool]  # (what is about to happen, why you are asked) -> approved


def refuse(action: str, reason: str) -> bool:
    """Default confirmer: with no human attached, the answer is no."""
    return False


class ToolError(Exception):
    """A failure the model should be told about and can react to."""


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], str]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.input_schema)


_TYPES: dict[str, type | tuple[type, ...]] = {"string": str, "integer": int, "boolean": bool}


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None):
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool

    def specs(self) -> list[ToolSpec]:
        return [t.spec for t in self._tools.values()]

    def dispatch(self, call: ToolCall) -> tuple[str, bool]:
        """(result text, is_error). Never raises for a problem the model
        caused; audit failures do propagate, because then nothing may run."""
        tool = self._tools.get(call.name)
        if tool is None:
            return f"Unknown tool '{call.name}'. Available: {', '.join(self._tools) or 'none'}.", True
        if call.invalid is not None:
            return f"The arguments were not valid JSON: {call.invalid}", True
        problem = _validate(call.arguments, tool.input_schema)
        if problem:
            return f"Invalid arguments for {tool.name}: {problem}", True
        try:
            return tool.handler(call.arguments), False
        except (ToolError, SandboxError, CredentialError) as exc:
            return str(exc), True


def _validate(args: dict[str, Any], schema: dict[str, Any]) -> str | None:
    props: dict[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in args:
            return f"missing required argument '{name}'"
    for name, value in args.items():
        if name not in props:
            return f"unexpected argument '{name}'"
        expected = _TYPES.get(props[name].get("type", ""))
        if expected and (not isinstance(value, expected) or (expected is int and isinstance(value, bool))):
            return f"'{name}' must be a {props[name]['type']}"
    return None
