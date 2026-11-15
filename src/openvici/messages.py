"""The conversation format the agent keeps internally.

Providers translate this to and from their own wire formats, so nothing else
in the codebase knows which model vendor is on the other end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    invalid: str | None = None  # set when the model sent arguments that were not valid JSON


@dataclass(frozen=True)
class Message:
    role: str  # "user" | "assistant" | "tool"
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
    is_error: bool = False

    def size(self) -> int:
        return len(self.text) + sum(len(str(c.arguments)) + len(c.name) for c in self.tool_calls)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ModelTurn:
    text: str
    tool_calls: tuple[ToolCall, ...] = field(default=())
    stop_reason: str = ""
