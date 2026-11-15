"""The conversation loop: ask the model, run the tools it asks for, repeat.

The loop itself holds no security logic. Every side effect goes through a
tool, and every tool goes through its own checks; the loop only bounds how
long a single user turn may run.
"""

from __future__ import annotations

from typing import Callable

from .context import ContextEngine
from .messages import Message, ToolCall
from .providers import ModelProvider
from .tools import ToolRegistry

OnToolCall = Callable[[ToolCall], None]


class Agent:
    def __init__(self, provider: ModelProvider, tools: ToolRegistry, context: ContextEngine | None = None,
                 max_steps: int = 25):
        self.provider, self.tools = provider, tools
        self.context = context or ContextEngine()
        self.max_steps = max_steps
        self.history: list[Message] = []

    def run_turn(self, user_text: str, on_tool_call: OnToolCall | None = None) -> str:
        """Handle one user message and return the assistant's final text. If
        the model API fails, the turn is rolled back so it can be retried."""
        checkpoint = len(self.history)
        self.history.append(Message("user", user_text))
        specs = self.tools.specs()
        system = self.context.system_prompt(specs)
        try:
            for _ in range(self.max_steps):
                turn = self.provider.complete(system, self.context.build(self.history), specs)
                self.history.append(Message("assistant", turn.text, tool_calls=turn.tool_calls))
                if not turn.tool_calls:
                    return turn.text
                for call in turn.tool_calls:
                    if on_tool_call:
                        on_tool_call(call)
                    text, is_error = self.tools.dispatch(call)
                    self.history.append(Message("tool", self.context.clip_tool_result(text),
                                                tool_call_id=call.id, is_error=is_error))
        except Exception:
            del self.history[checkpoint:]
            raise
        notice = f"Stopped after {self.max_steps} steps without finishing. Tell me how to continue."
        self.history.append(Message("assistant", notice))
        return notice
