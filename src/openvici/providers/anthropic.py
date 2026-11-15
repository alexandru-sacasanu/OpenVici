"""Anthropic Messages API."""

from __future__ import annotations

from typing import Any

from ..messages import Message, ModelTurn, ToolCall, ToolSpec
from .base import ProviderError, Transport, post_json, require_safe_base_url

DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicProvider:
    def __init__(self, model: str, api_key: str, base_url: str = DEFAULT_BASE_URL,
                 max_tokens: int = 4096, transport: Transport = post_json):
        if not api_key:
            raise ProviderError("the anthropic provider needs an API key (see [model] credential)")
        self.model, self.max_tokens, self.transport = model, max_tokens, transport
        self.url = require_safe_base_url(base_url) + "/v1/messages"
        self.headers = {"x-api-key": api_key, "anthropic-version": API_VERSION}

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> ModelTurn:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": to_wire(messages),
        }
        if tools:
            payload["tools"] = [{"name": t.name, "description": t.description,
                                 "input_schema": t.input_schema} for t in tools]
        data = self.transport(self.url, self.headers, payload)
        try:
            blocks = data["content"]
            text = "".join(b["text"] for b in blocks if b.get("type") == "text")
            calls = tuple(ToolCall(b["id"], b["name"], b.get("input") or {})
                          for b in blocks if b.get("type") == "tool_use")
        except (KeyError, TypeError) as exc:
            raise ProviderError(f"unexpected response shape from the model API: {exc}") from None
        return ModelTurn(text, calls, str(data.get("stop_reason", "")))


def to_wire(messages: list[Message]) -> list[dict[str, Any]]:
    """Tool results go back as ``tool_result`` blocks in a user message; all
    results answering one assistant turn must share that message."""
    wire: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "tool":
            block = {"type": "tool_result", "tool_use_id": msg.tool_call_id, "content": msg.text or "(no output)"}
            if msg.is_error:
                block["is_error"] = True
            if wire and wire[-1]["role"] == "user" and isinstance(wire[-1]["content"], list) \
                    and wire[-1]["content"][-1].get("type") == "tool_result":
                wire[-1]["content"].append(block)
            else:
                wire.append({"role": "user", "content": [block]})
        elif msg.role == "assistant":
            content: list[dict[str, Any]] = []
            if msg.text:
                content.append({"type": "text", "text": msg.text})
            content += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                        for c in msg.tool_calls]
            wire.append({"role": "assistant", "content": content or [{"type": "text", "text": "(empty)"}]})
        else:
            wire.append({"role": "user", "content": [{"type": "text", "text": msg.text}]})
    return wire
