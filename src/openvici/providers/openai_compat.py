"""Any server that speaks the OpenAI chat-completions format: OpenAI itself,
and local runners such as Ollama, llama.cpp or vLLM."""

from __future__ import annotations

import json
from typing import Any

from ..messages import Message, ModelTurn, ToolCall, ToolSpec
from .base import ProviderError, Transport, post_json, require_safe_base_url

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAICompatProvider:
    def __init__(self, model: str, api_key: str = "", base_url: str = DEFAULT_BASE_URL,
                 max_tokens: int = 4096, transport: Transport = post_json):
        self.model, self.max_tokens, self.transport = model, max_tokens, transport
        self.url = require_safe_base_url(base_url) + "/chat/completions"
        self.headers = {"authorization": f"Bearer {api_key}"} if api_key else {}

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> ModelTurn:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "system", "content": system}, *to_wire(messages)],
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.input_schema}} for t in tools]
        data = self.transport(self.url, self.headers, payload)
        try:
            choice = data["choices"][0]
            message = choice["message"]
            calls = tuple(_parse_call(c) for c in message.get("tool_calls") or [])
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"unexpected response shape from the model API: {exc}") from None
        return ModelTurn(message.get("content") or "", calls, str(choice.get("finish_reason", "")))


def _parse_call(raw: dict[str, Any]) -> ToolCall:
    fn = raw["function"]
    text = fn.get("arguments") or "{}"
    try:
        args = json.loads(text)
        if not isinstance(args, dict):
            raise ValueError
        return ToolCall(raw["id"], fn["name"], args)
    except ValueError:
        return ToolCall(raw["id"], fn["name"], {}, invalid=text[:500])


def to_wire(messages: list[Message]) -> list[dict[str, Any]]:
    wire: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "tool":
            prefix = "ERROR: " if msg.is_error else ""
            wire.append({"role": "tool", "tool_call_id": msg.tool_call_id,
                         "content": prefix + (msg.text or "(no output)")})
        elif msg.role == "assistant":
            entry: dict[str, Any] = {"role": "assistant", "content": msg.text or None}
            if msg.tool_calls:
                entry["tool_calls"] = [{"id": c.id, "type": "function", "function": {
                    "name": c.name, "arguments": json.dumps(c.arguments)}} for c in msg.tool_calls]
            wire.append(entry)
        else:
            wire.append({"role": "user", "content": msg.text})
    return wire
