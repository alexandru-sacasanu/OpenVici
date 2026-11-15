"""What every model provider must do, and the HTTP helper they share."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from ..messages import Message, ModelTurn, ToolSpec

Transport = Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]]
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ProviderError(Exception):
    pass


class ModelProvider(Protocol):
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> ModelTurn: ...


def require_safe_base_url(base_url: str) -> str:
    """API keys only travel over TLS; plain HTTP is accepted for a model
    running on this machine and nowhere else."""
    parts = urlsplit(base_url)
    if parts.scheme == "https" and parts.hostname:
        return base_url.rstrip("/")
    if parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS:
        return base_url.rstrip("/")
    raise ProviderError(f"model base_url must be https (or http on localhost): {base_url!r}")


def post_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float = 180) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={**headers, "content-type": "application/json", "user-agent": "openvici/0.0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode(errors="replace")
        raise ProviderError(f"model API returned HTTP {exc.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"could not reach the model API: {exc}") from None
    except ValueError:
        raise ProviderError("model API returned something that is not JSON") from None
