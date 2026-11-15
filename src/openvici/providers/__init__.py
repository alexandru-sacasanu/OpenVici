from .anthropic import AnthropicProvider
from .base import ModelProvider, ProviderError
from .openai_compat import OpenAICompatProvider


def make_provider(provider: str, model: str, api_key: str = "", base_url: str = "",
                  max_tokens: int = 4096) -> ModelProvider:
    if not model:
        raise ProviderError("no model configured: set name under [model] in config.toml")
    kwargs = {"model": model, "api_key": api_key, "max_tokens": max_tokens}
    if base_url:
        kwargs["base_url"] = base_url
    if provider == "anthropic":
        return AnthropicProvider(**kwargs)
    if provider in {"openai", "openai-compatible"}:
        return OpenAICompatProvider(**kwargs)
    raise ProviderError(f"unknown model provider '{provider}' (expected 'anthropic' or 'openai-compatible')")


__all__ = ["AnthropicProvider", "OpenAICompatProvider", "ModelProvider", "ProviderError", "make_provider"]
