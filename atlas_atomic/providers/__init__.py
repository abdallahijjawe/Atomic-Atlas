"""Provider abstraction and registry.

Providers are the only place ATLAS-Atomic talks to an LLM. They implement a
single ``chat`` method over a normalized message list, so the rest of the
framework never depends on a specific vendor SDK. Selecting a provider is a
config change (``provider.name``), resolved through ``build_provider``.
"""

from __future__ import annotations

from atlas_atomic.core.config import ProviderConfig
from atlas_atomic.providers.base import BaseProvider, ProviderError

# Registry maps a config name -> factory. Real SDK imports are deferred to the
# factory so that missing optional dependencies (openai, anthropic, requests)
# only error when that provider is actually selected.
_REGISTRY: dict[str, str] = {
    "mock": "atlas_atomic.providers.mock:MockProvider",
    "openai": "atlas_atomic.providers.openai:OpenAIProvider",
    "anthropic": "atlas_atomic.providers.anthropic:AnthropicProvider",
    "ollama": "atlas_atomic.providers.ollama:OllamaProvider",
    "http": "atlas_atomic.providers.http:HTTPProvider",
}


def _import_from_path(dotted: str) -> type[BaseProvider]:
    module_path, _, attr = dotted.partition(":")
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, attr)


def build_provider(config: ProviderConfig) -> BaseProvider:
    """Instantiate the provider named in ``config`` (default: mock)."""

    name = config.name.lower().strip()
    if name not in _REGISTRY:
        raise ProviderError(
            f"Unknown provider '{name}'. Available: {sorted(_REGISTRY)}"
        )
    provider_cls = _import_from_path(_REGISTRY[name])
    return provider_cls(config)


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


__all__ = [
    "BaseProvider",
    "ProviderError",
    "build_provider",
    "available_providers",
]
