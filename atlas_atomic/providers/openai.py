"""OpenAI provider.

Wraps the official ``openai`` SDK's Chat Completions API. The OpenAI message
schema is exactly our normalized schema, so this provider is a thin adapter.
Import is lazy so the dependency is optional.
"""

from __future__ import annotations

from atlas_atomic.core.models import Message, ProviderResponse
from atlas_atomic.providers.base import BaseProvider, ProviderError

_DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(BaseProvider):
    name = "openai"

    def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
        super().__init__(config)
        try:
            import openai  # noqa: F401
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise ProviderError(
                "The 'openai' package is required for the OpenAI provider. "
                "Install it with: pip install openai"
            ) from exc

        if config.model in ("", "mock-model"):
            self.model = _DEFAULT_MODEL

        import openai

        kwargs: dict = {}
        if config.api_key:
            kwargs["api_key"] = config.api_key
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = openai.OpenAI(**kwargs)

    def _chat(self, messages: list[Message]) -> ProviderResponse:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=self._to_openai_style(messages),
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            **self.config.options,
        )
        choice = resp.choices[0]
        return ProviderResponse(
            content=choice.message.content or "",
            model=resp.model,
            raw={"finish_reason": choice.finish_reason, "id": resp.id},
        )
