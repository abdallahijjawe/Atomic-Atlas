"""Anthropic (Claude) provider.

Wraps the official ``anthropic`` SDK. The Anthropic Messages API takes the
system prompt as a top-level argument rather than a message with role=system,
so we split it out here. Import of the SDK is lazy so the dependency is only
required when this provider is actually selected.
"""

from __future__ import annotations

from atlas_atomic.core.models import Message, ProviderResponse, Role
from atlas_atomic.providers.base import BaseProvider, ProviderError

# Default to the most capable current Claude model. Overridable via config.
_DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
        super().__init__(config)
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise ProviderError(
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install it with: pip install anthropic"
            ) from exc

        if config.model in ("", "mock-model"):
            self.model = _DEFAULT_MODEL

        import anthropic

        kwargs: dict = {}
        if config.api_key:
            kwargs["api_key"] = config.api_key
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = anthropic.Anthropic(**kwargs)

    def _chat(self, messages: list[Message]) -> ProviderResponse:
        system_parts = [m.content for m in messages if m.role == Role.SYSTEM]
        chat_messages = [
            {"role": self._map_role(m.role), "content": m.content}
            for m in messages
            if m.role != Role.SYSTEM
        ]

        create_kwargs: dict = {
            "model": self.model,
            "max_tokens": self.config.max_tokens,
            "messages": chat_messages,
        }
        if system_parts:
            create_kwargs["system"] = "\n\n".join(system_parts)
        # NOTE: current Claude models (Opus 4.8/4.7, Sonnet 5, Fable 5) reject
        # `temperature`/`top_p`/`top_k` with a 400, so we do NOT send them by
        # default. For older models that accept temperature, add it explicitly via
        # `provider.options` (merged below).
        create_kwargs.update(self.config.options)

        resp = self._client.messages.create(**create_kwargs)
        text = "".join(
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        )
        return ProviderResponse(
            content=text,
            model=resp.model,
            raw={"stop_reason": resp.stop_reason, "id": resp.id},
        )

    @staticmethod
    def _map_role(role: Role) -> str:
        # Anthropic understands user/assistant; tool outputs are folded into the
        # user turn as plain text for these emulations.
        return "assistant" if role == Role.ASSISTANT else "user"
