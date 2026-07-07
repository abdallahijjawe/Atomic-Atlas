"""Base provider interface.

Every provider converts a list of normalized :class:`Message` objects into a
:class:`ProviderResponse`. Concrete providers implement ``_chat``; the public
``chat`` wraps it with uniform error handling so a provider/network failure
becomes a ``ProviderResponse`` with ``error`` set (leading to an INCONCLUSIVE
verdict) rather than crashing a whole run.
"""

from __future__ import annotations

import abc
from typing import Any

from atlas_atomic.core.config import ProviderConfig
from atlas_atomic.core.logging import get_logger
from atlas_atomic.core.models import Message, ProviderResponse

log = get_logger("providers")


class ProviderError(RuntimeError):
    """Raised for configuration/setup problems (e.g. missing SDK or API key)."""


class BaseProvider(abc.ABC):
    """Abstract base class for all providers (Strategy pattern)."""

    #: Human-readable provider name, e.g. "openai".
    name: str = "base"

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.model = config.model

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def chat(self, messages: list[Message]) -> ProviderResponse:
        """Send a conversation and return a normalized response.

        Never raises for runtime/API errors -- those are captured into the
        returned response's ``error`` field so a single flaky call does not abort
        an entire test suite.
        """

        try:
            log.debug("%s.chat: %d message(s), model=%s", self.name, len(messages), self.model)
            return self._chat(messages)
        except ProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberate boundary
            log.warning("%s provider call failed: %s", self.name, exc)
            return ProviderResponse(
                content="",
                model=self.model,
                error=f"{type(exc).__name__}: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Subclass contract
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def _chat(self, messages: list[Message]) -> ProviderResponse:
        """Provider-specific implementation. Should return a ProviderResponse."""

    # ------------------------------------------------------------------ #
    # Helpers shared by concrete providers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _to_openai_style(messages: list[Message]) -> list[dict[str, Any]]:
        """Serialize messages to the widely-used OpenAI chat schema."""

        out: list[dict[str, Any]] = []
        for m in messages:
            entry: dict[str, Any] = {"role": m.role.value, "content": m.content}
            if m.name:
                entry["name"] = m.name
            if m.tool_call_id:
                entry["tool_call_id"] = m.tool_call_id
            out.append(entry)
        return out

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} model={self.model!r}>"
