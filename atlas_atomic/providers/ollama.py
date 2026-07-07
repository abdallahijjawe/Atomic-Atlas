"""Ollama provider.

Talks to a local Ollama server's ``/api/chat`` endpoint over plain HTTP using
the stdlib (no third-party dependency), so local models can be targeted with
zero extra installs. Configure ``base_url`` (default http://localhost:11434) and
``model`` (e.g. "llama3").
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from atlas_atomic.core.models import Message, ProviderResponse
from atlas_atomic.providers.base import BaseProvider

_DEFAULT_MODEL = "llama3"
_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
        super().__init__(config)
        if config.model in ("", "mock-model"):
            self.model = _DEFAULT_MODEL
        self.base_url = (config.base_url or _DEFAULT_BASE_URL).rstrip("/")

    def _chat(self, messages: list[Message]) -> ProviderResponse:
        payload = {
            "model": self.model,
            "messages": self._to_openai_style(messages),
            "stream": False,
            "options": {"temperature": self.config.temperature, **self.config.options},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return ProviderResponse(
                content="", model=self.model, error=f"OllamaConnectionError: {exc}"
            )

        content = (body.get("message") or {}).get("content", "")
        return ProviderResponse(
            content=content,
            model=body.get("model", self.model),
            raw={"done_reason": body.get("done_reason")},
        )
