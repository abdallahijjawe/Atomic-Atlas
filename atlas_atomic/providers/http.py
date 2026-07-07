"""Generic configurable HTTP provider.

Targets *any* custom chat application over HTTP without writing code -- you
describe the endpoint's request/response shape in the config's ``options`` block.
This is the provider to use when the system under test is your own chatbot with
its own REST API (not a raw OpenAI/Anthropic model endpoint).

It uses only the standard library (``urllib``), so there is no extra dependency.

Configuration (``ProviderConfig``)
----------------------------------
``base_url``       The endpoint URL (required).
``api_key_env``    Name of an env var whose value is substituted for the
                   ``{api_key}`` placeholder in headers.
``timeout_seconds``Request timeout.
``options`` keys:
    method            HTTP method (default ``POST``).
    headers           dict of header -> value; ``{api_key}`` is substituted.
                      Default ``{"Content-Type": "application/json"}``.
    prompt_field      Dotted path in the JSON body to place the prompt at
                      (default ``message``). Set to ``""``/``null`` to disable.
    prompt_mode       ``last_user`` (default) sends the latest user turn plus any
                      injected tool/RAG context after it; ``transcript`` sends the
                      whole role-tagged conversation as one string.
    messages_field    Optional dotted path to send the full OpenAI-style messages
                      array (``[{role, content}, ...]``) -- for apps that accept
                      history. Can be combined with, or used instead of,
                      ``prompt_field``.
    tool_role         Role name to map emulated TOOL messages to when building the
                      messages array (default ``user``).
    include_system    Include system messages in the messages array (default true).
    model_field       Optional dotted path to inject the model id into the body.
    extra_body        dict of static fields merged into the request body.
    response_path     Dotted path to extract the reply from the JSON response
                      (default ``reply``); supports list indices, e.g.
                      ``choices.0.message.content``. Empty -> use the raw body.

Examples
--------
Simple app -- ``POST /chat {"message": "..."} -> {"reply": "..."}``::

    provider:
      name: http
      base_url: https://my-app.internal/chat
      options: {}

OpenAI-compatible app with bearer auth::

    provider:
      name: http
      base_url: https://gw.internal/v1/chat/completions
      api_key_env: MY_API_KEY
      model: my-model
      options:
        headers: { Authorization: "Bearer {api_key}", Content-Type: application/json }
        prompt_field: ""                     # disable single-prompt mode
        messages_field: messages             # send full history instead
        model_field: model
        response_path: choices.0.message.content
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from atlas_atomic.core.models import Message, ProviderResponse, Role
from atlas_atomic.providers.base import BaseProvider, ProviderError

_BODY_METHODS = {"POST", "PUT", "PATCH"}


class HTTPProvider(BaseProvider):
    name = "http"

    def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
        super().__init__(config)
        if not config.base_url:
            raise ProviderError(
                "The http provider requires 'base_url' (the endpoint URL)."
            )
        opts: dict[str, Any] = config.options or {}
        self.url: str = config.base_url
        self.method: str = str(opts.get("method", "POST")).upper()
        self.prompt_field: str | None = opts.get("prompt_field", "message")
        self.prompt_mode: str = opts.get("prompt_mode", "last_user")
        self.messages_field: str | None = opts.get("messages_field")
        self.tool_role: str = opts.get("tool_role", "user")
        self.include_system: bool = bool(opts.get("include_system", True))
        self.model_field: str | None = opts.get("model_field")
        self.extra_body: dict[str, Any] = dict(opts.get("extra_body", {}))
        self.response_path: str = opts.get("response_path", "reply")
        self.headers = self._resolve_headers(
            opts.get("headers") or {"Content-Type": "application/json"}
        )

    # ------------------------------------------------------------------ #
    def _chat(self, messages: list[Message]) -> ProviderResponse:
        prompt = self._prompt_text(messages)

        if self.method in _BODY_METHODS:
            body = self._build_body(messages, prompt)
            data = json.dumps(body).encode("utf-8")
            url = self.url
        else:
            # GET/DELETE: pass the prompt as a query parameter.
            data = None
            param = self.prompt_field or "q"
            sep = "&" if "?" in self.url else "?"
            url = f"{self.url}{sep}{urllib.parse.urlencode({param: prompt})}"

        req = urllib.request.Request(
            url, data=data, headers=self.headers, method=self.method
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.config.timeout_seconds
            ) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                status = resp.status
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            return ProviderResponse(
                content="",
                model=self.model,
                error=f"HTTP {exc.code}: {detail}",
            )
        except urllib.error.URLError as exc:
            return ProviderResponse(
                content="", model=self.model, error=f"HTTPConnectionError: {exc}"
            )

        content = self._extract_reply(raw)
        return ProviderResponse(
            content=content, model=self.model, raw={"status": status}
        )

    # ------------------------------------------------------------------ #
    def _build_body(self, messages: list[Message], prompt: str) -> dict[str, Any]:
        # Deep copy so the template is never mutated across calls.
        body: dict[str, Any] = json.loads(json.dumps(self.extra_body))
        if self.prompt_field:
            _set_path(body, self.prompt_field, prompt)
        if self.messages_field:
            _set_path(body, self.messages_field, self._messages_payload(messages))
        if self.model_field:
            _set_path(body, self.model_field, self.model)
        return body

    def _messages_payload(self, messages: list[Message]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for m in messages:
            role = m.role.value
            if role == Role.TOOL.value:
                role = self.tool_role
            if role == Role.SYSTEM.value and not self.include_system:
                continue
            out.append({"role": role, "content": m.content})
        return out

    def _prompt_text(self, messages: list[Message]) -> str:
        if self.prompt_mode == "transcript":
            return "\n".join(f"[{m.role.value}] {m.content}" for m in messages)
        # last_user: the latest user turn PLUS any injected tool/system context
        # that follows it (so emulated RAG/tool payloads are still delivered).
        last_user_idx = None
        for i, m in enumerate(messages):
            if m.role == Role.USER:
                last_user_idx = i
        if last_user_idx is None:
            return messages[-1].content if messages else ""
        parts = [messages[last_user_idx].content]
        for m in messages[last_user_idx + 1 :]:
            if m.role in (Role.TOOL, Role.SYSTEM):
                parts.append(m.content)
        return "\n\n".join(parts)

    def _extract_reply(self, raw: str) -> str:
        if not self.response_path:
            return raw
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Not JSON -- return the raw text so evaluation can still run.
            return raw
        value = _get_path(data, self.response_path)
        if value is None:
            return raw  # path missed; surface the whole body for debugging
        return value if isinstance(value, str) else json.dumps(value)

    def _resolve_headers(self, headers: dict[str, Any]) -> dict[str, str]:
        api_key = self.config.api_key or ""
        return {k: str(v).replace("{api_key}", api_key) for k, v in headers.items()}


# --------------------------------------------------------------------------- #
# Dotted-path helpers (dict for set; dict/list for get, with numeric indices).
# --------------------------------------------------------------------------- #
def _set_path(obj: dict[str, Any], path: str, value: Any) -> None:
    keys = path.split(".")
    cur = obj
    for key in keys[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[keys[-1]] = value


def _get_path(obj: Any, path: str) -> Any:
    cur = obj
    for key in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(key)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            if key not in cur:
                return None
            cur = cur[key]
        else:
            return None
    return cur
