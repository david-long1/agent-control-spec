# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The model boundary.

The generator calls exactly one thing on a model, `complete(system, user)`,
returning the raw response text. Everything downstream treats that text as
untrusted input and validates it, so a host can substitute any provider,
a gateway, or a recorded transcript without changing the generator.

No provider is contacted at import time and no credential is read at import
time, so importing this package in a test or a CI job performs no network
input or output.
"""

from __future__ import annotations

import json
import os
from typing import Protocol
from urllib import error, parse, request

DEFAULT_API_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
REQUEST_TIMEOUT_SECONDS = 60


class LanguageModel(Protocol):
    """One completion call returning raw response text."""

    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleLanguageModel:
    """Chat completions against an OpenAI-compatible or Azure OpenAI endpoint.

    Azure mode is selected by an explicit `api_version` or by an
    `*.azure.com` host, and changes both the auth header and the query
    string. Sampling is pinned to `temperature=0` with a JSON response
    format, so the same prompt and the same deployment produce the same plan
    as far as the provider allows.
    """

    def __init__(
        self,
        *,
        api_base: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        api_version: str | None = None,
    ) -> None:
        self.api_base = (
            api_base or os.getenv("ACS_GENERATOR_API_BASE") or DEFAULT_API_BASE
        ).rstrip("/")
        self.api_key = api_key or os.getenv("ACS_GENERATOR_API_KEY")
        self.model = model or os.getenv("ACS_GENERATOR_MODEL") or DEFAULT_MODEL
        self.api_version = api_version or os.getenv("ACS_GENERATOR_API_VERSION")
        self.is_azure = self.api_version is not None or _is_azure_api_base(
            self.api_base
        )

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise RuntimeError(
                "no API key. Pass --api-key or set ACS_GENERATOR_API_KEY, or supply "
                "your own LanguageModel to GenerationEngine"
            )
        if any(char in self.api_key for char in "\r\n\x00"):
            # A key carrying a control character makes http.client raise with
            # the header value in the message, and the CLI prints the message.
            raise RuntimeError(
                "the API key contains a control character; check for a stray newline "
                "in the environment variable or the flag"
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        url = f"{self.api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.is_azure:
            if self.api_version:
                url += f"?api-version={self.api_version}"
            headers["api-key"] = self.api_key
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with _NO_REDIRECTS.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise RuntimeError(_http_error_detail(exc)) from exc
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                f"provider returned no completion content: {json.dumps(body)[:400]}"
            ) from exc


class _NoRedirects(request.HTTPRedirectHandler):
    """Refuse to follow a redirect on a credentialed request.

    The request carries the provider credential in a header. Following a
    redirect would re-issue it against whatever host the response named, so
    the redirect is surfaced as an error and the caller decides.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECTS = request.build_opener(_NoRedirects)


def _is_azure_api_base(api_base: str) -> bool:
    hostname = parse.urlparse(api_base).hostname or ""
    normalized = hostname.lower().rstrip(".")
    return normalized == "azure.com" or normalized.endswith(".azure.com")


def _http_error_detail(exc: error.HTTPError) -> str:
    """The provider's own reason, not just the status line.

    `urllib` surfaces only "HTTP Error 400: Bad Request", while the body
    carries what actually happened. Guardrail prose describing an attack the
    policy should block reads like an attack to a provider content filter,
    and the resulting 400 is otherwise indistinguishable from a malformed
    request.
    """
    base = f"LLM request failed with HTTP {exc.code}"
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - fall back to the bare status line
        return base
    err = payload.get("error", payload) if isinstance(payload, dict) else {}
    parts = [base]
    if isinstance(err, dict):
        if err.get("code"):
            parts.append(f"code={err['code']}")
        if err.get("message"):
            parts.append(str(err["message"]))
        inner = err.get("innererror") or {}
        filtered = (
            inner.get("content_filter_result") if isinstance(inner, dict) else None
        )
        if isinstance(filtered, dict):
            flagged = sorted(
                key
                for key, value in filtered.items()
                if isinstance(value, dict)
                and (value.get("filtered") or value.get("detected"))
            )
            if flagged:
                parts.append(f"content_filter={flagged}")
    return ". ".join(parts)


class StubLanguageModel:
    """A scripted model. Contacts nothing.

    Responses are returned in order and the last one repeats, so a single
    response covers a run that needs no repair and a list exercises the
    repair loop deterministically. Every prompt pair is recorded, which is
    how a test asserts what the generator asked for.
    """

    def __init__(self, responses: list[str | dict]) -> None:
        if not responses:
            raise ValueError("StubLanguageModel requires at least one response")
        self._responses = [
            json.dumps(item) if isinstance(item, dict) else item for item in responses
        ]
        self.prompts: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if len(self.prompts) <= len(self._responses):
            return self._responses[len(self.prompts) - 1]
        return self._responses[-1]
