"""
agent/llm/anthropic_provider.py

The Anthropic implementation of the seam - and the only module in the codebase
that imports the SDK.
"""

import os
from typing import Any

from agent.llm import LLMResponse


class AnthropicProvider:
    name = "anthropic"
    default_model = "claude-opus-4-8"

    def __init__(self, api_key: str | None = None, **_: Any):
        from anthropic import Anthropic  # local: keeps the SDK out of import paths that never call it
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = Anthropic(api_key=self._api_key)

    def configuration_error(self) -> str | None:
        """Why this provider cannot run, or None.

        The SDK constructs happily without a key and only fails at call time, so
        the caller needs to ask. Reported rather than raised: the analysis is
        optional by design, and a missing key must degrade the run, not abort it.
        """
        if not self._api_key:
            return "ANTHROPIC_API_KEY is not set"
        return None

    @staticmethod
    def explain_error(exc: Exception) -> str | None:
        """Plain-language cause for the two failures operators actually hit.

        Lives HERE because the remediation is vendor-specific - an Azure OpenAI
        operator sent to console.anthropic.com is worse off than one told
        nothing. Returns None when the error is not one we recognise, so the
        caller can say so honestly instead of inventing a cause (#337, one level
        down: never assert a cause you cannot explain).
        """
        msg = str(exc)
        low = msg.lower()
        if "credit balance is too low" in msg or "billing" in low:
            return ("Anthropic API credit exhausted - top up at "
                    "console.anthropic.com/settings/billing")
        if "authentication" in low or "401" in msg or "invalid x-api-key" in low:
            return "ANTHROPIC_API_KEY is invalid or revoked"
        return None

    def complete(self, *, model: str, system: str, messages: list[dict],
                 max_tokens: int, **kwargs: Any) -> LLMResponse:
        response = self._client.messages.create(
            model=model, system=system, messages=messages,
            max_tokens=max_tokens, **kwargs,
        )
        blocks = getattr(response, "content", None) or []
        return LLMResponse(
            text=(getattr(blocks[0], "text", "") if blocks else ""),
            usage=getattr(response, "usage", None),
            truncated=getattr(response, "stop_reason", None) == "max_tokens",
        )
