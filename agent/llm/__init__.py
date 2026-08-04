"""
agent/llm/

The one place that knows which LLM vendor is in use.

Above this package nothing touches a vendor SDK or a vendor response shape.
`DriftAgent` sends `(system, messages, max_tokens)` and gets back an
`LLMResponse` carrying the only three facts any caller needed from the
Anthropic object: the text, the usage block, and whether the reply was cut off
at the token cap.

Additive by design: `DRIFT_LLM_PROVIDER` defaults to `anthropic`, so an existing
deployment behaves identically and needs no configuration change.
"""

import os
from dataclasses import dataclass
from typing import Any, Protocol


class UnknownProviderError(ValueError):
    """Configured provider is not registered.

    Raised rather than falling back to the default: silently running against a
    provider the operator did not choose - and reporting the result as if they
    had - is the failure this tool exists to prevent, one level up.
    """


@dataclass
class LLMResponse:
    """A vendor-neutral completion.

    `truncated` is load-bearing, not decoration: the analysis call warns the
    operator when the reply hit `max_tokens`, and a truncated report that looks
    complete is worse than an obviously missing one. It defaults to False rather
    than None so `if response.truncated` is never ambiguous.

    `usage` is duck-typed on `input_tokens` / `output_tokens` (+ optional cache
    fields) because that is what `AgentUsage.record` reads. Translating a
    vendor's own names (OpenAI reports `prompt_tokens` / `completion_tokens`) is
    the PROVIDER's job - callers never see them.
    """

    text: str
    usage: Any = None
    truncated: bool = False


class LLMProvider(Protocol):
    """What a provider must offer. Deliberately small - the three call sites
    pass only system/messages/max_tokens, so anything wider would be inventing
    a requirement no caller has."""

    name: str
    default_model: str

    def complete(self, *, model: str, system: str, messages: list[dict],
                 max_tokens: int, **kwargs: Any) -> LLMResponse:
        ...


# name -> "module:attribute". Resolved one at a time so a provider whose SDK is
# not installed cannot break selection of one whose SDK is.
_REGISTRY = {
    "anthropic": "agent.llm.anthropic_provider:AnthropicProvider",
    "azure_openai": "agent.llm.azure_openai_provider:AzureOpenAIProvider",
}


def _load(path: str):
    import importlib
    module, _, attr = path.partition(":")
    return getattr(importlib.import_module(module), attr)


def get_provider(name: str | None = None, **kwargs: Any) -> LLMProvider:
    """Construct the configured provider. Defaults to anthropic."""
    chosen = (name or os.environ.get("DRIFT_LLM_PROVIDER") or "anthropic").strip().lower()
    if chosen not in _REGISTRY:
        raise UnknownProviderError(
            f"DRIFT_LLM_PROVIDER={chosen!r} is not a known provider. "
            f"Available: {', '.join(sorted(_REGISTRY))}"
        )
    return _load(_REGISTRY[chosen])(**kwargs)
