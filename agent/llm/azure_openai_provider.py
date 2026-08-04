"""
agent/llm/azure_openai_provider.py

Azure OpenAI behind the same seam.

The reason to run this instead of Anthropic is NOT cost - at one call per scan
the difference is cents. It is **Entra ID auth**: the deployment is reachable
with the workload identity CI already uses for every Azure call, which removes
`ANTHROPIC_API_KEY` from CI secrets entirely and makes the "no stored
credentials" claim in docs/SECURITY.md true rather than aspirational.

Configuration (all env, no code change):
    DRIFT_LLM_PROVIDER=azure_openai
    AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com/
    AZURE_OPENAI_DEPLOYMENT=<deployment name>      # NOT the model name
    AZURE_OPENAI_API_VERSION=2024-10-21            # optional
    AZURE_OPENAI_API_KEY=<key>                     # optional; omit to use Entra

With no key it uses `DefaultAzureCredential`, which needs the identity to hold
**Cognitive Services OpenAI User** on the account. That role is the whole point;
without it this is just another API key in a different vault.
"""

import os
from typing import Any

from agent.llm import LLMResponse

_SCOPE = "https://cognitiveservices.azure.com/.default"
_DEFAULT_API_VERSION = "2024-10-21"


def _import_sdk():
    """Isolated so tests can simulate its absence, and so selecting ANOTHER
    provider never depends on an SDK it does not use."""
    from openai import AzureOpenAI
    return AzureOpenAI


class _Usage:
    """OpenAI reports prompt/completion; `AgentUsage.record` reads input/output.

    Renaming happens HERE. Nothing above `agent/llm/` should know that two
    vendors disagree about what to call a token.
    """

    __slots__ = ("input_tokens", "output_tokens")

    def __init__(self, usage: Any):
        self.input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        self.output_tokens = getattr(usage, "completion_tokens", 0) or 0


class AzureOpenAIProvider:
    name = "azure_openai"

    def __init__(self, api_key: str | None = None, client: Any = None,
                 endpoint: str | None = None, deployment: str | None = None,
                 api_version: str | None = None, **_: Any):
        self.default_model = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "")
        # Discovered on first call, then remembered - see _cap_param below.
        self._cap_param = "max_completion_tokens"

        if client is not None:
            self._client = client
            return

        endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT")
        if not endpoint:
            raise ValueError(
                "AZURE_OPENAI_ENDPOINT is not set. Azure OpenAI needs the resource "
                "endpoint (https://<resource>.openai.azure.com/) and "
                "AZURE_OPENAI_DEPLOYMENT (the DEPLOYMENT name, not the model name)."
            )
        try:
            AzureOpenAI = _import_sdk()
        except ImportError as e:
            raise ImportError(
                "DRIFT_LLM_PROVIDER=azure_openai needs the OpenAI SDK: "
                "pip install openai"
            ) from e

        version = api_version or os.environ.get("AZURE_OPENAI_API_VERSION", _DEFAULT_API_VERSION)
        key = api_key or os.environ.get("AZURE_OPENAI_API_KEY")
        if key:
            self._client = AzureOpenAI(azure_endpoint=endpoint, api_key=key, api_version=version)
        else:
            # Entra path - the reason this provider exists.
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            self._client = AzureOpenAI(
                azure_endpoint=endpoint, api_version=version,
                azure_ad_token_provider=get_bearer_token_provider(
                    DefaultAzureCredential(), _SCOPE),
            )

    def complete(self, *, model: str, system: str, messages: list[dict],
                 max_tokens: int, **kwargs: Any) -> LLMResponse:
        # Anthropic takes `system` as its own argument; OpenAI wants it as the
        # first message. This translation IS the adapter - drop it and the model
        # silently loses every rule the prompt encodes, which no test above this
        # layer would notice.
        payload = [{"role": "system", "content": system}] if system else []
        payload += list(messages or [])

        try:
            response = self._client.chat.completions.create(
                model=model or self.default_model, messages=payload,
                **{self._cap_param: max_tokens}, **kwargs,
            )
        except Exception as e:
            # gpt-5 / o-series require `max_completion_tokens`; older deployments
            # want `max_tokens`. Sniffing the MODEL NAME to decide would be a
            # heuristic overriding evidence we can simply ask for - the defect
            # family that cost this project four PRs. So: send the modern
            # parameter, and when the API says otherwise, believe the API.
            other = "max_tokens" if self._cap_param == "max_completion_tokens" else "max_completion_tokens"
            if self._cap_param in str(e) and "supported" in str(e).lower():
                self._cap_param = other
                response = self._client.chat.completions.create(
                    model=model or self.default_model, messages=payload,
                    **{self._cap_param: max_tokens}, **kwargs,
                )
            else:
                raise

        choices = getattr(response, "choices", None) or []
        first = choices[0] if choices else None
        return LLMResponse(
            text=(getattr(getattr(first, "message", None), "content", "") or "") if first else "",
            usage=_Usage(getattr(response, "usage", None)),
            truncated=getattr(first, "finish_reason", None) == "length",
        )

    @staticmethod
    def explain_error(exc: Exception) -> str | None:
        """Name the cause an operator can act on, or say nothing.

        Quota is the known constraint for this deployment, so a bare 429 - the
        error most likely to be hit first - should not send anyone hunting.
        """
        msg = str(exc)
        low = msg.lower()
        if "429" in msg or "rate limit" in low or "exceeded token rate" in low:
            return ("Azure OpenAI TPM quota exceeded - the deployment's capacity is too low for "
                    "one analysis call (a measured call is ~14K tokens; capacity N = N,000 TPM, "
                    "and concurrent landing zones share it). Raise the deployment capacity.")
        if "401" in msg or "403" in msg or "permissiondenied" in low.replace(" ", "") \
                or "unauthorized" in low:
            return ("Azure OpenAI rejected the credential - with Entra auth the identity needs the "
                    "'Cognitive Services OpenAI User' role on the account; with key auth check "
                    "AZURE_OPENAI_API_KEY")
        if "deploymentnotfound" in low.replace(" ", "") or "404" in msg:
            return ("Azure OpenAI deployment not found - AZURE_OPENAI_DEPLOYMENT must be the "
                    "DEPLOYMENT name, which is not necessarily the model name")
        if "content filter" in low or "content_filter" in low:
            return ("Azure OpenAI content filter blocked the response - drift reports contain "
                    "resource ids and policy text that can trip it; review the filter tier")
        return None
