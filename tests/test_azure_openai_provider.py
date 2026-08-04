"""The Azure OpenAI provider: same seam, a genuinely different vendor shape.

This is what proves `agent/llm/` is an abstraction rather than an
Anthropic-shaped hole. Everything below runs with an injected fake client - no
Azure access, no API key, no quota - because a provider you cannot test until
infrastructure lands is a provider nobody writes.
"""

import unittest
from unittest import mock

from agent.llm import LLMResponse, get_provider
from agent.llm.azure_openai_provider import AzureOpenAIProvider


class _FakeCompletions:
    def __init__(self, outer):
        self._outer = outer

    def create(self, **kwargs):
        self._outer.calls.append(kwargs)
        if self._outer.reject_param and self._outer.reject_param in kwargs:
            raise RuntimeError(
                f"400 Unsupported parameter: '{self._outer.reject_param}' is not supported "
                "with this model. Use 'max_tokens' instead."
            )
        return _FakeResponse(self._outer.finish_reason)


class _FakeClient:
    """Shaped like the OpenAI SDK, named nothing like Anthropic."""

    def __init__(self, finish_reason="stop", reject_param=None):
        self.calls = []
        self.finish_reason = finish_reason
        self.reject_param = reject_param
        self.chat = type("Chat", (), {"completions": _FakeCompletions(self)})()


class _FakeResponse:
    def __init__(self, finish_reason):
        msg = type("Msg", (), {"content": "  the analysis  "})()
        self.choices = [type("Choice", (), {"message": msg, "finish_reason": finish_reason})()]
        self.usage = type("U", (), {"prompt_tokens": 11524, "completion_tokens": 2627})()


def _provider(**kw):
    return AzureOpenAIProvider(
        client=_FakeClient(**kw), endpoint="https://x.openai.azure.com/",
        deployment="gpt-5-mini",
    )


class TheVendorShapeIsTranslatedTests(unittest.TestCase):

    def test_the_system_prompt_becomes_a_system_MESSAGE(self):
        # Anthropic takes `system=` as its own argument; OpenAI wants it as the
        # first message. This translation IS the adapter - get it wrong and the
        # model silently loses every rule the prompt encodes.
        p = _provider()
        p.complete(model="gpt-5-mini", system="RULES", messages=[{"role": "user", "content": "hi"}],
                   max_tokens=100)
        sent = p._client.calls[0]["messages"]
        self.assertEqual(sent[0], {"role": "system", "content": "RULES"})
        self.assertEqual(sent[1], {"role": "user", "content": "hi"})

    def test_text_comes_from_choices_not_content_blocks(self):
        r = _provider().complete(model="m", system="s", messages=[], max_tokens=10)
        self.assertEqual(r.text.strip(), "the analysis")

    def test_usage_is_renamed_for_AgentUsage(self):
        # OpenAI says prompt/completion; AgentUsage.record reads input/output.
        # Translating is the PROVIDER's job - callers never see vendor names.
        r = _provider().complete(model="m", system="s", messages=[], max_tokens=10)
        self.assertEqual(r.usage.input_tokens, 11524)
        self.assertEqual(r.usage.output_tokens, 2627)

    def test_truncation_comes_from_finish_reason_length(self):
        r = _provider(finish_reason="length").complete(model="m", system="s", messages=[], max_tokens=10)
        self.assertTrue(r.truncated, "a truncated analysis would look complete")

    def test_a_normal_stop_is_not_truncated(self):
        self.assertFalse(_provider().complete(model="m", system="s", messages=[], max_tokens=10).truncated)

    def test_it_returns_the_shared_LLMResponse(self):
        self.assertIsInstance(_provider().complete(model="m", system="s", messages=[], max_tokens=1),
                              LLMResponse)


class TheTokenCapParameterIsDiscoveredNotGuessedTests(unittest.TestCase):
    """gpt-5 and o-series reject `max_tokens` and require
    `max_completion_tokens`; older deployments are the other way round. Sniffing
    the model NAME would be a heuristic overriding evidence we can actually get -
    the exact defect family that cost this project four PRs. So we send the
    modern parameter, and if the API says otherwise we believe the API."""

    def test_the_modern_parameter_is_sent_first(self):
        p = _provider()
        p.complete(model="m", system="s", messages=[], max_tokens=250)
        self.assertEqual(p._client.calls[0].get("max_completion_tokens"), 250)
        self.assertNotIn("max_tokens", p._client.calls[0])

    def test_a_rejection_is_retried_with_the_legacy_parameter(self):
        p = _provider(reject_param="max_completion_tokens")
        r = p.complete(model="m", system="s", messages=[], max_tokens=250)
        self.assertEqual(r.text.strip(), "the analysis")
        self.assertEqual(p._client.calls[-1].get("max_tokens"), 250)

    def test_the_discovery_happens_once_not_on_every_call(self):
        p = _provider(reject_param="max_completion_tokens")
        p.complete(model="m", system="s", messages=[], max_tokens=1)
        before = len(p._client.calls)
        p.complete(model="m", system="s", messages=[], max_tokens=1)
        self.assertEqual(len(p._client.calls) - before, 1, "it re-probed instead of remembering")


class ItExplainsItsOwnFailuresTests(unittest.TestCase):
    """Quota is the KNOWN constraint here - the deployment is capacity 10
    (10,000 TPM) and one measured call is ~14.2K tokens. A bare 429 would send
    someone hunting; the hint should name the actual cause."""

    def _hint(self, msg):
        return AzureOpenAIProvider.explain_error(RuntimeError(msg))

    def test_429_names_the_quota_cause(self):
        h = self._hint("Error code: 429 - Requests to the ChatCompletions Operation exceeded token rate limit")
        self.assertIn("TPM", h)
        self.assertIn("capacity", h.lower())

    def test_401_points_at_the_role_not_a_key(self):
        h = self._hint("Error code: 401 - PermissionDenied")
        self.assertIn("Cognitive Services OpenAI User", h)

    def test_a_missing_deployment_says_deployment_not_model(self):
        h = self._hint("Error code: 404 - DeploymentNotFound")
        self.assertIn("deployment", h.lower())
        self.assertIn("AZURE_OPENAI_DEPLOYMENT", h)

    def test_an_unrecognised_error_returns_None(self):
        # Never dress up an error we cannot explain (#337, one level down).
        self.assertIsNone(self._hint("connection reset by peer"))


class SelectingItIsSafeWhenTheSDKIsAbsentTests(unittest.TestCase):

    def test_anthropic_still_selectable_without_the_openai_package(self):
        # Registering a second provider must not make the first one's import
        # depend on an SDK it never uses.
        self.assertEqual(get_provider("anthropic").name, "anthropic")

    def test_a_missing_sdk_says_what_to_install(self):
        import agent.llm.azure_openai_provider as mod
        with mock.patch.object(mod, "_import_sdk",
                                        side_effect=ImportError("No module named 'openai'")):
            with self.assertRaises(ImportError) as cm:
                AzureOpenAIProvider(endpoint="https://x/", deployment="d")
        self.assertIn("pip install", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
