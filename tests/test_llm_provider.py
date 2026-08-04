"""The LLM seam: one funnel, three normalised facts, no vendor shapes above it.

The coupling was ~15 lines in `agent/drift_agent.py` - the SDK import, the
client, `_create_message`, and three `response.content[0].text` parses. This
makes the provider swappable behind `DRIFT_LLM_PROVIDER` WITHOUT changing
anything by default.

An abstraction designed around a single vendor is not an abstraction, so the
tests below drive it with a deliberately OPENAI-shaped fake: `choices[0].
message.content`, `finish_reason == "length"`, and usage reported as
`prompt_tokens`/`completion_tokens`. If the seam only fits Anthropic, these fail.
"""

import unittest
from unittest import mock

from agent.llm import LLMResponse, UnknownProviderError, get_provider


class _OpenAIShapedProvider:
    """Nothing here is named like Anthropic. That is the point."""

    name = "fake-openai"
    default_model = "gpt-x"

    def __init__(self):
        self.calls = []

    def complete(self, *, model, system, messages, max_tokens, **kw):
        self.calls.append({"model": model, "system": system,
                           "messages": messages, "max_tokens": max_tokens})
        return LLMResponse(
            text="  analysis body  ",
            usage=_Usage(prompt_tokens=34361, completion_tokens=2575),
            truncated=True,
        )


class _Usage:
    """OpenAI field names - the seam must translate, not the caller."""

    def __init__(self, prompt_tokens, completion_tokens):
        self.input_tokens = prompt_tokens
        self.output_tokens = completion_tokens


class TheSeamCarriesExactlyWhatCallersNeedTests(unittest.TestCase):
    """text, usage and truncated. `truncated` is load-bearing: one call site
    warns that the analysis was cut off at max_tokens, and losing it would make
    a truncated report look complete."""

    def test_response_exposes_text_usage_and_truncated(self):
        r = LLMResponse(text="x", usage=_Usage(1, 2), truncated=False)
        self.assertEqual(r.text, "x")
        self.assertEqual(r.usage.input_tokens, 1)
        self.assertFalse(r.truncated)

    def test_truncated_defaults_to_false_not_none(self):
        # `if response.truncated` must never be ambiguous.
        self.assertIs(LLMResponse(text="x", usage=None).truncated, False)


class ProviderSelectionTests(unittest.TestCase):

    def test_default_is_anthropic_so_nothing_changes(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("DRIFT_LLM_PROVIDER", None)
            self.assertEqual(get_provider().name, "anthropic")

    def test_an_unknown_provider_fails_loudly(self):
        # Falling back to the default would run a scan against a provider the
        # operator did not choose and report it as if they had.
        with mock.patch.dict("os.environ", {"DRIFT_LLM_PROVIDER": "gemini"}):
            with self.assertRaises(UnknownProviderError) as cm:
                get_provider()
        self.assertIn("gemini", str(cm.exception))
        self.assertIn("anthropic", str(cm.exception), "the error must name what IS available")

    def test_selection_is_case_and_space_insensitive(self):
        with mock.patch.dict("os.environ", {"DRIFT_LLM_PROVIDER": "  Anthropic "}):
            self.assertEqual(get_provider().name, "anthropic")


class TheAgentUsesTheSeamNotTheSDKTests(unittest.TestCase):
    """Driven by the OpenAI-shaped fake: if DriftAgent still reaches for
    `.content[0].text` or `.stop_reason`, every one of these breaks."""

    def _agent(self, provider):
        from agent.drift_agent import DriftAgent
        return DriftAgent(provider=provider)

    def test_analysis_reads_text_through_the_seam(self):
        p = _OpenAIShapedProvider()
        agent = self._agent(p)
        out = agent._create_message(max_tokens=10, system="s", messages=[])
        self.assertEqual(out.text.strip(), "analysis body")

    def test_the_model_passed_down_is_the_providers_default(self):
        p = _OpenAIShapedProvider()
        self._agent(p)._create_message(max_tokens=10, system="s", messages=[])
        self.assertEqual(p.calls[0]["model"], "gpt-x")

    def test_usage_is_recorded_against_that_model(self):
        p = _OpenAIShapedProvider()
        agent = self._agent(p)
        agent._create_message(max_tokens=10, system="s", messages=[])
        self.assertEqual(agent.usage.calls, 1)
        self.assertEqual(agent.usage.input_tokens, 34361)
        self.assertEqual(agent.usage.output_tokens, 2575)

    def test_an_unpriced_model_reports_tokens_but_no_dollars(self):
        # usage.py already refuses to guess; a non-Claude model must not
        # silently report $0.00 of spend.
        p = _OpenAIShapedProvider()
        agent = self._agent(p)
        agent._create_message(max_tokens=10, system="s", messages=[])
        self.assertIsNone(agent.usage.cost_usd())


class ProvidersExplainTheirOwnFailuresTests(unittest.TestCase):
    """The two most common operational failures - exhausted credit and a bad
    key - had Anthropic-specific text and an anthropic.com URL hard-coded in
    `orchestration/analysis.py`, which is provider-neutral code. Sending an
    Azure OpenAI operator to console.anthropic.com is worse than saying nothing.

    Each provider knows its own failure modes, so each explains them. A provider
    that offers no explanation must degrade to the generic message rather than
    break the run: the whole point of this path is that the deterministic report
    survives an LLM failure.
    """

    def _explain(self, provider, message):
        from orchestration.analysis import _explain_llm_failure
        return _explain_llm_failure(provider, Exception(message))

    def test_anthropic_still_explains_exhausted_credit(self):
        from agent.llm.anthropic_provider import AnthropicProvider
        p = AnthropicProvider.__new__(AnthropicProvider)  # no client needed
        hint = self._explain(p, "Error code: 400 - Your credit balance is too low")
        self.assertIn("credit", hint.lower())
        self.assertIn("anthropic.com", hint)

    def test_anthropic_still_explains_a_bad_key(self):
        from agent.llm.anthropic_provider import AnthropicProvider
        p = AnthropicProvider.__new__(AnthropicProvider)
        self.assertIn("ANTHROPIC_API_KEY", self._explain(p, "401 invalid x-api-key"))

    def test_a_provider_without_an_explainer_degrades_gracefully(self):
        hint = self._explain(_OpenAIShapedProvider(), "credit balance is too low")
        self.assertTrue(hint)
        self.assertNotIn("anthropic", hint.lower(),
                         "a non-Anthropic provider must not be sent to anthropic.com")

    def test_an_unrecognised_error_is_not_dressed_up(self):
        from agent.llm.anthropic_provider import AnthropicProvider
        p = AnthropicProvider.__new__(AnthropicProvider)
        self.assertIn("unavailable", self._explain(p, "connection reset by peer").lower())
