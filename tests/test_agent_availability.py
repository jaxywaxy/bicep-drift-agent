"""Whether an LLM is available is a PROVIDER question, not an Anthropic one.

`analyze_drift.py` decided it like this:

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    agent = DriftAgent(api_key=api_key) if api_key else None

So with DRIFT_LLM_PROVIDER=azure_openai and no Anthropic key - the entire point
of the Entra path, and the exact CI configuration - no agent was constructed and
the analysis was silently skipped. The run succeeded, the report was complete and
correct, and the narrative was simply absent. The only signal named a variable
the operator had deliberately not set.

The seam moved the CLIENT behind a provider and left the decision to have a
client at all keyed to one vendor. 1151 tests passed because every one of them
enters BELOW this line - `evals/run.py` constructs DriftAgent directly, which is
why the eval was green while the pipeline could not work.
"""

import unittest
from unittest import mock

from agent.llm import build_provider_or_reason

_AZURE_OK = {
    "DRIFT_LLM_PROVIDER": "azure_openai",
    "AZURE_OPENAI_ENDPOINT": "https://x.openai.azure.com/",
    "AZURE_OPENAI_DEPLOYMENT": "gpt-5-mini",
}


class _FakeSDKModule:
    def __init__(self, **kwargs):
        self.chat = type("Chat", (), {"completions": None})()


class AzureIsUsableWithoutAnAnthropicKeyTests(unittest.TestCase):
    """The regression that mattered."""

    def test_a_configured_azure_provider_is_returned(self):
        import agent.llm.azure_openai_provider as mod
        with mock.patch.dict("os.environ", _AZURE_OK, clear=True), \
             mock.patch.object(mod, "_import_sdk", return_value=_FakeSDKModule), \
             mock.patch.object(mod, "_bearer_token_provider", return_value=lambda: "t"):
            provider, reason = build_provider_or_reason()
        self.assertIsNotNone(provider, f"azure was configured yet refused: {reason}")
        self.assertIsNone(reason)
        self.assertEqual(provider.name, "azure_openai")

    def test_an_anthropic_key_is_not_required_for_azure(self):
        import agent.llm.azure_openai_provider as mod
        env = dict(_AZURE_OK)  # deliberately no ANTHROPIC_API_KEY
        with mock.patch.dict("os.environ", env, clear=True), \
             mock.patch.object(mod, "_import_sdk", return_value=_FakeSDKModule), \
             mock.patch.object(mod, "_bearer_token_provider", return_value=lambda: "t"):
            provider, _ = build_provider_or_reason()
        self.assertIsNotNone(provider)


class UnusableProvidersExplainThemselvesTests(unittest.TestCase):
    """Skipping the analysis is fine - it is optional by design. Skipping it
    without saying which provider and why is what wasted a live run."""

    def test_anthropic_without_a_key_is_unusable_and_says_so(self):
        with mock.patch.dict("os.environ", {"DRIFT_LLM_PROVIDER": "anthropic"}, clear=True):
            provider, reason = build_provider_or_reason()
        self.assertIsNone(provider)
        self.assertIn("ANTHROPIC_API_KEY", reason)

    def test_anthropic_with_a_key_is_usable(self):
        with mock.patch.dict("os.environ",
                             {"DRIFT_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "k"},
                             clear=True):
            provider, reason = build_provider_or_reason()
        self.assertIsNotNone(provider, reason)

    def test_azure_missing_its_deployment_names_that_variable(self):
        import agent.llm.azure_openai_provider as mod
        env = {"DRIFT_LLM_PROVIDER": "azure_openai",
               "AZURE_OPENAI_ENDPOINT": "https://x/"}
        with mock.patch.dict("os.environ", env, clear=True), \
             mock.patch.object(mod, "_import_sdk", return_value=_FakeSDKModule):
            provider, reason = build_provider_or_reason()
        self.assertIsNone(provider)
        self.assertIn("AZURE_OPENAI_DEPLOYMENT", reason)

    def test_the_reason_names_the_provider_that_was_selected(self):
        with mock.patch.dict("os.environ", {"DRIFT_LLM_PROVIDER": "anthropic"}, clear=True):
            _, reason = build_provider_or_reason()
        self.assertIn("anthropic", reason.lower())

    def test_an_unknown_provider_is_reported_not_raised(self):
        # The analysis is optional; a typo must degrade, not abort the scan.
        with mock.patch.dict("os.environ", {"DRIFT_LLM_PROVIDER": "gemini"}, clear=True):
            provider, reason = build_provider_or_reason()
        self.assertIsNone(provider)
        self.assertIn("gemini", reason)

    def test_a_missing_sdk_is_reported_not_raised(self):
        import agent.llm.azure_openai_provider as mod
        with mock.patch.dict("os.environ", _AZURE_OK, clear=True), \
             mock.patch.object(mod, "_import_sdk", side_effect=ImportError("No module named 'openai'")):
            provider, reason = build_provider_or_reason()
        self.assertIsNone(provider)
        self.assertIn("pip install", reason.lower())


class ThePipelineAsksTheSeamNotTheEnvironmentTests(unittest.TestCase):
    """Pins the actual regression site: analyze_drift must not decide agent
    availability by reading one vendor's variable."""

    def test_analyze_drift_does_not_gate_on_the_anthropic_key(self):
        import pathlib
        src = pathlib.Path("analyze_drift.py").read_text()
        self.assertNotIn('api_key = os.environ.get("ANTHROPIC_API_KEY")', src)
        self.assertIn("build_provider_or_reason", src)


if __name__ == "__main__":
    unittest.main()
