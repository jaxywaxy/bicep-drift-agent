"""
Unit tests for per-run Claude cost telemetry: AgentUsage accumulation, the
model pricing table (prefix matching, cache multipliers, unknown-model
behavior), and the DriftAgent._create_message recording path.
"""

import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.drift_agent import AgentUsage, DriftAgent
from agent.llm import LLMResponse


def _usage(inp=0, out=0, cw=0, cr=0):
    return SimpleNamespace(
        input_tokens=inp,
        output_tokens=out,
        cache_creation_input_tokens=cw,
        cache_read_input_tokens=cr,
    )


class AgentUsageTests(unittest.TestCase):
    def test_empty_usage_costs_zero(self):
        u = AgentUsage()
        self.assertEqual(u.cost_usd(), 0.0)
        self.assertEqual(u.to_dict()["estimated_cost_usd"], 0.0)

    def test_accumulates_across_calls(self):
        u = AgentUsage()
        u.record("claude-opus-4-8", _usage(1000, 200))
        u.record("claude-opus-4-8", _usage(500, 100))
        self.assertEqual(u.calls, 2)
        self.assertEqual(u.input_tokens, 1500)
        self.assertEqual(u.output_tokens, 300)

    def test_opus_pricing(self):
        u = AgentUsage()
        u.record("claude-opus-4-8", _usage(1_000_000, 1_000_000))
        self.assertAlmostEqual(u.cost_usd(), 5.00 + 25.00)

    def test_cache_multipliers(self):
        u = AgentUsage()
        # 1M cache-read at 0.1x input price + 1M cache-write at 1.25x
        u.record("claude-opus-4-8", _usage(0, 0, cw=1_000_000, cr=1_000_000))
        self.assertAlmostEqual(u.cost_usd(), 5.00 * 0.1 + 5.00 * 1.25)

    def test_dated_full_id_matches_alias_prefix(self):
        u = AgentUsage()
        u.record("claude-haiku-4-5-20251001", _usage(1_000_000, 0))
        self.assertAlmostEqual(u.cost_usd(), 1.00)

    def test_unknown_model_reports_tokens_but_no_dollars(self):
        u = AgentUsage()
        u.record("claude-future-9", _usage(1000, 1000))
        self.assertIsNone(u.cost_usd())
        d = u.to_dict()
        self.assertIsNone(d["estimated_cost_usd"])
        self.assertEqual(d["input_tokens"], 1000)
        self.assertIn("unknown", u.summary())

    def test_missing_cache_fields_tolerated(self):
        u = AgentUsage()
        u.record("claude-opus-4-8", SimpleNamespace(input_tokens=10, output_tokens=5))
        self.assertEqual(u.cache_read_input_tokens, 0)
        self.assertIsNotNone(u.cost_usd())

    def test_summary_contains_cost(self):
        u = AgentUsage()
        u.record("claude-opus-4-8", _usage(2000, 1000))
        self.assertIn("$", u.summary())
        self.assertIn("2000 in / 1000 out", u.summary())


class PricingOverrideTests(unittest.TestCase):
    """The built-in table is Anthropic-only, so the provider swap left the cost
    line reading "unknown". DRIFT_MODEL_PRICING keeps it current without a code
    change - Azure OpenAI rates vary by region and tier, so there is no single
    correct row to ship."""

    def _cost(self, model, pricing=None, inp=1_000_000, out=1_000_000):
        env = {"DRIFT_MODEL_PRICING": pricing} if pricing is not None else {}
        with mock.patch.dict(os.environ, env, clear=False):
            if pricing is None:
                os.environ.pop("DRIFT_MODEL_PRICING", None)
            u = AgentUsage()
            u.record(model, _usage(inp, out))
            return u.cost_usd()

    def test_an_override_prices_a_model_the_table_never_knew(self):
        self.assertAlmostEqual(
            self._cost("gpt-5-mini", '{"gpt-5-mini": [0.25, 2.00]}'), 2.25)

    def test_without_an_override_that_model_has_no_price(self):
        self.assertIsNone(self._cost("gpt-5-mini"),
                          "an unpriced model must report tokens without dollars, not a guess")

    def test_an_override_beats_a_built_in_row(self):
        # Prices move; the operator's number must win over the shipped one.
        self.assertAlmostEqual(
            self._cost("claude-opus-4-8", '{"claude-opus-4-8": [1.00, 1.00]}'), 2.00)

    def test_longest_matching_prefix_wins(self):
        # Not cosmetic: with both rows present, first-match would bill mini at
        # the full model's rate on dict order alone.
        both = '{"gpt-5": [1.25, 10.00], "gpt-5-mini": [0.25, 2.00]}'
        self.assertAlmostEqual(self._cost("gpt-5-mini", both), 2.25)
        self.assertAlmostEqual(self._cost("gpt-5", both), 11.25)

    def test_longest_prefix_wins_regardless_of_declaration_order(self):
        reversed_order = '{"gpt-5-mini": [0.25, 2.00], "gpt-5": [1.25, 10.00]}'
        self.assertAlmostEqual(self._cost("gpt-5-mini", reversed_order), 2.25)

    def test_malformed_pricing_leaves_cost_unknown_rather_than_wrong(self):
        # A pricing typo must never fail a scan, and must never half-parse into
        # a number someone is billed against.
        for bad in ('{oops', '[1, 2]', '{"gpt-5-mini": 0.25}',
                    '{"gpt-5-mini": [0.25]}', '{"gpt-5-mini": ["a", "b"]}',
                    '{"gpt-5-mini": [-1, 2]}', '{"gpt-5-mini": [true, true]}'):
            with self.subTest(bad=bad):
                with self.assertLogs("tools.config", level="WARNING"):
                    self.assertIsNone(self._cost("gpt-5-mini", bad))

    def test_one_bad_row_does_not_discard_the_good_ones(self):
        with self.assertLogs("tools.config", level="WARNING"):
            self.assertAlmostEqual(
                self._cost("gpt-5-mini", '{"gpt-5-mini": [0.25, 2.00], "bad": [1]}'), 2.25)

    def test_summary_names_the_variable_that_would_fix_it(self):
        u = AgentUsage()
        u.record("gpt-5-mini", _usage(10, 10))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DRIFT_MODEL_PRICING", None)
            self.assertIn("DRIFT_MODEL_PRICING", u.summary())


class PricingConfigValidationTests(unittest.TestCase):
    def test_a_set_but_unusable_variable_is_surfaced(self):
        # Silently ignored, the cost reads "unknown" and nobody connects it to
        # the override they set.
        from tools.config import validate_config
        with mock.patch.dict(os.environ, {"DRIFT_MODEL_PRICING": "{oops"}):
            with self.assertLogs("tools.config", level="WARNING"):
                warnings = validate_config()
        self.assertTrue(any("DRIFT_MODEL_PRICING" in w for w in warnings))

    def test_a_valid_variable_produces_no_warning(self):
        from tools.config import validate_config
        with mock.patch.dict(os.environ, {"DRIFT_MODEL_PRICING": '{"gpt-5-mini": [0.25, 2.0]}'}):
            self.assertFalse(any("DRIFT_MODEL_PRICING" in w for w in validate_config()))


class CreateMessageRecordingTests(unittest.TestCase):
    def _agent(self):
        agent = DriftAgent(api_key="test-key", model="claude-opus-4-8")
        # Stubbed at the SEAM, not at the vendor SDK: above agent/llm/ nothing
        # should know what an Anthropic response looks like.
        agent.provider = mock.MagicMock()
        agent.provider.complete.return_value = LLMResponse(
            text="do the thing", usage=_usage(1234, 56),
        )
        return agent

    def test_recommendation_call_records_usage(self):
        agent = self._agent()
        rec = agent.get_drift_recommendation(
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="st1",
            drift_type="property_drift",
            details={"changed_properties": {"properties.allowBlobPublicAccess": {}}},
        )
        self.assertEqual(rec, "do the thing")
        self.assertEqual(agent.usage.calls, 1)
        self.assertEqual(agent.usage.input_tokens, 1234)
        self.assertEqual(agent.usage.output_tokens, 56)

    def test_usage_survives_multiple_calls(self):
        agent = self._agent()
        for _ in range(3):
            agent.get_drift_recommendation(
                resource_type="t", resource_name="n", drift_type="extra_in_azure")
        self.assertEqual(agent.usage.calls, 3)
        self.assertEqual(agent.usage.to_dict()["models"], ["claude-opus-4-8"])


if __name__ == "__main__":
    unittest.main()
