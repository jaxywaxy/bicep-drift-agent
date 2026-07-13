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


class CreateMessageRecordingTests(unittest.TestCase):
    def _agent(self):
        agent = DriftAgent(api_key="test-key", model="claude-opus-4-8")
        agent.client = mock.MagicMock()
        agent.client.messages.create.return_value = SimpleNamespace(
            content=[SimpleNamespace(text="do the thing")],
            usage=_usage(1234, 56),
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
