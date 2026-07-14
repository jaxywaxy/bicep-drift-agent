"""
Unit tests for the recommendation cost guards.

A scan of a deleted resource group produced 53 missing_in_azure drifts and one
Claude recommendation call each: 54 calls, $0.88, 7+ minutes of near-identical
"redeploy" advice. Two guards bound the spend: an estate-level short-circuit
(everything missing + live state empty -> zero per-drift calls) and a
DRIFT_MAX_RECOMMENDATIONS cap prioritised by property severity.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyze_drift


class FakeAgent:
    def __init__(self):
        self.called_for = []

    def get_drift_recommendation(self, resource_type, resource_name, drift_type, details):
        self.called_for.append(resource_name)
        return f"rec for {resource_name}"


def _missing(name):
    return {"type": "Microsoft.Web/sites", "name": name,
            "drift_type": "missing_in_azure", "details": {}}


def _prop(name, severity=None):
    changed = {"properties.x": ({"severity": severity} if severity else {})}
    return {"type": "Microsoft.Web/sites", "name": name,
            "drift_type": "property_drift",
            "details": {"changed_properties": changed}}


class RecommendationGuardTests(unittest.TestCase):
    def test_estate_wipe_skips_all_claude_calls(self):
        agent = FakeAgent()
        drifts = [_missing(f"res{i}") for i in range(50)]
        analyze_drift._generate_recommendations(agent, drifts, live_resource_count=0)
        self.assertEqual(agent.called_for, [])
        for d in drifts:
            self.assertIn("Estate-level event", d["recommendation"])

    def test_estate_wipe_not_triggered_when_live_resources_exist(self):
        agent = FakeAgent()
        drifts = [_missing(f"res{i}") for i in range(3)]
        analyze_drift._generate_recommendations(agent, drifts, live_resource_count=17)
        self.assertEqual(len(agent.called_for), 3)

    def test_single_missing_with_empty_live_still_gets_recommendation(self):
        # One drift is not an estate event even if live state is empty.
        agent = FakeAgent()
        drifts = [_missing("res0")]
        analyze_drift._generate_recommendations(agent, drifts, live_resource_count=0)
        self.assertEqual(len(agent.called_for), 1)

    def test_cap_limits_calls_and_notes_the_rest(self):
        agent = FakeAgent()
        drifts = [_prop(f"res{i}") for i in range(20)]
        with mock.patch.dict(os.environ, {"DRIFT_MAX_RECOMMENDATIONS": "5"}):
            analyze_drift._generate_recommendations(agent, drifts, live_resource_count=20)
        self.assertEqual(len(agent.called_for), 5)
        capped = [d for d in drifts if "capped at 5" in d.get("recommendation", "")]
        self.assertEqual(len(capped), 15)

    def test_cap_prioritises_critical_property_drift(self):
        agent = FakeAgent()
        drifts = (
            [_missing(f"miss{i}") for i in range(10)]
            + [_prop("crit1", "critical"), _prop("crit2", "critical")]
            + [_prop("warn1", "warning")]
        )
        with mock.patch.dict(os.environ, {"DRIFT_MAX_RECOMMENDATIONS": "3"}):
            analyze_drift._generate_recommendations(agent, drifts, live_resource_count=20)
        self.assertEqual(sorted(agent.called_for), ["crit1", "crit2", "warn1"])

    def test_cap_zero_means_unlimited(self):
        agent = FakeAgent()
        drifts = [_prop(f"res{i}") for i in range(20)]
        with mock.patch.dict(os.environ, {"DRIFT_MAX_RECOMMENDATIONS": "0"}):
            analyze_drift._generate_recommendations(agent, drifts, live_resource_count=20)
        self.assertEqual(len(agent.called_for), 20)

    def test_default_cap_leaves_small_runs_untouched(self):
        agent = FakeAgent()
        drifts = [_prop(f"res{i}") for i in range(5)] + [_missing("gone")]
        env = {k: v for k, v in os.environ.items() if k != "DRIFT_MAX_RECOMMENDATIONS"}
        with mock.patch.dict(os.environ, env, clear=True):
            analyze_drift._generate_recommendations(agent, drifts, live_resource_count=9)
        self.assertEqual(len(agent.called_for), 6)

    def test_matched_unresolvable_still_skipped(self):
        agent = FakeAgent()
        drifts = [
            {"type": "t", "name": "reconciled", "drift_type": "matched_unresolvable", "details": {}},
            _prop("real"),
        ]
        analyze_drift._generate_recommendations(agent, drifts, live_resource_count=5)
        self.assertEqual(agent.called_for, ["real"])

    def test_no_agent_no_calls(self):
        drifts = [_prop("res0")]
        analyze_drift._generate_recommendations(None, drifts, live_resource_count=5)
        self.assertNotIn("recommendation", drifts[0])


if __name__ == "__main__":
    unittest.main()
