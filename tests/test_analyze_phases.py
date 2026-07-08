"""Regression tests for the deterministic phase functions extracted from
analyze_drift.main(). These exercise the smart-match -> ignore -> property-drift
merge pipeline without Claude or Azure."""

import unittest

import analyze_drift as ad
from tools.ignore_patterns import IgnorePatternList


def _report_with_unique_named_storage(bicep_sku, live_sku):
    return {
        "bicep_file": "main.bicep",
        "resource_group": "rg-test",
        "arm_resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "sttest[uniqueString(resourceGroup().id)]",
                "location": "eastus",
                "sku": {"name": bicep_sku},
                "properties": {},
            }
        ],
        "live_resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "sttestabc123",
                "location": "eastus",
                "sku": {"name": live_sku},
                "properties": {"provisioningState": "Succeeded"},
            }
        ],
        "drifts": [],
    }


class TestSmartMatching(unittest.TestCase):
    def test_reconciles_unique_string_name_to_live(self):
        report = _report_with_unique_named_storage("Standard_LRS", "Standard_LRS")
        ad._apply_smart_matching(report)
        self.assertIn("smart_matched", report)
        self.assertEqual(
            [m.get("matched_to") for m in report["smart_matched"]], ["sttestabc123"]
        )

    def test_no_unresolvable_names_is_noop(self):
        report = {
            "arm_resources": [
                {"type": "Microsoft.Storage/storageAccounts", "name": "stfixed", "properties": {}}
            ],
            "live_resources": [],
            "drifts": [],
        }
        ad._apply_smart_matching(report)
        self.assertNotIn("smart_matched", report)


class TestPropertyDriftMerge(unittest.TestCase):
    def test_sku_drift_on_matched_resource_merges_into_drifts(self):
        report = _report_with_unique_named_storage("Standard_LRS", "Standard_GRS")
        ad._apply_smart_matching(report)
        ignore_list = ad._apply_ignore_patterns(report, "main.bicep")
        ad._detect_and_merge_property_drift(report, ignore_list)

        prop = [d for d in report["drifts"] if d.get("drift_type") == "property_drift"]
        self.assertEqual(len(prop), 1)
        self.assertIn("sku.name", prop[0]["details"]["changed_properties"])

    def test_no_drift_when_config_matches(self):
        report = _report_with_unique_named_storage("Standard_LRS", "Standard_LRS")
        ad._apply_smart_matching(report)
        ignore_list = ad._apply_ignore_patterns(report, "main.bicep")
        ad._detect_and_merge_property_drift(report, ignore_list)
        prop = [d for d in report["drifts"] if d.get("drift_type") == "property_drift"]
        self.assertEqual(prop, [])


class TestIgnorePatterns(unittest.TestCase):
    def test_returns_ignore_pattern_list(self):
        report = {"arm_resources": [], "live_resources": [], "drifts": []}
        result = ad._apply_ignore_patterns(report, "main.bicep")
        self.assertIsInstance(result, IgnorePatternList)


class TestClaudeAndRecommendationsNoAgent(unittest.TestCase):
    def test_analysis_without_agent_returns_none(self):
        report = {"bicep_file": "m.bicep", "resource_group": "rg", "drifts": []}
        self.assertIsNone(ad._run_claude_analysis(None, report))

    def test_recommendations_without_agent_is_noop(self):
        drifts = [{"type": "X", "name": "y", "drift_type": "missing_in_azure"}]
        ad._generate_recommendations(None, drifts)
        self.assertNotIn("recommendation", drifts[0])

    def test_recommendations_skip_matched_unresolvable(self):
        # matched_unresolvable is informational, not actionable: it must NOT
        # trigger a Claude call, while real drift types still do.
        class _FakeAgent:
            def __init__(self):
                self.called_for = []

            def get_drift_recommendation(self, resource_type, resource_name, drift_type, details):
                self.called_for.append(resource_name)
                return "rec"

        drifts = [
            {"type": "X", "name": "missing", "drift_type": "missing_in_azure"},
            {"type": "X", "name": "reconciled", "drift_type": "matched_unresolvable"},
            {"type": "X", "name": "changed", "drift_type": "property_drift"},
        ]
        agent = _FakeAgent()
        ad._generate_recommendations(agent, drifts)

        self.assertEqual(sorted(agent.called_for), ["changed", "missing"])
        # The informational entry is left untouched (no recommendation added).
        reconciled = next(d for d in drifts if d["name"] == "reconciled")
        self.assertNotIn("recommendation", reconciled)


class TestLifecycleEmptyDrifts(unittest.TestCase):
    def test_no_drifts_skips_azure_calls(self):
        # With zero drifts the function returns immediately without touching Azure.
        report = {"drifts": []}
        self.assertEqual(ad._build_lifecycle_and_split(report, "rg-test"), [])


if __name__ == "__main__":
    unittest.main()
