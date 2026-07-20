"""Regression tests for the deterministic phase functions extracted from
analyze_drift.main(). These exercise the smart-match -> ignore -> property-drift
merge pipeline without Claude or Azure."""

import unittest

import analyze_drift as ad
from tools.ignore_patterns import IgnorePatternList
from tools.count_drifts import tally_report


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


class TestPropertyDriftCanonicalDriftTypes(unittest.TestCase):
    def test_extra_canonicalized_so_scoped_ignore_applies(self):
        # Regression: the Phase 2 diagnostic pass filtered with drift_type "extra"
        # while ignore rules are scoped to "extra_in_azure", so an ignored resource
        # (e.g. a PE's auto-created privatelink A record) leaked back into the
        # report's property_drifts section. The pass must canonicalize before
        # filtering.
        ignore_list = IgnorePatternList([{
            "resource_type": "Microsoft.Network/privateDnsZones/A",
            "resource_name": "privatelink.*",
            "drift_type": "extra_in_azure",
            "reason": "auto-created by PE dns zone group",
        }])
        report = {
            "arm_resources": [
                {"type": "Microsoft.Storage/storageAccounts", "name": "stfixed",
                 "location": "eastus", "sku": {"name": "Standard_LRS"},
                 "properties": {"accessTier": "Hot"}},
            ],
            "live_resources": [
                {"type": "Microsoft.Storage/storageAccounts", "name": "stfixed",
                 "location": "eastus", "sku": {"name": "Standard_LRS"},
                 "properties": {"accessTier": "Hot", "provisioningState": "Succeeded"}},
                {"type": "Microsoft.Network/privateDnsZones/A",
                 "name": "privatelink.vaultcore.azure.net/kv123",
                 "properties": {"ttl": 10}},
            ],
            "drifts": [],
        }
        ad._detect_and_merge_property_drift(report, ignore_list)
        leaked = [d for d in report.get("property_drifts", [])
                  if "privatelink" in (d.get("deployed_name") or d.get("resource_name") or "")]
        self.assertEqual(leaked, [], "ignored extra leaked into property_drifts")


class TestDriftTypeCounts(unittest.TestCase):
    """The summary handed to the analysis agent derives total_drift from these
    counts. property_drift must count as a modification or the summary reports
    total_drift: 0 next to critical findings (the contradiction the agent flagged)."""

    class _D:
        def __init__(self, drift_type):
            self.drift_type = drift_type

    def test_property_drift_counts_as_modified(self):
        missing, extra, modified = ad._drift_type_counts(
            [self._D("property_drift"), self._D("property_drift")]
        )
        self.assertEqual((missing, extra, modified), (0, 0, 2))

    def test_mixed_types_counted_by_bucket(self):
        drifts = [
            self._D("property_drift"),
            self._D("missing_in_azure"),
            self._D("extra_in_azure"),
            self._D("modified"),
        ]
        missing, extra, modified = ad._drift_type_counts(drifts)
        self.assertEqual((missing, extra, modified), (1, 1, 2))
        self.assertEqual(missing + extra + modified, 4)

    def test_matched_unresolvable_is_not_counted(self):
        self.assertEqual(
            ad._drift_type_counts([self._D("matched_unresolvable")]), (0, 0, 0)
        )


class TestFinalizeDriftCount(unittest.TestCase):
    """drift_count is stamped in Phase 1 on the raw drift list; after Phase 2/3
    reconciliation the drifts array is shorter, so the persisted count must be
    recomputed to match (the 40-vs-36 discrepancy seen in live reports)."""

    def test_recomputes_from_final_array(self):
        report = {"drift_count": 40, "drifts": [{"drift_type": "property_drift"}]
                  + [{"drift_type": "matched_unresolvable"} for _ in range(33)]}
        self.assertEqual(ad._finalize_drift_count(report), 1)
        self.assertEqual(report["drift_count"], 1)

    def test_excludes_reconciled_records(self):
        # The live artifact said drift_count: 35 for a run the CI summary and
        # the HTML report both called 2 changed resources, because this field
        # counted matched_unresolvable and they did not.
        report = {"drifts": [
            {"drift_type": "property_drift"},
            {"drift_type": "property_drift"},
        ] + [{"drift_type": "matched_unresolvable"} for _ in range(33)]}
        self.assertEqual(ad._finalize_drift_count(report), 2)

    def test_equals_tally_report_total_issues(self):
        # Both count via COUNTED_TYPES, so the JSON field and the CI headline
        # are the same number by construction, not by coincidence.
        report = {"drifts": [
            {"drift_type": "property_drift"},
            {"drift_type": "extra_in_azure"},
            {"drift_type": "missing_in_azure"},
            {"drift_type": "matched_unresolvable"},
        ]}
        self.assertEqual(ad._finalize_drift_count(report), tally_report(report)["total_issues"])

    def test_unrecognised_type_is_excluded_but_warned(self):
        # A new drift_type must not vanish from every surface in silence.
        report = {"drifts": [{"drift_type": "property_drift"},
                             {"drift_type": "brand_new_type"}]}
        with self.assertLogs(ad.logger, level="WARNING") as captured:
            self.assertEqual(ad._finalize_drift_count(report), 1)
        self.assertIn("brand_new_type", "\n".join(captured.output))

    def test_empty_array_is_zero(self):
        report = {"drift_count": 12, "drifts": []}
        self.assertEqual(ad._finalize_drift_count(report), 0)
        self.assertEqual(report["drift_count"], 0)

    def test_missing_drifts_key_is_zero(self):
        report = {"drift_count": 7}
        self.assertEqual(ad._finalize_drift_count(report), 0)


class TestAttributionRunsBeforeAnalysis(unittest.TestCase):
    """Attribution (_attribute_lifecycle) attaches change_origin + resource_id and
    MUST run before the Claude analysis so they land in the prompt; the policy
    split runs after. Regression: the two were reversed, so the agent saw null
    attribution and told users to 'investigate the Activity Log' even though the
    persisted report carried change_origin.changed_by."""

    def test_main_orders_attribute_analyze_split(self):
        import inspect
        src = inspect.getsource(ad.main)
        i_attr = src.index("_attribute_lifecycle(")
        i_analyze = src.index("_run_claude_analysis(")
        i_split = src.index("_split_policy_and_tag_owners(")
        self.assertLess(i_attr, i_analyze, "attribution must precede the analysis")
        self.assertLess(i_analyze, i_split, "the policy split must follow the analysis")


class TestSplitPreservesAttribution(unittest.TestCase):
    """The policy split moves change_origin.expected==True entries out; attribution
    must stay intact on both the actionable and policy-enforced sides."""

    def test_change_origin_survives_split(self):
        report = {"drifts": [
            {"type": "Microsoft.Network/firewallPolicies", "name": "a",
             "drift_type": "property_drift",
             "change_origin": {"expected": False, "changed_by": "someone@example.com"}},
            {"type": "Microsoft.Network/firewallPolicies", "name": "b",
             "drift_type": "property_drift",
             "change_origin": {"expected": True, "changed_by": "policy"}},
        ]}
        actionable = ad._split_policy_and_tag_owners(report)
        self.assertEqual([d["name"] for d in actionable], ["a"])
        self.assertEqual(report["policy_enforced_drifts"][0]["name"], "b")
        self.assertEqual(actionable[0]["change_origin"]["changed_by"], "someone@example.com")
        self.assertEqual(
            report["policy_enforced_drifts"][0]["change_origin"]["changed_by"], "policy")


class TestClaudeAnalysisNoAgent(unittest.TestCase):
    def test_analysis_without_agent_returns_none(self):
        report = {"bicep_file": "m.bicep", "resource_group": "rg", "drifts": []}
        self.assertIsNone(ad._run_claude_analysis(None, report))

class TestLifecycleEmptyDrifts(unittest.TestCase):
    def test_no_drifts_skips_azure_calls(self):
        # With zero drifts the function returns immediately without touching Azure.
        report = {"drifts": []}
        self.assertEqual(ad._build_lifecycle_and_split(report, "rg-test"), [])


if __name__ == "__main__":
    unittest.main()
