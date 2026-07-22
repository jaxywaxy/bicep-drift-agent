"""
Unit tests for AI resource drift (Azure OpenAI / AI Services).

Model deployments are ARM-REST-expanded children (Resource Graph doesn't index
them); the drift that matters is model VERSION (pinned vs upgraded) and
sku.capacity (TPM quota). Account networkAcls share Key Vault's
null-means-default-open semantics.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.get_live_state import (
    _cognitive_child,
    _cognitive_deployment_child,
    _is_system_managed_rai_policy,
    _qualify_child_resource_names,
)
from tools.property_drift import PropertyComparator

AI_TYPE = "Microsoft.CognitiveServices/accounts"
DEP_TYPE = "Microsoft.CognitiveServices/accounts/deployments"


def dep_props(version="2024-07-18", capacity=10, upgrade="NoAutoUpgrade"):
    return {
        "type": DEP_TYPE,
        "name": "aidrift/gpt-4o-mini",
        "sku": {"name": "GlobalStandard", "capacity": capacity},
        "properties": {
            "model": {"format": "OpenAI", "name": "gpt-4o-mini", "version": version},
            "versionUpgradeOption": upgrade,
        },
    }


class DeploymentChildShapeTests(unittest.TestCase):
    def test_child_is_named_account_slash_deployment(self):
        raw = {
            "name": "gpt-4o-mini",
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/aidrift/deployments/gpt-4o-mini",
            "sku": {"name": "GlobalStandard", "capacity": 10},
            "properties": {"model": {"name": "gpt-4o-mini", "version": "2024-07-18"}},
        }
        child = _cognitive_deployment_child("aidrift", "rg", raw)
        self.assertEqual(child["type"], DEP_TYPE)
        self.assertEqual(child["name"], "aidrift/gpt-4o-mini")
        self.assertEqual(child["sku"]["capacity"], 10)
        self.assertIsNone(child["location"])  # no false location drift
        self.assertEqual(child["resource_group"], "rg")


class DeploymentDriftTests(unittest.TestCase):
    def test_identical_deployment_is_clean(self):
        self.assertEqual(
            PropertyComparator.compare_properties(dep_props(), dep_props()), []
        )

    def test_model_version_change_is_drift(self):
        diffs = PropertyComparator.compare_properties(
            dep_props(version="2024-07-18"), dep_props(version="2025-01-01")
        )
        self.assertIn("properties.model.version", {d.property_path for d in diffs})

    def test_capacity_bump_is_critical_drift(self):
        # The out-of-band TPM quota bump.
        diffs = PropertyComparator.compare_properties(
            dep_props(capacity=10), dep_props(capacity=100)
        )
        hit = next((d for d in diffs if d.property_path == "sku.capacity"), None)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.severity, "critical")

    def test_azure_augmented_deployment_fields_are_not_drift(self):
        live = dep_props()
        live["properties"]["capabilities"] = {"chatCompletion": "true"}
        live["properties"]["rateLimits"] = [{"key": "request", "count": 10}]
        live["properties"]["provisioningState"] = "Succeeded"
        self.assertEqual(PropertyComparator.compare_properties(dep_props(), live), [])

    def test_upgrade_option_change_is_drift(self):
        diffs = PropertyComparator.compare_properties(
            dep_props(upgrade="NoAutoUpgrade"), dep_props(upgrade="OnceCurrentVersionExpired")
        )
        self.assertIn("properties.versionUpgradeOption", {d.property_path for d in diffs})


class AccountNetworkAclsTests(unittest.TestCase):
    def _acct(self, acls):
        return {
            "type": AI_TYPE,
            "name": "aidrift",
            "location": "australiaeast",
            "properties": {"publicNetworkAccess": "Enabled", "networkAcls": acls},
        }

    def test_null_acls_vs_bicep_default_is_clean(self):
        bicep = self._acct({"defaultAction": "Allow", "ipRules": [], "virtualNetworkRules": []})
        live = self._acct(None)
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_bicep_deny_vs_null_is_critical_drift(self):
        bicep = self._acct({"defaultAction": "Deny", "ipRules": [], "virtualNetworkRules": []})
        live = self._acct(None)
        diffs = PropertyComparator.compare_properties(bicep, live)
        hit = next((d for d in diffs if d.property_path == "properties.networkAcls.defaultAction"), None)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.severity, "critical")

    def test_live_added_ip_rule_is_drift(self):
        bicep = self._acct({"defaultAction": "Deny", "ipRules": []})
        live = self._acct({"defaultAction": "Deny", "ipRules": [{"value": "203.0.113.7"}]})
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertIn("properties.networkAcls.ipRules", {d.property_path for d in diffs})


def cf(name, source, threshold="Medium", enabled=True, blocking=True):
    return {"name": name, "source": source, "severityThreshold": threshold,
            "enabled": enabled, "blocking": blocking}


class ContentFilterTests(unittest.TestCase):
    """raiPolicies contentFilters: identity = (name, source) - names repeat
    across Prompt/Completion, so name-only pairing would cross-match."""

    RAI_TYPE = "Microsoft.CognitiveServices/accounts/raiPolicies"

    def _policy(self, filters):
        return {
            "type": self.RAI_TYPE,
            "name": "aidrift/drifttest-rai",
            "properties": {"basePolicyName": "Microsoft.DefaultV2", "mode": "Blocking",
                           "contentFilters": filters},
        }

    def test_reordered_filters_are_clean(self):
        a = [cf("Hate", "Prompt"), cf("Hate", "Completion"), cf("Violence", "Prompt")]
        b = [cf("Violence", "Prompt"), cf("Hate", "Completion"), cf("Hate", "Prompt")]
        self.assertEqual(
            PropertyComparator.compare_properties(self._policy(a), self._policy(b)), []
        )

    def test_loosened_threshold_on_one_source_is_drift(self):
        # Same name on both sources; only Completion loosened Medium->High.
        # Name-only pairing would match the untouched Prompt entry and miss it.
        bicep = [cf("Hate", "Prompt"), cf("Hate", "Completion")]
        live = [cf("Hate", "Prompt"), cf("Hate", "Completion", threshold="High")]
        diffs = PropertyComparator.compare_properties(self._policy(bicep), self._policy(live))
        self.assertIn("properties.contentFilters", {d.property_path for d in diffs})

    def test_filter_disabled_out_of_band_is_drift(self):
        bicep = [cf("Violence", "Prompt")]
        live = [cf("Violence", "Prompt", enabled=False)]
        diffs = PropertyComparator.compare_properties(self._policy(bicep), self._policy(live))
        self.assertIn("properties.contentFilters", {d.property_path for d in diffs})

    def test_removed_filter_entry_is_drift(self):
        bicep = [cf("Hate", "Prompt"), cf("Hate", "Completion")]
        live = [cf("Hate", "Prompt")]
        diffs = PropertyComparator.compare_properties(self._policy(bicep), self._policy(live))
        self.assertIn("properties.contentFilters", {d.property_path for d in diffs})


class RaiPolicyExpansionTests(unittest.TestCase):
    def test_system_managed_builtins_are_filtered(self):
        self.assertTrue(_is_system_managed_rai_policy(
            {"name": "Microsoft.Default", "properties": {"type": "SystemManaged"}}
        ))
        self.assertFalse(_is_system_managed_rai_policy(
            {"name": "drifttest-rai", "properties": {"type": "UserManaged"}}
        ))

    def test_cognitive_child_shape(self):
        child = _cognitive_child(
            "Microsoft.CognitiveServices/accounts/connections", "aidrift", "rg",
            {"name": "conn-blob", "id": "/x/conn-blob",
             "properties": {"category": "AzureBlob", "authType": "AAD"}},
        )
        self.assertEqual(child["name"], "aidrift/conn-blob")
        self.assertEqual(child["properties"]["authType"], "AAD")
        self.assertIsNone(child["location"])

    def test_project_connection_child_is_nested_name(self):
        child = _cognitive_child(
            "Microsoft.CognitiveServices/accounts/projects/connections",
            "aidrift/proj-drifttest", "rg", {"name": "conn-x", "properties": {}},
        )
        self.assertEqual(child["name"], "aidrift/proj-drifttest/conn-x")

    def test_already_qualified_name_is_not_double_prefixed(self):
        # The projects list API returns 'account/project' names already
        # (live-caught: 'aidrift/aidrift/proj-drifttest' double prefix).
        child = _cognitive_child(
            "Microsoft.CognitiveServices/accounts/projects", "aidrift", "rg",
            {"name": "aidrift/proj-drifttest", "properties": {}},
        )
        self.assertEqual(child["name"], "aidrift/proj-drifttest")


class FirstContactNoiseTests(unittest.TestCase):
    """Live-caught fixes from the SQL/monitoring/messaging first-contact scan."""

    def test_sql_admin_password_is_write_only_and_never_reported(self):
        # Azure never returns it - and comparing it LEAKED the desired value
        # into the report.
        bicep = {"type": "Microsoft.Sql/servers", "name": "sql1",
                 "properties": {"administratorLogin": "driftadmin",
                                "administratorLoginPassword": "S3cret!", "version": "12.0"}}
        live = {"type": "Microsoft.Sql/servers", "name": "sql1",
                "properties": {"administratorLogin": "driftadmin", "version": "12.0"}}
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_location_casing_is_not_drift(self):
        bicep = {"type": "Microsoft.Insights/actionGroups", "name": "ag", "location": "Global",
                 "properties": {"enabled": True}}
        live = {"type": "Microsoft.Insights/actionGroups", "name": "ag", "location": "global",
                "properties": {"enabled": True}}
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_graph_child_rows_get_parent_qualified_names(self):
        # Resource Graph returns SQL databases with the BARE child name, so
        # they double-report as missing+extra against 'server/db' bicep names.
        rows = [{
            "type": "Microsoft.Sql/servers/databases",
            "name": "driftdb",
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sqldrift1/databases/driftdb",
        }]
        _qualify_child_resource_names(rows)
        self.assertEqual(rows[0]["name"], "sqldrift1/driftdb")

    def test_placeholder_child_names_are_smart_matched(self):
        # 'sqldrift[86c9cbf6]/driftdb' has no function-call marker, but IS
        # runtime-generated; without placeholder detection it double-reports.
        from tools.smart_matching import (
            detect_unresolvable_expressions, smart_match_resources,
        )
        arm = {"resources": [
            {"type": "Microsoft.Sql/servers/databases", "name": "sqldrift[86c9cbf6]/driftdb"},
        ]}
        unresolvable = detect_unresolvable_expressions(arm)
        self.assertIn("Microsoft.Sql/servers/databases", unresolvable)

        azure = [
            {"type": "microsoft.sql/servers/databases", "name": "sqldrift3s7c7weddxr3s/master"},
            {"type": "microsoft.sql/servers/databases", "name": "sqldrift3s7c7weddxr3s/driftdb"},
        ]
        matched, _, _ = smart_match_resources(arm["resources"], azure, unresolvable)
        self.assertEqual(len(matched), 1)
        # Suffix tie-break: same-server siblings share the whole prefix; the
        # literal child segment must pick driftdb, not master.
        self.assertEqual(matched[0]["matched_to"], "sqldrift3s7c7weddxr3s/driftdb")

    def test_placeholder_names_skipped_in_phase1(self):
        from tools.diff_states import _should_compare_resource
        self.assertFalse(_should_compare_resource(
            {"type": "Microsoft.Sql/servers/databases", "name": "sqldrift[86c9cbf6]/driftdb"}
        ))
        self.assertTrue(_should_compare_resource(
            {"type": "Microsoft.Sql/servers/databases", "name": "sqldrift1/driftdb"}
        ))

    def test_master_system_database_is_not_extra(self):
        from tools.diff_states import diff_states
        live = [{"type": "microsoft.sql/servers/databases", "name": "sqldrift1/master",
                 "location": "australiaeast", "properties": {}}]
        drifts = diff_states([], live)
        self.assertEqual([d for d in drifts if "master" in d.resource_name], [])

    def test_default_storage_service_containers_are_not_extra(self):
        # blob/file/queue/table 'default' services are auto-created for every
        # storage account; undeclared ones must not be false extras.
        from tools.diff_states import diff_states
        live = [
            {"type": "Microsoft.Storage/storageAccounts/blobServices", "name": "st1/default",
             "location": None, "properties": {}},
            {"type": "Microsoft.Storage/storageAccounts/fileServices", "name": "st1/default",
             "location": None, "properties": {}},
        ]
        drifts = diff_states([], live)
        self.assertEqual([d for d in drifts if d.drift_type == "extra_in_azure"], [])

    def test_declared_blob_service_still_compares(self):
        # A template that DOES declare blobServices/default keeps its row so a
        # real change (e.g. delete-retention) still surfaces.
        from tools.diff_states import filter_unmanaged_live_resources
        bicep = [{"type": "Microsoft.Storage/storageAccounts/blobServices", "name": "st1/default"}]
        live = [{"type": "Microsoft.Storage/storageAccounts/blobServices", "name": "st1/default"},
                {"type": "Microsoft.Storage/storageAccounts/fileServices", "name": "st1/default"}]
        kept = filter_unmanaged_live_resources(live, bicep)
        kept_types = {(r["type"]).lower() for r in kept}
        self.assertIn("microsoft.storage/storageaccounts/blobservices", kept_types)
        self.assertNotIn("microsoft.storage/storageaccounts/fileservices", kept_types)

    def test_already_qualified_and_top_level_names_untouched(self):
        rows = [
            {"type": "Microsoft.Sql/servers/databases", "name": "sqldrift1/driftdb",
             "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sqldrift1/databases/driftdb"},
            {"type": "Microsoft.Storage/storageAccounts", "name": "st1",
             "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1"},
        ]
        _qualify_child_resource_names(rows)
        self.assertEqual(rows[0]["name"], "sqldrift1/driftdb")
        self.assertEqual(rows[1]["name"], "st1")


class PlaceholderPropertyValueTests(unittest.TestCase):
    """uniqueString placeholders inside PROPERTY values (not just names).

    Live-caught false positive: customSubDomainName = the account name =
    'aidrift[86c9cbf6]' compared literally against 'aidrift3s7c7weddxr3s'.
    """

    def _acct(self, sub_domain):
        return {
            "type": AI_TYPE,
            "name": "aidrift[86c9cbf6]",
            "properties": {"customSubDomainName": sub_domain, "publicNetworkAccess": "Enabled"},
        }

    def test_placeholder_value_matches_resolved_live_value(self):
        diffs = PropertyComparator.compare_properties(
            self._acct("aidrift[86c9cbf6]"), self._acct("aidrift3s7c7weddxr3s")
        )
        self.assertEqual([d for d in diffs if "customSubDomainName" in d.property_path], [])

    def test_placeholder_with_wrong_prefix_is_still_drift(self):
        diffs = PropertyComparator.compare_properties(
            self._acct("aidrift[86c9cbf6]"), self._acct("someoneelse123")
        )
        self.assertTrue([d for d in diffs if "customSubDomainName" in d.property_path])

    def test_placeholder_with_suffix_fixed_part(self):
        self.assertTrue(PropertyComparator._placeholder_value_matches(
            "st[86c9cbf6]data", "st3s7c7weddxr3sdata"
        ))
        self.assertFalse(PropertyComparator._placeholder_value_matches(
            "st[86c9cbf6]data", "st3s7c7weddxr3slogs"
        ))


if __name__ == "__main__":
    unittest.main()
