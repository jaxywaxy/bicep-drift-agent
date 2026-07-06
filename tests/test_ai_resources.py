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

from tools.get_live_state import _cognitive_deployment_child
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
