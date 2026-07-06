"""
Unit tests for Key Vault (and storage) security-property drift:
networkAcls null-vs-default normalization, exact-set allowlist comparison
(ipRules / virtualNetworkRules), and identity-keyed accessPolicies comparison.

These replace the old blanket .drift-ignore on properties.networkAcls, which
suppressed REAL firewall drift along with the null-vs-default noise.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator

KV_TYPE = "Microsoft.KeyVault/vaults"
ST_TYPE = "Microsoft.Storage/storageAccounts"

DEFAULT_ACLS = {
    "bypass": "AzureServices",
    "defaultAction": "Allow",
    "ipRules": [],
    "virtualNetworkRules": [],
}


def kv(properties, rtype=KV_TYPE, name="kv1"):
    """A property dict in the shape PropertyExtractor produces."""
    return {
        "type": rtype,
        "name": name,
        "location": "australiaeast",
        "properties": properties,
    }


def compare(bicep_props, deployed_props):
    return PropertyComparator.compare_properties(bicep_props, deployed_props)


def paths(diffs):
    return {d.property_path for d in diffs}


class NetworkAclsNullDefaultTests(unittest.TestCase):
    """The old noise source: bicep spells out the default, Azure returns null."""

    def test_bicep_default_vs_live_null_is_clean(self):
        bicep = kv({"sku": {"name": "standard"}, "networkAcls": dict(DEFAULT_ACLS)})
        live = kv({"sku": {"name": "standard"}, "networkAcls": None})
        self.assertEqual(compare(bicep, live), [])

    def test_bicep_default_vs_live_missing_key_is_clean(self):
        bicep = kv({"sku": {"name": "standard"}, "networkAcls": dict(DEFAULT_ACLS)})
        live = kv({"sku": {"name": "standard"}, "enableSoftDelete": True})
        self.assertEqual(compare(bicep, live), [])

    def test_bicep_deny_vs_live_null_IS_drift(self):
        # Template demands a locked-down vault; live was never configured (open).
        bicep = kv({"sku": {"name": "standard"}, "networkAcls": {**DEFAULT_ACLS, "defaultAction": "Deny"}})
        live = kv({"sku": {"name": "standard"}, "networkAcls": None})
        diffs = compare(bicep, live)
        self.assertIn("properties.networkAcls.defaultAction", paths(diffs))
        diff = next(d for d in diffs if d.property_path == "properties.networkAcls.defaultAction")
        self.assertEqual(diff.severity, "critical")

    def test_default_action_flip_is_critical_drift(self):
        # THE case the old blanket ignore was hiding.
        bicep = kv({"networkAcls": {**DEFAULT_ACLS, "defaultAction": "Deny"}, "sku": {"name": "standard"}})
        live = kv({"networkAcls": {**DEFAULT_ACLS, "defaultAction": "Allow"}, "sku": {"name": "standard"}})
        diffs = compare(bicep, live)
        self.assertIn("properties.networkAcls.defaultAction", paths(diffs))

    def test_injection_applies_to_storage_too(self):
        bicep = kv({"networkAcls": dict(DEFAULT_ACLS), "minimumTlsVersion": "TLS1_2"}, rtype=ST_TYPE, name="st1")
        live = kv({"networkAcls": None, "minimumTlsVersion": "TLS1_2"}, rtype=ST_TYPE, name="st1")
        self.assertEqual(compare(bicep, live), [])

    def test_no_injection_for_other_types(self):
        # A type outside the injection set keeps pre-existing behavior: the
        # deployed side stays null, so the bicep-specified key surfaces via the
        # generic 'removed' branch (info severity) - NOT as a critical
        # 'modified' diff against an injected default.
        bicep = kv({"networkAcls": {"defaultAction": "Deny"}}, rtype="Microsoft.Web/sites", name="app")
        live = kv({"networkAcls": None, "httpsOnly": True}, rtype="Microsoft.Web/sites", name="app")
        acl_diffs = [d for d in compare(bicep, live)
                     if d.property_path == "properties.networkAcls.defaultAction"]
        self.assertTrue(all(d.change_type == "removed" for d in acl_diffs))

    def test_enum_case_and_bypass_order_are_not_drift(self):
        bicep = kv({"networkAcls": {"bypass": "AzureServices, Logging", "defaultAction": "deny"}, "sku": {"name": "standard"}})
        live = kv({"networkAcls": {"bypass": "Logging,AzureServices", "defaultAction": "Deny"}, "sku": {"name": "standard"}})
        self.assertEqual(compare(bicep, live), [])


class AllowlistTests(unittest.TestCase):
    """ipRules / virtualNetworkRules: exact-set semantics, not subset."""

    def _bicep(self, ip_rules, vnet_rules=None):
        return kv({"networkAcls": {**DEFAULT_ACLS, "defaultAction": "Deny",
                                   "ipRules": ip_rules,
                                   "virtualNetworkRules": vnet_rules or []},
                   "sku": {"name": "standard"}})

    def test_same_rules_reordered_is_clean(self):
        bicep = self._bicep([{"value": "1.2.3.4/32"}, {"value": "5.6.7.0/24"}])
        live = self._bicep([{"value": "5.6.7.0/24"}, {"value": "1.2.3.4/32"}])
        self.assertEqual(compare(bicep, live), [])

    def test_live_added_ip_rule_IS_drift(self):
        # The firewall-opening blind spot: generic subset compare passes this.
        bicep = self._bicep([{"value": "1.2.3.4/32"}])
        live = self._bicep([{"value": "1.2.3.4/32"}, {"value": "203.0.113.7/32"}])
        diffs = compare(bicep, live)
        self.assertIn("properties.networkAcls.ipRules", paths(diffs))
        diff = next(d for d in diffs if d.property_path == "properties.networkAcls.ipRules")
        self.assertEqual(diff.severity, "critical")

    def test_live_added_rule_detected_even_with_empty_bicep_list(self):
        bicep = self._bicep([])
        live = self._bicep([{"value": "203.0.113.7/32"}])
        self.assertIn("properties.networkAcls.ipRules", paths(compare(bicep, live)))

    def test_removed_bicep_rule_is_drift(self):
        bicep = self._bicep([{"value": "1.2.3.4/32"}])
        live = self._bicep([])
        self.assertIn("properties.networkAcls.ipRules", paths(compare(bicep, live)))

    def test_azure_augmented_fields_are_not_drift(self):
        # Azure adds action/state fields to rules; identity + declared fields match.
        bicep = self._bicep([{"value": "1.2.3.4/32"}])
        live = self._bicep([{"value": "1.2.3.4/32", "action": "Allow"}])
        self.assertEqual(compare(bicep, live), [])

    def test_unresolved_vnet_rule_id_excuses_one_live_rule(self):
        sub = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
        bicep = self._bicep([], vnet_rules=[{"id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'v', 's')]"}])
        live = self._bicep([], vnet_rules=[{"id": sub}])
        self.assertEqual(compare(bicep, live), [])

    def test_unresolved_slot_does_not_excuse_two_live_rules(self):
        bicep = self._bicep([], vnet_rules=[{"id": "[resourceId('a','b','c')]"}])
        live = self._bicep([], vnet_rules=[{"id": "/subscriptions/x/s1"}, {"id": "/subscriptions/x/s2"}])
        self.assertIn("properties.networkAcls.virtualNetworkRules", paths(compare(bicep, live)))


class AccessPolicyTests(unittest.TestCase):
    """accessPolicies: identity-keyed, permissions as case-insensitive sets."""

    TENANT = "72f988bf-0000-0000-0000-2d7cd011db47"
    APP_OID = "11111111-1111-1111-1111-111111111111"

    def _policy(self, object_id, secrets=("get",), keys=(), certificates=(), storage=()):
        return {
            "tenantId": self.TENANT,
            "objectId": object_id,
            "permissions": {
                "secrets": list(secrets),
                "keys": list(keys),
                "certificates": list(certificates),
                "storage": list(storage),
            },
        }

    def _kv(self, policies):
        return kv({"accessPolicies": policies, "sku": {"name": "standard"}})

    def test_identical_policies_clean(self):
        self.assertEqual(
            compare(self._kv([self._policy(self.APP_OID)]), self._kv([self._policy(self.APP_OID)])),
            [],
        )

    def test_reordered_policies_and_permission_casing_clean(self):
        b = self._kv([self._policy(self.APP_OID, secrets=("get", "list")), self._policy("2222", keys=("get",))])
        d = self._kv([self._policy("2222", keys=("Get",)), self._policy(self.APP_OID, secrets=("List", "Get"))])
        self.assertEqual(compare(b, d), [])

    def test_live_added_policy_IS_drift(self):
        # Out-of-band vault access grant - invisible to generic subset compare.
        b = self._kv([self._policy(self.APP_OID)])
        d = self._kv([self._policy(self.APP_OID), self._policy("evil-0000")])
        diffs = compare(b, d)
        self.assertIn("properties.accessPolicies", paths(diffs))
        diff = next(x for x in diffs if x.property_path == "properties.accessPolicies")
        self.assertEqual(diff.severity, "critical")

    def test_live_added_policy_detected_with_empty_bicep_list(self):
        b = self._kv([])
        d = self._kv([self._policy("evil-0000")])
        self.assertIn("properties.accessPolicies", paths(compare(b, d)))

    def test_revoked_policy_is_drift(self):
        b = self._kv([self._policy(self.APP_OID)])
        d = self._kv([])
        self.assertIn("properties.accessPolicies", paths(compare(b, d)))

    def test_permission_added_within_category_is_drift(self):
        b = self._kv([self._policy(self.APP_OID, secrets=("get",))])
        d = self._kv([self._policy(self.APP_OID, secrets=("get", "set"))])
        self.assertIn("properties.accessPolicies", paths(compare(b, d)))

    def test_permission_added_in_omitted_category_is_drift(self):
        # bicep grants only secrets; someone adds a keys permission live.
        b = self._kv([{"tenantId": self.TENANT, "objectId": self.APP_OID,
                       "permissions": {"secrets": ["get"]}}])
        d = self._kv([self._policy(self.APP_OID, secrets=("get",), keys=("get",))])
        self.assertIn("properties.accessPolicies", paths(compare(b, d)))

    def test_runtime_object_id_excuses_one_policy(self):
        b = self._kv([{"tenantId": self.TENANT,
                       "objectId": "[reference(resourceId('Microsoft.Web/sites', 'app'), '2022-03-01', 'full').identity.principalId]",
                       "permissions": {"secrets": ["get"]}}])
        d = self._kv([self._policy("some-msi-oid")])
        self.assertEqual(compare(b, d), [])

    def test_runtime_object_id_does_not_excuse_two(self):
        b = self._kv([{"tenantId": self.TENANT,
                       "objectId": "[reference('app').identity.principalId]",
                       "permissions": {"secrets": ["get"]}}])
        d = self._kv([self._policy("msi-1"), self._policy("evil-0000")])
        self.assertIn("properties.accessPolicies", paths(compare(b, d)))


if __name__ == "__main__":
    unittest.main()
