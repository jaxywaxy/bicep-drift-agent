"""
Unit tests for SECURITY_SENTINELS: live-added keys on security-critical paths
the template omits (the subset-semantics gap). The canonical case: API server
authorizedIPRanges added out-of-band via `az aks update` when the bicep's
apiServerAccessProfile doesn't declare the key - previously invisible because
the generic comparison iterates bicep keys only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator


def aks_bicep(props=None):
    """Bicep-side AKS cluster mirroring drift-test-resources/bicep/aks.bicep:
    apiServerAccessProfile declared, but authorizedIPRanges omitted."""
    return {
        "type": "Microsoft.ContainerService/managedClusters",
        "name": "aks-drift-test",
        "properties": props if props is not None else {
            "dnsPrefix": "aksdrift",
            "enableRBAC": True,
            "apiServerAccessProfile": {"enablePrivateCluster": False},
        },
    }


def aks_live(props=None):
    return {
        "type": "Microsoft.ContainerService/managedClusters",
        "name": "aks-drift-test",
        "properties": props if props is not None else {
            "dnsPrefix": "aksdrift",
            "enableRBAC": True,
            "provisioningState": "Succeeded",
            "apiServerAccessProfile": {"enablePrivateCluster": False},
        },
    }


class AuthorizedIPRangesSentinelTests(unittest.TestCase):
    def test_live_added_authorized_ip_ranges_is_critical_drift(self):
        live = aks_live()
        live["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = [
            "203.0.113.0/24"
        ]
        diffs = PropertyComparator.compare_properties(aks_bicep(), live)
        paths = {d.property_path: d for d in diffs}
        self.assertIn("properties.apiServerAccessProfile.authorizedIPRanges", paths)
        d = paths["properties.apiServerAccessProfile.authorizedIPRanges"]
        self.assertEqual(d.change_type, "added")
        self.assertEqual(d.severity, "critical")
        self.assertEqual(d.desired_value, [])
        self.assertEqual(d.actual_value, ["203.0.113.0/24"])

    def test_absent_ranges_both_sides_is_clean(self):
        self.assertEqual(
            PropertyComparator.compare_properties(aks_bicep(), aks_live()), []
        )

    def test_null_live_value_means_default_and_is_clean(self):
        live = aks_live()
        live["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = None
        self.assertEqual(
            PropertyComparator.compare_properties(aks_bicep(), live), []
        )

    def test_empty_live_list_matches_default(self):
        live = aks_live()
        live["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = []
        self.assertEqual(
            PropertyComparator.compare_properties(aks_bicep(), live), []
        )

    def test_declared_ranges_left_to_generic_comparison(self):
        """When the template DOES declare the key, the sentinel stays out."""
        bicep = aks_bicep()
        bicep["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = [
            "203.0.113.0/24"
        ]
        live = aks_live()
        live["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = [
            "203.0.113.0/24"
        ]
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertEqual([d for d in diffs if d.change_type == "added"], [])

    def test_deployed_key_casing_is_irrelevant(self):
        live = aks_live()
        live["properties"]["apiserverAccessprofile"] = live["properties"].pop(
            "apiServerAccessProfile"
        )
        live["properties"]["apiserverAccessprofile"]["authorizedIPRanges"] = [
            "198.51.100.7/32"
        ]
        diffs = PropertyComparator.compare_properties(aks_bicep(), live)
        self.assertTrue(
            any(d.change_type == "added" and d.severity == "critical" for d in diffs)
        )


class OtherAksSentinelTests(unittest.TestCase):
    def test_local_accounts_disabled_out_of_band_is_drift(self):
        live = aks_live()
        live["properties"]["disableLocalAccounts"] = True
        diffs = PropertyComparator.compare_properties(aks_bicep(), live)
        d = next(
            d for d in diffs
            if d.property_path == "properties.disableLocalAccounts"
        )
        self.assertEqual(d.change_type, "added")
        self.assertEqual(d.severity, "critical")

    def test_local_accounts_at_default_is_clean(self):
        live = aks_live()
        live["properties"]["disableLocalAccounts"] = False
        self.assertEqual(
            PropertyComparator.compare_properties(aks_bicep(), live), []
        )

    def test_rbac_off_when_template_omits_it_is_drift(self):
        bicep = aks_bicep(props={
            "dnsPrefix": "aksdrift",
            "apiServerAccessProfile": {"enablePrivateCluster": False},
        })
        live = aks_live()
        live["properties"]["enableRBAC"] = False
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertTrue(
            any(d.property_path == "properties.enableRBAC" and d.severity == "critical"
                for d in diffs)
        )

    def test_sentinels_do_not_touch_uncovered_resource_types(self):
        bicep = {"type": "Microsoft.Network/virtualNetworks", "name": "vnet1",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}}
        live = {"type": "Microsoft.Network/virtualNetworks", "name": "vnet1",
                "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                               "provisioningState": "Succeeded",
                               "disableLocalAccounts": True,
                               "adminUserEnabled": True}}
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])


def _pair(rtype, name, live_extra, bicep_props=None):
    """(bicep, live) for a resource whose template omits the sentinel paths."""
    base = bicep_props or {"someDeclared": "x"}
    bicep = {"type": rtype, "name": name, "properties": dict(base)}
    live = {"type": rtype, "name": name,
            "properties": {**base, "provisioningState": "Succeeded", **live_extra}}
    return bicep, live


class GeneralizedSentinelTests(unittest.TestCase):
    """The sentinel table generalized beyond AKS: per-type absent-defaults for
    the classic portal flips (ACR admin account, storage TLS floor / public
    blobs, SQL public network access, KV soft delete, local-auth toggles)."""

    def _diffs(self, rtype, live_extra, **kw):
        bicep, live = _pair(rtype, "r1", live_extra, **kw)
        return PropertyComparator.compare_properties(bicep, live)

    def _single_critical(self, diffs, path_suffix):
        self.assertEqual(len(diffs), 1, diffs)
        d = diffs[0]
        self.assertTrue(d.property_path.lower().endswith(path_suffix.lower()), d)
        self.assertEqual(d.change_type, "added")
        self.assertEqual(d.severity, "critical")

    def test_acr_admin_user_enabled_is_critical_drift(self):
        diffs = self._diffs("Microsoft.ContainerRegistry/registries",
                            {"adminUserEnabled": True})
        self._single_critical(diffs, "adminUserEnabled")

    def test_acr_admin_user_disabled_is_clean(self):
        self.assertEqual(
            self._diffs("Microsoft.ContainerRegistry/registries",
                        {"adminUserEnabled": False}), [])

    def test_tls_floor_is_not_a_sentinel(self):
        # The absent-default for TLS floors is creation-API-version-dependent
        # (a fresh EventHub namespace @2021-11-01 materializes '1.0'), so an
        # OMITTED TLS floor must never sentinel-flag - whatever the live value.
        self.assertEqual(
            self._diffs("Microsoft.EventHub/namespaces",
                        {"minimumTlsVersion": "1.0"}), [])
        self.assertEqual(
            self._diffs("Microsoft.Storage/storageAccounts",
                        {"minimumTlsVersion": "TLS1_0"}), [])

    def test_declared_tls_floor_downgrade_is_critical_generic_drift(self):
        # A DECLARED floor weakened out-of-band is the generic comparison's
        # job, and the path is severity-critical.
        bicep, live = _pair("Microsoft.Storage/storageAccounts", "st1",
                            {"minimumTlsVersion": "TLS1_0"},
                            bicep_props={"minimumTlsVersion": "TLS1_2"})
        live["properties"]["minimumTlsVersion"] = "TLS1_0"
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertEqual(len(diffs), 1, diffs)
        self.assertEqual(diffs[0].severity, "critical")
        self.assertEqual(diffs[0].change_type, "modified")

    def test_sentinel_enum_default_is_case_insensitive(self):
        self.assertEqual(
            self._diffs("Microsoft.Sql/servers",
                        {"publicNetworkAccess": "enabled"}), [])

    def test_storage_public_blob_access_is_critical_drift(self):
        diffs = self._diffs("Microsoft.Storage/storageAccounts",
                            {"allowBlobPublicAccess": True})
        self._single_critical(diffs, "allowBlobPublicAccess")

    def test_sql_public_network_access_change_is_critical_drift(self):
        diffs = self._diffs("Microsoft.Sql/servers",
                            {"publicNetworkAccess": "Disabled"})
        self._single_critical(diffs, "publicNetworkAccess")

    def test_sql_public_network_access_default_is_clean(self):
        self.assertEqual(
            self._diffs("Microsoft.Sql/servers",
                        {"publicNetworkAccess": "Enabled"}), [])

    def test_keyvault_soft_delete_disabled_is_critical_drift(self):
        diffs = self._diffs("Microsoft.KeyVault/vaults",
                            {"enableSoftDelete": False})
        self._single_critical(diffs, "enableSoftDelete")

    def test_cosmos_local_auth_disabled_is_drift(self):
        diffs = self._diffs("Microsoft.DocumentDB/databaseAccounts",
                            {"disableLocalAuth": True})
        self._single_critical(diffs, "disableLocalAuth")

    def test_empty_string_live_value_means_default(self):
        self.assertEqual(
            self._diffs("Microsoft.Web/sites", {"publicNetworkAccess": ""}), [])

    def test_declared_path_left_to_generic_comparison(self):
        bicep, live = _pair("Microsoft.ContainerRegistry/registries", "r1",
                            {"adminUserEnabled": True},
                            bicep_props={"adminUserEnabled": True})
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertEqual([d for d in diffs if d.change_type == "added"], [])


if __name__ == "__main__":
    unittest.main()
