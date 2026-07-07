"""
Unit tests for batch-2 coverage: App Service config (app-settings key-set
redaction), diagnostic-setting name qualification, Defender pricing
declared-only fetch filter.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.get_live_state import qualify_diagnostic_setting_names
from tools.property_drift import PropertyComparator


class AppSettingsRedactionTests(unittest.TestCase):
    """App setting VALUES are secrets: compare key sets, never values."""

    def _cfg(self, settings, name="app1/appsettings"):
        return {"type": "Microsoft.Web/sites/config", "name": name, "properties": settings}

    def test_same_keys_different_values_is_clean_and_leak_free(self):
        bicep = self._cfg({"DB_PASSWORD": "[parameters('dbPass')]", "ENV": "test"})
        live = self._cfg({"DB_PASSWORD": "hunter2-actual-secret", "ENV": "test"})
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_added_key_is_drift_without_values(self):
        bicep = self._cfg({"ENV": "test"})
        live = self._cfg({"ENV": "test", "BACKDOOR_URL": "https://evil.example/secret-token"})
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertEqual(len(diffs), 1)
        d = diffs[0]
        self.assertEqual(d.property_path, "properties.appSettingKeys")
        self.assertEqual(d.actual_value, ["BACKDOOR_URL", "ENV"])
        # the secret value must never appear in the diff
        self.assertNotIn("secret-token", str(d.desired_value) + str(d.actual_value))

    def test_removed_key_is_drift(self):
        bicep = self._cfg({"ENV": "test", "FEATURE_FLAG": "on"})
        live = self._cfg({"ENV": "test"})
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertEqual(diffs[0].property_path, "properties.appSettingKeys")

    def test_config_web_still_property_compared(self):
        bicep = {"type": "Microsoft.Web/sites/config", "name": "app1/web",
                 "properties": {"minTlsVersion": "1.2", "ftpsState": "Disabled"}}
        live = {"type": "Microsoft.Web/sites/config", "name": "app1/web",
                "properties": {"minTlsVersion": "1.0", "ftpsState": "Disabled"}}
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertIn("properties.minTlsVersion", {d.property_path for d in diffs})


class DiagnosticNameQualificationTests(unittest.TestCase):
    def test_extension_resource_gets_scope_qualified_name(self):
        arm = [{
            "type": "Microsoft.Insights/diagnosticSettings",
            "name": "kv-audit",
            "scope": "Microsoft.KeyVault/vaults/kvdrift[86c9cbf6]",
            "properties": {},
        }]
        qualify_diagnostic_setting_names(arm)
        self.assertEqual(arm[0]["name"], "kvdrift[86c9cbf6]/kv-audit")

    def test_already_qualified_and_other_types_untouched(self):
        arm = [
            {"type": "Microsoft.Insights/diagnosticSettings", "name": "st1/audit",
             "scope": "Microsoft.Storage/storageAccounts/st1"},
            {"type": "Microsoft.Storage/storageAccounts", "name": "st1"},
        ]
        qualify_diagnostic_setting_names(arm)
        self.assertEqual(arm[0]["name"], "st1/audit")
        self.assertEqual(arm[1]["name"], "st1")

    def test_diag_setting_logs_loosening_is_drift(self):
        bicep = {"type": "Microsoft.Insights/diagnosticSettings", "name": "kv1/kv-audit",
                 "properties": {"logs": [{"category": "AuditEvent", "enabled": True}]}}
        live = {"type": "Microsoft.Insights/diagnosticSettings", "name": "kv1/kv-audit",
                "properties": {"logs": [{"category": "AuditEvent", "enabled": False}]}}
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertIn("properties.logs", {d.property_path for d in diffs})


class DefenderPricingFilterTests(unittest.TestCase):
    def test_only_declared_plans_fetched(self):
        from unittest import mock
        import io, json as _json
        from tools.get_live_state import fetch_declared_defender_pricings

        arm = [{"type": "Microsoft.Security/pricings", "name": "StorageAccounts",
                "properties": {"pricingTier": "Standard"}}]
        all_plans = {"value": [
            {"name": "StorageAccounts", "id": "p1", "properties": {"pricingTier": "Standard"}},
            {"name": "VirtualMachines", "id": "p2", "properties": {"pricingTier": "Free"}},
            {"name": "KeyVaults", "id": "p3", "properties": {"pricingTier": "Free"}},
        ]}

        def fake_urlopen(req, timeout=0):
            return io.BytesIO(_json.dumps(all_plans).encode())

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            rows = fetch_declared_defender_pricings(arm, "sub-id", token="t")
        self.assertEqual([r["name"] for r in rows], ["StorageAccounts"])

    def test_no_declared_plans_no_fetch(self):
        from tools.get_live_state import fetch_declared_defender_pricings
        self.assertEqual(fetch_declared_defender_pricings(
            [{"type": "Microsoft.Storage/storageAccounts", "name": "st1"}], "sub-id", token="t"
        ), [])


if __name__ == "__main__":
    unittest.main()
