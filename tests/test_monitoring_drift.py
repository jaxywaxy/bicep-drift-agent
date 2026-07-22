"""
Unit tests for Azure Monitor / alerting drift (Phase A - intrinsic properties).

These are "silent failure" resources: a disabled alert or a severed notification
path looks fine until an incident. Phase A covers the INTRINSIC properties that
resolve the same way in flat templates and in module builds (enabled, thresholds,
query text, retention, action-group receivers). Cross-resource references
(scopes, action-group linkage) are Phase B and deliberately not asserted here.

Key behaviours under test:
  * a receiver removed/added is drift (the generic bicep-keyed compare misses a
    fully-removed array member - the exact-set matcher catches it);
  * Azure-added receiver fields (status, useCommonAlertSchema) do NOT false-flag;
  * enabled -> false and threshold/retention loosening are CRITICAL, but only on
    monitoring types (the substrings must not over-flag other resources).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator


def diffs_by_path(diffs):
    return {d.property_path: d for d in diffs}


class ActionGroupTests(unittest.TestCase):
    TYPE = "Microsoft.Insights/actionGroups"

    def _ag(self, receivers, enabled=True):
        return {
            "type": self.TYPE,
            "properties": {
                "groupShortName": "drift",
                "enabled": enabled,
                "emailReceivers": receivers,
            },
        }

    def test_clean_when_azure_adds_status_and_schema_fields(self):
        bicep = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}])
        # Live augments each receiver with server-set fields.
        live = self._ag([{"name": "oncall", "emailAddress": "on@call.com",
                          "status": "Enabled", "useCommonAlertSchema": True}])
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_removed_receiver_is_critical_drift(self):
        bicep = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}])
        live = self._ag([])  # someone deleted the only notification path
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.emailReceivers", d)
        self.assertEqual(d["properties.emailReceivers"].severity, "critical")

    def test_added_receiver_out_of_band_is_drift(self):
        bicep = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}])
        live = self._ag([{"name": "oncall", "emailAddress": "on@call.com"},
                         {"name": "rogue", "emailAddress": "exfil@evil.com"}])
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.emailReceivers", d)

    def test_changed_receiver_address_is_drift(self):
        bicep = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}])
        live = self._ag([{"name": "oncall", "emailAddress": "someone-else@x.com"}])
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.emailReceivers", d)

    def test_reordered_receivers_are_clean(self):
        bicep = self._ag([{"name": "a", "emailAddress": "a@x.com"},
                          {"name": "b", "emailAddress": "b@x.com"}])
        live = self._ag([{"name": "b", "emailAddress": "b@x.com", "status": "Enabled"},
                         {"name": "a", "emailAddress": "a@x.com", "status": "Enabled"}])
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_disabled_action_group_is_critical(self):
        bicep = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}], enabled=True)
        live = self._ag([{"name": "oncall", "emailAddress": "on@call.com"}], enabled=False)
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.enabled", d)
        self.assertEqual(d["properties.enabled"].severity, "critical")

    def test_webhook_receiver_removed_is_drift(self):
        bicep = {"type": self.TYPE, "properties": {"enabled": True, "webhookReceivers": [
            {"name": "hook", "serviceUri": "https://hooks.example/x"}]}}
        live = {"type": self.TYPE, "properties": {"enabled": True, "webhookReceivers": []}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.webhookReceivers", d)


class MetricAlertTests(unittest.TestCase):
    TYPE = "Microsoft.Insights/metricAlerts"

    def test_disabled_alert_is_critical(self):
        bicep = {"type": self.TYPE, "properties": {"enabled": True, "severity": 2}}
        live = {"type": self.TYPE, "properties": {"enabled": False, "severity": 2}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertEqual(d["properties.enabled"].severity, "critical")

    def test_threshold_loosened_is_critical(self):
        crit = lambda t: [{"name": "c1", "metricName": "Percentage CPU",
                           "operator": "GreaterThan", "threshold": t, "timeAggregation": "Average"}]
        bicep = {"type": self.TYPE, "properties": {"enabled": True, "criteria": {"allOf": crit(80)}}}
        live = {"type": self.TYPE, "properties": {"enabled": True, "criteria": {"allOf": crit(99)}}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertTrue(any("criteria" in p for p in d))
        self.assertTrue(all(v.severity == "critical" for p, v in d.items() if "criteria" in p))


class ScheduledQueryTests(unittest.TestCase):
    TYPE = "Microsoft.Insights/scheduledQueryRules"

    def test_query_text_edited_is_critical(self):
        crit = lambda q: {"allOf": [{"query": q, "operator": "GreaterThan",
                                     "threshold": 0, "timeAggregation": "Count"}]}
        bicep = {"type": self.TYPE, "properties": {"enabled": True, "criteria": crit("Heartbeat | where X")}}
        live = {"type": self.TYPE, "properties": {"enabled": True, "criteria": crit("Heartbeat | where 1==0")}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertTrue(any("criteria" in p and v.severity == "critical" for p, v in d.items()))


class ApplicationInsightsTests(unittest.TestCase):
    TYPE = "Microsoft.Insights/components"

    def test_generated_fields_do_not_false_flag(self):
        # Bicep declares a handful of properties; Azure returns many generated
        # ones. Bicep-keyed comparison must ignore the extras entirely.
        bicep = {"type": self.TYPE, "properties": {
            "Application_Type": "web", "RetentionInDays": 90}}
        live = {"type": self.TYPE, "properties": {
            "Application_Type": "web", "RetentionInDays": 90,
            "InstrumentationKey": "00000000-0000-0000-0000-000000000000",
            "ConnectionString": "InstrumentationKey=...;IngestionEndpoint=...",
            "AppId": "abc", "provisioningState": "Succeeded",
            "CreationDate": "2026-01-01T00:00:00Z", "TenantId": "t",
            "IngestionMode": "LogAnalytics"}}
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_retention_shortened_is_critical(self):
        bicep = {"type": self.TYPE, "properties": {"Application_Type": "web", "RetentionInDays": 90}}
        live = {"type": self.TYPE, "properties": {"Application_Type": "web", "RetentionInDays": 30}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.RetentionInDays", d)
        self.assertEqual(d["properties.RetentionInDays"].severity, "critical")

    def test_ingestion_public_access_opened_is_critical(self):
        bicep = {"type": self.TYPE, "properties": {
            "Application_Type": "web", "publicNetworkAccessForIngestion": "Disabled"}}
        live = {"type": self.TYPE, "properties": {
            "Application_Type": "web", "publicNetworkAccessForIngestion": "Enabled"}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertEqual(d["properties.publicNetworkAccessForIngestion"].severity, "critical")


class SeverityScopingTests(unittest.TestCase):
    """The monitoring critical substrings must NOT bleed onto other types."""

    def test_enabled_on_keyvault_is_not_elevated_by_monitoring_rule(self):
        # A non-monitoring type with an 'enabled'-ish property must be untouched
        # by _elevate_monitoring_severity.
        bicep = {"type": "Microsoft.KeyVault/vaults",
                 "properties": {"enabledForDeployment": True}}
        live = {"type": "Microsoft.KeyVault/vaults",
                "properties": {"enabledForDeployment": False}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        # It still drifts (value changed), but not via the monitoring elevation.
        self.assertIn("properties.enabledForDeployment", d)
        self.assertNotEqual(d["properties.enabledForDeployment"].severity, "critical")

    def test_receivers_word_on_other_type_not_elevated(self):
        bicep = {"type": "Microsoft.Storage/storageAccounts",
                 "properties": {"someReceivers": [{"name": "a"}]}}
        live = {"type": "Microsoft.Storage/storageAccounts",
                "properties": {"someReceivers": []}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        for v in d.values():
            self.assertNotEqual(v.severity, "critical")


class MonitoringCrossRefTests(unittest.TestCase):
    """Phase B - alert cross-references (scopes + action-group linkage).

    The linkage ids are template expressions, so the generic subset compare
    treats them as a match: it catches a FULL removal (already, as warning) but
    never a re-point. These assert (a) re-point is now caught, (b) removal is
    now CRITICAL, (c) clean module builds (opaque reference() ids) stay
    zero-drift, and (d) the opaque->opaque re-point limit is honoured.
    """

    MA = "Microsoft.Insights/metricAlerts"
    AL = "Microsoft.Insights/activityLogAlerts"
    QR = "Microsoft.Insights/scheduledQueryRules"

    RID_AG = "resourceId('Microsoft.Insights/actionGroups','ag-drift-test')"
    LIVE_AG = "/subscriptions/S/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag-drift-test"
    LIVE_AG2 = "/subscriptions/S/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/rogue-ag"
    REF_SCOPE = "reference(resourceId('Microsoft.Resources/deployments','deploy-storage'),'2025-04-01').outputs.storageAccountId.value"
    LIVE_SCOPE = "/subscriptions/S/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sttest"
    LIVE_SCOPE2 = "/subscriptions/S/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/other"

    def _cmp(self, rtype, b_props, d_props):
        # a sibling property so enrichment detection passes
        b_props = {"enabled": True, **b_props}
        d_props = {"enabled": True, **d_props}
        return diffs_by_path(PropertyComparator.compare_properties(
            {"type": rtype, "properties": b_props},
            {"type": rtype, "properties": d_props},
        ))

    # --- action-group linkage (metricAlerts: actions[].actionGroupId) ---
    def test_action_group_repoint_is_critical(self):
        d = self._cmp(self.MA,
                      {"actions": [{"actionGroupId": self.RID_AG}]},
                      {"actions": [{"actionGroupId": self.LIVE_AG2}]})
        self.assertIn("properties.actions", d)
        self.assertEqual(d["properties.actions"].severity, "critical")

    def test_action_group_unlink_is_critical(self):
        d = self._cmp(self.MA,
                      {"actions": [{"actionGroupId": self.RID_AG}]},
                      {"actions": []})
        self.assertIn("properties.actions", d)
        self.assertEqual(d["properties.actions"].severity, "critical")

    def test_action_group_added_out_of_band_is_drift(self):
        d = self._cmp(self.MA,
                      {"actions": [{"actionGroupId": self.RID_AG}]},
                      {"actions": [{"actionGroupId": self.LIVE_AG},
                                   {"actionGroupId": self.LIVE_AG2}]})
        self.assertIn("properties.actions", d)

    def test_action_group_clean_resolveid_vs_live_id(self):
        d = self._cmp(self.MA,
                      {"actions": [{"actionGroupId": self.RID_AG}]},
                      {"actions": [{"actionGroupId": self.LIVE_AG}]})
        self.assertNotIn("properties.actions", d)

    # --- scopes (opaque reference() ids) ---
    def test_scope_descope_is_critical(self):
        d = self._cmp(self.MA, {"scopes": [self.REF_SCOPE]}, {"scopes": []})
        self.assertIn("properties.scopes", d)
        self.assertEqual(d["properties.scopes"].severity, "critical")

    def test_clean_opaque_scope_no_false_drift(self):
        d = self._cmp(self.MA, {"scopes": [self.REF_SCOPE]}, {"scopes": [self.LIVE_SCOPE]})
        self.assertNotIn("properties.scopes", d)

    def test_opaque_to_opaque_scope_repoint_is_invisible(self):
        # Documented limit: both sides unresolvable, same count -> no literal to compare.
        d = self._cmp(self.MA, {"scopes": [self.REF_SCOPE]}, {"scopes": [self.LIVE_SCOPE2]})
        self.assertNotIn("properties.scopes", d)

    # --- activity-log + query rule shapes (actions.actionGroups) ---
    def test_activity_alert_actiongroup_repoint(self):
        d = self._cmp(self.AL,
                      {"actions": {"actionGroups": [{"actionGroupId": self.RID_AG}]}},
                      {"actions": {"actionGroups": [{"actionGroupId": self.LIVE_AG2}]}})
        self.assertIn("properties.actions.actionGroups", d)
        self.assertEqual(d["properties.actions.actionGroups"].severity, "critical")

    def test_query_rule_bare_actiongroup_repoint(self):
        d = self._cmp(self.QR,
                      {"actions": {"actionGroups": [self.RID_AG]}},
                      {"actions": {"actionGroups": [self.LIVE_AG2]}})
        self.assertIn("properties.actions.actionGroups", d)

    def test_query_rule_bare_actiongroup_clean(self):
        d = self._cmp(self.QR,
                      {"actions": {"actionGroups": [self.RID_AG]}},
                      {"actions": {"actionGroups": [self.LIVE_AG]}})
        self.assertNotIn("properties.actions.actionGroups", d)

    # --- linkage severity substrings must not leak to other resource types ---
    def test_actions_substring_not_elevated_on_other_type(self):
        # A property containing 'actions' on a non-alert type must stay non-critical.
        bicep = {"type": "Microsoft.Logic/workflows",
                 "properties": {"definitionActions": ["a"]}}
        live = {"type": "Microsoft.Logic/workflows",
                "properties": {"definitionActions": []}}
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        for v in d.values():
            self.assertNotEqual(v.severity, "critical")


if __name__ == "__main__":
    unittest.main()
