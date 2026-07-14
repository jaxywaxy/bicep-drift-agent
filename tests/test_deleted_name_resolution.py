"""
Unit tests for recovering the real deployed name of a deleted
placeholder-named resource from its activity-log delete event.

Missing_in_azure records for uniqueString-named resources reported the bicep
expression ('log-[86c9cbf6]', "format('st{0}driftdefault', ...)/default") as
the resource name - unreadable, and useless in a recommendation. The matched
activity-log delete event carries the true Azure id; parse the real name out
of it.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyze_drift
from analyze_drift import _recover_deployed_name

SUB = "/subscriptions/594e0bd0-2a8d-4419-b281-87869c20fd03/resourceGroups/rg-x"


class RecoverDeployedNameTests(unittest.TestCase):
    def test_top_level_resource(self):
        rid = f"{SUB}/providers/Microsoft.OperationalInsights/workspaces/log-3s7c7weddxr3s"
        self.assertEqual(
            _recover_deployed_name("Microsoft.OperationalInsights/workspaces", rid),
            "log-3s7c7weddxr3s",
        )

    def test_nested_child_resource(self):
        rid = f"{SUB}/providers/Microsoft.EventHub/namespaces/eh-3s7c/eventhubs/drift-hub"
        self.assertEqual(
            _recover_deployed_name("Microsoft.EventHub/namespaces/eventhubs", rid),
            "eh-3s7c/drift-hub",
        )

    def test_extension_resource_uses_last_provider_section(self):
        rid = (f"{SUB}/providers/Microsoft.KeyVault/vaults/kv123"
               f"/providers/Microsoft.Insights/diagnosticSettings/kv-audit")
        self.assertEqual(
            _recover_deployed_name("Microsoft.Insights/diagnosticSettings", rid),
            "kv-audit",
        )

    def test_type_mismatch_returns_empty(self):
        rid = f"{SUB}/providers/Microsoft.Storage/storageAccounts/st123"
        self.assertEqual(
            _recover_deployed_name("Microsoft.OperationalInsights/workspaces", rid), ""
        )

    def test_case_insensitive_type_match(self):
        rid = f"{SUB}/providers/microsoft.storage/storageaccounts/st123"
        self.assertEqual(
            _recover_deployed_name("Microsoft.Storage/storageAccounts", rid), "st123"
        )

    def test_child_type_against_parent_id_returns_empty(self):
        rid = f"{SUB}/providers/Microsoft.EventHub/namespaces/eh-3s7c"
        self.assertEqual(
            _recover_deployed_name("Microsoft.EventHub/namespaces/eventhubs", rid), ""
        )

    def test_garbage_input_returns_empty(self):
        self.assertEqual(_recover_deployed_name("Microsoft.Web/sites", ""), "")
        self.assertEqual(_recover_deployed_name("", "/providers/x/y/z"), "")
        self.assertEqual(_recover_deployed_name("Microsoft.Web/sites", "not-an-id"), "")


class LifecycleRenameTests(unittest.TestCase):
    """The drift record's name is replaced by the recovered deployed name."""

    def _run(self, drift_name, events):
        report = {
            "drifts": [{
                "type": "Microsoft.OperationalInsights/workspaces",
                "name": drift_name,
                "drift_type": "missing_in_azure",
                "details": {},
            }],
            "live_resources": [],
        }
        with mock.patch.object(analyze_drift, "fetch_resource_group_activity", return_value=events), \
             mock.patch.object(analyze_drift, "fetch_policy_principal_ids", return_value=set()), \
             mock.patch.object(analyze_drift, "match_activity_for_resource", return_value=events):
            analyze_drift._build_lifecycle_and_split(report, "rg-x")
        return report["drifts"][0] if report["drifts"] else report["policy_enforced_drifts"][0]

    def test_placeholder_name_resolved_from_delete_event(self):
        events = [{
            "timestamp": "2026-07-13T21:58:34+00:00",
            "operation": "Microsoft.OperationalInsights/workspaces/delete",
            "caller": "jacqui@example.com",
            "status": "Succeeded",
            "resource_id": f"{SUB}/providers/Microsoft.OperationalInsights/workspaces/log-3s7c7weddxr3s",
        }]
        drift = self._run("log-[86c9cbf6]", events)
        self.assertEqual(drift["name"], "log-3s7c7weddxr3s")
        self.assertEqual(drift["bicep_name_expression"], "log-[86c9cbf6]")
        self.assertIn("log-3s7c7weddxr3s", drift["lifecycle"]["resource_id"])

    def test_literal_name_untouched(self):
        events = [{
            "timestamp": "2026-07-13T21:58:34+00:00",
            "operation": "Microsoft.OperationalInsights/workspaces/delete",
            "caller": "jacqui@example.com",
            "status": "Succeeded",
            "resource_id": f"{SUB}/providers/Microsoft.OperationalInsights/workspaces/log-literal",
        }]
        drift = self._run("log-literal", events)
        self.assertEqual(drift["name"], "log-literal")
        self.assertNotIn("bicep_name_expression", drift)

    def test_no_events_keeps_placeholder(self):
        drift = self._run("log-[86c9cbf6]", [])
        self.assertEqual(drift["name"], "log-[86c9cbf6]")
        self.assertNotIn("bicep_name_expression", drift)


if __name__ == "__main__":
    unittest.main()
