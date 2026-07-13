"""
Unit tests for missing_in_azure emission on unmatched placeholder-named resources.

Phase 1 deliberately skips unresolvable-named bicep resources (their literal name
never equals the deployed uniqueString name) and smart matching only ever produced
MATCHES - so deleting any uniqueString-named resource (storage, key vault, SQL,
LA workspace...) produced no drift at all. Found live: deleted LA workspace
log-[86c9cbf6] was invisible while the literal-named KV lock deletion surfaced.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyze_drift


def _apply(arm_resources, live_resources, drifts=None):
    report = {
        "arm_resources": arm_resources,
        "live_resources": live_resources,
        "drifts": drifts if drifts is not None else [],
    }
    analyze_drift._apply_smart_matching(report)
    return report


def _missing(report):
    return [
        (d["type"], d["name"])
        for d in report["drifts"]
        if d["drift_type"] == "missing_in_azure"
    ]


class PlaceholderDeletionTests(unittest.TestCase):
    def test_deleted_placeholder_resource_flagged_missing(self):
        # The live scenario: workspace declared with placeholder name, deleted live.
        report = _apply(
            arm_resources=[{"type": "Microsoft.OperationalInsights/workspaces",
                            "name": "log-[86c9cbf6]"}],
            live_resources=[],
        )
        self.assertEqual(
            _missing(report),
            [("Microsoft.OperationalInsights/workspaces", "log-[86c9cbf6]")],
        )
        details = report["drifts"][0]["details"]
        self.assertIn("note", details)

    def test_matched_placeholder_resource_not_flagged(self):
        report = _apply(
            arm_resources=[{"type": "Microsoft.OperationalInsights/workspaces",
                            "name": "log-[86c9cbf6]"}],
            live_resources=[{"type": "microsoft.operationalinsights/workspaces",
                             "name": "log-3s7c7weddxr3s"}],
        )
        self.assertEqual(_missing(report), [])
        self.assertEqual(len(report.get("smart_matched", [])), 1)

    def test_literal_named_resource_left_to_phase1(self):
        # Literal names ARE compared in Phase 1; re-flagging here would duplicate.
        report = _apply(
            arm_resources=[
                {"type": "Microsoft.Insights/dataCollectionRules", "name": "dcr-drift"},
                {"type": "Microsoft.Storage/storageAccounts", "name": "st[86c9cbf6]"},
            ],
            live_resources=[{"type": "microsoft.storage/storageaccounts",
                             "name": "stdrift123"}],
        )
        self.assertEqual(_missing(report), [])

    def test_identity_matched_types_excluded(self):
        # Role/policy assignments live in separate Resource Graph tables and are
        # compared by rbac/policy paths; their guid() names must not flag here.
        report = _apply(
            arm_resources=[
                {"type": "Microsoft.Authorization/roleAssignments",
                 "name": "guid(resourceGroup().id, 'reader')"},
                {"type": "Microsoft.KeyVault/vaults", "name": "kv[86c9cbf6]"},
            ],
            live_resources=[],
        )
        self.assertEqual(_missing(report), [("Microsoft.KeyVault/vaults", "kv[86c9cbf6]")])

    def test_module_deployments_excluded(self):
        report = _apply(
            arm_resources=[{"type": "Microsoft.Resources/deployments",
                            "name": "format('deploy-{0}', uniqueString(deployment().name))"}],
            live_resources=[],
        )
        self.assertEqual(_missing(report), [])

    def test_no_duplicate_when_drift_already_present(self):
        existing = {"type": "Microsoft.KeyVault/vaults", "name": "kv[86c9cbf6]",
                    "drift_type": "missing_in_azure", "details": {}}
        report = _apply(
            arm_resources=[{"type": "Microsoft.KeyVault/vaults", "name": "kv[86c9cbf6]"}],
            live_resources=[],
            drifts=[existing],
        )
        self.assertEqual(len(_missing(report)), 1)

    def test_more_declared_than_live_flags_the_leftover(self):
        # Two placeholder-named storage accounts declared, one live: the matcher
        # pairs one; the leftover means a deployed instance is gone.
        report = _apply(
            arm_resources=[
                {"type": "Microsoft.Storage/storageAccounts", "name": "stmain[86c9cbf6]"},
                {"type": "Microsoft.Storage/storageAccounts", "name": "stlogs[86c9cbf6]"},
            ],
            live_resources=[{"type": "microsoft.storage/storageaccounts",
                             "name": "stmain3s7c7wedd"}],
        )
        self.assertEqual(
            _missing(report),
            [("Microsoft.Storage/storageAccounts", "stlogs[86c9cbf6]")],
        )

    def test_deleted_parent_children_also_flagged(self):
        report = _apply(
            arm_resources=[
                {"type": "Microsoft.OperationalInsights/workspaces",
                 "name": "log-[86c9cbf6]"},
                {"type": "Microsoft.OperationalInsights/workspaces/tables",
                 "name": "log-[86c9cbf6]/CustomLog_CL"},
            ],
            live_resources=[],
        )
        self.assertEqual(len(_missing(report)), 2)


if __name__ == "__main__":
    unittest.main()
