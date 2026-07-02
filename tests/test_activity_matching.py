"""
Unit tests for activity_log.match_activity_for_resource.

Key regression: a child resource (e.g. a management lock nested under a storage
account) must NOT match its parent's activity events.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.activity_log import match_activity_for_resource

SA = "/subscriptions/s/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st1"
LOCK = SA + "/providers/microsoft.authorization/locks/policy-lock"


def ev(rid, op, caller):
    return {"resource_id": rid, "operation": op, "caller": caller, "timestamp": "2026-07-02T00:00:00Z"}


class MatchActivityTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            ev(SA, "microsoft.storage/storageaccounts/write", "policy-modify-msi"),
            ev(LOCK, "microsoft.authorization/locks/write", "policy-dine-msi"),
            ev("/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1/providers/microsoft.authorization/locks/kv-lock",
               "microsoft.authorization/locks/write", "jane@corp.com"),
        ]

    def test_lock_does_not_match_parent_storage_events(self):
        m = match_activity_for_resource(self.events, LOCK, "Microsoft.Authorization/locks")
        callers = {e["caller"] for e in m}
        self.assertEqual(callers, {"policy-dine-msi"}, "lock must match only its own event, not the parent SA write")

    def test_storage_matches_its_own_and_subresource_events(self):
        # A storage account matches its own writes AND its sub-resources (the lock under it).
        m = match_activity_for_resource(self.events, SA, "Microsoft.Storage/storageAccounts")
        rids = {e["resource_id"] for e in m}
        self.assertIn(SA, rids)
        self.assertIn(LOCK, rids)  # sub-resource path 'SA/...'
        # but not the unrelated key vault lock
        self.assertTrue(all("keyvault" not in r for r in rids))

    def test_deleted_resource_falls_back_to_type_match(self):
        # No id match (deleted, unresolvable id) -> type-substring fallback.
        deleted_id = "/subscriptions/s/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/log-[hash]"
        events = [ev("/subscriptions/s/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/log-real",
                     "microsoft.operationalinsights/workspaces/delete", "jane@corp.com")]
        m = match_activity_for_resource(events, deleted_id, "Microsoft.OperationalInsights/workspaces")
        self.assertEqual(len(m), 1)


if __name__ == "__main__":
    unittest.main()
