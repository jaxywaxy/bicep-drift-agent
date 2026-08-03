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


class SubscriptionScopeActivityFetchTests(unittest.TestCase):
    """A subscription-scoped scan is driven by '*' or a glob, and that selector
    was passed straight into the Activity Log $filter as
    `resourceGroupName eq '*'`. The API treats it as a LITERAL name, so it
    matched nothing and EVERY drift came back origin=unknown with the reason
    "No activity log entries found (logs may have expired)" - which reads as an
    empty log rather than a query aimed at a resource group called '*'.

    Found live 2026-08-03: 15 of 15 rows unattributed on a subscription-scoped
    landing zone, while the Activity Log held every delete event naming the
    actor. Both landing zones in lz-index.yml are subscription-scoped, so this
    was every scheduled run of both.

    The whole-window fetch is already the design (see the docstring: pull once,
    match per resource in memory via match_activity_for_resource, which keys off
    resource_id) - so dropping the resourceGroupName clause for a selector is
    the same strategy with a wider net, not a new one.
    """

    def _captured_filter(self, selector):
        from unittest import mock
        import tools.activity_log as al

        seen = {}

        class _Logs:
            def list(self, filter):
                seen["filter"] = filter
                return []

        class _Client:
            def __init__(self, *a, **kw):
                self.activity_logs = _Logs()

        with mock.patch.dict("sys.modules", {
            "azure.mgmt.monitor": mock.MagicMock(MonitorManagementClient=_Client)
        }), mock.patch.object(al, "DefaultAzureCredential", mock.MagicMock()):
            al.fetch_resource_group_activity("sub-1", selector, days=30)
        return seen.get("filter", "")

    def test_wildcard_does_not_filter_on_a_resource_group_named_star(self):
        f = self._captured_filter("*")
        self.assertNotIn("resourceGroupName", f,
                         f"'*' was passed to the API as a literal RG name: {f}")

    def test_glob_does_not_filter_on_a_literal_glob(self):
        f = self._captured_filter("jacquidev-*")
        self.assertNotIn("resourceGroupName", f,
                         f"a glob was passed to the API as a literal RG name: {f}")

    def test_the_time_window_is_still_applied(self):
        # Dropping the RG clause must not drop the bound that keeps the query sane.
        self.assertIn("eventTimestamp ge", self._captured_filter("*"))

    def test_a_real_resource_group_still_filters_on_it(self):
        f = self._captured_filter("rg-drift-test")
        self.assertIn("resourceGroupName eq 'rg-drift-test'", f)
