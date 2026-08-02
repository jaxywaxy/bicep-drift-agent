"""
Unit tests for tools.change_origin.select_relevant_activity.

Locks in the behavior around:
- missing drift -> the DELETE event
- property/modified drift -> the WRITE event (reads/lists excluded)
- stale-delete guard: a create/write NEWER than a delete wins (recreated resource)
- empty input
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.change_origin import select_relevant_activity


def ev(ts, op, caller="user@example.com"):
    return {"timestamp": ts, "operation": op, "caller": caller, "status": "Succeeded", "properties": {}}


class SelectRelevantActivityTests(unittest.TestCase):

    def test_empty_returns_empty(self):
        self.assertEqual(select_relevant_activity([], "missing_in_azure"), [])
        self.assertEqual(select_relevant_activity(None, "property_drift"), [])

    def test_missing_picks_delete(self):
        logs = [
            ev("2026-07-01T03:00:00Z", "microsoft.storage/storageaccounts/read"),
            ev("2026-07-01T05:31:10Z", "microsoft.operationalinsights/workspaces/delete"),
        ]
        result = select_relevant_activity(logs, "missing_in_azure")
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["operation"].endswith("/delete"))

    def test_modified_picks_write_not_read(self):
        logs = [
            ev("2026-07-01T02:00:00Z", "microsoft.storage/storageaccounts/read"),
            ev("2026-07-01T03:50:00Z", "microsoft.storage/storageaccounts/write"),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["operation"].endswith("/write"))

    def test_stale_delete_guard_prefers_newer_write(self):
        # Resource deleted at 05:31 but re-created (write) at 20:46 -> exists now.
        logs = [
            ev("2026-07-01T05:31:10Z", "microsoft.storage/storageaccounts/delete"),
            ev("2026-07-01T20:46:00Z", "microsoft.storage/storageaccounts/write"),
        ]
        result = select_relevant_activity(logs, "missing_in_azure")
        self.assertEqual(len(result), 1)
        # newer write wins over the older delete
        self.assertTrue(result[0]["operation"].endswith("/write"))
        self.assertEqual(result[0]["timestamp"], "2026-07-01T20:46:00Z")

    def test_delete_wins_when_newer_than_write(self):
        logs = [
            ev("2026-07-01T02:00:00Z", "microsoft.storage/storageaccounts/write"),
            ev("2026-07-01T09:00:00Z", "microsoft.storage/storageaccounts/delete"),
        ]
        result = select_relevant_activity(logs, "missing_in_azure")
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["operation"].endswith("/delete"))

    def test_returns_single_most_recent_write(self):
        logs = [
            ev("2026-07-01T01:00:00Z", "microsoft.storage/storageaccounts/write", caller="old@x.com"),
            ev("2026-07-01T08:00:00Z", "microsoft.storage/storageaccounts/write", caller="new@x.com"),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["caller"], "new@x.com")


class PlatformTelemetryIsNotAConfigWriteTests(unittest.TestCase):
    """
    Regression: the 2026-08-02 live round scaled a VMSS 0 -> 1 and the report
    named NO actor, because `"update" in op` matched
    'Microsoft.Resourcehealth/healthevent/Updated/action' - platform telemetry
    with caller=None that every VM and scale-set instance emits continuously.
    It was newer than the user's own write, so it won the latest-first sort and
    the drift read "manual change by <nobody>" while the real actor sat in the
    same event list. Operation names must match on PATH SEGMENTS, not substrings.
    """

    def test_health_telemetry_does_not_outrank_the_real_write(self):
        logs = [
            ev("2026-08-02T20:37:14.288Z", "Microsoft.Compute/virtualMachineScaleSets/write",
               caller="user@example.com"),
            ev("2026-08-02T20:37:19.608Z", "Microsoft.Resourcehealth/healthevent/Updated/action",
               caller=None),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertEqual(len(result), 1)
        self.assertTrue(
            result[0]["operation"].endswith("/write"),
            f"health telemetry was selected over the real write: {result[0]['operation']}",
        )
        self.assertEqual(result[0]["caller"], "user@example.com")

    def test_health_telemetry_alone_is_not_promoted_to_a_write(self):
        # Only telemetry present: the non-read fallback may still return it, but
        # it must never be chosen while a genuine write exists (above). Here we
        # simply assert we do not crash and do not invent an actor.
        logs = [
            ev("2026-08-02T20:37:19.608Z", "Microsoft.Resourcehealth/healthevent/Updated/action",
               caller=None),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertTrue(len(result) <= 1)
        if result:
            self.assertIsNone(result[0]["caller"])

    def test_genuine_update_action_still_matches(self):
        # 'update' as a real path segment must keep working - the fix narrows
        # substring matching, it must not narrow legitimate operations.
        logs = [
            ev("2026-08-02T01:00:00Z", "microsoft.sql/servers/read"),
            ev("2026-08-02T02:00:00Z", "microsoft.sql/servers/databases/update/action"),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertEqual(len(result), 1)
        self.assertIn("update", result[0]["operation"])

    def test_actor_bearing_event_preferred_over_actorless_at_same_recency(self):
        # Defence in depth: "manual change by nobody" is never useful. Even if
        # some future telemetry verb slips the segment filter, an event that
        # names someone should outrank one that names no one.
        # The actorless event is listed FIRST on purpose: Python's sort is
        # stable, so asserting on input order would pass without the fix and
        # prove nothing.
        logs = [
            ev("2026-08-02T03:00:00Z", "microsoft.compute/virtualmachinescalesets/write",
               caller=None),
            ev("2026-08-02T03:00:00Z", "microsoft.compute/virtualmachinescalesets/write",
               caller="user@example.com"),
        ]
        result = select_relevant_activity(logs, "property_drift")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["caller"], "user@example.com")


if __name__ == "__main__":
    unittest.main()
