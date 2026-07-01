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


if __name__ == "__main__":
    unittest.main()
