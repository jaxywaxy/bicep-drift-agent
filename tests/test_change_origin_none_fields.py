"""
Activity-log events with null caller/operation must not crash classification.

Found live in the policy-split test: a SQL database's lifecycle attribution
failed with "'NoneType' object has no attribute 'lower'" and fell back to
origin=unknown. Cause is the classic dict.get trap - `d.get('caller', '')`
returns None when the key is PRESENT but null (the default only applies when
the key is ABSENT), and Azure activity events do carry explicit nulls. The
failure was swallowed (fail-soft), so the only visible symptom was a lost
lifecycle on that entry - but any drift whose newest event had a null caller
lost its attribution.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.change_origin import (
    _create_lifecycle_event,
    build_resource_lifecycle,
    classify_change_origin,
)


def _event(**over):
    e = {"timestamp": "2026-07-15T21:36:56+00:00", "operation": "write",
         "caller": "someone@example.com", "status": "Succeeded",
         "resource_id": "/subscriptions/s/resourceGroups/rg/x/y"}
    e.update(over)
    return e


class NoneFieldEventTests(unittest.TestCase):
    def test_null_caller_does_not_crash(self):
        co = classify_change_origin([_event(caller=None)], set())
        self.assertIsNotNone(co.origin)

    def test_null_operation_does_not_crash(self):
        co = classify_change_origin([_event(operation=None)], set())
        self.assertIsNotNone(co.origin)

    def test_both_null_does_not_crash(self):
        co = classify_change_origin([_event(caller=None, operation=None)], set())
        self.assertIsNotNone(co.origin)

    def test_null_method_does_not_crash(self):
        co = classify_change_origin([_event(method=None)], set())
        self.assertIsNotNone(co.origin)

    def test_lifecycle_event_tolerates_nulls(self):
        ev = _create_lifecycle_event(_event(caller=None, operation=None))
        self.assertIsNotNone(ev)

    def test_build_lifecycle_tolerates_nulls(self):
        lc = build_resource_lifecycle("/subscriptions/s/rg/x",
                                      [_event(caller=None, operation=None)])
        self.assertEqual(len(lc.events), 1)

    def test_normal_event_still_attributes(self):
        # The fix must not change behaviour for well-formed events.
        co = classify_change_origin([_event(caller="jane@x.com", operation="write")], set())
        self.assertEqual(co.changed_by, "jane@x.com")


if __name__ == "__main__":
    unittest.main()
