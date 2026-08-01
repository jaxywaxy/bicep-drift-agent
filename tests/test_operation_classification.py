"""Tests for operation-type classification and the lifecycle milestones built
from it (tools/change_origin.py).

The bug these pin down was found on a live estate: the CREATE branch substring
-matched "put" against the WHOLE operation name, and 'Microsoft.Compute' contains
'put', so every Compute delete classified as a create. A deliberately deleted
availability set was reported with operation 'create' and a null deleted_at -
detection was right, attribution was not.

The second half covers ARM's /write, which means create OR update. Classifying
every write as a create overwrote created_at on each pass and left
last_modified_* permanently empty, so the MODIFY branch was unreachable.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.change_origin import (
    OperationType,
    _classify_operation_type,
    build_resource_lifecycle,
    select_relevant_activity,
)

RESOURCE_ID = (
    "/subscriptions/S/resourceGroups/rg/providers/"
    "Microsoft.Compute/availabilitySets/avset-drift-test"
)
T0 = datetime(2026, 7, 26, 3, 0, tzinfo=timezone.utc)


def _entry(operation, offset_minutes=0, caller="someone@example.com", **props):
    # Azure Monitor hands back a datetime (log.event_timestamp), not a string.
    return {
        "timestamp": T0 + timedelta(minutes=offset_minutes),
        "operation": operation,
        "caller": caller,
        "status": "Succeeded",
        "properties": props,
    }


class OperationVerbTests(unittest.TestCase):
    def test_compute_delete_is_not_a_create(self):
        """'Microsoft.Compute' contains 'put' - the original substring bug."""
        for rtype in ("availabilitySets", "virtualMachines", "disks",
                      "virtualMachineScaleSets"):
            with self.subTest(rtype=rtype):
                self.assertEqual(
                    _classify_operation_type(f"Microsoft.Compute/{rtype}/delete"),
                    OperationType.DELETE,
                )

    def test_deletes_across_providers(self):
        for op in (
            "Microsoft.Storage/storageAccounts/delete",
            "Microsoft.Network/networkSecurityGroups/delete",
            "Microsoft.KeyVault/vaults/delete",
        ):
            with self.subTest(op=op):
                self.assertEqual(_classify_operation_type(op), OperationType.DELETE)

    def test_write_is_indeterminate_not_create(self):
        self.assertEqual(
            _classify_operation_type("Microsoft.Storage/storageAccounts/write"),
            OperationType.WRITE,
        )

    def test_remediation_matches_the_type_not_the_verb(self):
        # The verb here is 'write'; 'remediation' identifies the resource type.
        self.assertEqual(
            _classify_operation_type("Microsoft.PolicyInsights/remediations/write"),
            OperationType.REMEDIATE,
        )

    def test_read_and_unknown_verbs_do_not_classify_as_writes(self):
        for op in ("Microsoft.Compute/virtualMachines/read",
                   "Microsoft.Compute/virtualMachines/restart/action"):
            with self.subTest(op=op):
                self.assertEqual(_classify_operation_type(op), OperationType.UNKNOWN)

    def test_none_and_empty_are_unknown(self):
        self.assertEqual(_classify_operation_type(None), OperationType.UNKNOWN)
        self.assertEqual(_classify_operation_type(""), OperationType.UNKNOWN)


class LifecycleMilestoneTests(unittest.TestCase):
    def test_deleted_compute_resource_records_the_deletion(self):
        """The live failure: created_at was set from the delete, deleted_at null."""
        logs = [
            _entry("Microsoft.Compute/availabilitySets/write", 0, caller="pipeline"),
            _entry("Microsoft.Compute/availabilitySets/delete", 30, caller="alice"),
        ]

        lc = build_resource_lifecycle(RESOURCE_ID, logs)

        self.assertEqual(lc.deleted_by, "alice")
        self.assertEqual(lc.deleted_at, T0 + timedelta(minutes=30))
        self.assertEqual(lc.created_by, "pipeline")
        self.assertEqual(lc.created_at, T0)
        self.assertEqual(
            [e.operation for e in lc.events],
            [OperationType.CREATE, OperationType.DELETE],
        )

    def test_first_write_creates_and_later_writes_modify(self):
        logs = [
            _entry("Microsoft.Storage/storageAccounts/write", 0, caller="pipeline"),
            _entry("Microsoft.Storage/storageAccounts/write", 20, caller="alice"),
            _entry("Microsoft.Storage/storageAccounts/write", 40, caller="someone-else"),
        ]

        lc = build_resource_lifecycle("/subscriptions/S/.../storageAccounts/st", logs)

        self.assertEqual(lc.created_by, "pipeline")
        self.assertEqual(lc.created_at, T0)
        # last_modified tracks the MOST RECENT modification, not the first.
        self.assertEqual(lc.last_modified_by, "someone-else")
        self.assertEqual(lc.last_modified_at, T0 + timedelta(minutes=40))
        self.assertEqual(
            [e.operation for e in lc.events],
            [OperationType.CREATE, OperationType.MODIFY, OperationType.MODIFY],
        )

    def test_created_at_is_not_moved_by_a_later_create(self):
        """Previously every create overwrote created_at, so the NEWEST won."""
        logs = [
            _entry("Microsoft.Compute/disks/write", 0, caller="pipeline"),
            _entry("Microsoft.Compute/disks/delete", 10, caller="alice"),
            _entry("Microsoft.Compute/disks/write", 20, caller="alice"),
        ]

        lc = build_resource_lifecycle("/subscriptions/S/.../disks/d", logs)

        self.assertEqual(lc.created_at, T0)  # not the 20-minute write
        self.assertEqual(lc.deleted_at, T0 + timedelta(minutes=10))

    def test_write_never_leaks_into_a_report(self):
        logs = [_entry("Microsoft.Network/virtualNetworks/write", 0)]

        lc = build_resource_lifecycle("/subscriptions/S/.../virtualNetworks/v", logs)

        for event in lc.events:
            self.assertNotEqual(event.operation, OperationType.WRITE)
            self.assertNotIn("write", event.to_dict()["reason"].lower())


class PipelineShapeTests(unittest.TestCase):
    """Drive the REAL production path: select_relevant_activity narrows a
    resource's log to a ONE-event list, and only then does the lifecycle get
    built. The first version of this fix resolved /write by event ordering and
    passed its unit tests by feeding the builder several events directly - which
    production never does. With one event there is no "later" write, so every
    modification still reported operation 'create' (live run 2026-07-26).
    """

    def _lifecycle(self, logs, drift_type):
        relevant = select_relevant_activity(logs, drift_type)
        return relevant, build_resource_lifecycle("/x/r", relevant, drift_type=drift_type)

    def test_property_drift_on_an_existing_resource_is_a_modification(self):
        logs = [
            _entry("Microsoft.Storage/storageAccounts/write", 0, caller="pipeline"),
            _entry("Microsoft.Storage/storageAccounts/write", 30, caller="alice"),
        ]

        relevant, lc = self._lifecycle(logs, "property_drift")

        self.assertEqual(len(relevant), 1, "production narrows to one event")
        self.assertEqual([e.operation for e in lc.events], [OperationType.MODIFY])
        self.assertEqual(lc.last_modified_by, "alice")
        self.assertEqual(lc.last_modified_at, T0 + timedelta(minutes=30))
        # The write did not create this resource, so created_* must stay empty.
        self.assertIsNone(lc.created_at)
        self.assertIsNone(lc.created_by)

    def test_extra_in_azure_write_really_is_a_creation(self):
        logs = [_entry("Microsoft.Network/networkSecurityGroups/write", 0, caller="alice")]

        _, lc = self._lifecycle(logs, "extra_in_azure")

        self.assertEqual([e.operation for e in lc.events], [OperationType.CREATE])
        self.assertEqual(lc.created_by, "alice")
        self.assertIsNone(lc.last_modified_at)

    def test_missing_in_azure_still_reports_the_deletion(self):
        logs = [
            _entry("Microsoft.Compute/availabilitySets/write", 0, caller="pipeline"),
            _entry("Microsoft.Compute/availabilitySets/delete", 30, caller="alice"),
        ]

        _, lc = self._lifecycle(logs, "missing_in_azure")

        self.assertEqual([e.operation for e in lc.events], [OperationType.DELETE])
        self.assertEqual(lc.deleted_by, "alice")
        self.assertEqual(lc.deleted_at, T0 + timedelta(minutes=30))

    def test_no_drift_context_falls_back_to_ordering(self):
        logs = [
            _entry("Microsoft.Storage/storageAccounts/write", 0),
            _entry("Microsoft.Storage/storageAccounts/write", 30),
        ]

        lc = build_resource_lifecycle("/x/r", logs)  # no drift_type

        self.assertEqual(
            [e.operation for e in lc.events],
            [OperationType.CREATE, OperationType.MODIFY],
        )


if __name__ == "__main__":
    unittest.main()
