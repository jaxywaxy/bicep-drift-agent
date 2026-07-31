"""An operation that did not succeed is not a cause, and 'arm' is not a verb.

Both found in the 2026-07-30 rerun of the teardown report, on the same two
Microsoft.Web/serverfarms rows, which shared one event:

    {"timestamp": "...09:27:37.165346", "operation": "delete",
     "method": "ARM Deployment", "status": "Failed"}

  A. _extract_method substring-matched "arm" against the whole operation name,
     and "serverf(arm)s" contains it - so every App Service Plan operation was
     reported as an ARM deployment. These were manual deletions. The same trap
     _classify_operation_type documents for 'put' inside 'Microsoft.Compute',
     which anchors on the last segment; this function never got the fix.
  B. event_explains_drift checked the operation verb only, so a status="Failed"
     delete counted as the explanation for a missing resource and still
     populated deleted_at/deleted_by. A failed delete removed nothing.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import orchestration.attribution as attribution
from tools.change_origin import (
    _extract_method,
    event_explains_drift,
    event_succeeded,
    select_relevant_activity,
)

FARMS = "Microsoft.Web/serverfarms"
RG = "/subscriptions/s/resourceGroups/rg-drift-test/providers"
USER = "someone@example.com"


def _event(status, ts_second, operation=f"{FARMS}/delete".lower()):
    return {
        "operation": operation, "caller": USER, "status": status,
        "timestamp": datetime(2026, 7, 28, 9, 27, ts_second, tzinfo=timezone.utc),
        "resource_id": f"{RG}/{FARMS}/asp-test-drift",
    }


class MethodIsReadFromTheTypeNotTheVerbTests(unittest.TestCase):
    def test_serverfarms_is_not_an_arm_deployment(self):
        self.assertNotEqual(
            _extract_method(USER, "Microsoft.Web/serverfarms/delete", {}),
            "ARM Deployment",
        )

    def test_a_real_arm_deployment_is_still_recognised(self):
        self.assertEqual(
            _extract_method(USER, "Microsoft.Resources/deployments/write", {}),
            "ARM Deployment",
        )

    def test_a_deployments_child_operation_is_still_recognised(self):
        self.assertEqual(
            _extract_method(USER, "Microsoft.Resources/deployments/validate/action", {}),
            "ARM Deployment",
        )

    def test_an_unknown_method_stays_unknown_rather_than_guessing(self):
        self.assertEqual(
            _extract_method(USER, "Microsoft.Web/serverfarms/delete", {}), "Unknown")

    def test_the_explicit_method_property_still_wins(self):
        self.assertEqual(
            _extract_method(USER, "Microsoft.Web/serverfarms/delete",
                            {"method": "Azure Portal"}),
            "Azure Portal",
        )


class AFailedOperationIsNotACauseTests(unittest.TestCase):
    def test_a_failed_delete_does_not_explain_a_missing_resource(self):
        self.assertFalse(
            event_explains_drift(_event("Failed", 37), "missing_in_azure"))

    def test_a_succeeded_delete_still_does(self):
        self.assertTrue(
            event_explains_drift(_event("Succeeded", 37), "missing_in_azure"))

    def test_a_non_terminal_status_is_not_treated_as_a_non_event(self):
        # Rejecting these would drop attribution the report already gets right:
        # a delete logged only as Started, against a resource demonstrably gone,
        # is ingestion lag.
        for status in ("Started", "Accepted", "Unknown", ""):
            with self.subTest(status=status):
                self.assertTrue(event_succeeded(_event(status, 37)))

    def test_cancelled_counts_as_uneffective_in_both_spellings(self):
        self.assertFalse(event_succeeded(_event("Canceled", 37)))
        self.assertFalse(event_succeeded(_event("Cancelled", 37)))

    def test_the_selector_prefers_the_operation_that_took_effect(self):
        # The failure is NEWER; picking purely by timestamp chose it.
        succeeded, failed = _event("Succeeded", 30), _event("Failed", 37)
        self.assertEqual(
            select_relevant_activity([succeeded, failed], "missing_in_azure"),
            [succeeded],
        )

    def test_a_recreate_that_failed_does_not_clear_the_deletion(self):
        """Caught reviewing the status work: the stale-delete guard reads a
        write NEWER than the delete as 'the resource came back', without
        checking the write succeeded. A failed recreate recreated nothing, and
        taking it suppressed the real deletion.
        """
        deleted = _event("Succeeded", 0)
        failed_recreate = _event("Failed", 30, operation=f"{FARMS}/write".lower())
        self.assertEqual(
            select_relevant_activity([deleted, failed_recreate], "missing_in_azure"),
            [deleted],
        )

    def test_a_recreate_that_succeeded_still_clears_it(self):
        deleted = _event("Succeeded", 0)
        recreate = _event("Succeeded", 30, operation=f"{FARMS}/write".lower())
        self.assertEqual(
            select_relevant_activity([deleted, recreate], "missing_in_azure"),
            [recreate],
        )

    def test_a_failure_is_still_returned_when_it_is_all_there_is(self):
        # The timeline keeps its context; event_explains_drift is what stops it
        # being named as the cause.
        failed = _event("Failed", 37)
        self.assertEqual(
            select_relevant_activity([failed], "missing_in_azure"), [failed])


class ThroughThePipelineTests(unittest.TestCase):
    """The units above pass whether or not the status check is wired into the
    stage that builds the record. See the call-path lesson."""

    def _attribute(self, events):
        report = {"drifts": [{"type": FARMS, "name": "asp-test-drift",
                              "drift_type": "missing_in_azure", "details": {}}],
                  "live_resources": []}
        with mock.patch.object(attribution, "fetch_resource_group_activity",
                               return_value=events), \
             mock.patch.object(attribution, "fetch_policy_principal_ids",
                               return_value=set()), \
             mock.patch.object(attribution, "detect_scanning_identity",
                               return_value=set()), \
             mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": "s"}):
            attribution._attribute_lifecycle(report, "rg-drift-test")
        return report["drifts"][0]

    def test_a_failed_delete_is_not_named_as_the_cause(self):
        d = self._attribute([_event("Failed", 37)])
        self.assertEqual(d["change_origin"]["origin"], "unknown")

    def test_it_does_not_assert_a_deletion_that_failed(self):
        d = self._attribute([_event("Failed", 37)])
        self.assertIsNone(d["lifecycle"]["deleted_at"])
        self.assertIsNone(d["lifecycle"]["deleted_by"])

    def test_the_failure_survives_in_the_timeline_as_context(self):
        d = self._attribute([_event("Failed", 37)])
        self.assertTrue(d["lifecycle"]["events"])
        self.assertEqual(d["lifecycle"]["events"][0]["status"], "Failed")

    def test_the_method_reported_is_not_a_false_arm_deployment(self):
        d = self._attribute([_event("Failed", 37)])
        methods = [e["method"] for e in d["lifecycle"]["events"]]
        self.assertNotIn("ARM Deployment", methods)

    def test_a_succeeded_delete_alongside_the_failure_is_attributed(self):
        d = self._attribute([_event("Succeeded", 30), _event("Failed", 37)])
        self.assertEqual(d["change_origin"]["origin"], "manual_change")
        self.assertEqual(d["change_origin"]["changed_by"], USER)
        self.assertIsNotNone(d["lifecycle"]["deleted_at"])


if __name__ == "__main__":
    unittest.main()
