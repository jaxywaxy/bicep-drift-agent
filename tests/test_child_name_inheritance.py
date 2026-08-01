"""A child should use the real parent name its own parent row already recovered.

A parent whose Bicep name is a runtime expression is rescued from its Activity
Log event, which carries the true Azure id. A CHILD normally has no event of its
own - Azure logs the parent's delete, not each child's - so nothing rescues it
and it keeps the placeholder.

The 2026-08-01 teardown report shows both halves at once: 15 parents resolved to
real names while 18 children still read `sqldrift[86c9cbf6]/driftdb`, with
`sqldrift3s7c7weddxr3s` sitting in the same report.

Not only legibility: the placeholder is embedded in the child's synthetic
resource_id, so the id is not a real ARM id, and an unresolved name keeps the
row off the id-match path and into the type fallback narrowed in #358.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import orchestration.attribution as attribution
from orchestration.attribution import _inherit_recovered_parent_names

RG = "/subscriptions/s/resourceGroups/rg-drift-test/providers"
SQL = "Microsoft.Sql/servers"
SQL_DB = "Microsoft.Sql/servers/databases"


def _parent(name="sqldrift3s7c7weddxr3s", expr="sqldrift[86c9cbf6]"):
    return {"type": SQL, "name": name, "bicep_name_expression": expr,
            "lifecycle": {"resource_id": f"{RG}/{SQL}/{name}"}}


def _child(name="sqldrift[86c9cbf6]/driftdb"):
    return {"type": SQL_DB, "name": name,
            "lifecycle": {"resource_id": f"{RG}/{SQL_DB}/{name}"}}


class AChildInheritsItsParentsRecoveredNameTests(unittest.TestCase):
    def test_the_placeholder_segment_is_replaced(self):
        drifts = [_parent(), _child()]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["name"], "sqldrift3s7c7weddxr3s/driftdb")

    def test_the_original_expression_is_kept_like_a_rescued_parent(self):
        drifts = [_parent(), _child()]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["bicep_name_expression"], "sqldrift[86c9cbf6]/driftdb")

    def test_the_synthetic_id_becomes_a_real_arm_id(self):
        drifts = [_parent(), _child()]
        _inherit_recovered_parent_names(drifts)
        self.assertNotIn("[86c9cbf6]", drifts[1]["lifecycle"]["resource_id"])
        self.assertTrue(
            drifts[1]["lifecycle"]["resource_id"].endswith("sqldrift3s7c7weddxr3s/driftdb"))

    def test_a_grandchild_inherits_too(self):
        drifts = [
            {"type": "Microsoft.EventHub/namespaces", "name": "eh-3s7c7weddxr3s",
             "bicep_name_expression": "eh-[86c9cbf6]", "lifecycle": {}},
            {"type": "Microsoft.EventHub/namespaces/eventhubs/consumergroups",
             "name": "eh-[86c9cbf6]/drift-hub/driftcg", "lifecycle": {}},
        ]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["name"], "eh-3s7c7weddxr3s/drift-hub/driftcg")

    def test_order_does_not_matter(self):
        """Drift order is arbitrary - a child can be attributed before the
        parent that rescues its name, which is why this is a pass after the
        loop rather than work done inside it."""
        drifts = [_child(), _parent()]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[0]["name"], "sqldrift3s7c7weddxr3s/driftdb")


class ItDoesNotRewriteWhatItShouldNotTests(unittest.TestCase):
    def test_a_child_whose_parent_was_never_rescued_is_untouched(self):
        drifts = [_parent(), {"type": "Microsoft.Web/sites/config",
                              "name": "app-test-drift/appsettings", "lifecycle": {}}]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["name"], "app-test-drift/appsettings")
        self.assertNotIn("bicep_name_expression", drifts[1])

    def test_a_row_that_already_carries_provenance_is_left_alone(self):
        """A row rescued on its own evidence must not be reinterpreted from its
        parent - its own event is the better evidence, and clobbering
        bicep_name_expression would lose what the name originally was.

        Constructed so the guard is what decides it: the name still leads with a
        recovered placeholder, so without the guard this row WOULD be rewritten.
        """
        already = _child()  # name still leads with sqldrift[86c9cbf6]
        already["bicep_name_expression"] = "recovered-from-its-own-event"
        drifts = [_parent(), already]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["bicep_name_expression"], "recovered-from-its-own-event")
        self.assertEqual(drifts[1]["name"], "sqldrift[86c9cbf6]/driftdb")

    def test_a_top_level_row_is_never_touched(self):
        drifts = [_parent(), {"type": "Microsoft.Web/sites", "name": "app-test-drift",
                              "lifecycle": {}}]
        _inherit_recovered_parent_names(drifts)
        self.assertNotIn("bicep_name_expression", drifts[1])

    def test_a_partial_segment_match_is_not_a_parent(self):
        """'sqldrift[86c9cbf6]x/db' is a different resource - only a whole
        leading segment counts."""
        drifts = [_parent(), _child("sqldrift[86c9cbf6]x/driftdb")]
        _inherit_recovered_parent_names(drifts)
        self.assertEqual(drifts[1]["name"], "sqldrift[86c9cbf6]x/driftdb")

    def test_nothing_recovered_means_nothing_changes(self):
        drifts = [_child()]
        self.assertEqual(_inherit_recovered_parent_names(drifts), 0)
        self.assertEqual(drifts[0]["name"], "sqldrift[86c9cbf6]/driftdb")


class ThePipelineActuallyCallsItTests(unittest.TestCase):
    """The unit tests pass whether or not _attribute_lifecycle runs the pass."""

    def test_a_child_is_renamed_by_the_real_attribution_stage(self):
        delete_event = {
            "operation": "delete", "caller": "someone@example.com", "status": "Succeeded",
            "timestamp": datetime(2026, 8, 1, 1, 33, tzinfo=timezone.utc),
            "resource_id": f"{RG}/{SQL}/sqldrift3s7c7weddxr3s",
        }
        report = {"drifts": [
            {"type": SQL, "name": "sqldrift[86c9cbf6]", "drift_type": "missing_in_azure",
             "details": {}},
            {"type": SQL_DB, "name": "sqldrift[86c9cbf6]/driftdb",
             "drift_type": "missing_in_azure", "details": {}},
        ], "live_resources": []}

        with mock.patch.object(attribution, "fetch_resource_group_activity",
                               return_value=[delete_event]), \
                mock.patch.object(attribution, "fetch_policy_principal_ids", return_value=set()), \
                mock.patch.object(attribution, "detect_scanning_identity", return_value=set()), \
                mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": "s"}):
            attribution._attribute_lifecycle(report, "rg-drift-test")

        self.assertEqual(report["drifts"][0]["name"], "sqldrift3s7c7weddxr3s")
        self.assertEqual(report["drifts"][1]["name"], "sqldrift3s7c7weddxr3s/driftdb")


if __name__ == "__main__":
    unittest.main()
