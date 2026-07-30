"""An event must be about THIS resource, not a same-type sibling.

Issue #350, found in the 2026-07-28 teardown run. The function app
'func-drift-[86c9cbf6]' was reported as 'app-test-drift', carrying the App
Service's deletion event and actor - so 'app-test-drift' appeared deleted twice
and the func app's own deletion was invisible.

Two guards both passed and neither checked identity: the type-substring fallback
in match_activity_for_resource collects EVERY event of a type, and
deployed_name_from_event_id verifies only the TYPE CHAIN.

This is the same family as #337 one level down. #346 added OPERATION coherence -
a create cannot explain a deletion. Here the operation is fine: a delete does
explain a missing resource. It is the wrong resource's delete.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import orchestration.attribution as attribution
from tools.activity_log import could_be_same_resource, match_activity_for_resource

RG = "/subscriptions/s/resourceGroups/rg-drift-test/providers"
SITES = "Microsoft.Web/sites"
APP_DELETE = {
    "operation": "delete", "caller": "someone@example.com",
    "timestamp": datetime(2026, 7, 28, 9, 26, 30, tzinfo=timezone.utc),
    "resource_id": f"{RG}/{SITES}/app-test-drift",
}
FUNC_DELETE = {
    "operation": "delete", "caller": "someone@example.com",
    "timestamp": datetime(2026, 7, 28, 9, 27, 1, tzinfo=timezone.utc),
    "resource_id": f"{RG}/{SITES}/func-drift-3s7c7weddxr3s",
}


class NameCompatibilityTests(unittest.TestCase):
    def test_a_sibling_sharing_only_the_type_is_rejected(self):
        self.assertFalse(could_be_same_resource("func-drift-[86c9cbf6]", "app-test-drift"))

    def test_the_resources_own_deployed_name_is_accepted(self):
        self.assertTrue(
            could_be_same_resource("func-drift-[86c9cbf6]", "func-drift-3s7c7weddxr3s"))

    def test_a_child_matches_on_its_literal_tail(self):
        # The declared parent is an unresolved expression and the event id
        # carries only the leaf, so the shared name is entirely at the end.
        self.assertTrue(could_be_same_resource("kvdrift[86c9cbf6]/kv-audit", "kv-audit"))

    def test_the_pair_from_find_best_match_s_docstring(self):
        # smart_matching already records this exact live failure one level up:
        # "a function app's 'format(...)/appsettings' matched 'app-test-drift/web'".
        self.assertFalse(could_be_same_resource(
            "format('func-drift-{0}', uniqueString(resourceGroup().id))/appsettings",
            "app-test-drift/web"))

    def test_a_coincidental_letter_or_two_is_not_a_match(self):
        self.assertFalse(could_be_same_resource("ab-thing-[86c9cbf6]", "ab"))

    def test_every_rename_the_teardown_report_made_still_holds(self):
        # Regression corpus: the real (declared -> recovered) pairs from the
        # 2026-07-28 run. The fix must reject exactly one of them.
        for declared, deployed in [
            ("sttestdrift[86c9cbf6]", "sttestdrift3s7c7weddxr3s"),
            ("kvdrift[86c9cbf6]", "kvdrift3s7c7weddxr3s"),
            ("drift-wf-[86c9cbf6]", "drift-wf-3s7c7weddxr3s"),
            ("log-[86c9cbf6]", "log-3s7c7weddxr3s"),
            ("eh-[86c9cbf6]", "eh-3s7c7weddxr3s"),
            ("acrtestdrift[86c9cbf6]", "acrtestdrift3s7c7weddxr3s"),
            ("aci-test-drift-[86c9cbf6]", "aci-test-drift-3s7c7weddxr3s"),
            ("aidrift[86c9cbf6]", "aidrift3s7c7weddxr3s"),
            ("sqldrift[86c9cbf6]", "sqldrift3s7c7weddxr3s"),
            ("sbdrift[86c9cbf6]", "sbdrift3s7c7weddxr3s"),
            ("tmdrift[86c9cbf6]", "tmdrift3s7c7weddxr3s"),
            ("pgflex-drift-[86c9cbf6]", "pgflex-drift-3s7c7wed"),
            ("evgt-drift-[86c9cbf6]", "evgt-drift-3s7c7weddxr3s"),
            ("evgst-storage-[86c9cbf6]", "evgst-storage-3s7c7weddxr3s"),
        ]:
            with self.subTest(declared=declared):
                self.assertTrue(could_be_same_resource(declared, deployed))


class EventMatchingTests(unittest.TestCase):
    """The wrong event drove change_origin and lifecycle too, not just the
    displayed name - so the filter belongs at the match, not at the rename."""

    def test_the_type_fallback_no_longer_returns_a_siblings_events(self):
        matched = match_activity_for_resource(
            [APP_DELETE], f"{RG}/{SITES}/func-drift-[86c9cbf6]", SITES)
        self.assertEqual(matched, [])

    def test_the_resources_own_event_is_still_found_among_siblings(self):
        matched = match_activity_for_resource(
            [APP_DELETE, FUNC_DELETE], f"{RG}/{SITES}/func-drift-[86c9cbf6]", SITES)
        self.assertEqual([e["resource_id"] for e in matched],
                         [FUNC_DELETE["resource_id"]])

    def test_an_exact_id_match_is_untouched(self):
        # The primary path must not go anywhere near the name filter.
        matched = match_activity_for_resource(
            [APP_DELETE], f"{RG}/{SITES}/app-test-drift", SITES)
        self.assertEqual(matched, [APP_DELETE])


class AConventionPrefixIsNotIdentityTests(unittest.TestCase):
    """The 2026-07-30 rerun, one round on: both App Service Plans adopted a
    single event because 'asp-test-drift' and 'asp-func-drift-test' share the
    four characters 'asp-'. A shared-affix threshold cannot fix this - Azure
    naming conventions mean every resource of a type shares a lead by design.
    The test is now the declared name's own SHAPE.
    """

    def test_the_two_app_service_plans_are_not_compatible(self):
        self.assertFalse(
            could_be_same_resource("asp-test-drift", "asp-func-drift-test"))
        self.assertFalse(
            could_be_same_resource("asp-func-drift-test", "asp-test-drift"))

    def test_a_fully_resolved_name_matches_only_itself(self):
        self.assertTrue(could_be_same_resource("asp-test-drift", "asp-test-drift"))
        self.assertFalse(could_be_same_resource("nsg-drift-test", "rt-drift-test"))

    def test_a_placeholder_stands_for_one_segment_not_a_boundary(self):
        # A hole must not swallow a '/' and match across parent and child.
        self.assertTrue(could_be_same_resource(
            "kvdrift[86c9cbf6]/kv-audit", "kvdrift3s7c7weddxr3s/kv-audit"))
        self.assertFalse(could_be_same_resource(
            "kvdrift[86c9cbf6]/kv-audit", "kvdrift3s/other/kv-audit"))

    def test_siblings_differing_only_after_the_placeholder(self):
        self.assertTrue(could_be_same_resource(
            "eh-[86c9cbf6]/drift-hub", "eh-3s7c7weddxr3s/drift-hub"))
        self.assertFalse(could_be_same_resource(
            "eh-[86c9cbf6]/drift-hub", "eh-3s7c7weddxr3s/other-hub"))

    def test_a_name_still_carrying_raw_expression_text_keeps_the_fallback(self):
        # Nothing to anchor on, so attribution degrades rather than disappears.
        self.assertTrue(could_be_same_resource(
            "format('func-drift-{0}', uniqueString(x))/appsettings",
            "func-drift-3s7c7weddxr3s/appsettings"))


class BothPlansKeepTheirOwnEventTests(unittest.TestCase):
    """Driven through match_activity_for_resource, the stage that owns the
    type fallback."""

    FARMS = "Microsoft.Web/serverfarms"

    def setUp(self):
        self.asp_delete = {
            "operation": "microsoft.web/serverfarms/delete",
            "caller": "someone@example.com", "status": "Succeeded",
            "timestamp": datetime(2026, 7, 28, 9, 27, 37, tzinfo=timezone.utc),
            "resource_id": f"{RG}/{self.FARMS}/asp-test-drift",
        }

    def _match(self, declared):
        return match_activity_for_resource(
            [self.asp_delete], f"{RG}/{self.FARMS}/{declared}", self.FARMS)

    def test_the_plan_the_event_belongs_to_still_matches(self):
        self.assertEqual(self._match("asp-test-drift"), [self.asp_delete])

    def test_the_other_plan_does_not_adopt_it(self):
        self.assertEqual(self._match("asp-func-drift-test"), [])


class ThroughThePipelineTests(unittest.TestCase):
    """Enter the stage the pipeline enters - the unit tests above pass whether
    or not the filter is wired in. See the call-path lesson."""

    def _attribute(self, events):
        report = {"drifts": [{"type": SITES, "name": "func-drift-[86c9cbf6]",
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

    def test_the_func_app_is_not_renamed_to_the_app_service(self):
        d = self._attribute([APP_DELETE])
        self.assertEqual(d["name"], "func-drift-[86c9cbf6]")
        self.assertNotEqual(d["name"], "app-test-drift")

    def test_it_does_not_inherit_the_app_services_deletion(self):
        # The report showed 'app-test-drift' deleted twice, at one timestamp,
        # by one actor. An unattributed drift is the correct answer instead.
        d = self._attribute([APP_DELETE])
        self.assertEqual(d["change_origin"]["origin"], "unknown")
        self.assertIsNone(d["lifecycle"]["deleted_at"])
        self.assertIsNone(d["lifecycle"]["deleted_by"])

    def test_its_own_deletion_is_still_recovered_and_attributed(self):
        d = self._attribute([APP_DELETE, FUNC_DELETE])
        self.assertEqual(d["name"], "func-drift-3s7c7weddxr3s")
        self.assertEqual(d["bicep_name_expression"], "func-drift-[86c9cbf6]")
        self.assertEqual(d["change_origin"]["origin"], "manual_change")
        self.assertEqual(d["change_origin"]["changed_by"], "someone@example.com")


if __name__ == "__main__":
    unittest.main()
