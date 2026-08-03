"""An attribution must be able to ACCOUNT for the drift it is attached to.

Issue #337. Two ways a record ended up naming a cause that could not be one:

  1. select_relevant_activity falls back to a write when no delete exists - good
     history, false cause. A create cannot explain a resource being GONE. The
     2026-07-28 teardown run carried four of these, each reading "Deployed by
     authorized pipeline identity" for a resource that no longer existed.
  2. The policy-tag claim rewrote `origin` to policy_modify but inherited
     `changed_by` from whatever last wrote the resource. On rsv-drift-test that
     was a backup-retention edit on a CHILD resource 45 minutes later, so the
     record asserted "a policy did this, and the person who did it was <name>".

Both enter through the same stage the pipeline uses, not the helpers alone -
see the call-path lesson that has bitten this project three times.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.attribution import _claim_policy_required_tags
from tools.change_origin import (
    ChangeCategory,
    ChangeOrigin,
    ChangeSeverity,
    classify_change_origin,
    event_explains_drift,
)

PIPELINE = "11111111-1111-1111-1111-111111111111"
DEPLOYERS = {PIPELINE}
CREATE = {"operation": "create", "caller": PIPELINE, "timestamp": "2026-07-27T20:51:36Z"}
WRITE = {"operation": "write", "caller": PIPELINE, "timestamp": "2026-07-27T20:51:36Z"}
DELETE = {"operation": "delete", "caller": "someone@example.com",
          "timestamp": "2026-07-27T23:47:25Z"}


def _classify(event, drift_type):
    """Enter the way orchestration/attribution.py does."""
    return classify_change_origin(
        [event], None, DEPLOYERS,
        explained=event_explains_drift(event, drift_type),
    )


class AnEventMustAccountForTheDriftTests(unittest.TestCase):
    def test_a_create_cannot_explain_a_deletion(self):
        self.assertFalse(event_explains_drift(CREATE, "missing_in_azure"))

    def test_a_missing_resource_attributed_to_a_create_becomes_unknown(self):
        # The exact shape of four findings in the teardown run: the resource is
        # gone, the only event is the pipeline CREATING it, and the report said
        # "Deployed by authorized pipeline identity".
        info = _classify(CREATE, "missing_in_azure")
        self.assertEqual(info.origin, ChangeOrigin.UNKNOWN)
        self.assertNotEqual(info.origin, ChangeOrigin.AUTHORIZED_DEPLOYMENT)
        self.assertIn("no activity log event accounts", info.reason.lower())

    def test_the_admitted_gap_outranks_a_false_reassurance(self):
        # UNKNOWN rates MEDIUM; authorized_deployment rates LOW. A genuinely
        # unattributed change must not sort below a wrong confident one.
        unknown = _classify(CREATE, "missing_in_azure")
        confident = _classify(DELETE, "missing_in_azure")
        self.assertEqual(unknown.severity.value, "medium")
        self.assertFalse(unknown.expected)
        self.assertEqual(confident.origin, ChangeOrigin.MANUAL_CHANGE)

    def test_a_real_deletion_still_names_who_did_it(self):
        info = _classify(DELETE, "missing_in_azure")
        self.assertEqual(info.origin, ChangeOrigin.MANUAL_CHANGE)
        self.assertEqual(info.changed_by, "someone@example.com")

    def test_a_write_still_explains_property_drift(self):
        # The guard must not swallow the ordinary case it was built around.
        self.assertTrue(event_explains_drift(WRITE, "property_drift"))
        info = _classify(WRITE, "property_drift")
        self.assertEqual(info.origin, ChangeOrigin.AUTHORIZED_DEPLOYMENT)

    def test_a_delete_does_not_explain_property_drift(self):
        self.assertFalse(event_explains_drift(DELETE, "property_drift"))

    def test_no_events_at_all_keeps_its_own_distinct_reason(self):
        # "logs may have expired" and "events exist but none fit" are different
        # facts; collapsing them would hide which one the reader is looking at.
        info = classify_change_origin([], None, DEPLOYERS, explained=False)
        self.assertIn("no activity log entries found", info.reason.lower())


class TheGuardIsWiredIntoThePipelineTests(unittest.TestCase):
    """Everything above calls classify_change_origin with `explained` computed
    by hand, which proves the units and NOT the wiring - deleting `explained=`
    from the call site in orchestration/attribution.py passed all of them. Same
    trap as tests/test_dns_and_table_collectors.py and the two rounds before it,
    so this one drives the real stage."""

    def _attribute(self, drift_type, event_op):
        from unittest import mock
        import orchestration.attribution as attr

        # A real datetime, as fetch_resource_group_activity returns: a string
        # here made build_resource_lifecycle raise, the handler swallowed it,
        # and the origin came back "unknown" for the WRONG reason - a vacuous
        # pass that would have proved nothing.
        event = {"operation": event_op, "caller": PIPELINE,
                 "timestamp": datetime(2026, 7, 27, 20, 51, 36, tzinfo=timezone.utc),
                 "resource_id": "/subscriptions/s/resourceGroups/rg/providers/"
                                "Microsoft.Authorization/policyAssignments/p"}
        report = {"drifts": [{"type": "Microsoft.Authorization/policyAssignments",
                              "name": "p", "drift_type": drift_type, "details": {}}],
                  "live_resources": []}
        with mock.patch.object(attr, "fetch_resource_group_activity", return_value=[event]), \
             mock.patch.object(attr, "fetch_policy_principal_ids", return_value=set()), \
             mock.patch.object(attr, "detect_scanning_identity", return_value={PIPELINE}), \
             mock.patch.object(attr, "match_activity_for_resource", return_value=[event]):
            attr._attribute_lifecycle(report, "rg")
        return report["drifts"][0]

    def test_the_pipeline_does_not_attribute_a_deletion_to_a_create(self):
        d = self._attribute("missing_in_azure", "create")
        self.assertEqual(d["change_origin"]["origin"], "unknown")
        self.assertIn("no activity log event accounts",
                      d["change_origin"]["reason"].lower())

    def test_the_timeline_still_shows_what_was_found(self):
        # The point is not to lose the history - only to stop asserting it as
        # the cause.
        d = self._attribute("missing_in_azure", "create")
        self.assertTrue(d["lifecycle"]["events"],
                        "the create must survive as context in the timeline")

    def test_the_pipeline_still_attributes_a_real_write(self):
        d = self._attribute("property_drift", "write")
        self.assertEqual(d["change_origin"]["origin"], "authorized_deployment")
        self.assertEqual(d["change_origin"]["changed_by"], PIPELINE)


class AClaimMustNotInheritAStaleActorTests(unittest.TestCase):
    """agent/prompts.py instructs the analysis to 'cite changed_by directly',
    so a stale actor there is quoted as the person who made the change."""

    def _claimed(self, changed_by, timestamp):
        report = {
            "policy_required_tags": {"environment": {
                "value": "production", "assignment": "drift-inherit-environment",
                "assignment_id": "/subs/x/policyAssignments/drift-inherit-environment",
                "scope": "/subs/x/rg",
                "definition_ref": "cd3aa116-8754-49c9-a813-ad46512ece54",
                "mode": "replace"}},
            "drifts": [{
                "type": "Microsoft.RecoveryServices/vaults", "name": "rsv-drift-test",
                "drift_type": "property_drift",
                "details": {"changed_properties": {
                    "tags.environment": {"desired": "test", "actual": "production"}}},
                "change_origin": {"origin": "manual_change", "expected": False,
                                  "changed_by": changed_by, "timestamp": timestamp}}],
            "property_drifts": [],
        }
        _claim_policy_required_tags(report)
        return report["drifts"][0]["change_origin"]

    def test_the_actor_of_an_unrelated_write_is_not_kept_as_changed_by(self):
        co = self._claimed("someone@example.com", "2026-07-27T21:44:39+00:00")
        self.assertEqual(co["origin"], "policy_modify")
        self.assertIsNone(co["changed_by"],
                          "a Modify effect has no actor - it rides someone else's write")

    def test_the_last_write_is_kept_under_a_name_that_says_what_it_is(self):
        # Losing the history is not the goal; asserting it as the cause is.
        co = self._claimed("someone@example.com", "2026-07-27T21:44:39+00:00")
        self.assertEqual(co["last_write_by"], "someone@example.com")
        self.assertEqual(co["last_write_at"], "2026-07-27T21:44:39+00:00")


class PlatformTelemetryMustNotEraseTheActorTests(unittest.TestCase):
    """A manual change attributed to NOBODY is not an attribution.

    Live, 2026-08-02: a VMSS was scaled 0 -> 1 out of band. The report said
    manual_change / out_of_band / severity high with an EMPTY actor, because
    'Microsoft.Resourcehealth/healthevent/Updated/action' - platform telemetry
    on the scale set's VM instance, caller=None - matched the `"update" in op`
    substring test and, being 5s newer, beat the user's own write.

    This drives orchestration/attribution.py, not select_relevant_activity
    alone: the unit is where the bug lives, but the pipeline is where it showed.
    """

    ACTOR = "user@example.com"

    def _attribute_vmss(self, events):
        from unittest import mock
        import orchestration.attribution as attr

        report = {"drifts": [{"type": "Microsoft.Compute/virtualMachineScaleSets",
                              "name": "vmss-drift-test",
                              "drift_type": "property_drift",
                              "details": {"changed_properties": {
                                  "sku.capacity": {"desired": 0, "actual": 1,
                                                   "severity": "critical"}}}}],
                  "live_resources": []}
        with mock.patch.object(attr, "fetch_resource_group_activity", return_value=events), \
             mock.patch.object(attr, "fetch_policy_principal_ids", return_value=set()), \
             mock.patch.object(attr, "detect_scanning_identity", return_value=set()), \
             mock.patch.object(attr, "match_activity_for_resource", return_value=events):
            attr._attribute_lifecycle(report, "rg")
        return report["drifts"][0]

    def _ev(self, op, caller, minute, second):
        return {"operation": op, "caller": caller,
                "timestamp": datetime(2026, 8, 2, 20, minute, second, tzinfo=timezone.utc),
                "resource_id": "/subscriptions/s/resourceGroups/rg/providers/"
                               "Microsoft.Compute/virtualMachineScaleSets/vmss-drift-test"}

    def test_the_real_actor_survives_a_newer_health_event(self):
        events = [
            self._ev("Microsoft.Compute/virtualMachineScaleSets/write", self.ACTOR, 37, 14),
            self._ev("Microsoft.Resourcehealth/healthevent/Updated/action", None, 37, 19),
        ]
        d = self._attribute_vmss(events)
        self.assertEqual(
            d["change_origin"]["changed_by"], self.ACTOR,
            "the out-of-band actor was erased by platform telemetry",
        )

    def test_an_out_of_band_change_is_never_attributed_to_nobody(self):
        # The invariant, stated independently of which verb caused it: if we
        # are going to call something a manual change, we must be able to say
        # who made it.
        events = [
            self._ev("Microsoft.Compute/virtualMachineScaleSets/write", self.ACTOR, 37, 14),
            self._ev("Microsoft.Resourcehealth/healthevent/Updated/action", None, 37, 19),
        ]
        co = self._attribute_vmss(events)["change_origin"]
        if co.get("origin") == "manual_change":
            self.assertTrue(co.get("changed_by"),
                            "manual_change with no actor is not an attribution")


if __name__ == "__main__":
    unittest.main()


class AManualChangeMustBeAbleToNameSomeoneTests(unittest.TestCase):
    """`manual_change` asserts a PERSON acted outside the pipeline. When the
    Activity Log entry carries no caller, that assertion is unsupported and the
    report renders it literally:

        "reason": "Manual change by  (out-of-band)"   <- note the blank

    Seen in the 2026-08-02 CI run on sqldrift.../driftdb: origin manual_change,
    category out_of_band, severity high, `changed_by: ""`. The health-telemetry
    fix (#375) only re-ORDERS candidate events; it cannot help when the single
    event that explains the drift has no actor at all.

    The change is deliberately NOT a downgrade. An out-of-band change we cannot
    attribute is still out-of-band and still urgent - what is false is only the
    claim that a person did it. Dropping to UNKNOWN/MEDIUM here would collide
    with the #327 invariant that classification never downgrades a finding.
    """

    def _nameless(self, caller):
        event = {"operation": "write", "caller": caller,
                 "timestamp": "2026-08-02T20:03:50Z"}
        return classify_change_origin(
            [event], None, DEPLOYERS,
            explained=event_explains_drift(event, "property_drift"),
        )

    def test_a_nameless_change_is_not_called_a_manual_change(self):
        for caller in (None, "", "   "):
            with self.subTest(caller=repr(caller)):
                info = self._nameless(caller)
                self.assertNotEqual(
                    info.origin, ChangeOrigin.MANUAL_CHANGE,
                    "manual_change asserts a person acted; no actor was recorded",
                )

    def test_the_urgency_is_not_downgraded(self):
        # Still out-of-band, still HIGH, still actionable - only the actor claim
        # is withdrawn. A silent drop to MEDIUM would hide a real finding.
        info = self._nameless(None)
        self.assertEqual(info.category, ChangeCategory.OUT_OF_BAND)
        self.assertEqual(info.severity, ChangeSeverity.HIGH)
        self.assertFalse(info.expected)

    def test_the_reason_never_renders_a_blank_name(self):
        for caller in (None, "", "   "):
            with self.subTest(caller=repr(caller)):
                reason = self._nameless(caller).reason
                self.assertNotIn("by  ", reason, f"blank actor rendered: {reason!r}")
                self.assertFalse(reason.rstrip().endswith("by"), reason)

    def test_changed_by_is_null_not_empty_string(self):
        # An empty string reads as "we know the actor and it is nothing".
        self.assertIsNone(self._nameless(None).changed_by)

    def test_a_named_manual_change_is_untouched(self):
        info = self._nameless("someone@example.com")
        self.assertEqual(info.origin, ChangeOrigin.MANUAL_CHANGE)
        self.assertEqual(info.changed_by, "someone@example.com")
        self.assertEqual(info.severity, ChangeSeverity.HIGH)


class AResourceGroupDeletionMustNameItsActorTests(unittest.TestCase):
    """The deletion of a resource group is the most consequential event that can
    happen to a subscription-scoped landing zone - and it was the ONE finding
    that could not name who did it, while its orphaned children named the actor
    correctly.

    Two independent reasons, both in the constructed fallback id:

        /subscriptions/<sub>/resourceGroups/<SELECTOR>/providers/<type>/<name>

    1. `<SELECTOR>` is the scan selector, which is '*' or a glob at subscription
       scope. A resource group literally named '*' does not exist.
    2. A resource group's real id has NO providers segment at all:
           /subscriptions/<sub>/resourceGroups/jacquidev-rg-logging
       so even with the right selector the shape would never match.

    The resource-type fallback cannot rescue it either: it matches events whose
    resource_id CONTAINS the type string, and 'microsoft.resources/resourcegroups'
    never appears in a resource group's id (verified live).
    """

    SUB = "bd48a22c-91b9-46e6-a2ff-15893e348d83"
    RG = "jacquidev-rg-logging"

    def _rg_delete_event(self):
        # Verbatim shape from the live Activity Log.
        return {
            "operation": "Microsoft.Resources/subscriptions/resourcegroups/delete",
            "resource_id": f"/subscriptions/{self.SUB}/resourcegroups/{self.RG}",
            "caller": "jacqui.anker@gmail.com",
            "status": "Succeeded",
            "timestamp": datetime(2026, 8, 3, 21, 56, 7, tzinfo=timezone.utc),
        }

    def _attribute(self, selector):
        from unittest import mock
        import orchestration.attribution as attr

        event = self._rg_delete_event()
        report = {
            "drifts": [{"type": "Microsoft.Resources/resourceGroups",
                        "name": self.RG, "drift_type": "missing_in_azure",
                        "details": {}}],
            "live_resources": [],
        }
        with mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": self.SUB}), \
             mock.patch.object(attr, "fetch_resource_group_activity", return_value=[event]), \
             mock.patch.object(attr, "fetch_policy_principal_ids", return_value=set()), \
             mock.patch.object(attr, "detect_scanning_identity", return_value=set()):
            attr._attribute_lifecycle(report, selector)
        return report["drifts"][0]

    def test_a_deleted_resource_group_names_its_actor(self):
        co = self._attribute("*")["change_origin"]
        self.assertEqual(
            co.get("changed_by"), "jacqui.anker@gmail.com",
            "the resource group deletion - the cause of every orphan - was unattributed",
        )

    def test_the_constructed_id_has_no_selector_in_it(self):
        rid = self._attribute("*")["lifecycle"]["resource_id"]
        self.assertNotIn("/*", rid, f"the scan selector was baked into a resource id: {rid}")

    def test_a_resource_group_id_has_no_providers_segment(self):
        rid = self._attribute("*")["lifecycle"]["resource_id"]
        self.assertNotIn("providers/", rid.lower(), f"malformed resource group id: {rid}")
        self.assertTrue(rid.lower().endswith(f"/resourcegroups/{self.RG}".lower()), rid)

    def test_it_also_works_for_a_glob_selector(self):
        co = self._attribute("jacquidev-*")["change_origin"]
        self.assertEqual(co.get("changed_by"), "jacqui.anker@gmail.com")


class ALiteralNamedOrphanStillGetsARealIdTests(unittest.TestCase):
    """`_declared_in_rg` is stamped only on PLACEHOLDER-named rows, because only
    smart matching creates those. A literal-named resource in a deleted resource
    group (jacquidev-law) therefore had no group to build an id from and fell to
    the honest-but-blank "" path.

    It still attributed correctly via the type fallback, but a blank
    lifecycle.resource_id is not good enough: the analysis prompt reasons by it.
    The declaration in arm_resources carries `_target_rg` - read it.
    """

    SUB = "s"

    def _attribute(self):
        from unittest import mock
        import orchestration.attribution as attr
        event = {"operation": "Microsoft.OperationalInsights/workspaces/delete",
                 "resource_id": f"/subscriptions/{self.SUB}/resourcegroups/rg-logging"
                                "/providers/microsoft.operationalinsights/workspaces/law",
                 "caller": "someone@example.com", "status": "Succeeded",
                 "timestamp": datetime(2026, 8, 3, 22, 5, 47, tzinfo=timezone.utc)}
        report = {
            "arm_resources": [{"type": "Microsoft.OperationalInsights/workspaces",
                               "name": "law", "_target_rg": "rg-logging"}],
            "live_resources": [],
            "drifts": [{"type": "Microsoft.OperationalInsights/workspaces", "name": "law",
                        "drift_type": "missing_in_azure", "details": {}}],
        }
        with mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": self.SUB}), \
             mock.patch.object(attr, "fetch_resource_group_activity", return_value=[event]), \
             mock.patch.object(attr, "fetch_policy_principal_ids", return_value=set()), \
             mock.patch.object(attr, "detect_scanning_identity", return_value=set()):
            attr._attribute_lifecycle(report, "*")
        return report["drifts"][0]

    def test_the_resource_id_is_not_blank(self):
        rid = self._attribute()["lifecycle"]["resource_id"]
        self.assertTrue(rid, "a literal-named orphan was left with no resource id")
        self.assertIn("rg-logging", rid)
        self.assertNotIn("/*", rid)

    def test_it_is_still_attributed(self):
        self.assertEqual(
            self._attribute()["change_origin"].get("changed_by"), "someone@example.com")
