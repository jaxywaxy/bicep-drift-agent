"""An unidentifiable name must attribute NOTHING, not everything of its type.

Found 2026-08-23 on the first scan of a template the agent was not built
around: azure-alz-avm, which composes public AVM registry modules. The report
named a subnet 'vnet-drift-test/default' - a resource in neither the template
nor the subscription. 'kv-audit' and a peering from an unrelated estate were
invented the same way.

AVM is what exposed it. Every optional child in a registry module is named
`coalesce(parameters('subnets'), createArray())[copyIndex()].name`, which
resolves to a single name segment for a two-level type, so no valid ARM id can
be built for it and deployed_name_from_event_id parses nothing back out. The
hand-written templates this repo was verified against rarely produce that.

The type fallback then returned every event of the type in the resource group,
and attribution.py rewrites drift["name"] from the first match - so the finding
was renamed to a stale sibling, carrying its actor and timestamp.

Same family as #337/#350/#352. #352 added the could_be_same_resource identity
check but left the `if not declared_name` early return ABOVE it, so the guard
was bypassed exactly where the name is least knowable.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import orchestration.attribution as attribution
from tools.activity_log import could_be_same_resource, match_activity_for_resource

RG = "/subscriptions/s/resourceGroups/rg-connectivity/providers"
SUBNETS = "Microsoft.Network/virtualNetworks/subnets"

# How AVM names an optional child. Unresolvable by construction.
AVM_SUBNET_NAME = "coalesce(parameters('subnets'), createArray())[copyIndex()].name"

# A real event, for a subnet of a vnet that has nothing to do with the template.
STALE_SIBLING = {
    "operation": "microsoft.network/virtualnetworks/subnets/write",
    "caller": "someone-else@example.com", "status": "Succeeded",
    "timestamp": datetime(2026, 8, 1, 3, 15, 0, tzinfo=timezone.utc),
    "resource_id": f"{RG}/Microsoft.Network/virtualNetworks/vnet-drift-test/subnets/default",
}
OTHER_SIBLING = {
    "operation": "microsoft.network/virtualnetworks/subnets/write",
    "caller": "other@example.com", "status": "Succeeded",
    "timestamp": datetime(2026, 8, 2, 4, 20, 0, tzinfo=timezone.utc),
    "resource_id": f"{RG}/Microsoft.Network/virtualNetworks/jacquiprod-vnet-hub/subnets/snet-web",
}


class UnidentifiableNameMatchesNothingTests(unittest.TestCase):
    """Driven through match_activity_for_resource, the stage owning the fallback."""

    def _match(self, declared):
        return match_activity_for_resource(
            [STALE_SIBLING, OTHER_SIBLING], f"{RG}/{SUBNETS}/{declared}", SUBNETS)

    def test_an_unresolvable_avm_name_adopts_no_events(self):
        # The whole defect in one line: two unrelated subnets, both adopted.
        self.assertEqual(self._match(AVM_SUBNET_NAME), [])

    def test_it_is_the_name_not_the_type_that_disqualifies_them(self):
        # Same events, same type, a name that CAN be identified: the matching
        # one still comes back. Without this the fix could be "return [] always"
        # and both tests above would still pass.
        matched = match_activity_for_resource(
            [STALE_SIBLING, OTHER_SIBLING],
            f"{RG}/Microsoft.Network/virtualNetworks/vnet-drift-test/subnets/default",
            SUBNETS,
        )
        self.assertEqual(matched, [STALE_SIBLING])

    def test_a_placeholder_name_still_attributes(self):
        # The case the fallback EXISTS for - a deleted resource whose Bicep name
        # is a uniqueString placeholder - parses to a name and keeps working.
        workspaces = "Microsoft.OperationalInsights/workspaces"
        event = {
            "operation": "microsoft.operationalinsights/workspaces/delete",
            "caller": "someone@example.com", "status": "Succeeded",
            "timestamp": datetime(2026, 8, 3, 1, 0, 0, tzinfo=timezone.utc),
            "resource_id": f"{RG}/{workspaces}/log-3s7c7weddxr3s",
        }
        matched = match_activity_for_resource(
            [event], f"{RG}/{workspaces}/log-[86c9cbf6]", workspaces)
        self.assertEqual(matched, [event])


class AKnownParentStillAnchorsTests(unittest.TestCase):
    """The second defect, found verifying the fix for the first.

    `vnet-hub/coalesce(...)` builds a VALID id - the parent segment is literal,
    so the type chain interleaves and a declared name parses back out. It
    reached could_be_same_resource, which tested '(' across the WHOLE name,
    discarded the known parent, and accepted an unrelated vnet's subnet on the
    shared 'vnet-' lead.
    """

    DECLARED = f"vnet-hub/{AVM_SUBNET_NAME}"

    def test_a_different_parent_is_a_different_resource(self):
        self.assertFalse(could_be_same_resource(self.DECLARED, "vnet-drift-test/default"))

    def test_the_right_parents_child_still_matches(self):
        # The child is genuinely unknowable, so any child of the RIGHT parent is
        # still a candidate - degrading attribution, not abandoning it.
        self.assertTrue(could_be_same_resource(self.DECLARED, "vnet-hub/snet-identity"))

    def test_the_residual_rule_survives_where_nothing_anchors(self):
        # Pinned by test_sibling_identity: a name whose every segment carries
        # expression text keeps the shared-affix fallback. Here the literal
        # '/appsettings' tail is what agrees.
        self.assertTrue(could_be_same_resource(
            "format('func-drift-{0}', uniqueString(x))/appsettings",
            "func-drift-3s7c7weddxr3s/appsettings"))


class ThroughThePipelineTests(unittest.TestCase):
    """Enter the stage the pipeline enters - the unit tests above pass whether
    or not the filter is wired in. See the call-path lesson."""

    def _attribute(self, events):
        report = {"drifts": [{"type": SUBNETS, "name": AVM_SUBNET_NAME,
                              "drift_type": "missing_in_azure", "details": {}}],
                  "live_resources": []}
        with mock.patch.object(attribution, "fetch_resource_group_activity",
                               return_value=events), \
             mock.patch.object(attribution, "fetch_policy_principal_ids",
                               return_value=set()), \
             mock.patch.object(attribution, "detect_scanning_identity",
                               return_value=set()), \
             mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": "s"}):
            attribution._attribute_lifecycle(report, "rg-connectivity")
        return report["drifts"][0]

    def test_the_finding_is_not_renamed_to_a_resource_that_exists_nowhere(self):
        drift = self._attribute([STALE_SIBLING, OTHER_SIBLING])
        self.assertEqual(drift["name"], AVM_SUBNET_NAME)
        self.assertNotEqual(drift["name"], "vnet-drift-test/default")

    def test_it_does_not_borrow_the_siblings_actor(self):
        # An unattributed drift - "no event accounts for this change" - is the
        # correct answer. Naming the wrong engineer is not a softer failure.
        drift = self._attribute([STALE_SIBLING, OTHER_SIBLING])
        lifecycle = drift.get("lifecycle") or {}
        self.assertNotIn("someone-else@example.com", str(lifecycle))
        self.assertNotIn("other@example.com", str(lifecycle))


if __name__ == "__main__":
    unittest.main()
