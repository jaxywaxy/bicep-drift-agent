"""Tag drift semantics.

Only tags DECLARED in the Bicep are compared. Client estates commonly leave
tagging to Azure Policy - a mandatory set enforced on write, plus inherit-from-
resource-group Modify effects - so a tag present live but absent from the
template is almost always policy-applied, not drift. Reporting those additions
would make every resource in such an estate permanently drifted.

Deletions are the opposite case. A declared tag is an assertion by the template
author, mandatory tag sets are policy-enforced, and Azure returns the tag map
faithfully - so an absent declared key really was removed. It therefore scores
the same as changing that tag's value, rather than the blanket 'info' used for
properties Azure may simply not project.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator

TYPE = "Microsoft.Network/virtualNetworks"
DECLARED_TAGS = {"environment": "test", "managed": "true", "purpose": "drift-detection-test"}
# Enough deployed properties to clear the "incomplete projection" guard that
# suppresses removals when live state looks truncated.
PROPS = {
    "addressSpace": {"addressPrefixes": ["10.99.0.0/24"]},
    # Truthy on purpose: the removal branch skips falsy declared values as
    # "optional property not set".
    "privateEndpointVNetPolicies": "Disabled",
}


def _pair(live_tags, live_props=None):
    bicep = {"type": TYPE, "name": "vnet-drift-test", "tags": DECLARED_TAGS, "properties": PROPS}
    live = {
        "type": TYPE,
        "name": "vnet-drift-test",
        "tags": live_tags,
        "properties": live_props if live_props is not None else PROPS,
    }
    return bicep, live


def _by_path(diffs):
    return {d.property_path: d for d in diffs}


class DeclaredTagRemovedTests(unittest.TestCase):
    def test_removed_tag_is_not_buried_at_info(self):
        """The live failure mode: deleting a mandatory tag scored lower than
        changing it, so it sorted to the bottom of the report."""
        bicep, live = _pair({"environment": "test", "managed": "true"})  # purpose deleted

        diffs = _by_path(PropertyComparator.compare_properties(bicep, live))

        self.assertIn("tags.purpose", diffs)
        removed = diffs["tags.purpose"]
        self.assertEqual(removed.change_type, "removed")
        self.assertNotEqual(removed.severity, "info")

    def test_removing_a_tag_scores_the_same_as_changing_it(self):
        removed = _by_path(
            PropertyComparator.compare_properties(*_pair({"environment": "test", "managed": "true"}))
        )["tags.purpose"]
        changed = _by_path(
            PropertyComparator.compare_properties(
                *_pair({**DECLARED_TAGS, "purpose": "something-else"})
            )
        )["tags.purpose"]

        self.assertEqual(removed.severity, changed.severity)

    def test_non_tag_removal_still_scores_info(self):
        """The carve-out is tags only - other absent properties keep the
        blanket 'info', which hedges against fields Azure never projects."""
        bicep, live = _pair(DECLARED_TAGS, live_props={"addressSpace": PROPS["addressSpace"]})

        diffs = _by_path(PropertyComparator.compare_properties(bicep, live))

        self.assertEqual(diffs["properties.privateEndpointVNetPolicies"].severity, "info")


class AddedTagTests(unittest.TestCase):
    def test_policy_applied_tag_is_not_drift(self):
        """Inherit-from-RG and mandatory-tag policies add tags the template
        never declares. Reporting them would drift every resource in a
        policy-governed estate on every scan."""
        bicep, live = _pair({**DECLARED_TAGS, "costCentre": "CC-1234", "owner": "rogue"})

        diffs = PropertyComparator.compare_properties(bicep, live)

        self.assertEqual(diffs, [], "added tags must be ignored")

    def test_declared_tag_still_compared_alongside_added_ones(self):
        """Ignoring additions must not blind the comparison to a real change
        on a declared key sitting in the same map."""
        bicep, live = _pair({**DECLARED_TAGS, "environment": "production", "costCentre": "CC-1234"})

        diffs = _by_path(PropertyComparator.compare_properties(bicep, live))

        self.assertEqual(list(diffs), ["tags.environment"])
        self.assertEqual(diffs["tags.environment"].actual_value, "production")


if __name__ == "__main__":
    unittest.main()
