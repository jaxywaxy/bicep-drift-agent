"""Attribution for in-flight Modify policy effects (issue #321).

An inherit-tag Modify rewrites the value inside the deploying identity's own
write. The activity log therefore holds ONE event whose caller is the pipeline,
the policy identity never appears, and a compliant estate never runs a
remediation task either - so the caller-based path in change_origin cannot see
it. A live round produced 37 tag drifts attributed to the pipeline with
policy_enforced_drifts empty, and an analysis recommending "fix at source and
redeploy", which re-runs the same race forever.

The signal used instead is what policy REQUIRES: template says X, live says Y,
and an in-scope assignment mandates exactly Y.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.attribution import _claim_policy_required_tags
from tools.policy import resolve_policy_required_tags

INHERIT_REPLACE = "cd3aa116-8754-49c9-a813-ad46512ece54"
INHERIT_IF_MISSING = "ea3f2387-9b95-492a-a190-fcdc54f7b070"
RG_TAGS = {"environment": "production", "costCentre": "CC-1234"}


def _assignment(definition_ref, tag_name, name="drift-inherit-environment"):
    return {
        "name": name,
        "display_name": name,
        "definition_ref": definition_ref,
        "parameters": {"tagName": {"value": tag_name}},
    }


def _tag_drift(actual="production", desired="test", extra_props=None):
    changed = {"tags.environment": {"desired": desired, "actual": actual}}
    changed.update(extra_props or {})
    return {
        "type": "Microsoft.Storage/storageAccounts",
        "name": "sttestdrift",
        "drift_type": "property_drift",
        "details": {"changed_properties": changed},
        "change_origin": {"origin": "authorized_deployment", "expected": False},
    }


class ResolverTests(unittest.TestCase):
    def test_inherit_tag_assignment_yields_the_rg_value(self):
        req = resolve_policy_required_tags(
            [_assignment(INHERIT_REPLACE, "environment")], RG_TAGS)

        self.assertEqual(req["environment"]["value"], "production")
        self.assertEqual(req["environment"]["assignment"], "drift-inherit-environment")
        self.assertEqual(req["environment"]["mode"], "replace")

    def test_unrelated_assignment_requires_nothing(self):
        audit = {"name": "drift-audit-manageddisks",
                 "definition_ref": "06a78e20-9358-41c9-923c-fb736d382a4d",
                 "parameters": {}}

        self.assertEqual(resolve_policy_required_tags([audit], RG_TAGS), {})

    def test_no_rg_tag_means_no_requirement(self):
        """The built-in rule short-circuits on `resourceGroup().tags[x] != ''`,
        so with no RG tag the policy imposes nothing and any drift is real."""
        req = resolve_policy_required_tags(
            [_assignment(INHERIT_REPLACE, "environment")], {"costCentre": "CC-1234"})

        self.assertEqual(req, {})

    def test_replace_wins_over_if_missing_on_the_same_key(self):
        req = resolve_policy_required_tags([
            _assignment(INHERIT_IF_MISSING, "environment", "inherit-if-missing"),
            _assignment(INHERIT_REPLACE, "environment", "inherit-replace"),
        ], RG_TAGS)

        self.assertEqual(req["environment"]["assignment"], "inherit-replace")

    def test_tag_name_is_matched_case_insensitively(self):
        req = resolve_policy_required_tags(
            [_assignment(INHERIT_REPLACE, "Environment")], {"environment": "production"})

        self.assertEqual(req["environment"]["value"], "production")


class ClaimTests(unittest.TestCase):
    def _report(self, drifts, required=None):
        return {
            "drifts": drifts,
            "policy_required_tags": required if required is not None else {
                "environment": {"value": "production", "assignment": "drift-inherit-environment",
                                "definition_ref": INHERIT_REPLACE, "mode": "replace"}},
        }

    def test_policy_imposed_tag_is_claimed_and_explained(self):
        drift = _tag_drift()
        report = self._report([drift])

        self.assertEqual(_claim_policy_required_tags(report), 1)
        self.assertNotIn("tags.environment", drift["details"]["changed_properties"])
        claimed = drift["policy_enforced_properties"]["tags.environment"]
        self.assertEqual(claimed["policy_assignment"], "drift-inherit-environment")
        self.assertIn("reconcile the template", claimed["reason"].lower())
        # Never tell the operator to redeploy - that loses the race every cycle.
        self.assertNotIn("redeploy the", claimed["reason"].lower())

    def test_whole_drift_becomes_policy_enforced_when_nothing_remains(self):
        drift = _tag_drift()
        _claim_policy_required_tags(self._report([drift]))

        self.assertTrue(drift["change_origin"]["expected"])
        self.assertEqual(drift["change_origin"]["origin"], "policy_modify")

    def test_a_critical_sibling_property_stays_actionable(self):
        """The storage account in the live round: tags.environment was policy
        -imposed while allowBlobPublicAccess was a genuine critical. Claiming the
        whole record would bury the exposure in the governance section."""
        drift = _tag_drift(extra_props={
            "properties.allowBlobPublicAccess": {"desired": False, "actual": True}})

        _claim_policy_required_tags(self._report([drift]))

        self.assertIn("properties.allowBlobPublicAccess",
                      drift["details"]["changed_properties"])
        self.assertIn("tags.environment", drift["policy_enforced_properties"])
        self.assertIsNot(drift["change_origin"].get("expected"), True)

    def test_a_third_value_is_not_claimed(self):
        """Live is neither the template's value nor policy's - someone else moved
        it and policy has not reconverged. That is real drift."""
        drift = _tag_drift(actual="staging")

        self.assertEqual(_claim_policy_required_tags(self._report([drift])), 0)
        self.assertIn("tags.environment", drift["details"]["changed_properties"])

    def test_untracked_tag_is_not_claimed(self):
        drift = {"type": "Microsoft.Storage/storageAccounts", "name": "st",
                 "drift_type": "property_drift",
                 "details": {"changed_properties": {
                     "tags.owner": {"desired": "team-a", "actual": "rogue"}}}}

        self.assertEqual(_claim_policy_required_tags(self._report([drift])), 0)

    def test_no_requirements_is_a_no_op(self):
        drift = _tag_drift()

        self.assertEqual(_claim_policy_required_tags(self._report([drift], required={})), 0)
        self.assertIn("tags.environment", drift["details"]["changed_properties"])

    def test_non_property_drifts_are_untouched(self):
        extra = {"type": "Microsoft.Network/networkSecurityGroups",
                 "name": "nsg-rogue-drift", "drift_type": "extra_in_azure", "details": {}}

        self.assertEqual(_claim_policy_required_tags(self._report([extra])), 0)
        self.assertNotIn("policy_enforced_properties", extra)


if __name__ == "__main__":
    unittest.main()
