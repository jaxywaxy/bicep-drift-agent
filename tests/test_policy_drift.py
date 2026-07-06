"""
Unit tests for policy assignment/exemption drift (tools/policy.py) -
the governance twin of RBAC drift: policyresources table, identity matching.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.policy import (
    _definition_ref,
    compare_policy_resources,
    extract_bicep_policy_assignments,
    policy_drift_enabled,
)
from tools.ownership import classify_owner, PLATFORM

SUB = "00000000-0000-0000-0000-000000000001"
TDE_GUID = "06a78e20-9358-41c9-923c-fb736d382a4d"  # Deploy SQL DB TDE (built-in)


def live_assignment(name="tde-dine", definition=TDE_GUID, scope=None,
                    display="Deploy TDE", assigned_by=None, created_by=None):
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/policyAssignments/{name}",
        "name": name,
        "scope": scope or f"/subscriptions/{SUB}/resourceGroups/rg-drift-test",
        "display_name": display,
        "definition_ref": definition.lower(),
        "assignment_id": "",
        "enforcement_mode": "Default",
        "exemption_category": None,
        "expires_on": None,
        "created_by": created_by,
        "created_on": "2026-07-06T10:00:00Z" if created_by else None,
        "assigned_by": assigned_by,
    }


def live_exemption(name="waive-tde", assignment_id=None, scope=None, category="Waiver"):
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/policyExemptions/{name}",
        "name": name,
        "scope": scope or f"/subscriptions/{SUB}/resourceGroups/rg-drift-test",
        "display_name": name,
        "definition_ref": None,
        "assignment_id": (assignment_id or "").lower(),
        "enforcement_mode": None,
        "exemption_category": category,
        "expires_on": None,
        "created_by": "someone",
        "created_on": "2026-07-06T10:00:00Z",
        "assigned_by": None,
    }


class DefinitionRefTests(unittest.TestCase):
    def test_full_arm_id(self):
        self.assertEqual(
            _definition_ref(f"/providers/Microsoft.Authorization/policyDefinitions/{TDE_GUID}"),
            TDE_GUID,
        )

    def test_policy_set_definition_id(self):
        self.assertEqual(
            _definition_ref("/providers/Microsoft.Authorization/policySetDefinitions/mySet"),
            "myset",
        )

    def test_unresolved_expression_with_literal_tail(self):
        expr = f"[subscriptionResourceId('Microsoft.Authorization/policyDefinitions', '{TDE_GUID}')]"
        self.assertEqual(_definition_ref(expr), TDE_GUID)

    def test_fully_parameterised_is_none(self):
        self.assertIsNone(_definition_ref("[parameters('policyDefId')]"))
        self.assertIsNone(_definition_ref(None))


class BicepExtractionTests(unittest.TestCase):
    def test_extracts_literal_assignment(self):
        arm = [{
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "tde-dine",
            "properties": {"policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{TDE_GUID}",
                           "displayName": "Deploy TDE"},
        }]
        extracted, skipped = extract_bicep_policy_assignments(arm)
        self.assertEqual(skipped, 0)
        self.assertEqual(extracted[0]["definition_ref"], TDE_GUID)
        self.assertEqual(extracted[0]["name"], "tde-dine")

    def test_unresolvable_definition_is_skipped(self):
        arm = [{
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "x",
            "properties": {"policyDefinitionId": "[parameters('defId')]"},
        }]
        extracted, skipped = extract_bicep_policy_assignments(arm)
        self.assertEqual((extracted, skipped), ([], 1))


class CompareTests(unittest.TestCase):
    def test_matched_by_name_no_drift(self):
        arm = [{
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "tde-dine",
            "properties": {"policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{TDE_GUID}"},
        }]
        self.assertEqual(compare_policy_resources(arm, [live_assignment()], []), [])

    def test_matched_by_definition_when_name_is_guid_expression(self):
        arm = [{
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "[guid(resourceGroup().id)]",
            "properties": {"policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{TDE_GUID}"},
        }]
        self.assertEqual(
            compare_policy_resources(arm, [live_assignment(name="a1b2c3")], []), []
        )

    def test_out_of_band_assignment_is_extra_with_provenance(self):
        drifts = compare_policy_resources(
            [], [live_assignment(assigned_by="jacqui", created_by="70afebf7")], []
        )
        self.assertEqual(len(drifts), 1)
        d = drifts[0]
        self.assertEqual(d["drift_type"], "extra_in_azure")
        self.assertEqual(d["type"], "Microsoft.Authorization/policyAssignments")
        self.assertEqual(d["details"]["assigned_by"], "jacqui")
        self.assertEqual(d["details"]["definition_ref"], TDE_GUID)

    def test_bicep_assignment_not_deployed_is_missing(self):
        arm = [{
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "tde-dine",
            "properties": {"policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{TDE_GUID}"},
        }]
        drifts = compare_policy_resources(arm, [], [])
        self.assertEqual(drifts[0]["drift_type"], "missing_in_azure")

    def test_out_of_band_exemption_is_extra(self):
        ex = live_exemption(assignment_id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/tde-dine")
        drifts = compare_policy_resources([], [], [ex])
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["type"], "Microsoft.Authorization/policyExemptions")
        self.assertEqual(drifts[0]["drift_type"], "extra_in_azure")
        self.assertEqual(drifts[0]["details"]["exemption_category"], "Waiver")

    def test_bicep_declared_exemption_is_not_drift(self):
        aid = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/tde-dine"
        arm = [{
            "type": "Microsoft.Authorization/policyExemptions",
            "name": "planned-waiver",
            "properties": {"policyAssignmentId": aid},
        }]
        self.assertEqual(compare_policy_resources(arm, [], [live_exemption(assignment_id=aid)]), [])


class OwnershipAndFlagTests(unittest.TestCase):
    def test_policy_types_are_platform(self):
        self.assertEqual(classify_owner("Microsoft.Authorization/policyAssignments", {}), PLATFORM)
        self.assertEqual(classify_owner("Microsoft.Authorization/policyExemptions", {}), PLATFORM)

    def test_kill_switch(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(policy_drift_enabled())
        with mock.patch.dict(os.environ, {"INCLUDE_POLICY_ASSIGNMENTS": "false"}):
            self.assertFalse(policy_drift_enabled())


class NotificationTests(unittest.TestCase):
    def test_policy_extra_event_carries_provenance(self):
        from tools.send_notifications import _event_from_drift
        drift = {
            "type": "Microsoft.Authorization/policyAssignments",
            "name": "Deploy TDE",
            "drift_type": "extra_in_azure",
            "details": {"policy_display_name": "Deploy TDE",
                        "scope": f"/subscriptions/{SUB}/resourceGroups/rg",
                        "assigned_by": "jacqui", "created_on": "2026-07-06T10:00:00Z"},
        }
        ev = _event_from_drift(drift)
        self.assertIn("policy assignment 'Deploy TDE'", ev.details)
        self.assertIn("by jacqui", ev.details)

    def test_exemption_event_is_flagged(self):
        from tools.send_notifications import _event_from_drift
        drift = {
            "type": "Microsoft.Authorization/policyExemptions",
            "name": "waive-tde",
            "drift_type": "extra_in_azure",
            "details": {"exemption_category": "Waiver", "scope": "/subscriptions/x/resourceGroups/rg"},
        }
        self.assertIn("policy EXEMPTION (Waiver)", _event_from_drift(drift).details)


if __name__ == "__main__":
    unittest.main()


class GovernanceWriteAttributionTests(unittest.TestCase):
    """A human writing a policy ASSIGNMENT must stay actionable - live-caught:
    the 'policy' substring in 'policyassignments/write' mis-attributed the
    out-of-band TDE assignment as policy-ENFORCED (expected) and silently
    dropped it from the actionable set."""

    def test_human_policy_assignment_write_is_not_policy_enforced(self):
        from tools.change_origin import classify_change_origin
        info = classify_change_origin([{
            "operation": "microsoft.authorization/policyassignments/write",
            "caller": "jacqui.anker@gmail.com",
            "timestamp": "2026-07-06T21:53:15Z",
            "properties": {},
        }])
        self.assertFalse(info.expected)

    def test_dine_effect_operation_still_policy_enforced(self):
        from tools.change_origin import classify_change_origin
        info = classify_change_origin([{
            "operation": "microsoft.authorization/policyinsights/policystates/deployifnotexists/action",
            "caller": "some-msi-guid",
            "timestamp": "2026-07-06T21:53:15Z",
            "properties": {"policyAssignmentId": "/subscriptions/x/providers/Microsoft.Authorization/policyAssignments/p"},
        }])
        self.assertTrue(info.expected)
