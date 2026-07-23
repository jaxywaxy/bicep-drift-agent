"""
Unit tests for change_origin.classify_change_origin — ensures policy / system
changes are marked expected=True (so they get split into the policy-enforced
section) while manual changes stay expected=False (actionable drift).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.change_origin import ChangeOrigin, classify_change_origin


def _log(operation, caller="user@example.com", properties=None):
    return [{
        "timestamp": "2026-07-02T01:00:00Z",
        "operation": operation,
        "caller": caller,
        "status": "Succeeded",
        "properties": properties or {},
    }]


class ClassifyChangeOriginTests(unittest.TestCase):

    def test_no_events_is_unknown_not_expected(self):
        info = classify_change_origin([])
        self.assertEqual(info.origin, ChangeOrigin.UNKNOWN)
        self.assertFalse(info.expected)

    def test_manual_change_not_expected(self):
        info = classify_change_origin(_log("microsoft.keyvault/vaults/write", caller="jane@corp.com"))
        self.assertEqual(info.origin, ChangeOrigin.MANUAL_CHANGE)
        self.assertFalse(info.expected)

    def test_policy_caller_is_expected(self):
        info = classify_change_origin(_log("microsoft.resources/tags/write", caller="Azure Policy"))
        self.assertTrue(info.expected)

    def test_policy_assignment_id_signal_is_expected(self):
        # caller is a managed-identity GUID, but properties carry the policy assignment
        info = classify_change_origin(_log(
            "microsoft.resources/tags/write",
            caller="8f3e...msi-guid",
            properties={"policyAssignmentId": "/subscriptions/x/.../policyAssignments/add-tag"},
        ))
        self.assertTrue(info.expected)
        self.assertEqual(info.origin, ChangeOrigin.POLICY_MODIFY)

    def test_policy_managed_identity_caller_is_expected(self):
        # Real DINE/Modify writes: caller is the assignment's MSI GUID, no
        # policyAssignmentId on the write. Mapping the principal id attributes it to policy.
        msi = "4ba5674e-b9e7-46c1-9945-329f529f4512"
        logs = _log("microsoft.authorization/locks/write", caller=msi)
        # Without the principal set -> looks manual
        self.assertFalse(classify_change_origin(logs).expected)
        # With the principal set -> policy-enforced
        info = classify_change_origin(logs, policy_principal_ids={msi})
        self.assertTrue(info.expected)
        # With a principal->name map -> the policy name is surfaced
        info2 = classify_change_origin(logs, policy_principal_ids={msi: "DINE storage lock (drift test)"})
        self.assertTrue(info2.expected)
        self.assertEqual(info2.policy_name, "DINE storage lock (drift test)")

    def test_dine_operation_is_policy_dine(self):
        info = classify_change_origin(_log(
            "microsoft.authorization/policies/deployIfNotExists/action",
            caller="Azure Policy",
            properties={"policyAssignmentId": "/.../policyAssignments/deploy-diag"},
        ))
        self.assertTrue(info.expected)
        self.assertEqual(info.origin, ChangeOrigin.POLICY_DINE)


if __name__ == "__main__":
    unittest.main()
