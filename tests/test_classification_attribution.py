"""
The classifier must honour an attribution the pipeline already resolved.

_classify_drift reasoned from resource type and drift type alone. That is right
when we do not know who changed what - but by the time a finding reaches the
agent, _attribute_lifecycle and _claim_policy_required_tags have often already
established it. Ignoring that produced findings the agent argued with in the
live 2026-07-27 analysis:

    "the report labels four of these high/security_drift - that severity
     reflects the RESOURCE's sensitivity, not the CHANGE"
    "the redeploy_bicep recommendation on these 19 is wrong"

Two of five Confidence bullets were spent correcting inputs we control (#327).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.classification import DriftClassifier
from agent.findings import DriftCategory, DriftSeverity, RemediationAction
from tools.models import Drift

POLICY_MODIFY = {"origin": "policy_modify", "category": "policy", "expected": True,
                 "severity": "low", "policy_name": "drift-inherit-environment"}
CLAIMED_DETAILS = {"policy_enforced_summary":
                   "tags.environment: test -> production "
                   "(imposed by policy assignment 'drift-inherit-environment')"}
CRITICAL_DETAILS = {"changed_properties": {"properties.allowBlobPublicAccess": {
    "desired": False, "actual": True, "severity": "critical"}}}


def _classify(resource_type, drift_type="property_drift", details=None, change_origin=None):
    c = DriftClassifier.__new__(DriftClassifier)   # no __init__ deps for classification
    return c._classify_drift(Drift(
        resource_type=resource_type, resource_name="r", drift_type=drift_type,
        details=details if details is not None else {}, change_origin=change_origin))


class PolicyClaimedFindingsTests(unittest.TestCase):
    """A fully-claimed record is governance, whatever the resource type is."""

    SECURITY_SENSITIVE = [
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/privateDnsZones",
        "Microsoft.Network/privateEndpoints",
        "Microsoft.KeyVault/vaults",
    ]

    def test_a_claimed_tag_on_a_sensitive_resource_is_not_a_security_finding(self):
        # The exact four the live analysis called out. The only thing that
        # drifted is a tag; the resource's sensitivity is not the change's.
        for rtype in self.SECURITY_SENSITIVE:
            with self.subTest(rtype):
                f = _classify(rtype, details=CLAIMED_DETAILS, change_origin=POLICY_MODIFY)
                self.assertEqual(f.category, DriftCategory.GOVERNANCE_DRIFT)
                self.assertNotEqual(f.severity, DriftSeverity.HIGH)

    def test_a_claimed_finding_is_never_told_to_redeploy(self):
        # A Modify effect re-imposes the value inside the deploying identity's
        # own write, so redeploying loses the race on the very next write.
        for rtype in self.SECURITY_SENSITIVE:
            with self.subTest(rtype):
                f = _classify(rtype, details=CLAIMED_DETAILS, change_origin=POLICY_MODIFY)
                self.assertNotEqual(f.recommended_action, RemediationAction.REDEPLOY_BICEP)
                self.assertEqual(f.recommended_action, RemediationAction.APPROVE_EXCEPTION)

    def test_the_attributed_severity_is_used_verbatim(self):
        f = _classify("Microsoft.Network/networkSecurityGroups",
                      details=CLAIMED_DETAILS, change_origin=POLICY_MODIFY)
        self.assertEqual(f.severity, DriftSeverity.LOW)

    def test_an_unparseable_attributed_severity_falls_back_to_low(self):
        origin = {**POLICY_MODIFY, "severity": "catastrophic"}
        f = _classify("Microsoft.Network/networkSecurityGroups",
                      details=CLAIMED_DETAILS, change_origin=origin)
        self.assertEqual(f.severity, DriftSeverity.LOW)

    def test_approve_exception_not_no_action(self):
        # There IS a decision - reconcile the template to the policy, or narrow
        # the assignment. "No action" would hide a real template-vs-policy
        # conflict rather than surface it as governance.
        f = _classify("Microsoft.Network/networkSecurityGroups",
                      details=CLAIMED_DETAILS, change_origin=POLICY_MODIFY)
        self.assertNotEqual(f.recommended_action, RemediationAction.NO_ACTION)


class AttributionMustNotBuryRealDriftTests(unittest.TestCase):
    """The override is bounded. `expected` describes the CHANGE's provenance,
    not its content."""

    def test_a_critical_property_survives_an_expected_attribution(self):
        # A DINE-created resource can still carry a genuinely critical property.
        # Downgrading it to keep the governance section tidy would repeat the
        # mistake this fix exists to undo.
        f = _classify("Microsoft.Storage/storageAccounts", details=CRITICAL_DETAILS,
                      change_origin={"origin": "policy_dine", "expected": True,
                                     "severity": "low"})
        self.assertEqual(f.severity, DriftSeverity.CRITICAL)
        self.assertNotEqual(f.category, DriftCategory.GOVERNANCE_DRIFT)

    def test_a_manual_out_of_band_change_is_untouched(self):
        f = _classify("Microsoft.Storage/storageAccounts", details=CRITICAL_DETAILS,
                      change_origin={"origin": "manual_change", "expected": False,
                                     "severity": "high"})
        self.assertEqual(f.severity, DriftSeverity.CRITICAL)
        self.assertEqual(f.recommended_action, RemediationAction.REDEPLOY_BICEP)

    def test_the_partly_claimed_storage_account_keeps_its_critical_finding(self):
        # The live shape: allowBlobPublicAccess flipped manually AND a claimed
        # tag. A partial claim deliberately does not mark the record expected,
        # so nothing here should move - asserted because burying this row is
        # the single worst outcome of the whole policy-claim feature.
        f = _classify("Microsoft.Storage/storageAccounts", details=CRITICAL_DETAILS,
                      change_origin={"origin": "manual_change", "category": "out_of_band",
                                     "expected": False, "severity": "high"})
        self.assertEqual(f.severity, DriftSeverity.CRITICAL)


class AttributionAbsentOrMalformedTests(unittest.TestCase):
    """No attribution means fall back to the type heuristics, unchanged."""

    def test_no_change_origin_preserves_the_old_classification(self):
        f = _classify("Microsoft.Network/networkSecurityGroups", details=CLAIMED_DETAILS)
        self.assertEqual(f.category, DriftCategory.SECURITY_DRIFT)
        self.assertEqual(f.severity, DriftSeverity.HIGH)

    def test_expected_false_preserves_the_old_classification(self):
        f = _classify("Microsoft.Network/networkSecurityGroups", details=CLAIMED_DETAILS,
                      change_origin={"origin": "manual_change", "expected": False})
        self.assertEqual(f.category, DriftCategory.SECURITY_DRIFT)

    def test_a_non_dict_change_origin_does_not_raise(self):
        # change_origin is threaded from the report; a malformed one must not
        # take the whole analysis down.
        for bad in ("policy_modify", ["policy_modify"], 7):
            with self.subTest(bad):
                f = _classify("Microsoft.Network/networkSecurityGroups",
                              details=CLAIMED_DETAILS, change_origin=bad)
                self.assertEqual(f.category, DriftCategory.SECURITY_DRIFT)


class SystemManagedTests(unittest.TestCase):
    def test_system_managed_is_informational_and_ignored(self):
        f = _classify("Microsoft.Network/networkWatchers", drift_type="extra_in_azure",
                      change_origin={"origin": "system_managed", "expected": True,
                                     "severity": "low"})
        self.assertEqual(f.category, DriftCategory.SYSTEM_MANAGED)
        self.assertEqual(f.severity, DriftSeverity.INFORMATIONAL)
        self.assertEqual(f.recommended_action, RemediationAction.IGNORE_SYSTEM_MANAGED)


if __name__ == "__main__":
    unittest.main()
