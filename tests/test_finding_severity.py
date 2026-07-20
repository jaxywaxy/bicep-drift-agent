"""
Unit tests for finding-level severity propagation.

The property-drift detector assigns per-property severity (CRITICAL_PROPERTIES,
security sentinels), but DriftFinding classified 'property_drift' as severity
"unknown" - none of the classifier's drift_type checks matched the substring,
so an ACR admin-user or storage https-only critical drift surfaced as
severity=unknown in the analysis summary and notifications.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.drift_agent import DriftAgent, DriftSeverity, DriftCategory, RemediationAction
from tools.models import Drift


def _classify(resource_type, drift_type="property_drift", changed=None):
    agent = DriftAgent(api_key="test-key")
    details = {}
    if changed is not None:
        details["changed_properties"] = changed
    return agent._classify_drift(Drift(
        resource_type=resource_type,
        resource_name="res1",
        drift_type=drift_type,
        details=details,
    ))


class FindingSeverityTests(unittest.TestCase):
    def test_critical_property_yields_critical_finding(self):
        # The live case: ACR adminUserEnabled sentinel marked critical, but the
        # finding reported severity unknown.
        finding = _classify(
            "microsoft.containerregistry/registries",
            changed={"properties.adminUserEnabled": {"desired": False, "actual": True,
                                                     "severity": "critical"}},
        )
        self.assertEqual(finding.severity, DriftSeverity.CRITICAL)
        self.assertEqual(finding.category, DriftCategory.CONFIGURATION_DRIFT)
        self.assertEqual(finding.recommended_action, RemediationAction.REDEPLOY_BICEP)

    def test_warning_property_yields_medium(self):
        finding = _classify(
            "microsoft.insights/metricalerts",
            changed={"properties.actions": {"severity": "warning"}},
        )
        self.assertEqual(finding.severity, DriftSeverity.MEDIUM)

    def test_info_property_yields_low(self):
        finding = _classify(
            "microsoft.web/serverfarms",
            changed={"properties.reserved": {"severity": "info"}},
        )
        self.assertEqual(finding.severity, DriftSeverity.LOW)

    def test_max_across_properties_wins(self):
        finding = _classify(
            "microsoft.web/serverfarms",
            changed={
                "properties.a": {"severity": "info"},
                "properties.b": {"severity": "critical"},
                "properties.c": {"severity": "warning"},
            },
        )
        self.assertEqual(finding.severity, DriftSeverity.CRITICAL)

    def test_property_drift_no_longer_unknown_without_severities(self):
        finding = _classify(
            "microsoft.web/serverfarms",
            changed={"properties.reserved": {"desired": True, "actual": False}},
        )
        self.assertEqual(finding.severity, DriftSeverity.MEDIUM)
        self.assertEqual(finding.category, DriftCategory.CONFIGURATION_DRIFT)
        self.assertNotEqual(finding.severity, DriftSeverity.UNKNOWN)

    def test_critical_property_upgrades_governance_category(self):
        # Governance modified used to floor at MEDIUM even for critical props.
        finding = _classify(
            "microsoft.insights/diagnosticsettings",
            changed={"properties.logs": {"severity": "critical"}},
        )
        self.assertEqual(finding.category, DriftCategory.GOVERNANCE_DRIFT)
        self.assertEqual(finding.severity, DriftSeverity.CRITICAL)

    def test_system_managed_still_suppresses_azure_created_extras(self):
        # The category's real job: a NIC Azure created for a VM/private endpoint
        # showing up as an extra resource is not drift.
        finding = _classify("microsoft.network/networkinterfaces", drift_type="extra_in_azure")
        self.assertEqual(finding.category, DriftCategory.SYSTEM_MANAGED)
        self.assertEqual(finding.severity, DriftSeverity.INFORMATIONAL)
        self.assertEqual(finding.recommended_action, RemediationAction.IGNORE_SYSTEM_MANAGED)

    def test_system_managed_type_does_not_swallow_property_drift(self):
        # Previously the type shortcut ran first and unconditionally, so a
        # DECLARED disk whose networkAccessPolicy was manually flipped
        # DenyAll -> AllowAll came back "ignore_system_managed" at severity
        # informational. A property drift means the resource was matched from
        # the Bicep, so it is template-managed and the finding is actionable.
        finding = _classify(
            "microsoft.compute/disks",
            changed={"properties.networkAccessPolicy": {"desired": "DenyAll",
                                                        "actual": "AllowAll",
                                                        "severity": "critical"}},
        )
        self.assertEqual(finding.category, DriftCategory.CONFIGURATION_DRIFT)
        self.assertEqual(finding.severity, DriftSeverity.CRITICAL)
        self.assertEqual(finding.recommended_action, RemediationAction.REDEPLOY_BICEP)

    def test_missing_in_azure_unaffected(self):
        finding = _classify("microsoft.web/sites", drift_type="missing_in_azure")
        self.assertEqual(finding.severity, DriftSeverity.HIGH)


if __name__ == "__main__":
    unittest.main()
