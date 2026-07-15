"""
WAF detection-coverage drift is CRITICAL, not just WAF mode/state.

Live round (first time the WAF paths were ever exercised - the estate's only
WAF policy used to be gated behind a ~$180/mo App Gateway): mode->Detection
and state->Disabled correctly rated critical, but two ways to gut the WAF
while it still reads Enabled/Prevention rated only 'warning':
  - managedRules.managedRuleSets: an OWASP version downgrade silently drops rules
  - policySettings.requestBodyCheck=false: POST payloads stop being inspected

Azure structurally protects the ruleset (the primary rule set cannot be removed
- NoValidPrimaryRuleSetsAttached - and duplicates are rejected), so a VERSION
DOWNGRADE is the realistic coverage-reduction vector, not removal.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator

WAF_TYPE = "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"


def _waf(mode="Prevention", state="Enabled", version="3.2", body_check=True,
         live_augmented=False):
    rule_set = {"ruleSetType": "OWASP", "ruleSetVersion": version}
    if live_augmented:
        rule_set["ruleGroupOverrides"] = []
    return {
        "type": WAF_TYPE,
        "name": "waf-drift-test",
        "properties": {
            "policySettings": {
                "state": state,
                "mode": mode,
                "requestBodyCheck": body_check,
                "maxRequestBodySizeInKb": 128,
                "fileUploadLimitInMb": 100,
            },
            "managedRules": {"managedRuleSets": [rule_set]},
        },
    }


def _sev(bicep, live, path):
    diffs = [d for d in PropertyComparator.compare_properties(bicep, live)
             if d.property_path == path]
    return diffs[0].severity if diffs else None


class WafDriftTests(unittest.TestCase):
    def test_baseline_no_drift_despite_live_augmentation(self):
        # Azure adds ruleGroupOverrides to the managed rule set - not drift.
        diffs = PropertyComparator.compare_properties(_waf(), _waf(live_augmented=True))
        self.assertEqual([d.property_path for d in diffs
                          if d.property_path.startswith("properties.")], [])

    def test_mode_flip_to_detection_is_critical(self):
        self.assertEqual(
            _sev(_waf(), _waf(mode="Detection"), "properties.policySettings.mode"),
            "critical")

    def test_state_disabled_is_critical(self):
        self.assertEqual(
            _sev(_waf(), _waf(state="Disabled"), "properties.policySettings.state"),
            "critical")

    def test_ruleset_version_downgrade_is_critical(self):
        # OWASP 3.2 -> 3.1 = silently reduced attack coverage.
        self.assertEqual(
            _sev(_waf(), _waf(version="3.1", live_augmented=True),
                 "properties.managedRules.managedRuleSets"),
            "critical")

    def test_request_body_check_disabled_is_critical(self):
        # WAF still reads Enabled/Prevention but stops inspecting POST bodies.
        self.assertEqual(
            _sev(_waf(), _waf(body_check=False),
                 "properties.policySettings.requestBodyCheck"),
            "critical")

    def test_unrelated_waf_setting_stays_warning(self):
        # Size limits are operational tuning, not a security-coverage change.
        bicep = _waf()
        live = _waf()
        live["properties"]["policySettings"]["fileUploadLimitInMb"] = 200
        self.assertEqual(
            _sev(bicep, live, "properties.policySettings.fileUploadLimitInMb"),
            "warning")


if __name__ == "__main__":
    unittest.main()
