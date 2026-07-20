"""
Unit tests for the analysis-prompt slimming: matched_unresolvable entries are
NOT drift (runtime-named resources reconciled to deployed counterparts) and
must not reach the Claude analysis as findings - on real estates they dominated
~30:3, inflating cost and making the model caveat "unresolved" rows instead of
analysing actionable drift. They are reduced to a count in the context.
"""

import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.drift_agent import DriftAgent
from tools.models import DriftReport, Drift


def _report(n_reconciled, n_actionable):
    drifts = []
    for i in range(n_reconciled):
        drifts.append(Drift(
            resource_type="microsoft.storage/storageaccounts",
            resource_name=f"reconciled{i:02d}xyz",
            drift_type="matched_unresolvable",
        ))
    for i in range(n_actionable):
        drifts.append(Drift(
            resource_type="microsoft.containerregistry/registries",
            resource_name=f"acrdrifted{i:02d}",
            drift_type="modified",
            severity="critical",
            details={"changed_properties": {"properties.adminUserEnabled": {}}},
        ))
    return DriftReport(bicep_file="bicep/main.bicep", resource_group="rg-x",
                       drifts=drifts, total_modified=n_actionable)


class AnalysisPromptTests(unittest.TestCase):
    def _agent_and_prompt(self, report):
        agent = DriftAgent(api_key="test-key", model="claude-opus-4-8")
        captured = {}

        def fake_create(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                content=[SimpleNamespace(text="analysis")],
                usage=SimpleNamespace(input_tokens=1, output_tokens=1),
            )

        agent._create_message = fake_create
        agent.analyze_drift(report)
        return json.loads(
            captured["messages"][0]["content"].split("\n\n", 1)[1]
        )

    def test_reconciled_entries_excluded_from_findings(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=30, n_actionable=3))
        self.assertEqual(len(ctx["findings"]), 3)
        names = json.dumps(ctx["findings"])
        self.assertNotIn("reconciled00xyz", names)
        self.assertEqual(ctx["reconciled_resources"]["count"], 30)

    def test_prompt_shrinks_substantially(self):
        big = self._agent_and_prompt(_report(30, 3))
        # Reconstruct what the old behavior would have sent: same report with
        # the reconciled entries relabeled so they pass the filter.
        rpt = _report(0, 3)
        for i in range(30):
            rpt.drifts.append(Drift(
                resource_type="microsoft.storage/storageaccounts",
                resource_name=f"reconciled{i:02d}xyz",
                drift_type="extra"))
        old = self._agent_and_prompt(rpt)
        self.assertLess(len(json.dumps(big)), len(json.dumps(old)) / 2)

    def test_no_reconciled_key_when_none(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=0, n_actionable=2))
        self.assertNotIn("reconciled_resources", ctx)
        self.assertEqual(len(ctx["findings"]), 2)

    def test_all_reconciled_yields_empty_findings_with_count(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=5, n_actionable=0))
        self.assertEqual(ctx["findings"], [])
        self.assertEqual(ctx["reconciled_resources"]["count"], 5)

    def test_original_report_object_not_mutated(self):
        report = _report(4, 1)
        agent = DriftAgent(api_key="test-key")
        agent._create_message = lambda **kw: SimpleNamespace(
            content=[SimpleNamespace(text="x")], usage=None)
        agent.analyze_drift(report)
        self.assertEqual(len(report.drifts), 5)


class AttributionInPromptTests(unittest.TestCase):
    """The report already resolves who/how (change_origin) and the ARM id
    (lifecycle.resource_id). Both must reach the agent so it cites them instead
    of re-deriving attribution or caveating a 'null resource_id'."""

    CHANGE_ORIGIN = {
        "origin": "manual_change",
        "category": "out_of_band",
        "changed_by": "someone@example.com",
        "reason": "Manual change by someone@example.com (out-of-band)",
    }
    RID = ("/subscriptions/xxx/resourceGroups/rg-x/providers/"
           "Microsoft.Network/firewallPolicies/fwpol-drift-test")

    def _prompt_ctx(self):
        report = DriftReport(
            bicep_file="bicep/main.bicep", resource_group="rg-x", total_modified=1,
            drifts=[Drift(
                resource_type="Microsoft.Network/firewallPolicies",
                resource_name="fwpol-drift-test",
                drift_type="property_drift",
                severity="critical",
                details={"changed_properties": {"properties.threatIntelMode": {}}},
                resource_id=self.RID,
                change_origin=self.CHANGE_ORIGIN,
            )],
        )
        return AnalysisPromptTests()._agent_and_prompt(report)

    def test_change_origin_reaches_prompt(self):
        finding = self._prompt_ctx()["findings"][0]
        self.assertEqual(finding["change_origin"], self.CHANGE_ORIGIN)

    def test_resource_id_reaches_prompt(self):
        finding = self._prompt_ctx()["findings"][0]
        self.assertEqual(finding["resource_id"], self.RID)


class RemediationGuidanceTests(unittest.TestCase):
    """The system prompt must carry the Azure-specific remediation rules that
    Opus previously got wrong (locks, redeploy scope, using existing attribution)."""

    def test_prompt_encodes_azure_remediation_rules(self):
        sp = DriftAgent._get_system_prompt()
        # Locks don't stop config drift
        self.assertIn("CanNotDelete", sp)
        self.assertIn("blocks deletion", sp)
        # Prefer the narrowest redeploy scope
        self.assertIn("NARROWEST", sp)
        # Don't tell the user to pull Activity Logs — attribution is provided
        self.assertIn("Activity Logs", sp)
        self.assertIn("change_origin", sp)
        # Rogue top-level child needs explicit delete, not redeploy
        self.assertIn("TOP-LEVEL child", sp)

    def test_prompt_warns_that_platform_enforced_hardening_survives_redeploy(self):
        # A live round drifted encryptionAtHost false -> true and the analysis
        # said a redeploy would turn it back off. If the subscription enforces
        # encryption (policy Modify/DINE, default disk encryption set), the
        # redeploy lands and the setting comes straight back - so the analysis
        # must send the reader to check the enforcement scope first.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("encryptionAtHost", sp)
        self.assertIn("MORE secure", sp)
        self.assertIn("management-group scope", sp)
        self.assertIn("az policy assignment list", sp)
        # And must offer the "make the template declare the enforced value" branch.
        self.assertIn("declare the enforced value", sp)

    def test_prompt_splits_deny_from_modify(self):
        # The first version named only Modify/DINE, so the analysis promised
        # silent re-drift. Most BUILT-IN hardening policies are Deny, where the
        # redeploy fails outright - opposite operator expectation.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("`Deny`", sp)
        self.assertIn("FAILS outright", sp)
        self.assertIn("`Modify` / `deployIfNotExists`", sp)
        self.assertIn("back on the next run", sp)

    def test_prompt_rejects_the_bogus_subscription_encryption_default(self):
        # EncryptionAtHost is a subscription FEATURE REGISTRATION (permits the
        # setting, never applies it); the default disk encryption set governs a
        # different property. Sending the reader to either explains nothing.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("FEATURE REGISTRATION", sp)
        self.assertIn("Microsoft.Compute/EncryptionAtHost", sp)
        self.assertIn("properties.encryption.type", sp)

    def test_prompt_carries_the_deallocation_constraint(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("cannot be changed while instances are allocated", sp)
        self.assertIn("sku.capacity", sp)


class EvidenceDisciplineTests(unittest.TestCase):
    """A live round invented a disk-to-VMSS attachment and reported an opened
    networkAccessPolicy without saying publicNetworkAccess was still Disabled."""

    def test_prompt_forbids_inventing_relationships(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Never assert a RELATIONSHIP that is not in the data", sp)
        self.assertIn("unverified", sp)

    def test_prompt_requires_mitigating_fields(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("MITIGATING fields", sp)
        self.assertIn("publicNetworkAccess", sp)

    def test_prompt_denies_treating_missing_policy_attribution_as_proof(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("policy_enforced_drifts", sp)
        self.assertIn("confirmed manual", sp)


if __name__ == "__main__":
    unittest.main()
