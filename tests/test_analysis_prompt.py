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


if __name__ == "__main__":
    unittest.main()
