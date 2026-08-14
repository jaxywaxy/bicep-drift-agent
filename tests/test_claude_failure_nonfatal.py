"""
A Claude API failure must be NON-FATAL to the deterministic drift report.

Seen live: the Anthropic key ran out of credit, the Claude analysis call raised
a 400, and _run_claude_analysis re-raised - aborting Phase 2 AFTER smart
matching reconciled the report but BEFORE the persist. The shipped report fell
back to the raw Phase 1 dump: every uniqueString-named resource false-flagged
extra_in_azure. The deterministic pipeline is Claude-independent and its results
must survive an AI outage.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyze_drift as ad


class _Report:
    bicep_file = "bicep/main.bicep"
    resource_group = "rg-x"


def _report_data(drifts=None):
    # Defaults to ONE actionable drift on purpose: with no actionable drift the
    # analysis call is skipped entirely (see test_skip_clean_analysis), so these
    # failure-path tests would never reach Claude and would prove nothing.
    return {
        "bicep_file": "bicep/main.bicep",
        "resource_group": "rg-x",
        "drifts": drifts if drifts is not None else [
            {"type": "Microsoft.Web/sites", "name": "app1",
             "drift_type": "missing_in_azure", "details": {}},
        ],
    }


class ClaudeFailureNonFatalTests(unittest.TestCase):
    def test_no_agent_returns_none(self):
        self.assertIsNone(ad._run_claude_analysis(None, _report_data()))

    def test_credit_exhausted_returns_none_not_raise(self):
        class Broken:
            def analyze_drift(self, report):
                raise Exception(
                    "Error code: 400 - Your credit balance is too low to access the Anthropic API."
                )
        # Must NOT raise.
        result = ad._run_claude_analysis(Broken(), _report_data())
        self.assertIsNone(result)

    def test_auth_failure_returns_none_not_raise(self):
        class Broken:
            def analyze_drift(self, report):
                raise Exception("authentication_error: invalid x-api-key")
        self.assertIsNone(ad._run_claude_analysis(Broken(), _report_data()))

    def test_generic_failure_returns_none_not_raise(self):
        class Broken:
            def analyze_drift(self, report):
                raise RuntimeError("connection reset")
        self.assertIsNone(ad._run_claude_analysis(Broken(), _report_data()))

    def test_failure_is_recorded_in_the_report_not_only_the_log(self):
        """Non-fatal must not mean invisible.

        The report carried no trace of a failed analysis, so a provider that was
        configured but unreachable rendered exactly like no provider: an empty
        footer. A torn-down endpoint produced green runs with silently missing
        analysis, spotted only because the cost line vanished.
        """
        class Broken:
            def analyze_drift(self, report):
                raise RuntimeError("connection reset")

        data = _report_data()
        self.assertIsNone(ad._run_claude_analysis(Broken(), data))
        recorded = data.get("agent_analysis_error")
        self.assertIsNotNone(recorded, "the failure left no trace in the report")
        self.assertEqual("RuntimeError", recorded["error_type"])
        self.assertTrue(recorded["hint"])

    def test_the_raw_exception_text_is_never_persisted(self):
        """Only the provider's curated hint goes in the artifact. Raw SDK
        exceptions embed request URLs and headers, and this report is published
        to a GitHub issue."""
        class Broken:
            def analyze_drift(self, report):
                raise RuntimeError(
                    "connect failed https://drift-agent-openai.openai.azure.com/"
                    "openai/deployments/x?api-key=sk-secret-value"
                )

        data = _report_data()
        ad._run_claude_analysis(Broken(), data)
        self.assertNotIn("sk-secret-value", json.dumps(data))
        self.assertNotIn("api-key", json.dumps(data))

    def test_a_successful_run_records_no_failure(self):
        class Fine:
            def analyze_drift(self, report):
                return "## Summary\n\nAll good."

        data = _report_data()
        ad._run_claude_analysis(Fine(), data)
        self.assertIsNone(data.get("agent_analysis_error"))

    def test_report_drifts_untouched_on_failure(self):
        # The deterministic drift set the caller will persist must be preserved.
        drifts = [
            {"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg",
             "drift_type": "property_drift",
             "details": {"changed_properties": {"properties.securityRules": {"severity": "critical"}}}},
            {"type": "Microsoft.OperationalInsights/workspaces", "name": "log-real",
             "drift_type": "matched_unresolvable", "details": {}},
        ]
        data = _report_data(drifts)

        class Broken:
            def analyze_drift(self, report):
                raise Exception("credit balance is too low")

        ad._run_claude_analysis(Broken(), data)
        self.assertEqual(len(data["drifts"]), 2)
        self.assertNotIn("agent_analysis", data)  # no narrative, but drifts intact

    def test_successful_analysis_still_stored(self):
        class Ok:
            def analyze_drift(self, report):
                return "the analysis narrative"
        data = _report_data()
        result = ad._run_claude_analysis(Ok(), data)
        self.assertEqual(result, "the analysis narrative")
        self.assertEqual(data["agent_analysis"], "the analysis narrative")


if __name__ == "__main__":
    unittest.main()
