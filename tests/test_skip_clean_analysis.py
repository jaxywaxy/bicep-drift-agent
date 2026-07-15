"""
No actionable drift => no Claude analysis call.

Measured on a real clean scan of rg-drift-test: 1 Claude call, 1134 output
tokens, $0.034, ~105s - about 75% of that run's wall clock - spent having
Claude narrate "**No drift detected.** ... Total drift findings: 0", which
drift_count already states deterministically. A clean estate is the COMMON
case for a scheduled scan, so this is the single biggest saving available
(profiling showed the whole Azure/deterministic pipeline is only ~35s of a
185s run; ~80% is Claude latency, and the analysis call dominates it).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyze_drift as ad


class SpyAgent:
    """Records whether the analysis call was made."""

    def __init__(self, result="claude narrative"):
        self.calls = 0
        self._result = result

    def analyze_drift(self, report):
        self.calls += 1
        return self._result


def _data(drifts=None, **extra):
    d = {"bicep_file": "bicep/main.bicep", "resource_group": "rg-x",
         "drifts": drifts if drifts is not None else []}
    d.update(extra)
    return d


def _reconciled(n):
    return [{"type": "microsoft.keyvault/vaults", "name": f"kv{i}",
             "drift_type": "matched_unresolvable", "details": {}} for i in range(n)]


def _actionable(n=1):
    return [{"type": "Microsoft.Web/sites", "name": f"app{i}",
             "drift_type": "missing_in_azure", "details": {}} for i in range(n)]


class SkipCleanAnalysisTests(unittest.TestCase):
    def test_no_drift_at_all_skips_claude(self):
        agent = SpyAgent()
        out = ad._run_claude_analysis(agent, _data())
        self.assertEqual(agent.calls, 0)
        self.assertIn("No drift detected.", out)

    def test_only_reconciled_entries_skips_claude(self):
        # The real clean-run shape: 0 actionable, 34 matched_unresolvable.
        agent = SpyAgent()
        data = _data(_reconciled(34))
        out = ad._run_claude_analysis(agent, data)
        self.assertEqual(agent.calls, 0)
        self.assertIn("Resources reconciled: 34", out)
        self.assertEqual(data["agent_analysis"], out)

    def test_actionable_drift_still_calls_claude(self):
        agent = SpyAgent()
        out = ad._run_claude_analysis(agent, _data(_actionable(1)))
        self.assertEqual(agent.calls, 1)
        self.assertEqual(out, "claude narrative")

    def test_one_actionable_among_many_reconciled_still_calls(self):
        # Must not skip just because reconciled entries dominate.
        agent = SpyAgent()
        ad._run_claude_analysis(agent, _data(_reconciled(30) + _actionable(1)))
        self.assertEqual(agent.calls, 1)

    def test_no_agent_still_returns_none(self):
        # The no-API-key contract is unchanged.
        self.assertIsNone(ad._run_claude_analysis(None, _data()))

    def test_summary_reports_ignored_count(self):
        out = ad._run_claude_analysis(
            SpyAgent(), _data(_reconciled(2), ignored_drifts=[{"a": 1}, {"b": 2}]))
        self.assertIn("Suppressed by ignore rules: 2", out)

    def test_summary_omits_zero_counts(self):
        out = ad._run_claude_analysis(SpyAgent(), _data())
        self.assertNotIn("Resources reconciled", out)
        self.assertNotIn("Suppressed by ignore rules", out)

    def test_summary_names_scope_and_template(self):
        out = ad._run_claude_analysis(SpyAgent(), _data())
        self.assertIn("rg-x", out)
        self.assertIn("bicep/main.bicep", out)

    def test_summary_is_markdown_like_claude_output(self):
        # The analysis lands in reports/<label>-analysis.md and the JSON report,
        # so it must stay markdown-shaped.
        out = ad._run_claude_analysis(SpyAgent(), _data())
        self.assertTrue(out.startswith("# Bicep Drift Analysis"))
        self.assertIn("## Executive Summary", out)


if __name__ == "__main__":
    unittest.main()
