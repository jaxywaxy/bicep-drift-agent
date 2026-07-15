"""
Characterization tests for the HTML report renderer.

html_report.py had ZERO test coverage while carrying the largest function in
the codebase (generate_html_report, 746 lines - ~4x the next). These tests were
written BEFORE extracting the 562-line static CSS block to a module constant,
to pin the rendered output; the extraction was then proven byte-identical
against a real 35-drift report.

They are deliberately behavioural, not golden-file: they assert the report
CONTAINS what each section is responsible for, so the renderer can be
refactored further without churning a snapshot, while a section silently
disappearing still fails.
"""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.html_report import generate_html_report, _REPORT_CSS


def _report(**overrides):
    """A compact report exercising every render path."""
    data = {
        "resource_group": "rg-drift-test",
        "bicep_file": "bicep/main.bicep",
        "drift_count": 3,
        "drifts": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "name": "nsg-drift-test",
                "drift_type": "property_drift",
                "details": {"changed_properties": {
                    "properties.securityRules": {
                        "desired": [{"name": "deny-ssh"}],
                        "actual": [{"name": "allow-rdp-anywhere"}],
                        "severity": "critical"}}},
                "owner": "platform",
                "change_origin": {"origin": "manual_change", "category": "unauthorized",
                                  "severity": "high", "expected": False,
                                  "changed_by": "someone@example.com",
                                  "reason": "Manual change"},
                "lifecycle": {"resource_id": "/subscriptions/s/rg/x/nsg-drift-test",
                              "events": [], "deleted_at": None,
                              "last_modified_at": "2026-07-15T01:00:00+00:00",
                              "last_modified_by": "someone@example.com"},
                "recommendation": "Remove the allow-rdp-anywhere rule.",
            },
            {
                "type": "Microsoft.Authorization/locks",
                "name": "keyvault-cannotdelete",
                "drift_type": "missing_in_azure",
                "details": {},
                "owner": "workload",
            },
            {
                "type": "microsoft.storage/storageaccounts",
                "name": "stunmanaged",
                "drift_type": "extra_in_azure",
                "details": {},
                "owner": "unknown",
            },
            {
                "type": "microsoft.keyvault/vaults",
                "name": "kvdrift3s7c",
                "drift_type": "matched_unresolvable",
                "details": {},
                "is_matched": True,
                "match_confidence": "high",
                "bicep_name_expression": "kvdrift[86c9cbf6]",
            },
        ],
        "property_drifts": [],
        "ignored_drifts": [{"type": "Microsoft.OperationalInsights/workspaces/tables",
                            "name": "log-x/CustomLog_CL", "drift_type": "missing_in_azure",
                            "details": {}, "ignored_reason": "Blanket ignore"}],
        "policy_enforced_drifts": [{
            "type": "microsoft.storage/storageaccounts", "name": "stpolicy",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.x": {"desired": 1, "actual": 2,
                                                                "severity": "info"}}},
            "change_origin": {"origin": "policy_dine", "category": "expected",
                              "severity": "info", "expected": True,
                              "policy_name": "Deploy diagnostics",
                              "reason": "Policy DINE"},
        }],
        "smart_matched": [{"type": "microsoft.keyvault/vaults",
                           "name": "kvdrift[86c9cbf6]", "matched_to": "kvdrift3s7c",
                           "match_confidence": "high", "match_reason": "same type"}],
        "agent_analysis": "## Summary\n\nThree drifts found.",
        "agent_usage": {"calls": 3, "input_tokens": 2751, "output_tokens": 3579,
                        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                        "models": ["claude-opus-4-8"], "estimated_cost_usd": 0.114655},
    }
    data.update(overrides)
    return data


def _render(**overrides):
    with tempfile.TemporaryDirectory() as d:
        src, out = Path(d) / "r-drift.json", Path(d) / "r-drift.html"
        src.write_text(json.dumps(_report(**overrides)))
        generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
        return out.read_text()


class HtmlReportRenderTests(unittest.TestCase):
    def test_renders_valid_shell(self):
        h = _render()
        self.assertIn("<!DOCTYPE html>", h)
        self.assertIn("</html>", h)
        self.assertIn("<style>", h)
        self.assertIn("</style>", h)

    def test_drift_names_and_types_present(self):
        h = _render()
        for expected in ("nsg-drift-test", "keyvault-cannotdelete", "stunmanaged"):
            self.assertIn(expected, h)

    def test_critical_property_drift_rendered(self):
        h = _render()
        self.assertIn("properties.securityRules", h)
        self.assertIn("critical", h.lower())

    def test_agent_analysis_rendered(self):
        # The consolidated remediation narrative is now the report's remediation
        # content. (298ed60 had removed it as duplicating the per-drift
        # recommendation cards; those cards are gone - the narrative is ONE call
        # that sees every drift, so it can order the work and say "investigate
        # before overwriting", which N blind per-resource calls could not.)
        h = _render()
        self.assertIn("Remediation Analysis", h)
        self.assertIn("Three drifts found.", h)

    def test_per_drift_recommendation_cards_are_gone(self):
        # The old O(N)-call cards. Pinned so the fan-out is not reintroduced.
        self.assertNotIn('class="recommendation-item"', _render())

    def test_analysis_markdown_is_rendered_not_raw(self):
        h = _render(agent_analysis="## Plan\n\n| Order | Action |\n|---|---|\n| 1 | Redeploy |")
        self.assertIn("<table>", h)
        self.assertIn("<h2>Plan</h2>", h)
        self.assertNotIn("|---|---|", h)

    def test_analysis_cannot_inject_markup(self):
        # The narrative is model output quoting live resource names.
        h = _render(agent_analysis="## Plan\n\n<script>alert(1)</script> and <img src=x onerror=y>")
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertNotIn("<img src=x", h)
        self.assertIn("&lt;script&gt;", h)

    def test_no_analysis_section_when_absent(self):
        self.assertNotIn("Remediation Analysis", _render(agent_analysis=None))

    def test_agent_usage_footer_shows_cost(self):
        h = _render()
        self.assertIn("claude-opus-4-8", h)
        self.assertIn("0.11", h)

    def test_usage_footer_absent_when_no_usage(self):
        h = _render(agent_usage=None)
        self.assertNotIn("claude-opus-4-8", h)

    def test_policy_enforced_section_rendered(self):
        self.assertIn("Deploy diagnostics", _render())

    def test_smart_matched_section_rendered(self):
        h = _render()
        self.assertIn("kvdrift[86c9cbf6]", h)

    def test_owner_badges_rendered(self):
        h = _render()
        self.assertIn("platform", h)
        self.assertIn("workload", h)

    def test_clean_report_renders(self):
        h = _render(drifts=[], drift_count=0, property_drifts=[],
                    policy_enforced_drifts=[], smart_matched=[], agent_analysis=None)
        self.assertIn("<!DOCTYPE html>", h)
        self.assertIn("rg-drift-test", h)

    def test_html_escaping_of_hostile_names(self):
        # A resource name must never break out into markup.
        h = _render(drifts=[{"type": "microsoft.storage/storageaccounts",
                             "name": "<script>alert(1)</script>",
                             "drift_type": "extra_in_azure", "details": {}}])
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;", h)


class ReportCssTests(unittest.TestCase):
    """The CSS was extracted from an f-string, where all 168 of its braces had
    to be doubled. Pin that it is now literal, static CSS."""

    def test_css_is_a_plain_static_string(self):
        self.assertIsInstance(_REPORT_CSS, str)
        self.assertGreater(len(_REPORT_CSS), 1000)

    def test_css_braces_are_literal_not_doubled(self):
        self.assertNotIn("{{", _REPORT_CSS)
        self.assertNotIn("}}", _REPORT_CSS)
        self.assertIn("box-sizing: border-box;", _REPORT_CSS)

    def test_css_has_no_interpolation_placeholders(self):
        # Static CSS: no leftover {name} that an f-string would have filled.
        self.assertEqual(re.findall(r"(?<!\{)\{[a-z_]+\}(?!\})", _REPORT_CSS), [])

    def test_css_is_embedded_verbatim_in_output(self):
        self.assertIn(_REPORT_CSS, _render())


if __name__ == "__main__":
    unittest.main()
