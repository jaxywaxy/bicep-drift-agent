"""
RISK severity is computed on every scan and reaches the report.

Live 2026-08-09: a standing subscription-scope Owner grant, absent from Bicep,
rendered as a grey "Unknown" badge. DriftClassifier rated that same row HIGH -
but the classifier was reachable only through DriftAgent, so its verdict went
into the LLM prompt and nowhere else, and a scan with no provider never
computed it at all. The only severity on the row was change_origin's MEDIUM,
which is a statement about ATTRIBUTION CONFIDENCE ("the Activity Log was
silent"), not about risk.

The two must stay separate and the provenance one must never soften the risk
one - that conflation is the #343 shape.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.analysis import classify_drifts
from tools.html_report import _get_severity_badge

SUB = "/subscriptions/bd48a22c-91b9-46e6-a2ff-15893e348d83"

# change_origin as the pipeline builds it when the Activity Log has nothing:
# MEDIUM because we cannot say who, not because it is a medium problem.
UNATTRIBUTED = {
    "origin": "unknown",
    "category": "unknown",
    "severity": "medium",
    "expected": False,
    "reason": "No activity log entries found (logs may have expired)",
}

OWNER_GRANT = {
    "type": "Microsoft.Authorization/roleAssignments",
    "name": "Owner -> User:70afebf7-5bdd-45d9-9cfc-534af9a95589",
    "drift_type": "extra_in_azure",
    "details": {
        "role_name": "Owner",
        "principal_type": "User",
        "scope": SUB,
        "privileged": True,
        "assignment_id": f"{SUB}/providers/Microsoft.Authorization/RoleAssignments/79565f05",
    },
    "change_origin": dict(UNATTRIBUTED),
}


def report_with(*drifts):
    return {
        "bicep_file": "main.bicep",
        "resource_group": "subscription",
        "drifts": [dict(d) for d in drifts],
        "live_resources": [],
    }


class ClassificationIsUnconditionalTests(unittest.TestCase):
    """classify_drifts takes no agent and no provider - that IS the fix. These
    pin that it works on a bare report dict, which is what a scan with no LLM
    configured has."""

    def test_a_privileged_owner_grant_is_high_not_medium(self):
        report = report_with(OWNER_GRANT)
        classify_drifts(report)
        self.assertEqual(report["drifts"][0]["severity"], "high")

    def test_provenance_severity_is_left_alone(self):
        """Both survive, in their own fields. Folding one into the other is how
        'we could not attribute it' becomes 'it matters less'."""
        report = report_with(OWNER_GRANT)
        classify_drifts(report)
        row = report["drifts"][0]
        self.assertEqual(row["change_origin"]["severity"], "medium")
        self.assertEqual(row["severity"], "high")

    def test_a_category_is_stamped_too(self):
        report = report_with(OWNER_GRANT)
        classify_drifts(report)
        self.assertEqual(report["drifts"][0]["category"], "unmanaged_resource")

    def test_every_row_is_stamped_and_rows_are_not_reordered(self):
        """_build_findings SORTS by severity; classify_drifts zips rows to
        drifts positionally, so it must not."""
        missing_rg = {"type": "Microsoft.Resources/resourceGroups",
                      "name": "jacquidev-rg-apps", "drift_type": "missing_in_azure",
                      "details": {}, "change_origin": dict(UNATTRIBUTED)}
        report = report_with(missing_rg, OWNER_GRANT)
        classify_drifts(report)
        self.assertEqual([r["name"] for r in report["drifts"]],
                         ["jacquidev-rg-apps", OWNER_GRANT["name"]])
        self.assertTrue(all(r.get("severity") for r in report["drifts"]))

    def test_an_empty_report_is_not_an_error(self):
        report = report_with()
        classify_drifts(report)
        self.assertEqual(report["drifts"], [])


class ClassificationIsWiredIntoTheDeterministicPathTests(unittest.TestCase):
    """The unit tests above call classify_drifts directly, so they would all
    still pass if nothing in the pipeline called it - which is the exact bug
    being fixed (a classifier nobody reached). Pin the wiring at its site, the
    way test_agent_availability pins the provider seam.
    """

    def _main_source(self):
        import pathlib
        src = pathlib.Path("analyze_drift.py").read_text(encoding="utf-8")
        return src[src.index("def main("):]

    def test_main_classifies_every_run(self):
        self.assertIn("classify_drifts(report_data)", self._main_source())

    def test_it_runs_outside_the_provider_branch(self):
        """It must not sit behind `if agent:` - a scan with no LLM still needs
        severities."""
        src = self._main_source()
        call = src.index("classify_drifts(report_data)")
        line_start = src.rindex("\n", 0, call) + 1
        indent = len(src[line_start:call]) - len(src[line_start:call].lstrip())
        self.assertLessEqual(
            indent, 8,
            "classify_drifts is nested inside a conditional; it must be unconditional")

    def test_it_runs_after_attribution_and_before_the_analysis(self):
        """Order matters both ways: _honour_attribution reads change_origin, and
        the agent's prompt should see the same severities the report keeps."""
        src = self._main_source()
        self.assertLess(src.index("_attribute_lifecycle(report_data"),
                        src.index("classify_drifts(report_data)"))
        self.assertLess(src.index("classify_drifts(report_data)"),
                        src.index("_run_claude_analysis(agent"))


class SeverityReachesTheHtmlTests(unittest.TestCase):
    def test_a_high_row_renders_as_high(self):
        badge = _get_severity_badge("high")
        self.assertIn("severity-high", badge)
        self.assertIn("High", badge)

    def test_an_unclassified_row_does_not_claim_a_severity(self):
        """A row from an older report has no severity key. It must render as a
        dash, not silently as 'informational' or 'critical'."""
        badge = _get_severity_badge(None)
        self.assertIn("severity-unknown", badge)
        self.assertNotIn("severity-critical", badge)

    def test_the_owner_grant_is_no_longer_only_a_grey_unknown(self):
        """The end-to-end point of the change: classify, render, and the row
        carries a red HIGH chip even though its origin badge stays Unknown."""
        from tools.html_report import _get_origin_badge
        report = report_with(OWNER_GRANT)
        classify_drifts(report)
        row = report["drifts"][0]
        self.assertIn("origin-unknown", _get_origin_badge(row["change_origin"]),
                      "origin is genuinely unknown - that part was correct")
        self.assertIn("severity-high", _get_severity_badge(row.get("severity")))


if __name__ == "__main__":
    unittest.main()
