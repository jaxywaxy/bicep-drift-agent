"""
Unit tests for the landing-zone drift issue publisher.

Workload teams can't read the drift-agent repo, so the Actions-run link in
their notifications was a 404. The run now publishes a rolling "Drift Report"
issue in the LZ repo (which workload teams CAN read): created/updated while
drift exists, closed with a comment when a scan comes back clean. The issue
carries the digest lines plus the per-resource recommendations that no longer
go to chat.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import publish_lz_issue as pli
from tools.send_notifications import DriftEvent, NotificationRouter


def _write_report(directory, rg="rg-app", drifts=None, analysis=None):
    report = {"resource_group": rg, "drifts": drifts if drifts is not None else []}
    if analysis is not None:
        report["agent_analysis"] = analysis
    path = os.path.join(directory, f"{rg}-drift.json")
    with open(path, "w") as f:
        json.dump(report, f)
    return path


def _drift(name="app1", rec=None, owner="workload"):
    d = {
        "type": "Microsoft.Web/sites",
        "name": name,
        "drift_type": "missing_in_azure",
        "details": {},
        "owner": owner,
    }
    if rec:
        d["recommendation"] = rec
    return d


class BuildIssueBodyTests(unittest.TestCase):
    def test_body_contains_marker_digest_and_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            _write_report(d, drifts=[_drift()],
                          analysis="## Remediation Plan\n\n| Order | Action |\n|---|---|\n| 1 | Redeploy |")
            body, total = pli.build_issue_body(d, "test-resources", "https://gh/run/1")
        self.assertEqual(total, 1)
        self.assertIn(pli.ISSUE_MARKER, body)
        self.assertIn("drift-report:test-resources", body)
        self.assertIn("**[MISSING]** `Microsoft.Web/sites/app1`", body)
        self.assertIn("_(owner: workload)_", body)
        self.assertIn("[workflow run](https://gh/run/1)", body)
        self.assertIn("Remediation Analysis", body)
        self.assertIn("<details>", body)
        # GitHub renders markdown natively - the table must be passed through
        # verbatim, NOT converted (unlike the HTML report).
        self.assertIn("| Order | Action |", body)

    def test_analysis_section_absent_when_no_analysis(self):
        # e.g. no API key, or the Claude call failed (non-fatal).
        with tempfile.TemporaryDirectory() as d:
            _write_report(d, drifts=[_drift()])
            body, total = pli.build_issue_body(d, "lz", "u")
        self.assertEqual(total, 1)
        self.assertNotIn("Remediation Analysis", body)
        self.assertIn("**[MISSING]**", body)  # the drift list still renders

    def test_matched_unresolvable_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            _write_report(d, drifts=[
                {"type": "t", "name": "reconciled", "drift_type": "matched_unresolvable",
                 "details": {}},
            ], analysis="should not appear")
            body, total = pli.build_issue_body(d, "lz", "u")
        self.assertEqual(total, 0)
        # No actionable drift -> no section for this RG at all.
        self.assertNotIn("should not appear", body)

    def test_multiple_rgs_get_sections(self):
        with tempfile.TemporaryDirectory() as d:
            _write_report(d, rg="rg-one", drifts=[_drift("a")])
            _write_report(d, rg="rg-two", drifts=[_drift("b")])
            body, total = pli.build_issue_body(d, "lz", "u")
        self.assertEqual(total, 2)
        self.assertIn("### `rg-one`", body)
        self.assertIn("### `rg-two`", body)


class PublishFlowTests(unittest.TestCase):
    def _publish(self, drifts, api_responses):
        """Run publish() with mocked API. api_responses: list of (status, json)."""
        calls = []

        def fake_api(method, url, token, payload=None):
            calls.append((method, url, payload))
            return api_responses[min(len(calls) - 1, len(api_responses) - 1)]

        with tempfile.TemporaryDirectory() as d:
            _write_report(d, drifts=drifts)
            with mock.patch.object(pli, "_api_request", side_effect=fake_api):
                url = pli.publish(d, "org/lz-repo", "lz", "https://gh/run/1", "tok")
        return url, calls

    def test_drift_creates_issue_when_none_open(self):
        url, calls = self._publish(
            [_drift()],
            [(200, []),  # list open issues -> none
             (201, {"number": 7, "html_url": "https://gh/org/lz-repo/issues/7"})],
        )
        self.assertEqual(url, "https://gh/org/lz-repo/issues/7")
        self.assertEqual(calls[1][0], "POST")
        self.assertIn("/repos/org/lz-repo/issues", calls[1][1])

    def test_drift_updates_existing_issue(self):
        existing = {"number": 7, "html_url": "https://gh/i/7",
                    "body": f"{pli.ISSUE_MARKER}\n<!-- drift-report:lz -->"}
        url, calls = self._publish(
            [_drift()],
            [(200, [existing]),
             (200, {"number": 7, "html_url": "https://gh/i/7"})],
        )
        self.assertEqual(url, "https://gh/i/7")
        self.assertEqual(calls[1][0], "PATCH")

    def test_clean_scan_closes_open_issue(self):
        existing = {"number": 7, "html_url": "https://gh/i/7",
                    "body": f"{pli.ISSUE_MARKER}\n<!-- drift-report:lz -->"}
        url, calls = self._publish(
            [],
            [(200, [existing]), (201, {}), (200, {})],
        )
        self.assertEqual(url, "")
        methods = [(c[0], c[1].split("/")[-1]) for c in calls]
        self.assertIn(("POST", "comments"), methods)   # resolution comment
        self.assertEqual(calls[-1][2].get("state"), "closed")

    def test_clean_scan_no_issue_is_noop(self):
        url, calls = self._publish([], [(200, [])])
        self.assertEqual(url, "")
        self.assertEqual(len(calls), 1)  # only the lookup

    def test_permission_denied_returns_empty_not_raise(self):
        url, _ = self._publish([_drift()], [(200, []), (403, None)])
        self.assertEqual(url, "")

    def test_other_lz_issue_not_matched(self):
        other = {"number": 3, "html_url": "https://gh/i/3",
                 "body": f"{pli.ISSUE_MARKER}\n<!-- drift-report:OTHER-lz -->"}
        url, calls = self._publish(
            [_drift()],
            [(200, [other]),
             (201, {"number": 8, "html_url": "https://gh/i/8"})],
        )
        self.assertEqual(url, "https://gh/i/8")  # created new, didn't touch #3
        self.assertEqual(calls[1][0], "POST")


class WorkloadLinkRoutingTests(unittest.TestCase):
    """Every team links to the LZ issue when one exists (it carries the run
    link for platform folks); the Actions run is the fallback."""

    def _events(self):
        return [DriftEvent(event_type="MISSING", resource_type="Microsoft.Web/sites",
                           resource_name="app1", details="", owner="workload"),
                DriftEvent(event_type="MISSING", resource_type="Microsoft.Network/virtualNetworks",
                           resource_name="vnet1", details="", owner="platform")]

    def _sent(self, teams, context):
        with mock.patch.dict(os.environ, {"DRIFT_NOTIFICATIONS": json.dumps(teams)}, clear=False):
            router = NotificationRouter()
        sent = []
        with mock.patch.object(router, "_send_to_slack",
                               side_effect=lambda u, m: sent.append((u, m)) or True):
            router.send_notifications(self._events(), context)
        return dict(sent)

    def test_all_teams_get_issue_url_when_published(self):
        sent = self._sent(
            {"app-team": {"slack": "https://hooks/w", "owners": ["workload"]},
             "platform-team": {"slack": "https://hooks/p", "owners": ["platform"]}},
            {"report_url": "https://gh/run/1", "issue_url": "https://gh/lz/issues/7"},
        )
        self.assertIn("https://gh/lz/issues/7", sent["https://hooks/w"])
        self.assertNotIn("https://gh/run/1", sent["https://hooks/w"])
        self.assertIn("https://gh/lz/issues/7", sent["https://hooks/p"])

    def test_no_issue_url_leaves_run_link(self):
        sent = self._sent(
            {"app-team": {"slack": "https://hooks/w", "owners": ["workload"]}},
            {"report_url": "https://gh/run/1", "issue_url": ""},
        )
        self.assertIn("https://gh/run/1", sent["https://hooks/w"])

    def test_unrouted_team_gets_issue_link(self):
        # The live case: the flat single-channel config (no owners key) must
        # link to the issue too.
        sent = self._sent(
            {"everything": {"slack": "https://hooks/all"}},
            {"report_url": "https://gh/run/1", "issue_url": "https://gh/lz/issues/7"},
        )
        self.assertIn("https://gh/lz/issues/7", sent["https://hooks/all"])

    def test_custom_template_can_use_run_url(self):
        with mock.patch.dict(os.environ, {"DRIFT_NOTIFICATIONS": json.dumps(
            {"t": {"slack": "https://hooks/t",
                   "template": "{{ report_url }} | {{ run_url }}"}}
        )}, clear=False):
            router = NotificationRouter()
        sent = []
        with mock.patch.object(router, "_send_to_slack",
                               side_effect=lambda u, m: sent.append(m) or True):
            router.send_notifications(self._events()[:1],
                                      {"report_url": "https://gh/run/1",
                                       "issue_url": "https://gh/lz/issues/7"})
        self.assertEqual(sent[0], "https://gh/lz/issues/7 | https://gh/run/1")


if __name__ == "__main__":
    unittest.main()
