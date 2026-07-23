"""
Unit tests for digest-style notifications.

Channel messages used to be one POST per drift, each carrying the full Claude
recommendation (~1KB of markdown) - unreadable at any real drift count. The
default is now ONE digest per team per run: GitHub-summary-style lines plus a
link to the report; recommendations stay in the report.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.send_notifications import (
    DIGEST_MAX_LINES,
    DriftEvent,
    NotificationRouter,
    build_digest,
    events_from_report,
)


def _event(name, event_type="MISSING", details="in Bicep but not deployed", severity=""):
    return DriftEvent(event_type=event_type, resource_type="Microsoft.Web/sites",
                      resource_name=name, details=details, severity=severity)


class BuildDigestTests(unittest.TestCase):
    def test_summary_style_lines_and_report_link(self):
        events = [
            _event("app1"),
            _event("acr1", "DRIFT", "properties differ: properties.adminUserEnabled", "critical"),
        ]
        msg = build_digest(events, {"report_url": "https://gh/run/1"})
        self.assertIn("*Bicep Drift Detected* — 2 issue(s) (1 critical)", msg)
        self.assertIn("• [MISSING] Microsoft.Web/sites/app1 — in Bicep but not deployed", msg)
        self.assertIn("• [DRIFT] Microsoft.Web/sites/acr1 — properties differ: properties.adminUserEnabled", msg)
        self.assertIn("*Report:* https://gh/run/1", msg)

    def test_caps_lines_and_points_at_report(self):
        events = [_event(f"res{i}") for i in range(DIGEST_MAX_LINES + 7)]
        msg = build_digest(events, {"report_url": "u"})
        self.assertEqual(msg.count("• ["), DIGEST_MAX_LINES)
        self.assertIn("and 7 more — see the report", msg)

    def test_multiline_details_take_first_line_only(self):
        events = [_event("app1", details="line one\nline two\nline three")]
        msg = build_digest(events, {})
        self.assertIn("line one", msg)
        self.assertNotIn("line two", msg)

    def test_teams_platform_uses_double_asterisk_bold(self):
        msg = build_digest([_event("a")], {"report_url": "u"}, platform="teams")
        self.assertIn("**Bicep Drift Detected**", msg)

    def test_teams_platform_uses_blank_line_breaks(self):
        # Teams markdown collapses single newlines into one paragraph.
        msg = build_digest([_event("a"), _event("b")], {"report_url": "u"}, platform="teams")
        self.assertNotIn("\n•", msg.replace("\n\n", ""))
        self.assertEqual(msg.count("\n\n"), 3)  # header|line|line|footer

    def test_slack_platform_uses_single_newlines(self):
        msg = build_digest([_event("a"), _event("b")], {"report_url": "u"}, platform="slack")
        self.assertNotIn("\n\n", msg)
        self.assertEqual(msg.count("\n"), 3)

    def test_no_report_url_omits_footer(self):
        msg = build_digest([_event("a")], {})
        self.assertNotIn("Report:", msg)


class EventsCarryNoRecommendationTests(unittest.TestCase):
    def test_recommendation_not_in_event_details(self):
        report = {"drifts": [{
            "type": "Microsoft.Authorization/locks",
            "name": "keyvault-cannotdelete",
            "drift_type": "missing_in_azure",
            "details": {},
            "recommendation": "## Remediation\n```bash\naz lock create ...\n```",
        }]}
        with tempfile.NamedTemporaryFile("w", suffix="-drift.json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            events = events_from_report(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(events), 1)
        self.assertNotIn("Remediation", events[0].details)
        self.assertNotIn("💡", events[0].details)


class RouterDigestTests(unittest.TestCase):
    def _router(self, teams):
        with mock.patch.dict(os.environ, {"DRIFT_NOTIFICATIONS": json.dumps(teams)}, clear=False):
            return NotificationRouter()

    def test_default_team_sends_one_digest(self):
        router = self._router({"team": {"slack": "https://hooks.slack/z"}})
        sent = []
        with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append(m) or True):
            router.send_notifications([_event(f"r{i}") for i in range(5)],
                                      {"report_url": "https://gh/run/9"})
        self.assertEqual(len(sent), 1)
        self.assertIn("5 issue(s)", sent[0])
        self.assertIn("https://gh/run/9", sent[0])

    def test_custom_template_keeps_per_event_messages(self):
        router = self._router({"team": {
            "slack": "https://hooks.slack/z",
            "template": "custom: {{ resource_name }}",
        }})
        sent = []
        with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append(m) or True):
            router.send_notifications([_event("a"), _event("b")], {})
        self.assertEqual(sent, ["custom: a", "custom: b"])

    def test_legacy_webhook_sends_digest(self):
        # The legacy path used to pass (url, event, context) into a two-argument
        # sender - a TypeError on any run that reached it.
        with mock.patch.dict(os.environ,
                             {"SLACK_WEBHOOK_URL": "https://hooks.slack/legacy",
                              "DRIFT_NOTIFICATIONS": ""}, clear=False):
            router = NotificationRouter()
        sent = []
        with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append((u, m)) or True):
            ok = router.send_notifications([_event("a"), _event("b")], {"report_url": "u"})
        self.assertTrue(ok)
        self.assertEqual(len(sent), 1)
        self.assertIn("2 issue(s)", sent[0][1])


if __name__ == "__main__":
    unittest.main()
