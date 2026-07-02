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


if __name__ == "__main__":
    unittest.main()
