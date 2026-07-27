"""Collectors for the two types issue #329 left invisible.

Both were suppressed by .drift-ignore rules standing in for a COLLECTION gap:
Resource Graph indexes neither, so a declared instance reported missing forever.
Suppressing the false positive also suppressed the real thing.

`token="t"` carries `# nosec B106` (hardcoded_password_funcarg), matching
tests/test_retry_wiring.py. It is not a credential: these collectors accept a
PRE-ACQUIRED ARM token so one can be shared across them, and passing a dummy
is precisely what keeps these tests off DefaultAzureCredential. The transport
is faked - nothing authenticates and no value here reaches a real endpoint.
"""

import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.live_state.collectors.private_dns import (
    _shape_zone_group, query_private_dns_zone_groups)
from tools.live_state.collectors.workspace_tables import (
    _declared_table_leaves, _shape_table, fetch_declared_workspace_tables)
from tools.property_drift import PropertyComparator

SUB = "/subscriptions/s/resourceGroups/rg"
PE = {"type": "Microsoft.Network/privateEndpoints", "name": "pe-kv",
      "id": f"{SUB}/providers/Microsoft.Network/privateEndpoints/pe-kv",
      "resource_group": "rg"}
WS = {"type": "Microsoft.OperationalInsights/workspaces", "name": "log-real",
      "id": f"{SUB}/providers/Microsoft.OperationalInsights/workspaces/log-real",
      "resource_group": "rg"}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        import json
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _urlopen_returning(by_url):
    """Fake arm_urlopen: dict of url-substring -> payload, or an HTTPError."""
    def _fake(req, timeout=30):
        url = req.full_url
        for frag, payload in by_url.items():
            if frag in url:
                if isinstance(payload, Exception):
                    raise payload
                return _FakeResponse(payload)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    return _fake


class ZoneGroupShapeTests(unittest.TestCase):
    def test_named_to_match_the_bicep_child(self):
        shaped = _shape_zone_group("pe-kv", "rg", {
            "name": "default", "id": "/x",
            "properties": {"privateDnsZoneConfigs": [{"name": "vaultcore"}]}})
        self.assertEqual(shaped["name"], "pe-kv/default")
        self.assertEqual(shaped["type"],
                         "Microsoft.Network/privateEndpoints/privateDnsZoneGroups")
        self.assertEqual(shaped["properties"]["privateDnsZoneConfigs"][0]["name"], "vaultcore")


class ZoneGroupCollectorTests(unittest.TestCase):
    def test_groups_are_fetched_per_private_endpoint(self):
        payload = {"value": [{"name": "default", "id": "/g",
                              "properties": {"privateDnsZoneConfigs": [{"name": "vaultcore"}]}}]}
        with mock.patch("tools.live_state.collectors.private_dns.arm_urlopen",
                        _urlopen_returning({"privateDnsZoneGroups": payload})):
            out = query_private_dns_zone_groups([PE, WS], "s", token="t")  # nosec B106
        self.assertEqual([r["name"] for r in out], ["pe-kv/default"])

    def test_no_private_endpoints_means_no_calls(self):
        # Guard against a collector that authenticates or calls ARM for nothing.
        with mock.patch("tools.live_state.collectors.private_dns.arm_urlopen") as m:
            self.assertEqual(query_private_dns_zone_groups([WS], "s", token="t"), [])  # nosec B106
        m.assert_not_called()

    def test_a_failing_endpoint_does_not_sink_the_others(self):
        good = {"value": [{"name": "default", "id": "/g", "properties": {}}]}
        pe2 = {**PE, "name": "pe-two",
               "id": f"{SUB}/providers/Microsoft.Network/privateEndpoints/pe-two"}
        with mock.patch("tools.live_state.collectors.private_dns.arm_urlopen",
                        _urlopen_returning({"pe-kv": RuntimeError("boom"), "pe-two": good})):
            out = query_private_dns_zone_groups([PE, pe2], "s", token="t")  # nosec B106
        self.assertEqual([r["name"] for r in out], ["pe-two/default"])


class DeclaredTableSelectionTests(unittest.TestCase):
    """Bicep-driven on purpose: the workspace carries the whole built-in
    catalogue (679 tables / 2.8 MB on the drift-test workspace), and listing it
    to keep one row would bloat every report artifact."""

    def test_leaves_are_taken_from_the_placeholder_parent(self):
        # The declared parent is a uniqueString() placeholder, so only the leaf
        # is usable for matching.
        leaves = _declared_table_leaves([
            {"type": "Microsoft.OperationalInsights/workspaces/tables",
             "name": "log-[86c9cbf6]/CustomLog_CL"},
            {"type": "Microsoft.OperationalInsights/workspaces", "name": "log-[86c9cbf6]"},
        ])
        self.assertEqual(leaves, {"CustomLog_CL"})

    def test_nothing_declared_means_no_calls(self):
        with mock.patch("tools.live_state.collectors.workspace_tables.arm_urlopen") as m:
            self.assertEqual(fetch_declared_workspace_tables([], [WS], token="t"), [])  # nosec B106
        m.assert_not_called()

    def test_only_the_declared_table_is_requested(self):
        seen = []

        def _fake(req, timeout=30):
            seen.append(req.full_url)
            return _FakeResponse({"name": "CustomLog_CL", "id": "/t",
                                  "properties": {"totalRetentionInDays": 30}})

        arm = [{"type": "Microsoft.OperationalInsights/workspaces/tables",
                "name": "log-[86c9cbf6]/CustomLog_CL"}]
        with mock.patch("tools.live_state.collectors.workspace_tables.arm_urlopen", _fake):
            out = fetch_declared_workspace_tables(arm, [WS], token="t")  # nosec B106
        self.assertEqual(len(seen), 1, "one GET per declared table, not a list call")
        self.assertIn("/tables/CustomLog_CL", seen[0])
        self.assertEqual(out[0]["name"], "log-real/CustomLog_CL")

    def test_a_builtin_table_can_be_declared(self):
        # Setting retention on Heartbeat is a normal pattern, so this must not
        # filter to custom '_CL' tables.
        self.assertEqual(
            _declared_table_leaves([{
                "type": "Microsoft.OperationalInsights/workspaces/tables",
                "name": "log-[86c9cbf6]/Heartbeat"}]),
            {"Heartbeat"})


class MissingTableIsAbsentNotAnErrorTests(unittest.TestCase):
    def test_404_yields_no_row(self):
        # A declared table that does not exist must stay ABSENT from live state
        # so the diff reports missing_in_azure. That is the detection #329 was
        # opened to restore, and it is the whole reason 404 is handled apart
        # from other errors.
        arm = [{"type": "Microsoft.OperationalInsights/workspaces/tables",
                "name": "log-[86c9cbf6]/GoneTable"}]
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch("tools.live_state.collectors.workspace_tables.arm_urlopen",
                        _urlopen_returning({"GoneTable": err})):
            with self.assertLogs("tools.live_state.collectors.workspace_tables",
                                 level="WARNING") as logs:
                out = fetch_declared_workspace_tables(arm, [WS], token="t")  # nosec B106
                # assertLogs demands at least one record; the INFO summary is
                # not one, so emit a sentinel to keep the assertion honest.
                import logging
                logging.getLogger(
                    "tools.live_state.collectors.workspace_tables").warning("sentinel")
        self.assertEqual(out, [])
        self.assertEqual([r for r in logs.output if "GoneTable" in r], [],
                         "404 is the answer, not a failure - must not warn")

    def test_a_real_error_still_warns(self):
        arm = [{"type": "Microsoft.OperationalInsights/workspaces/tables",
                "name": "log-[86c9cbf6]/CustomLog_CL"}]
        err = urllib.error.HTTPError("u", 500, "Server Error", {}, None)
        with mock.patch("tools.live_state.collectors.workspace_tables.arm_urlopen",
                        _urlopen_returning({"CustomLog_CL": err})):
            with self.assertLogs("tools.live_state.collectors.workspace_tables",
                                 level="WARNING") as logs:
                out = fetch_declared_workspace_tables(arm, [WS], token="t")  # nosec B106
        self.assertEqual(out, [])
        self.assertTrue(any("CustomLog_CL" in r for r in logs.output),
                        "a 500 is a failure and must be logged with context")


class SeverityTests(unittest.TestCase):
    def _sev(self, rtype, bicep_props, live_props):
        diffs = PropertyComparator.compare_properties(
            {"type": rtype, "name": "n", "properties": bicep_props},
            {"type": rtype, "name": "n", "properties": live_props})
        return {d.property_path: d.severity for d in diffs}

    def test_zone_group_config_change_is_critical(self):
        # Repointing privateDnsZoneId sends Private Link traffic to the public
        # endpoint with no error anywhere.
        sev = self._sev(
            "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
            {"privateDnsZoneConfigs": [{"name": "vaultcore", "properties": {
                "privateDnsZoneId": "/zones/right"}}]},
            {"privateDnsZoneConfigs": [{"name": "vaultcore", "properties": {
                "privateDnsZoneId": "/zones/WRONG"}}]})
        self.assertTrue(sev, "a repointed zone must produce a diff")
        self.assertTrue(all(v == "critical" for v in sev.values()), sev)

    def test_table_retention_cut_is_critical(self):
        sev = self._sev("Microsoft.OperationalInsights/workspaces/tables",
                        {"totalRetentionInDays": 30}, {"totalRetentionInDays": 7})
        self.assertEqual(sev.get("properties.totalRetentionInDays"), "critical")

    def test_table_plan_downgrade_is_critical(self):
        sev = self._sev("Microsoft.OperationalInsights/workspaces/tables",
                        {"plan": "Analytics"}, {"plan": "Basic"})
        self.assertEqual(sev.get("properties.plan"), "critical")

    def test_retention_on_other_types_is_not_elevated(self):
        # Type-scoped for the same reason backup retention is: retentionInDays
        # also appears on the workspace itself, on ACR retention policies and on
        # diagnostic settings, where the default warning is right.
        sev = self._sev("Microsoft.OperationalInsights/workspaces",
                        {"retentionInDays": 30}, {"retentionInDays": 7})
        self.assertNotEqual(sev.get("properties.retentionInDays"), "critical")


if __name__ == "__main__":
    unittest.main()
