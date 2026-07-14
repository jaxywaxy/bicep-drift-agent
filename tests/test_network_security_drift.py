"""
Regression tests from the NSG/route-table live round.

Three injected network drifts (allow-RDP-anywhere rule added, deny-SSH rule
flipped to Allow, default route next-hop moved off the firewall appliance)
were initially invisible: the LZ's stale platform-fabric ignore swallowed the
records (LZ-repo fix) and, once visible, rated only 'warning'. A transient
policy-fetch failure also fabricated a missing policy assignment.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator, DriftDetector
import tools.policy as policy


def _nsg(rules):
    return {
        "type": "Microsoft.Network/networkSecurityGroups",
        "name": "nsg-drift-test",
        "properties": {"securityRules": rules},
    }


def _rule(name, access="Allow", port="443", extra_live_fields=False):
    rule = {"name": name, "properties": {
        "priority": 100, "direction": "Inbound", "access": access,
        "protocol": "Tcp", "sourcePortRange": "*", "destinationPortRange": port,
        "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "*",
    }}
    if extra_live_fields:
        rule["etag"] = "W/\"x\""
        rule["id"] = "/subscriptions/s/…/securityRules/" + name
        rule["type"] = "Microsoft.Network/networkSecurityGroups/securityRules"
        rule["properties"]["provisioningState"] = "Succeeded"
    return rule


class NsgRuleDriftTests(unittest.TestCase):
    def test_identical_rules_with_live_augmentation_no_drift(self):
        bicep = _nsg([_rule("a"), _rule("b", access="Deny", port="22")])
        live = _nsg([_rule("a", extra_live_fields=True),
                     _rule("b", access="Deny", port="22", extra_live_fields=True)])
        diffs = PropertyComparator.compare_properties(bicep, live)
        self.assertNotIn("properties.securityRules",
                         [d.property_path for d in diffs])

    def test_live_added_rule_is_critical_drift(self):
        # The classic unauthorized change: allow-RDP-anywhere added out-of-band.
        bicep = _nsg([_rule("a")])
        live = _nsg([_rule("a", extra_live_fields=True),
                     _rule("allow-rdp-anywhere", port="3389", extra_live_fields=True)])
        diffs = [d for d in PropertyComparator.compare_properties(bicep, live)
                 if d.property_path == "properties.securityRules"]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].severity, "critical")

    def test_rule_access_flip_is_critical_drift(self):
        # deny-ssh-from-internet flipped Deny -> Allow out-of-band.
        bicep = _nsg([_rule("ssh", access="Deny", port="22")])
        live = _nsg([_rule("ssh", access="Allow", port="22", extra_live_fields=True)])
        diffs = [d for d in PropertyComparator.compare_properties(bicep, live)
                 if d.property_path == "properties.securityRules"]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].severity, "critical")

    def test_route_next_hop_flip_is_critical_drift(self):
        # 0.0.0.0/0 moved off the firewall appliance = inspection bypass.
        def rt(next_hop, ip=None):
            props = {"addressPrefix": "0.0.0.0/0", "nextHopType": next_hop}
            if ip:
                props["nextHopIpAddress"] = ip
            return {"type": "Microsoft.Network/routeTables", "name": "rt",
                    "properties": {"disableBgpRoutePropagation": True,
                                   "routes": [{"name": "default", "properties": props}]}}
        diffs = [d for d in PropertyComparator.compare_properties(
                     rt("VirtualAppliance", "10.99.0.62"), rt("Internet"))
                 if d.property_path == "properties.routes"]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].severity, "critical")

    def test_detector_end_to_end(self):
        bicep = [_nsg([_rule("a")])]
        live = [_nsg([_rule("a", extra_live_fields=True),
                      _rule("added", extra_live_fields=True)])]
        drifts = DriftDetector.detect_drift(bicep, live)
        modified = [d for d in drifts if d.drift_type == "modified"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0].resource_name, "nsg-drift-test")


class PolicyFetchFailureTests(unittest.TestCase):
    """A failed policy fetch must RAISE (after one retry), never return ([], []) -
    the empty result is indistinguishable from 'no live assignments' and
    fabricated a missing_in_azure for every declared assignment (seen live)."""

    def _client(self, side_effects):
        client = mock.MagicMock()
        client.resources.side_effect = side_effects
        return client

    def _run(self, side_effects):
        fake = mock.MagicMock()
        fake.ResourceGraphClient.return_value = self._client(side_effects)
        modules = {
            "azure.identity": mock.MagicMock(),
            "azure.mgmt.resourcegraph": fake,
            "azure.mgmt.resourcegraph.models": mock.MagicMock(),
        }
        with mock.patch.dict(sys.modules, modules):
            return policy.fetch_policy_resources("sub-id", "rg-x", credential=mock.MagicMock())

    def test_transient_failure_retries_and_succeeds(self):
        ok = mock.MagicMock(data=[], skip_token=None)
        assignments, exemptions = self._run(
            [ConnectionResetError("peer"), ok, ok])
        self.assertEqual((assignments, exemptions), ([], []))

    def test_persistent_failure_raises(self):
        with self.assertRaises(ConnectionResetError):
            self._run([ConnectionResetError("peer"), ConnectionResetError("peer")])


if __name__ == "__main__":
    unittest.main()
