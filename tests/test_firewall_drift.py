"""
Azure Firewall drift coverage: policy rule collection groups + security posture.

The firewall's rules live in ruleCollectionGroups CHILDREN of the (nearly
empty) firewallPolicies row - invisible to Resource Graph, so they need child
expansion like SQL firewallRules. And the security-posture properties (rules,
threat intel, DNS settings, IDPS) must rate CRITICAL: an out-of-band allow
rule or threatIntelMode->Off guts the firewall while it still reads healthy -
the NSG securityRules / WAF requestBodyCheck precedent.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator
from tools.get_live_state import _CHILD_EXPANSION_SPECS

RCG_TYPE = "Microsoft.Network/firewallPolicies/ruleCollectionGroups"
POLICY_TYPE = "Microsoft.Network/firewallPolicies"


def _rcg(action="Deny", port="443", priority=200):
    return {
        "type": RCG_TYPE,
        "name": "fwpol-drift/rcg-default",
        "properties": {
            "priority": priority,
            "ruleCollections": [{
                "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                "name": "net-rules",
                "priority": 200,
                "action": {"type": action},
                "rules": [{
                    "ruleType": "NetworkRule",
                    "name": "allow-https-out",
                    "ipProtocols": ["TCP"],
                    "sourceAddresses": ["10.99.0.0/24"],
                    "destinationAddresses": ["*"],
                    "destinationPorts": [port],
                }],
            }],
        },
    }


def _policy(ti_mode="Alert", proxy_enabled=False, whitelist=None):
    props = {
        "sku": {"tier": "Standard"},
        "threatIntelMode": ti_mode,
        "dnsSettings": {"enableProxy": proxy_enabled},
    }
    if whitelist is not None:
        props["threatIntelWhitelist"] = whitelist
    return {"type": POLICY_TYPE, "name": "fwpol-drift", "properties": props}


def _sev(bicep, live, path_prefix):
    for d in PropertyComparator.compare_properties(bicep, live):
        if d.property_path.startswith(path_prefix):
            return d.severity
    return None


class FirewallRuleSeverityTests(unittest.TestCase):
    def test_rule_action_flip_is_critical(self):
        self.assertEqual(
            _sev(_rcg(action="Deny"), _rcg(action="Allow"), "properties.ruleCollections"),
            "critical",
        )

    def test_rule_port_widening_is_critical(self):
        self.assertEqual(
            _sev(_rcg(port="443"), _rcg(port="*"), "properties.ruleCollections"),
            "critical",
        )

    def test_identical_rcg_is_clean(self):
        self.assertEqual(PropertyComparator.compare_properties(_rcg(), _rcg()), [])

    def test_out_of_band_added_rule_is_critical_drift(self):
        # Rules are a NAMED collection: a live-added rule the bicep never
        # declared (the classic firewall opening) must be drift, not vacuous
        # subset-match.
        live = _rcg()
        live["properties"]["ruleCollections"][0]["rules"].append({
            "ruleType": "NetworkRule",
            "name": "allow-any-any",
            "ipProtocols": ["Any"],
            "sourceAddresses": ["*"],
            "destinationAddresses": ["*"],
            "destinationPorts": ["*"],
        })
        self.assertEqual(_sev(_rcg(), live, "properties.ruleCollections"), "critical")

    def test_out_of_band_dns_server_is_critical_drift(self):
        # Plain-string list with empty bicep side: generic subset compare is
        # vacuous, exact-set semantics make the added server drift.
        bicep = _policy()
        live = _policy()
        bicep["properties"]["dnsSettings"]["servers"] = []
        live["properties"]["dnsSettings"]["servers"] = ["203.0.113.53"]
        self.assertEqual(_sev(bicep, live, "properties.dnsSettings"), "critical")


class FirewallPolicyPostureTests(unittest.TestCase):
    def test_threat_intel_off_is_critical(self):
        self.assertEqual(
            _sev(_policy(ti_mode="Alert"), _policy(ti_mode="Off"), "properties.threatIntelMode"),
            "critical",
        )

    def test_threat_intel_whitelist_addition_is_critical(self):
        self.assertEqual(
            _sev(_policy(whitelist={"ipAddresses": []}),
                 _policy(whitelist={"ipAddresses": ["203.0.113.6"]}),
                 "properties.threatIntelWhitelist"),
            "critical",
        )

    def test_dns_proxy_flip_is_critical(self):
        self.assertEqual(
            _sev(_policy(proxy_enabled=False), _policy(proxy_enabled=True),
                 "properties.dnsSettings"),
            "critical",
        )

    def test_classic_firewall_rule_collections_are_critical(self):
        # Non-policy firewalls carry rules inline on the azureFirewalls row.
        self.assertEqual(
            PropertyComparator._get_severity("properties.networkRuleCollections[0].rules"),
            "critical",
        )
        self.assertEqual(
            PropertyComparator._get_severity("properties.firewallPolicy.id"),
            "critical",
        )


class FirewallChildExpansionTests(unittest.TestCase):
    def test_rcg_expansion_registered(self):
        spec = [s for s in _CHILD_EXPANSION_SPECS
                if s[0] == "microsoft.network/firewallpolicies"]
        self.assertEqual(len(spec), 1)
        parent, list_path, api, child_type, skip = spec[0]
        self.assertEqual(list_path, "ruleCollectionGroups")
        self.assertEqual(child_type, RCG_TYPE)
        self.assertIsNone(skip)


if __name__ == "__main__":
    unittest.main()
