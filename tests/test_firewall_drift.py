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


def _diffs(bicep, live):
    return PropertyComparator.compare_properties(bicep, live)


def _paths(bicep, live):
    return {d.property_path for d in _diffs(bicep, live)}


class GranularFirewallDiffTests(unittest.TestCase):
    """The ruleCollections differ pinpoints the collection/rule/field that
    changed instead of dumping both whole arrays - and catches a scalar-list
    widening on its own, which the generic subset compare misses."""

    def test_port_widening_by_addition_is_caught(self):
        # THE latent false negative: ['443'] is a SUBSET of ['443','3389'], so
        # the generic compare saw no drift unless a sibling change failed the
        # match. Exact-set semantics on scalar rule lists flag the added port.
        bicep = _rcg(port="443")
        live = _rcg(port="443")
        live["properties"]["ruleCollections"][0]["rules"][0]["destinationPorts"] = ["443", "3389"]
        paths = _paths(bicep, live)
        self.assertIn(
            "properties.ruleCollections[net-rules].rules[allow-https-out].destinationPorts",
            paths,
        )

    def test_action_flip_pinpointed(self):
        diffs = _diffs(_rcg(action="Deny"), _rcg(action="Allow"))
        hit = [d for d in diffs if d.property_path.endswith(".action.type")]
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0].desired_value, hit[0].actual_value), ("Deny", "Allow"))
        self.assertEqual(hit[0].severity, "critical")
        # The change is isolated - no opaque whole-array properties.ruleCollections diff.
        self.assertNotIn("properties.ruleCollections", _paths(_rcg("Deny"), _rcg("Allow")))

    def test_added_rule_pinpointed_as_added(self):
        live = _rcg()
        live["properties"]["ruleCollections"][0]["rules"].append({
            "ruleType": "NetworkRule",
            "name": "allow-any-any",
            "ipProtocols": ["Any"],
            "sourceAddresses": ["*"],
            "destinationAddresses": ["*"],
            "destinationPorts": ["*"],
        })
        hit = [d for d in _diffs(_rcg(), live) if "allow-any-any" in d.property_path]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].change_type, "added")
        self.assertEqual(hit[0].desired_value, None)

    def test_rogue_collection_pinpointed_as_added(self):
        live = _rcg()
        live["properties"]["ruleCollections"].append({
            "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
            "name": "rogue-collection",
            "priority": 500,
            "action": {"type": "Allow"},
            "rules": [],
        })
        hit = [d for d in _diffs(_rcg(), live) if "rogue-collection" in d.property_path]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].change_type, "added")

    def test_removed_rule_pinpointed(self):
        bicep = _rcg()
        bicep["properties"]["ruleCollections"][0]["rules"].append({
            "ruleType": "NetworkRule",
            "name": "deny-telnet",
            "ipProtocols": ["TCP"],
            "sourceAddresses": ["*"],
            "destinationAddresses": ["*"],
            "destinationPorts": ["23"],
        })
        hit = [d for d in _diffs(bicep, _rcg()) if "deny-telnet" in d.property_path]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].change_type, "removed")

    def test_azure_augmentation_fields_not_flagged(self):
        # Azure populates read-only fields on the live rule (ipv6Rule,
        # sourceIpGroups: [], fqdnTags: [], ...). None of these are drift.
        live = _rcg()
        live["properties"]["ruleCollections"][0]["rules"][0].update({
            "ipv6Rule": False,
            "sourceIpGroups": [],
            "destinationIpGroups": [],
            "destinationFqdns": [],
        })
        self.assertEqual(_diffs(_rcg(), live), [])


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
