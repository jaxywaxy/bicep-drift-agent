"""
Unit tests for the generic data-plane child expansion
(storage containers/shares, Service Bus queues/topics, EventHub children,
DNS record sets + private-zone links, MSI federated credentials).
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.get_live_state import (
    _expand_data_plane_children,
    _skip_apex_ns_soa,
    _skip_default_consumer_group,
)

SUB = "/subscriptions/s/resourceGroups/rg/providers"


def _resource(rtype, name, rid):
    return {"type": rtype, "name": name, "id": rid, "resource_group": "rg"}


def _fake_urlopen(responses):
    """urlopen replacement serving canned {url-substring: value-list} JSON."""
    def opener(req, timeout=0):
        url = req.full_url
        for frag, value in responses.items():
            if frag in url:
                return io.BytesIO(json.dumps({"value": value}).encode())
        return io.BytesIO(b'{"value": []}')
    return opener


class SkipPredicateTests(unittest.TestCase):
    def test_default_consumer_group_skipped(self):
        self.assertTrue(_skip_default_consumer_group({"name": "$Default"}))
        self.assertFalse(_skip_default_consumer_group({"name": "driftcg"}))

    def test_apex_ns_soa_skipped_but_real_records_kept(self):
        self.assertTrue(_skip_apex_ns_soa({"name": "@", "type": "Microsoft.Network/dnszones/SOA"}))
        self.assertTrue(_skip_apex_ns_soa({"name": "@", "type": "Microsoft.Network/dnszones/NS"}))
        self.assertFalse(_skip_apex_ns_soa({"name": "www", "type": "Microsoft.Network/dnszones/A"}))
        self.assertFalse(_skip_apex_ns_soa({"name": "@", "type": "Microsoft.Network/dnszones/A"}))


class ExpansionTests(unittest.TestCase):
    def _expand(self, resources, responses):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            return _expand_data_plane_children(resources, token="t")

    def test_storage_children_carry_default_infix(self):
        st = _resource("Microsoft.Storage/storageAccounts", "st1",
                       f"{SUB}/Microsoft.Storage/storageAccounts/st1")
        children = self._expand([st], {
            "/blobServices/default/containers?": [
                {"name": "data", "id": "x", "properties": {"publicAccess": "None"}}],
            "/fileServices/default/shares?": [
                {"name": "share1", "id": "y", "properties": {}}],
        })
        names = {c["name"] for c in children}
        # bicep child names include the implicit 'default' blob/file service
        self.assertIn("st1/default/data", names)
        self.assertIn("st1/default/share1", names)

    def test_eventhub_grandchildren_and_default_cg_filter(self):
        ns = _resource("Microsoft.EventHub/namespaces", "eh1",
                       f"{SUB}/Microsoft.EventHub/namespaces/eh1")
        children = self._expand([ns], {
            "/eventhubs?": [{"name": "hub", "id": f"{SUB}/Microsoft.EventHub/namespaces/eh1/eventhubs/hub",
                             "properties": {"partitionCount": 2}}],
            "/consumergroups?": [{"name": "$Default", "id": "d"}, {"name": "driftcg", "id": "c"}],
            "/authorizationRules?": [{"name": "listen", "id": "a", "properties": {"rights": ["Listen"]}}],
        })
        names = {c["name"] for c in children}
        self.assertIn("eh1/hub", names)
        self.assertIn("eh1/hub/driftcg", names)
        self.assertIn("eh1/hub/listen", names)
        self.assertNotIn("eh1/hub/$Default", names)

    def test_recordsets_use_item_own_type(self):
        zone = _resource("Microsoft.Network/dnszones", "drifttest.example.com",
                         f"{SUB}/Microsoft.Network/dnszones/drifttest.example.com")
        children = self._expand([zone], {
            "/recordsets?": [
                {"name": "@", "type": "Microsoft.Network/dnszones/SOA", "id": "s"},
                {"name": "@", "type": "Microsoft.Network/dnszones/NS", "id": "n"},
                {"name": "www", "type": "Microsoft.Network/dnszones/A", "id": "a",
                 "properties": {"ARecords": [{"ipv4Address": "203.0.113.10"}], "TTL": 300}},
            ],
        })
        self.assertEqual(len(children), 1)  # SOA/NS apex filtered
        self.assertEqual(children[0]["type"], "Microsoft.Network/dnszones/A")
        self.assertEqual(children[0]["name"], "drifttest.example.com/www")

    def test_federated_credentials_and_private_dns_links(self):
        msi = _resource("Microsoft.ManagedIdentity/userAssignedIdentities", "id1",
                        f"{SUB}/Microsoft.ManagedIdentity/userAssignedIdentities/id1")
        zone = _resource("Microsoft.Network/privateDnsZones", "priv.internal",
                         f"{SUB}/Microsoft.Network/privateDnsZones/priv.internal")
        children = self._expand([msi, zone], {
            "/federatedIdentityCredentials?": [
                {"name": "gha", "id": "f",
                 "properties": {"issuer": "https://token.actions.githubusercontent.com",
                                "subject": "repo:org/repo:ref:refs/heads/main"}}],
            "/virtualNetworkLinks?": [
                {"name": "link1", "id": "l",
                 "properties": {"registrationEnabled": False}}],
        })
        names = {c["name"] for c in children}
        self.assertIn("id1/gha", names)
        self.assertIn("priv.internal/link1", names)

    def test_no_parents_no_calls(self):
        self.assertEqual(_expand_data_plane_children(
            [_resource("Microsoft.Web/sites", "app", f"{SUB}/Microsoft.Web/sites/app")],
            token="t",
        ), [])


if __name__ == "__main__":
    unittest.main()


class Batch3ExpansionTests(unittest.TestCase):
    """SQL firewall rules (child expansion) + DCR associations (extension)."""

    def _expand(self, resources, responses):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            return _expand_data_plane_children(resources, token="t")

    def test_sql_firewall_rules_expanded(self):
        srv = _resource("Microsoft.Sql/servers", "sql1",
                        f"{SUB}/Microsoft.Sql/servers/sql1")
        children = self._expand([srv], {
            "/firewallRules?": [
                {"name": "AllowHome", "id": "f1",
                 "properties": {"startIpAddress": "203.0.113.5", "endIpAddress": "203.0.113.5"}},
                {"name": "AllowAll", "id": "f2",
                 "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}},
            ],
        })
        names = {c["name"] for c in children}
        self.assertIn("sql1/AllowHome", names)
        self.assertIn("sql1/AllowAll", names)
        self.assertEqual(
            next(c for c in children if c["name"] == "sql1/AllowAll")["type"],
            "Microsoft.Sql/servers/firewallRules")

    def test_dcr_associations_expanded_for_vm(self):
        from tools.get_live_state import _expand_extension_resources
        vm = _resource("Microsoft.Compute/virtualMachines", "vm1",
                       f"{SUB}/Microsoft.Compute/virtualMachines/vm1")
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen({
            "/dataCollectionRuleAssociations?": [
                {"name": "vm1-dcra", "id": "a1",
                 "properties": {"dataCollectionRuleId": f"{SUB}/Microsoft.Insights/dataCollectionRules/dcr1"}}],
            "/diagnosticSettings?": [],
        })):
            children = _expand_extension_resources([vm], token="t")
        self.assertEqual(
            [c["name"] for c in children if "dcra" in c["name"]], ["vm1/vm1-dcra"])
        self.assertEqual(children[0]["type"], "Microsoft.Insights/dataCollectionRuleAssociations")

    def test_qualify_extension_names_covers_both_types(self):
        from tools.get_live_state import qualify_extension_resource_names
        arm = [
            {"type": "Microsoft.Insights/diagnosticSettings", "name": "kv-audit",
             "scope": "Microsoft.KeyVault/vaults/kv1"},
            {"type": "Microsoft.Insights/dataCollectionRuleAssociations", "name": "vm-dcra",
             "scope": "Microsoft.Compute/virtualMachines/vm1"},
        ]
        qualify_extension_resource_names(arm)
        self.assertEqual(arm[0]["name"], "kv1/kv-audit")
        self.assertEqual(arm[1]["name"], "vm1/vm-dcra")


class ContainerAppsSecurityTests(unittest.TestCase):
    def test_ingress_exposure_paths_are_critical(self):
        from tools.property_drift import PropertyComparator
        self.assertEqual(
            PropertyComparator._get_severity("properties.configuration.ingress.external"),
            "critical")
        self.assertEqual(
            PropertyComparator._get_severity("properties.configuration.ingress.allowInsecure"),
            "critical")


class FrontDoorExpansionTests(unittest.TestCase):
    """Front Door Standard/Premium (Microsoft.Cdn/profiles) child + grandchild
    expansion: endpoints/originGroups/securityPolicies, then origins/routes."""

    def _expand(self, resources, responses):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            return _expand_data_plane_children(resources, token="t")

    def test_frontdoor_children_and_grandchildren(self):
        profile = _resource("Microsoft.Cdn/profiles", "fd1",
                            f"{SUB}/Microsoft.Cdn/profiles/fd1")
        children = self._expand([profile], {
            "/afdEndpoints?": [
                {"name": "ep1", "id": f"{SUB}/Microsoft.Cdn/profiles/fd1/afdEndpoints/ep1",
                 "properties": {"enabledState": "Enabled"}}],
            "/originGroups?": [
                {"name": "og1", "id": f"{SUB}/Microsoft.Cdn/profiles/fd1/originGroups/og1",
                 "properties": {}}],
            "/securityPolicies?": [
                {"name": "waf-assoc", "id": "sp1", "properties": {}}],
            "/ruleSets?": [],
            # grandchildren
            "/origins?": [
                {"name": "origin1", "id": "o1",
                 "properties": {"hostName": "backend.example.com"}}],
            "/routes?": [
                {"name": "route1", "id": "r1",
                 "properties": {"forwardingProtocol": "HttpsOnly", "httpsRedirect": "Enabled"}}],
        })
        names = {c["name"] for c in children}
        self.assertIn("fd1/ep1", names)
        self.assertIn("fd1/og1", names)
        self.assertIn("fd1/waf-assoc", names)
        self.assertIn("fd1/og1/origin1", names)      # origin grandchild
        self.assertIn("fd1/ep1/route1", names)        # route grandchild
        origin = next(c for c in children if c["name"] == "fd1/og1/origin1")
        self.assertEqual(origin["type"], "Microsoft.Cdn/profiles/originGroups/origins")

    def test_routes_expanded_when_endpoint_is_a_base_query_row(self):
        # Regression: afdEndpoints are returned by the base Resource Graph query
        # (lowercase type), so the child pass dedups the endpoint out of `children`
        # by id. The grandchild pass must still expand its routes — otherwise every
        # AFD route false-flags missing_in_azure. Here the endpoint is supplied as a
        # base resource AND returned by the /afdEndpoints listing with the same id.
        ep_id = f"{SUB}/Microsoft.Cdn/profiles/fd1/afdEndpoints/ep1"
        profile = _resource("Microsoft.Cdn/profiles", "fd1",
                            f"{SUB}/Microsoft.Cdn/profiles/fd1")
        endpoint_base = _resource("microsoft.cdn/profiles/afdendpoints", "fd1/ep1", ep_id)
        children = self._expand([profile, endpoint_base], {
            "/afdEndpoints?": [{"name": "ep1", "id": ep_id, "properties": {}}],
            "/originGroups?": [],
            "/securityPolicies?": [],
            "/ruleSets?": [],
            "/routes?": [
                {"name": "route1", "id": "r1",
                 "properties": {"forwardingProtocol": "HttpsOnly"}}],
        })
        names = {c["name"] for c in children}
        # Endpoint itself is deduped (already a base row), but its route is expanded.
        self.assertIn("fd1/ep1/route1", names)


class AksAgentPoolExpansionTests(unittest.TestCase):
    """AKS agent pools declared as separate agentPools children are invisible to
    Resource Graph; they must be expanded from the cluster so a declared pool
    matches (and a deleted/scaled one surfaces)."""

    def test_agent_pools_expanded_from_cluster(self):
        cluster = _resource("microsoft.containerservice/managedclusters", "aks1",
                            f"{SUB}/Microsoft.ContainerService/managedClusters/aks1")
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen({
            "/agentPools?": [
                {"name": "system", "id": "ap1",
                 "properties": {"count": 1, "mode": "System", "vmSize": "Standard_D2s_v3"}},
                {"name": "userpool", "id": "ap2",
                 "properties": {"count": 1, "mode": "User", "vmSize": "Standard_D2s_v3"}},
            ],
        })):
            children = _expand_data_plane_children([cluster], token="t")
        names = {(c["type"], c["name"]) for c in children}
        self.assertIn(("Microsoft.ContainerService/managedClusters/agentPools", "aks1/system"), names)
        self.assertIn(("Microsoft.ContainerService/managedClusters/agentPools", "aks1/userpool"), names)
        userpool = next(c for c in children if c["name"] == "aks1/userpool")
        self.assertEqual(userpool["properties"]["count"], 1)


class EventGridSubscriptionExpansionTests(unittest.TestCase):
    """Event Grid event subscriptions are extension resources under a topic
    (nested-provider path) or system topic (plain child path); both parents are
    base Resource Graph rows."""

    def _expand(self, resources, responses):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            return _expand_data_plane_children(resources, token="t")

    def test_topic_and_systemtopic_subscriptions_expanded(self):
        topic = _resource("microsoft.eventgrid/topics", "evgt1",
                          f"{SUB}/Microsoft.EventGrid/topics/evgt1")
        systopic = _resource("microsoft.eventgrid/systemtopics", "evgst1",
                             f"{SUB}/Microsoft.EventGrid/systemTopics/evgst1")
        children = self._expand([topic, systopic], {
            "topics/evgt1/providers/Microsoft.EventGrid/eventSubscriptions": [
                {"name": "sub-drift", "id": "es1",
                 "properties": {"destination": {"endpointType": "EventHub"}}}],
            "systemTopics/evgst1/eventSubscriptions": [
                {"name": "sub-drift", "id": "es2",
                 "properties": {"destination": {"endpointType": "EventHub"}}}],
        })
        names = {(c["type"], c["name"]) for c in children}
        self.assertIn(("Microsoft.EventGrid/topics/eventSubscriptions", "evgt1/sub-drift"), names)
        self.assertIn(("Microsoft.EventGrid/systemTopics/eventSubscriptions", "evgst1/sub-drift"), names)

    def test_subscription_destination_is_critical(self):
        from tools.property_drift import PropertyComparator
        self.assertEqual(
            PropertyComparator._get_severity("properties.destination.endpointType"),
            "critical")


class VirtualHubRoutingExpansionTests(unittest.TestCase):
    """Virtual Hub routing children (routingIntent + hubRouteTables) are invisible
    to Resource Graph; without expansion a declared route table / routing intent
    false-flags missing_in_azure and an out-of-band firewall bypass goes
    undetected."""

    def _expand(self, resources, responses):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            return _expand_data_plane_children(resources, token="t")

    def test_routing_intent_and_route_tables_expanded(self):
        hub = _resource("microsoft.network/virtualhubs", "hub1",
                        f"{SUB}/Microsoft.Network/virtualHubs/hub1")
        fw = f"{SUB}/Microsoft.Network/azureFirewalls/fw1"
        children = self._expand([hub], {
            "/routingIntent?": [
                {"name": "hub1-intent", "id": "ri1",
                 "properties": {"routingPolicies": [
                     {"name": "InternetTraffic", "destinations": ["Internet"], "nextHop": fw},
                     {"name": "PrivateTraffic", "destinations": ["PrivateTraffic"], "nextHop": fw},
                 ]}}],
            "/hubRouteTables?": [
                {"name": "defaultRouteTable", "id": "rt1",
                 "properties": {"routes": [
                     {"name": "to-fw", "destinationType": "CIDR",
                      "destinations": ["0.0.0.0/0"], "nextHopType": "ResourceId", "nextHop": fw}]}}],
        })
        names = {(c["type"], c["name"]) for c in children}
        self.assertIn(("Microsoft.Network/virtualHubs/routingIntent", "hub1/hub1-intent"), names)
        self.assertIn(("Microsoft.Network/virtualHubs/hubRouteTables", "hub1/defaultRouteTable"), names)

    def test_no_hub_no_calls(self):
        # A resource that is not a parent type in any spec triggers no expansion.
        self.assertEqual(_expand_data_plane_children(
            [_resource("Microsoft.Web/sites", "app", f"{SUB}/Microsoft.Web/sites/app")],
            token="t",
        ), [])


class VirtualHubOwnershipAndSeverityTests(unittest.TestCase):
    def test_hub_routing_is_platform(self):
        from tools.ownership import classify_owner, PLATFORM
        self.assertEqual(classify_owner("Microsoft.Network/virtualHubs"), PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualHubs/hubRouteTables"), PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualHubs/routingIntent"), PLATFORM)

    def test_routing_bypass_paths_are_critical(self):
        from tools.property_drift import PropertyComparator
        # routing intent nextHop repointed off the firewall
        self.assertEqual(
            PropertyComparator._get_severity(
                "properties.routingPolicies[0].nextHop"), "critical")
        # hub route table route nextHop change
        self.assertEqual(
            PropertyComparator._get_severity("properties.routes[0].nextHop"), "critical")


class FrontDoorOwnershipAndSeverityTests(unittest.TestCase):
    def test_frontdoor_and_waf_are_platform(self):
        from tools.ownership import classify_owner, PLATFORM
        self.assertEqual(classify_owner("Microsoft.Cdn/profiles"), PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"), PLATFORM)

    def test_route_tls_downgrade_paths_are_critical(self):
        from tools.property_drift import PropertyComparator
        self.assertEqual(
            PropertyComparator._get_severity("properties.forwardingProtocol"), "critical")
        self.assertEqual(
            PropertyComparator._get_severity("properties.httpsRedirect"), "critical")
