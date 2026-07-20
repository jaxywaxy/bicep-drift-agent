"""Unit tests for tools.ownership.classify_owner (Phase 4)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ownership import classify_owner, PLATFORM, WORKLOAD


class OwnershipTests(unittest.TestCase):
    def test_vnet_is_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/virtualNetworks"), PLATFORM)

    def test_subnet_is_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/virtualNetworks/subnets"), PLATFORM)

    def test_peering_is_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/virtualNetworks/virtualNetworkPeerings"), PLATFORM)

    def test_nsg_resource_is_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/networkSecurityGroups"), PLATFORM)

    def test_nsg_security_rule_child_is_workload(self):
        self.assertEqual(
            classify_owner("Microsoft.Network/networkSecurityGroups/securityRules"), WORKLOAD
        )

    def test_nsg_with_only_securityrules_change_is_workload(self):
        drift = {"details": {"changed_properties": {"properties.securityRules": {}}}}
        self.assertEqual(classify_owner("Microsoft.Network/networkSecurityGroups", drift), WORKLOAD)

    def test_nsg_with_non_rule_change_stays_platform(self):
        drift = {"details": {"changed_properties": {"properties.provisioningState": {}}}}
        self.assertEqual(classify_owner("Microsoft.Network/networkSecurityGroups", drift), PLATFORM)

    def test_route_table_and_natgateway_are_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/routeTables"), PLATFORM)
        self.assertEqual(classify_owner("Microsoft.Network/natGateways"), PLATFORM)
        self.assertEqual(classify_owner("Microsoft.Network/publicIPAddresses"), PLATFORM)

    def test_private_endpoint_is_workload(self):
        # A private endpoint is the app's connection to a PaaS resource -> workload,
        # even though it is a Microsoft.Network type.
        self.assertEqual(classify_owner("Microsoft.Network/privateEndpoints"), WORKLOAD)

    def test_workload_resource_defaults_to_workload(self):
        self.assertEqual(classify_owner("Microsoft.Storage/storageAccounts"), WORKLOAD)
        self.assertEqual(classify_owner("Microsoft.KeyVault/vaults"), WORKLOAD)
        self.assertEqual(classify_owner("Microsoft.Web/serverfarms"), WORKLOAD)
        self.assertEqual(classify_owner("Microsoft.Web/sites"), WORKLOAD)
        self.assertEqual(classify_owner("Microsoft.DocumentDB/databaseAccounts"), WORKLOAD)

    def test_firewall_policy_and_rule_collection_groups_are_platform(self):
        # The policy root was already platform; its ruleCollectionGroups child
        # (the central egress rules) must follow it, not fall through to the
        # workload default. Regression: firewall RCG drift routed to the workload
        # channel instead of platform.
        self.assertEqual(classify_owner("Microsoft.Network/firewallPolicies"), PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.Network/firewallPolicies/ruleCollectionGroups"),
            PLATFORM,
        )

    def test_load_balancer_and_app_gateway_are_platform(self):
        self.assertEqual(classify_owner("Microsoft.Network/loadBalancers"), PLATFORM)
        self.assertEqual(classify_owner("Microsoft.Network/applicationGateways"), PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"),
            PLATFORM,
        )

    def test_config_override_of_platform_types(self):
        # A config can declare its own platform-owned set.
        self.assertEqual(
            classify_owner("Microsoft.Storage/storageAccounts",
                           platform_types={"Microsoft.Storage/storageAccounts"}),
            PLATFORM,
        )
        # and something not in the override is workload
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualNetworks",
                           platform_types={"Microsoft.Storage/storageAccounts"}),
            WORKLOAD,
        )


if __name__ == "__main__":
    unittest.main()
