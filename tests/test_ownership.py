"""Unit tests for tools.ownership.classify_owner (Phase 4)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ownership import PLATFORM, WORKLOAD, classify_owner


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


class PlatformLandingZoneDefaultTests(unittest.TestCase):
    """An enterprise/platform LZ owns its whole subscription. Classifying by
    resource TYPE reads that estate as an app team's - observed live on a CAF LZ
    where the Key Vaults, Cosmos, storage, workspace, managed identity, private
    endpoints AND every resource group came out `workload`, and only the role
    assignments came out `platform`. Notifications route by owner, so the
    platform team was paged for almost nothing and the app team for all of it."""

    def test_default_is_unchanged_when_nothing_is_configured(self):
        # The whole feature must be inert for every existing landing zone.
        self.assertEqual(classify_owner("Microsoft.KeyVault/vaults"), WORKLOAD)
        self.assertEqual(classify_owner("Microsoft.Resources/resourceGroups"), WORKLOAD)

    def test_platform_model_flips_the_fallback(self):
        for rtype in ("Microsoft.KeyVault/vaults", "Microsoft.Resources/resourceGroups",
                      "Microsoft.DocumentDB/databaseAccounts",
                      "Microsoft.OperationalInsights/workspaces"):
            with self.subTest(rtype=rtype):
                self.assertEqual(classify_owner(rtype, default_owner=PLATFORM), PLATFORM)

    def test_platform_model_does_not_disturb_what_was_already_platform(self):
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualNetworks", default_owner=PLATFORM),
            PLATFORM)

    def test_rg_scoped_role_assignment_follows_the_model(self):
        # "App teams grant their own identities access to their own RG" is a
        # default, not a fact - in a platform LZ every RG belongs to platform.
        drift = {"details": {"scope": "/subscriptions/s/resourceGroups/rg-logging"}}
        self.assertEqual(classify_owner("Microsoft.Authorization/roleAssignments", drift),
                         WORKLOAD)
        self.assertEqual(
            classify_owner("Microsoft.Authorization/roleAssignments", drift,
                           default_owner=PLATFORM),
            PLATFORM)


class ModuleOwnershipTests(unittest.TestCase):
    """The module a resource is declared in says which codebase - and so which
    team - owns it. Resource type cannot: the same Key Vault is platform-owned in
    a connectivity subscription and workload-owned in an app team's spoke."""

    MAP = {"networking": "platform", "logging": "platform", "apps": "workload"}

    def test_module_decides_against_the_type_default(self):
        # A Key Vault would be workload by type; declared in a platform module
        # it is not.
        self.assertEqual(
            classify_owner("Microsoft.KeyVault/vaults", module="logging",
                           module_owners=self.MAP),
            PLATFORM)

    def test_module_beats_the_platform_type_list_too(self):
        # Evidence outranks the heuristic in BOTH directions, or it is not
        # evidence - a VNet an app team genuinely owns must be routable to them.
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualNetworks", module="apps",
                           module_owners=self.MAP),
            WORKLOAD)

    def test_module_overrides_the_nsg_rules_carve_out(self):
        # The securityRules-are-app-owned rule is a good default, not a fact. An
        # LZ mapping its networking module to platform is saying its own rules
        # are not delegated, and it knows better than a default written here.
        drift = {"details": {"changed_properties": {"properties.securityRules": {}}}}
        self.assertEqual(
            classify_owner("Microsoft.Network/networkSecurityGroups", drift),
            WORKLOAD)
        self.assertEqual(
            classify_owner("Microsoft.Network/networkSecurityGroups", drift,
                           module="networking", module_owners=self.MAP),
            PLATFORM)

    def test_unmapped_module_falls_through_to_the_type_rules(self):
        self.assertEqual(
            classify_owner("Microsoft.Network/virtualNetworks", module="unmapped",
                           module_owners=self.MAP),
            PLATFORM)
        self.assertEqual(
            classify_owner("Microsoft.KeyVault/vaults", module="unmapped",
                           module_owners=self.MAP, default_owner=PLATFORM),
            PLATFORM)

    def test_no_module_is_not_a_guess(self):
        # extra_in_azure findings have no declaring module at all.
        self.assertEqual(
            classify_owner("Microsoft.KeyVault/vaults", module=None,
                           module_owners=self.MAP),
            WORKLOAD)

    def test_globs_and_nested_module_paths(self):
        mapping = {"storage-*": "platform", "apps/*": "workload"}
        self.assertEqual(classify_owner("Microsoft.Storage/storageAccounts",
                                        module="storage-logs", module_owners=mapping), PLATFORM)
        self.assertEqual(classify_owner("Microsoft.KeyVault/vaults",
                                        module="apps/keyvault", module_owners=mapping), WORKLOAD)

    def test_longest_pattern_wins_regardless_of_declaration_order(self):
        # `apps/*` must carve an exception out of `*` whichever way the config
        # happens to be written, or ownership depends on dict ordering.
        for mapping in ({"*": "platform", "apps/*": "workload"},
                        {"apps/*": "workload", "*": "platform"}):
            with self.subTest(mapping=list(mapping)):
                self.assertEqual(classify_owner("Microsoft.KeyVault/vaults",
                                                module="apps/kv", module_owners=mapping), WORKLOAD)
                self.assertEqual(classify_owner("Microsoft.KeyVault/vaults",
                                                module="logging", module_owners=mapping), PLATFORM)

    def test_module_matching_is_case_insensitive(self):
        self.assertEqual(
            classify_owner("Microsoft.KeyVault/vaults", module="Logging",
                           module_owners={"logging": "platform"}),
            PLATFORM)


if __name__ == "__main__":
    unittest.main()


class PlatformTypesOverrideIsReachableTests(unittest.TestCase):
    """`classify_owner` advertised a platform_types override in its own comment
    and no call site ever passed one, so the documented escape hatch did not
    exist. Same family as DRIFT_MODEL_PRICING being set and never plumbed."""

    def test_the_env_var_parses_into_a_type_set(self):
        import importlib
        import os
        from unittest import mock
        with mock.patch.dict(os.environ,
                             {"DRIFT_PLATFORM_TYPES": "Microsoft.Storage/storageAccounts, Foo/bar"}):
            import tools.config as config
            importlib.reload(config)
            self.assertEqual(config.platform_types(),
                             {"microsoft.storage/storageaccounts", "foo/bar"})

    def test_unset_means_use_the_builtin_set(self):
        import importlib
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DRIFT_PLATFORM_TYPES", None)
            import tools.config as config
            importlib.reload(config)
            self.assertIsNone(config.platform_types())

    def test_the_orchestrator_actually_passes_it(self):
        # The field existing is not the same as it reaching classify_owner -
        # which is exactly how it stayed dead.
        import inspect

        from orchestration import attribution
        self.assertIn("platform_types=configured_types", inspect.getsource(attribution))
