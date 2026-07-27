"""
Unit tests for tools.ignore_patterns.IgnorePatternList.filter_drifts.

These lock in the behavior around several regressions we hit:
- Property-scoped patterns must ONLY apply to property_drift, never suppress
  missing_in_azure / extra_in_azure (PR #137).
- Property patterns must match nested sub-properties (PR #137).
- drift_type-scoped patterns only apply to that drift type (PR #133/#138).
- Type-only patterns still suppress all drift for that type (baseline).
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml

from tools.ignore_patterns import IgnorePatternList


def _names(drifts):
    return {(d["type"], d["name"], d["drift_type"]) for d in drifts}


class PropertyScopedPatternTests(unittest.TestCase):
    """A pattern with a `property` field must only affect property_drift."""

    def setUp(self):
        self.il = IgnorePatternList([
            {
                "resource_type": "Microsoft.KeyVault/vaults",
                "property": "properties.networkAcls",
                "reason": "null vs empty object",
            }
        ])

    def test_extra_keyvault_is_not_suppressed(self):
        drifts = [{"type": "Microsoft.KeyVault/vaults", "name": "kv-manual",
                   "drift_type": "extra_in_azure", "details": {}}]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)

    def test_missing_keyvault_is_not_suppressed(self):
        drifts = [{"type": "Microsoft.KeyVault/vaults", "name": "kv-deleted",
                   "drift_type": "missing_in_azure", "details": {}}]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)

    def test_matching_property_drift_is_ignored(self):
        drifts = [{
            "type": "Microsoft.KeyVault/vaults", "name": "kv",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.networkAcls": {}}},
        }]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 0)
        self.assertEqual(len(ignored), 1)

    def test_nested_subproperty_is_ignored(self):
        # pattern 'properties.networkAcls' must also cover '.defaultAction' / '.bypass'
        drifts = [{
            "type": "Microsoft.KeyVault/vaults", "name": "kv",
            "drift_type": "property_drift",
            "details": {"changed_properties": {
                "properties.networkAcls.defaultAction": {},
                "properties.networkAcls.bypass": {},
            }},
        }]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(ignored), 1)

    def test_unrelated_property_drift_is_kept(self):
        drifts = [{
            "type": "Microsoft.KeyVault/vaults", "name": "kv",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.enableSoftDelete": {}}},
        }]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)


class DriftTypeScopedPatternTests(unittest.TestCase):
    """A pattern with drift_type only applies to that drift type."""

    def setUp(self):
        self.il = IgnorePatternList([
            {
                "resource_type": "Microsoft.OperationalInsights/workspaces",
                "drift_type": "extra_in_azure",
                "reason": "Defender auto-created workspace",
            }
        ])

    def test_extra_workspace_ignored(self):
        drifts = [{"type": "Microsoft.OperationalInsights/workspaces", "name": "log-x",
                   "drift_type": "extra_in_azure", "details": {}}]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(ignored), 1)

    def test_missing_workspace_not_ignored(self):
        # a deleted IaC-managed workspace must still surface
        drifts = [{"type": "Microsoft.OperationalInsights/workspaces", "name": "log-x",
                   "drift_type": "missing_in_azure", "details": {}}]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)


class TypeOnlyPatternTests(unittest.TestCase):
    """A type-only pattern (no property, no drift_type) suppresses all drift for the type."""

    def setUp(self):
        self.il = IgnorePatternList([
            {"resource_type": "Microsoft.Network/networkWatchers",
             "reason": "auto-created per region"}
        ])

    def test_all_drift_types_suppressed(self):
        drifts = [
            {"type": "Microsoft.Network/networkWatchers", "name": "nw1",
             "drift_type": "extra_in_azure", "details": {}},
            {"type": "Microsoft.Network/networkWatchers", "name": "nw2",
             "drift_type": "missing_in_azure", "details": {}},
        ]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 0)
        self.assertEqual(len(ignored), 2)

    def test_other_types_untouched(self):
        drifts = [{"type": "Microsoft.Storage/storageAccounts", "name": "st1",
                   "drift_type": "extra_in_azure", "details": {}}]
        filtered, ignored = self.il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)


class NameScopedPatternTests(unittest.TestCase):
    def test_name_glob_match(self):
        il = IgnorePatternList([
            {"resource_type": "microsoft.insights/actiongroups",
             "resource_name": "*Smart Detection*", "reason": "auto"}
        ])
        drifts = [
            {"type": "microsoft.insights/actiongroups", "name": "Application Insights Smart Detection",
             "drift_type": "extra_in_azure", "details": {}},
            {"type": "microsoft.insights/actiongroups", "name": "my-custom-ag",
             "drift_type": "extra_in_azure", "details": {}},
        ]
        filtered, ignored = il.filter_drifts(drifts)
        self.assertEqual(_names(filtered), {("microsoft.insights/actiongroups", "my-custom-ag", "extra_in_azure")})
        self.assertEqual(len(ignored), 1)


class EmptyAndNoMatchTests(unittest.TestCase):
    def test_no_patterns_keeps_everything(self):
        il = IgnorePatternList([])
        drifts = [{"type": "X/y", "name": "n", "drift_type": "property_drift",
                   "details": {"changed_properties": {"a": {}}}}]
        filtered, ignored = il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(ignored), 0)


class RepoIgnoreLoadBalancerPublicIpScopingTests(unittest.TestCase):
    """The baseline .drift-ignore LB/PublicIP rules must be scoped to
    extra_in_azure only: auto-created LBs/PIPs (extras) are suppressed, but an
    IaC-declared LB/PIP must still surface property_drift and missing_in_azure.
    Guards the real repo file (regression: bare type match silenced a live probe
    change on a declared load balancer)."""

    @classmethod
    def setUpClass(cls):
        repo_ignore = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".drift-ignore"
        )
        cls.il = IgnorePatternList.from_file(repo_ignore)

    def _one(self, drift):
        filtered, ignored = self.il.filter_drifts([drift])
        return bool(ignored)

    def test_extra_lb_and_pip_still_ignored(self):
        self.assertTrue(self._one({"type": "Microsoft.Network/loadBalancers",
                                   "name": "kubernetes", "drift_type": "extra_in_azure"}))
        self.assertTrue(self._one({"type": "Microsoft.Network/publicIPAddresses",
                                   "name": "pip-auto", "drift_type": "extra_in_azure"}))

    def test_declared_lb_property_and_missing_surface(self):
        self.assertFalse(self._one({
            "type": "Microsoft.Network/loadBalancers", "name": "lb-drift-test",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.probes": {}}}}))
        self.assertFalse(self._one({"type": "Microsoft.Network/loadBalancers",
                                    "name": "lb-drift-test", "drift_type": "missing_in_azure"}))

    def test_declared_pip_property_surfaces(self):
        self.assertFalse(self._one({
            "type": "Microsoft.Network/publicIPAddresses", "name": "pip-lb-drift-test",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.sku.name": {}}}}))


class RepoIgnoreRecoveryServicesVaultScopingTests(unittest.TestCase):
    """A Recovery Services vault must surface property drift. The baseline
    carried a rule scoped only by type + drift_type ("API version differences
    are metadata"), so it discarded EVERY property drift on a vault - it hid a
    real tags.environment change on 2026-07-26, and would equally hide
    publicNetworkAccess or a soft-delete flip on a backup vault.

    It cannot come back property-scoped either: apiVersion is never compared
    (tools/property_drift/extractor.py skips it as ARM template metadata), so an
    API-version-scoped rule would match nothing while looking like protection.
    Vault CHILDREN keep their own name-expression rules - those are unaffected."""

    @classmethod
    def setUpClass(cls):
        repo_ignore = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".drift-ignore"
        )
        cls.il = IgnorePatternList.from_file(repo_ignore)

    def _ignored(self, drift):
        _, ignored = self.il.filter_drifts([drift])
        return bool(ignored)

    def _vault_property_drift(self, prop):
        return {"type": "Microsoft.RecoveryServices/vaults", "name": "rsv-drift-test",
                "drift_type": "property_drift",
                "details": {"changed_properties": {prop: {"desired": "a", "actual": "b"}}}}

    def test_vault_tag_change_is_not_swallowed(self):
        """The exact drift the old rule hid."""
        self.assertFalse(self._ignored(self._vault_property_drift("tags.environment")))

    def test_vault_security_properties_are_not_swallowed(self):
        for prop in ("properties.publicNetworkAccess",
                     "properties.securitySettings.softDeleteSettings.softDeleteState",
                     "properties.securitySettings.softDeleteSettings.enhancedSecurityState"):
            with self.subTest(prop=prop):
                self.assertFalse(self._ignored(self._vault_property_drift(prop)))

    def test_vault_lifecycle_drift_still_surfaces(self):
        for dt in ("missing_in_azure", "extra_in_azure"):
            with self.subTest(drift_type=dt):
                self.assertFalse(self._ignored({
                    "type": "Microsoft.RecoveryServices/vaults",
                    "name": "rsv-drift-test", "drift_type": dt}))

    def test_vault_child_name_expression_rules_still_apply(self):
        """Removing the parent rule must not disturb the child rules.

        The example used to be backupPolicies. That was wrong: a collector
        fetches backupPolicies over ARM REST, so a declared policy that is gone
        from the vault is real drift and must surface. This now uses a child we
        genuinely do not collect - see
        CollectedTypesAreNotBlanketIgnoredTests for the line between the two."""
        self.assertTrue(self._ignored({
            "type": "Microsoft.RecoveryServices/vaults/replicationFabrics",
            "name": "rsv-drift-test/fabric", "drift_type": "missing_in_azure"}))

    def test_a_collected_backup_policy_that_vanished_is_reported(self):
        # The counterpart. tools/live_state/collectors/backup.py fetches these,
        # so "missing" means the policy is actually gone, not that we failed to
        # look - and a deleted backup policy is exactly what this tool is for.
        self.assertFalse(self._ignored({
            "type": "Microsoft.RecoveryServices/vaults/backupPolicies",
            "name": "rsv-drift-test/drift-vm-daily", "drift_type": "missing_in_azure"}))


class RepoIgnorePrivatelinkRecordScopingTests(unittest.TestCase):
    """A records in privatelink.* zones are auto-created by a private endpoint's
    DNS zone group, so their extras are suppressed — but ONLY extras, and ONLY in
    privatelink zones. Guards the real repo file (regression: a PE deployment's
    auto-managed A record false-flagged extra_in_azure)."""

    @classmethod
    def setUpClass(cls):
        repo_ignore = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".drift-ignore"
        )
        cls.il = IgnorePatternList.from_file(repo_ignore)

    def _ignored(self, drift):
        _, ignored = self.il.filter_drifts([drift])
        return bool(ignored)

    def test_privatelink_extra_record_ignored(self):
        self.assertTrue(self._ignored({
            "type": "Microsoft.Network/privateDnsZones/A",
            "name": "privatelink.vaultcore.azure.net/kvdrift123",
            "drift_type": "extra_in_azure"}))

    def test_normal_zone_extra_record_surfaces(self):
        # a hand-added record in an ordinary private zone is real drift
        self.assertFalse(self._ignored({
            "type": "Microsoft.Network/privateDnsZones/A",
            "name": "drifttest.internal/rogue",
            "drift_type": "extra_in_azure"}))

    def test_privatelink_missing_and_property_surface(self):
        self.assertFalse(self._ignored({
            "type": "Microsoft.Network/privateDnsZones/A",
            "name": "privatelink.vaultcore.azure.net/db",
            "drift_type": "missing_in_azure"}))
        self.assertFalse(self._ignored({
            "type": "Microsoft.Network/privateDnsZones/A",
            "name": "privatelink.vaultcore.azure.net/db",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.aRecords": {}}}}))


class RepoIgnoreAksScopingTests(unittest.TestCase):
    """The AKS rules must be narrowly scoped (regression: blanket ignores hid
    security-posture drift). Cluster: ONLY properties.agentPoolProfiles noise is
    ignored - enableRBAC / apiServerAccessProfile changes and cluster deletion
    surface. agentPools children: extras (inline system pools) ignored, but a
    declared pool's deletion or scale surfaces. Guards the real repo file."""

    AKS = "Microsoft.ContainerService/managedClusters"
    POOL = AKS + "/agentPools"

    @classmethod
    def setUpClass(cls):
        repo_ignore = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".drift-ignore"
        )
        cls.il = IgnorePatternList.from_file(repo_ignore)

    def _ignored(self, drift):
        _, ignored = self.il.filter_drifts([drift])
        return bool(ignored)

    def test_agent_pool_profiles_noise_ignored(self):
        self.assertTrue(self._ignored({
            "type": self.AKS, "name": "aks-drift-test", "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.agentPoolProfiles": {}}}}))

    def test_security_posture_drift_surfaces(self):
        for prop in ("properties.enableRBAC",
                     "properties.apiServerAccessProfile.enablePrivateCluster",
                     "properties.networkProfile.networkPolicy"):
            self.assertFalse(self._ignored({
                "type": self.AKS, "name": "aks-drift-test", "drift_type": "property_drift",
                "details": {"changed_properties": {prop: {}}}}), prop)

    def test_cluster_missing_and_extra_surface(self):
        self.assertFalse(self._ignored({"type": self.AKS, "name": "aks-x",
                                        "drift_type": "missing_in_azure"}))
        self.assertFalse(self._ignored({"type": self.AKS, "name": "aks-rogue",
                                        "drift_type": "extra_in_azure"}))

    def test_inline_system_pool_extra_ignored(self):
        self.assertTrue(self._ignored({"type": self.POOL, "name": "aks-drift-test/system",
                                       "drift_type": "extra_in_azure"}))

    def test_declared_pool_deletion_and_scale_surface(self):
        self.assertFalse(self._ignored({"type": self.POOL, "name": "aks-drift-test/userpool",
                                        "drift_type": "missing_in_azure"}))
        self.assertFalse(self._ignored({
            "type": self.POOL, "name": "aks-drift-test/userpool", "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.count": {}}}}))


class PropertyScopedStrippingTests(unittest.TestCase):
    """A property-scoped rule strips ONLY the matching properties; the drift is
    fully ignored only when nothing survives. Regression: the AKS
    agentPoolProfiles noise rule used to drop the WHOLE cluster drift, swallowing
    a real authorizedIPRanges finding riding in the same record (live repro on
    rg-drift-test)."""

    AKS = "Microsoft.ContainerService/managedClusters"

    def setUp(self):
        self.il = IgnorePatternList([{
            "resource_type": self.AKS,
            "property": "properties.agentPoolProfiles",
            "reason": "noise",
        }])

    def test_real_finding_survives_alongside_ignored_noise(self):
        drift = {
            "type": self.AKS, "name": "aks-drift-test", "drift_type": "property_drift",
            "details": {"changed_properties": {
                "properties.agentPoolProfiles": {"desired": [], "actual": []},
                "properties.apiServerAccessProfile.authorizedIPRanges": {
                    "desired": [], "actual": ["121.99.101.109/32"], "severity": "critical"},
            }},
        }
        filtered, ignored = self.il.filter_drifts([drift])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(ignored, [])
        surviving = filtered[0]["details"]["changed_properties"]
        self.assertEqual(
            list(surviving), ["properties.apiServerAccessProfile.authorizedIPRanges"])
        # the stripped noise is preserved for transparency
        self.assertIn("properties.agentPoolProfiles",
                      filtered[0].get("ignored_properties", {}))

    def test_drift_fully_ignored_when_all_properties_match(self):
        drift = {
            "type": self.AKS, "name": "aks-drift-test", "drift_type": "property_drift",
            "details": {"changed_properties": {
                "properties.agentPoolProfiles": {"desired": [], "actual": []}}},
        }
        filtered, ignored = self.il.filter_drifts([drift])
        self.assertEqual(filtered, [])
        self.assertEqual(len(ignored), 1)
        self.assertEqual(ignored[0]["ignored_reason"], "noise")

    def test_name_scoped_property_rule_respects_name(self):
        il = IgnorePatternList([{
            "resource_type": self.AKS,
            "resource_name": "other-cluster",
            "property": "properties.agentPoolProfiles",
        }])
        drift = {
            "type": self.AKS, "name": "aks-drift-test", "drift_type": "property_drift",
            "details": {"changed_properties": {
                "properties.agentPoolProfiles": {"desired": [], "actual": []}}},
        }
        filtered, ignored = il.filter_drifts([drift])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(
            list(filtered[0]["details"]["changed_properties"]),
            ["properties.agentPoolProfiles"])


class CollectedTypesAreNotBlanketIgnoredTests(unittest.TestCase):
    """A type we go to the trouble of FETCHING must not be discarded wholesale.

    The baseline carried type-only rules for vaults/backupPolicies and
    vaults/backupconfig. They dated from before
    tools/live_state/collectors/backup.py existed, when Resource Graph's failure
    to index those children made a declared backupconfig look permanently
    missing. The collector solved that over ARM REST - and the rules stayed,
    silently discarding every drift the backup comparator produced (soft-delete
    disabled, retention shortened, schedule moved) for roughly a month. Nothing
    looked wrong because the fixture vault happened to be clean.

    Most type-only rules in the baseline are legitimate: Azure-created children
    that Bicep never declares and we never fetch. The line is not "type-only is
    banned", it is "collected implies comparable". This test derives the
    collected set from the collectors themselves so it cannot go stale."""

    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @classmethod
    def setUpClass(cls):
        collectors = os.path.join(cls.REPO, "tools", "live_state", "collectors")
        pattern = re.compile(r'"type":\s*"(Microsoft\.[A-Za-z0-9/]+)"')
        cls.collected = set()
        for entry in sorted(os.listdir(collectors)):
            if not entry.endswith(".py"):
                continue
            with open(os.path.join(collectors, entry), encoding="utf-8") as f:
                cls.collected |= set(pattern.findall(f.read()))

        with open(os.path.join(cls.REPO, ".drift-ignore"), encoding="utf-8") as f:
            rules = (yaml.safe_load(f) or {}).get("ignore") or []
        cls.rules = rules
        cls.blanket = {
            r["resource_type"] for r in rules
            if set(r) <= {"resource_type", "reason"} and r.get("resource_type")
        }

    def test_the_extraction_actually_found_collectors(self):
        # Guard against a vacuous pass: if the regex or the layout changes and
        # nothing is extracted, every assertion below succeeds while measuring
        # nothing. Both sides must be non-empty for the cross-reference to mean
        # anything.
        self.assertGreaterEqual(len(self.collected), 5,
                                "no collected types extracted - the check is vacuous")
        self.assertGreaterEqual(len(self.blanket), 5,
                                "no blanket rules parsed - the check is vacuous")

    def test_no_collected_type_is_blanket_ignored(self):
        overlap = sorted(t for t in self.collected
                         if any(t.lower() == b.lower() for b in self.blanket))
        self.assertEqual(overlap, [],
                         "these types are fetched by a collector AND discarded by a "
                         "type-only ignore rule, so their comparator is dead: "
                         f"{overlap}")

    def test_backup_children_specifically_survive_the_real_baseline(self):
        # The two that were actually dead. Named explicitly so the regression is
        # legible even if the derivation above is later reworked.
        il = IgnorePatternList.from_file(os.path.join(self.REPO, ".drift-ignore"))
        for rtype, name in (
            ("Microsoft.RecoveryServices/vaults/backupPolicies", "rsv-drift-test/drift-vm-daily"),
            ("Microsoft.RecoveryServices/vaults/backupconfig", "rsv-drift-test/vaultconfig"),
        ):
            kept, ignored = il.filter_drifts([{
                "type": rtype, "name": name, "drift_type": "property_drift",
                "details": {"changed_properties": {
                    "properties.softDeleteFeatureState": {"desired": "Enabled",
                                                          "actual": "Disabled"}}}}])
            self.assertEqual(len(kept), 1, f"{rtype} property drift is being discarded")
            self.assertEqual(ignored, [])


class RepoIgnorePrivateDnsZoneGroupScopingTests(unittest.TestCase):
    """The zone-group rule may suppress the collection gap, not real drift.

    It was type-only, with the reason "Child resource with unresolvable
    parameter expressions in name" - and it fired on 'pe-kv-drift-test/default',
    a fully literal name, so the reason was false for the record it suppressed.
    A deleted zone group breaks private-endpoint name resolution and can send
    traffic to the public endpoint, so the blanket form hid something that
    matters."""

    @classmethod
    def setUpClass(cls):
        cls.il = IgnorePatternList.from_file(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".drift-ignore"))

    def _drift(self, drift_type):
        return {"type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
                "name": "pe-kv-drift-test/default", "drift_type": drift_type,
                "details": {"changed_properties": {
                    "properties.privateDnsZoneConfigs": {"desired": "a", "actual": []}}}}

    def test_missing_is_no_longer_suppressed(self):
        # This asserted the opposite until #329. The scoped rule was a stopgap
        # for a COLLECTION gap: nothing fetched zone groups, so every declared
        # group reported missing. private_dns.py now fetches them, so "missing"
        # means the group is genuinely gone - private endpoint name resolution
        # is broken and traffic falls back to the public endpoint. Suppressing
        # that would be the failure the rule was accused of.
        kept, ignored = self.il.filter_drifts([self._drift("missing_in_azure")])
        self.assertEqual(len(kept), 1, "a deleted zone group must surface")
        self.assertEqual(ignored, [])

    def test_property_drift_is_not_suppressed(self):
        kept, ignored = self.il.filter_drifts([self._drift("property_drift")])
        self.assertEqual(len(kept), 1, "a zone-group config change must surface")
        self.assertEqual(ignored, [])

    def test_a_declared_workspace_table_is_not_suppressed(self):
        # Same round, same shape: the type-only rule read "parent name contains
        # unresolved parameter expressions", which was true of the NAME but is a
        # matching problem, not grounds to discard the type. The record it hid
        # claimed the table "has been deleted or was never created" - and
        # CustomLog_CL was present all along.
        for dt in ("missing_in_azure", "property_drift"):
            with self.subTest(dt):
                kept, ignored = self.il.filter_drifts([{
                    "type": "Microsoft.OperationalInsights/workspaces/tables",
                    "name": "log-[86c9cbf6]/CustomLog_CL", "drift_type": dt,
                    "details": {"changed_properties": {
                        "properties.totalRetentionInDays": {"desired": 30, "actual": 7}}}}])
                self.assertEqual(len(kept), 1)
                self.assertEqual(ignored, [])


if __name__ == "__main__":
    unittest.main()
