"""At subscription scope a resource group is a declared resource, not the frame.

An enterprise estate has both shapes and the agent supports both:
  - RG scope        -> the RG is the frame of the scan. It cannot even be
                       declared by an RG-scoped template, and its absence is a
                       targeting failure (see test_scope_not_found).
  - subscription    -> the template DECLARES its resource groups. In a CAF
                       platform landing zone they are part of what it owns, so
                       one going missing is drift and must be reported.

Before this, flatten_resources skipped Microsoft.Resources/resourceGroups
unconditionally as "infrastructure". A deleted RG in a landing zone was
therefore silent, while every resource inside it fired as an independent
deletion - N findings, none of them naming the cause.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_drift_check
from tools.diff_states import ResourceDrift
from tools.live_state.collectors.resource_groups import (
    RESOURCE_GROUP_TYPE,
    query_resource_groups,
)
from tools.live_state.common import CollectionGaps, ScopeNotFoundError
from tools.normalizer import flatten_resources

SUB_SCHEMA = "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#"
RG_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"


def _template(schema):
    return {
        "$schema": schema,
        "resources": [
            {"type": "Microsoft.Resources/resourceGroups", "name": "rg-networking",
             "location": "australiaeast"},
            {"type": "Microsoft.Storage/storageAccounts", "name": "stplatform"},
        ],
    }


class ResourceGroupsAreDeclaredAtSubscriptionScopeTests(unittest.TestCase):

    def test_subscription_scope_keeps_the_resource_group(self):
        flat = flatten_resources(_template(SUB_SCHEMA), {}, {}, subscription_scoped=True)
        self.assertIn(RESOURCE_GROUP_TYPE, [r["type"] for r in flat])

    def test_resource_group_scope_still_skips_it(self):
        # There the RG is the frame, not a resource in the scan.
        flat = flatten_resources(_template(RG_SCHEMA), {}, {}, subscription_scoped=False)
        self.assertNotIn(RESOURCE_GROUP_TYPE, [r["type"] for r in flat])

    def test_default_is_the_conservative_resource_group_behaviour(self):
        flat = flatten_resources(_template(RG_SCHEMA), {}, {})
        self.assertNotIn(RESOURCE_GROUP_TYPE, [r["type"] for r in flat])


class TargetResourceGroupIsStampedTests(unittest.TestCase):
    """A resource must record which RG it was deployed into, or an orphan cannot
    be tied back to the group that vanished. Previously stamped only for
    CROSS-SUBSCRIPTION modules, which is not the landing-zone case."""

    def _module_template(self, with_sub):
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "name": "deploy-net",
            "resourceGroup": "rg-networking",
            "properties": {"template": {
                "resources": [{"type": "Microsoft.Network/virtualNetworks", "name": "vnet-hub"}],
            }},
        }
        if with_sub:
            deployment["subscriptionId"] = "sub-two"
        return {"$schema": SUB_SCHEMA, "resources": [deployment]}

    def test_same_subscription_module_stamps_target_rg(self):
        flat = flatten_resources(self._module_template(with_sub=False), {}, {},
                                 subscription_scoped=True)
        vnet = [r for r in flat if r["type"] == "Microsoft.Network/virtualNetworks"][0]
        self.assertEqual(vnet["_target_rg"], "rg-networking")
        self.assertNotIn("_target_subscription", vnet)

    def test_cross_subscription_module_still_stamps_both(self):
        flat = flatten_resources(self._module_template(with_sub=True), {}, {},
                                 subscription_scoped=True)
        vnet = [r for r in flat if r["type"] == "Microsoft.Network/virtualNetworks"][0]
        self.assertEqual(vnet["_target_rg"], "rg-networking")
        self.assertEqual(vnet["_target_subscription"], "sub-two")


class ResourceGroupCollectorTests(unittest.TestCase):
    """Resources does not contain resource groups - ResourceContainers does.
    Verified live: `Resources | where type =~ '...resourcegroups' | count` -> 0.
    Without this collector every declared RG compares against nothing."""

    def test_containers_rows_become_comparable_resources(self):
        response = mock.Mock(data=[
            {"name": "rg-networking", "location": "australiaeast",
             "tags": {"env": "prod"}, "id": "/subscriptions/s/resourceGroups/rg-networking"},
        ])
        out = query_resource_groups(lambda kql: response, "sub")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], RESOURCE_GROUP_TYPE)
        self.assertEqual(out[0]["name"], "rg-networking")
        self.assertEqual(out[0]["tags"], {"env": "prod"})

    def test_it_queries_resourcecontainers_not_resources(self):
        seen = {}

        def capture(kql):
            seen["kql"] = kql
            return mock.Mock(data=[])

        query_resource_groups(capture, "sub")
        self.assertIn("ResourceContainers", seen["kql"])

    def test_a_failed_read_is_a_gap_not_an_empty_subscription(self):
        gaps = CollectionGaps()
        out = query_resource_groups(
            mock.Mock(side_effect=RuntimeError("throttled")), "sub", gaps=gaps)
        self.assertEqual(out, [])
        self.assertTrue(gaps.covers(RESOURCE_GROUP_TYPE))


class OrphanAttributionTests(unittest.TestCase):
    """One deleted RG is one finding with attributed contents, not N deletions."""

    def _drifts(self):
        return [
            ResourceDrift(RESOURCE_GROUP_TYPE, "rg-networking", "missing_in_azure"),
            ResourceDrift("Microsoft.Network/virtualNetworks", "vnet-hub", "missing_in_azure"),
            ResourceDrift("Microsoft.Storage/storageAccounts", "stelsewhere", "missing_in_azure"),
        ]

    ARM = [
        {"type": "Microsoft.Network/virtualNetworks", "name": "vnet-hub",
         "_target_rg": "rg-networking"},
        {"type": "Microsoft.Storage/storageAccounts", "name": "stelsewhere",
         "_target_rg": "rg-apps"},
    ]

    def test_contents_of_a_deleted_rg_are_attributed_to_it(self):
        drifts = self._drifts()
        attributed = run_drift_check._attribute_orphans_to_missing_rgs(drifts, self.ARM)
        self.assertEqual(attributed, 1)
        vnet = drifts[1]
        self.assertEqual(vnet.details["orphaned_by_missing_resource_group"], "rg-networking")
        self.assertIn("no longer exists", vnet.details["note"])

    def test_a_resource_in_a_surviving_rg_is_not_attributed(self):
        drifts = self._drifts()
        run_drift_check._attribute_orphans_to_missing_rgs(drifts, self.ARM)
        self.assertNotIn("orphaned_by_missing_resource_group", drifts[2].details)

    def test_orphans_are_annotated_not_suppressed(self):
        # They really are gone: the cost guard needs them, and whoever restores
        # the RG needs the inventory.
        drifts = self._drifts()
        run_drift_check._attribute_orphans_to_missing_rgs(drifts, self.ARM)
        self.assertEqual(len(drifts), 3)
        self.assertTrue(all(d.drift_type == "missing_in_azure" for d in drifts))

    def test_no_missing_rg_means_no_annotation(self):
        drifts = [ResourceDrift("Microsoft.Network/virtualNetworks", "vnet-hub",
                                "missing_in_azure")]
        self.assertEqual(run_drift_check._attribute_orphans_to_missing_rgs(drifts, self.ARM), 0)
        self.assertNotIn("orphaned_by_missing_resource_group", drifts[0].details)


class EmptySubscriptionFailsTests(unittest.TestCase):
    """One RG of many missing is drift. NONE of them is a user/config error -
    the wrong subscription, a credential without read access, or an environment
    never deployed - and reporting a whole landing zone as deleted would be the
    same false alarm the RG-scope guard exists to prevent."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, self._cwd)

    def test_empty_subscription_scan_raises(self):
        with self.assertRaises(ScopeNotFoundError) as ctx:
            run_drift_check._guard_empty_subscription("*", "main.bicep")
        self.assertIn("no resources at all", str(ctx.exception))

    def test_it_writes_the_marker_report_too(self):
        import json
        with self.assertRaises(ScopeNotFoundError):
            run_drift_check._guard_empty_subscription("*", "main.bicep")
        with open(os.path.join("reports", "subscription-drift.json")) as f:
            self.assertEqual(json.load(f)["scope_status"], "not_found")

    def test_subscription_scope_takes_the_subscription_guard(self):
        with mock.patch("run_drift_check.get_live_state", return_value=[]), \
             mock.patch("run_drift_check._guard_empty_subscription") as sub_guard, \
             mock.patch("run_drift_check._guard_unverifiable_scope") as rg_guard:
            run_drift_check._fetch_live_state("*", "subscription", [], None)
        sub_guard.assert_called_once()
        rg_guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
