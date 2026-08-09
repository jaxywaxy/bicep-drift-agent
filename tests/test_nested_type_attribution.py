"""
A NESTED resource type must be attributable from the Activity Log.

Live 2026-08-09 (post-#420 empty-estate scan): both VNet peerings and both
Cosmos children came back `origin: unknown` / `severity: medium` with a null
actor and an empty event list, while every FLAT type in the same scan named
`jacqui.anker@gmail.com`. The split was exactly flat-vs-nested.

Two independent bugs had to line up to produce that, so each has its own test
below - fixing either one alone still leaves nested types unattributed on some
path:

  1. _fallback_resource_id concatenated the whole type then the whole name,
     but ARM INTERLEAVES them. The id it built could not exist.
  2. The type fallback in match_activity_for_resource was a SUBSTRING test,
     which no nested type can pass however the id was built - the name
     segments split the type string.

These tests drive `_attribute_lifecycle` with the real matcher in place and
only the network calls stubbed. Patching `match_activity_for_resource` (as the
older attribution tests do) would skip the stage that actually broke.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import orchestration.attribution as attr
from orchestration.attribution import _fallback_resource_id
from tools.activity_log import match_activity_for_resource, provider_path

SUB = "bd48a22c-91b9-46e6-a2ff-15893e348d83"
RG = "jacquidev-rg-apps"
ACTOR = "jacqui.anker@gmail.com"

PEERING_TYPE = "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"
SQLDB_TYPE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases"
CONTAINER_TYPE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers"


def arm_id(rg, tail):
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{tail}"


def delete_event(resource_id, operation, actor=ACTOR):
    return {
        "resource_id": resource_id,
        "operation": operation,
        "caller": actor,
        "status": "Succeeded",
        "timestamp": datetime(2026, 8, 7, 6, 10, 28, tzinfo=timezone.utc),
    }


def attribute(drift_type, resource_type, name, events, target_rg=RG):
    """Run the real Phase 3 attribution over one drift; stub only the network."""
    report = {
        "drifts": [{"type": resource_type, "name": name, "drift_type": drift_type}],
        "arm_resources": [{"type": resource_type, "name": name, "_target_rg": target_rg}],
        "live_resources": [],
    }
    with mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": SUB}), \
         mock.patch.object(attr, "fetch_resource_group_activity", return_value=events), \
         mock.patch.object(attr, "fetch_policy_principal_ids", return_value=set()), \
         mock.patch.object(attr, "detect_scanning_identity", return_value=set()):
        attr._attribute_lifecycle(report, target_rg)
    return report["drifts"][0]


class NestedTypesAreAttributedTests(unittest.TestCase):
    """The four rows that came back anonymous in the live scan."""

    def test_vnet_peering_deletion_names_its_actor(self):
        real_id = arm_id(
            "jacquidev-rg-networking",
            "Microsoft.Network/virtualNetworks/jacquidev-vnet-hub"
            "/virtualNetworkPeerings/hub-to-apps",
        )
        drift = attribute(
            "missing_in_azure", PEERING_TYPE, "jacquidev-vnet-hub/hub-to-apps",
            [delete_event(real_id, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete")],
            target_rg="jacquidev-rg-networking",
        )
        self.assertEqual(drift["change_origin"]["changed_by"], ACTOR)
        self.assertEqual(drift["lifecycle"]["deleted_by"], ACTOR)

    def test_cosmos_child_deletion_names_its_actor(self):
        real_id = arm_id(
            RG, "Microsoft.DocumentDB/databaseAccounts/jacquidev-cosmos-m4fg23"
                "/sqlDatabases/appdb")
        drift = attribute(
            "missing_in_azure", SQLDB_TYPE, "jacquidev-cosmos-m4fg23/appdb",
            [delete_event(real_id, "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete")],
        )
        self.assertEqual(drift["change_origin"]["changed_by"], ACTOR)

    def test_cosmos_grandchild_deletion_names_its_actor(self):
        """Three levels deep - the interleave has to hold for every segment."""
        real_id = arm_id(
            RG, "Microsoft.DocumentDB/databaseAccounts/jacquidev-cosmos-m4fg23"
                "/sqlDatabases/appdb/containers/items")
        drift = attribute(
            "missing_in_azure", CONTAINER_TYPE, "jacquidev-cosmos-m4fg23/appdb/items",
            [delete_event(real_id,
                          "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete")],
        )
        self.assertEqual(drift["change_origin"]["changed_by"], ACTOR)

    def test_a_placeholder_named_child_is_attributed_and_renamed(self):
        """The #419 case, one level down: the parent segment is a placeholder,
        so the id cannot be built exactly and the TYPE fallback must carry it."""
        real_id = arm_id(
            RG, "Microsoft.DocumentDB/databaseAccounts/jacquidev-cosmos-m4fg23"
                "/sqlDatabases/appdb")
        drift = attribute(
            "missing_in_azure", SQLDB_TYPE, "jacquidev-cosmos-[86c9cbf6]/appdb",
            [delete_event(real_id, "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete")],
        )
        self.assertEqual(drift["change_origin"]["changed_by"], ACTOR)
        self.assertEqual(drift["name"], "jacquidev-cosmos-m4fg23/appdb")
        self.assertEqual(drift["bicep_name_expression"], "jacquidev-cosmos-[86c9cbf6]/appdb")


class NestedMatchingStaysHonestTests(unittest.TestCase):
    """Attributing children must not become a licence to adopt a sibling's
    event - the #350 failure mode one level down."""

    def test_a_sibling_database_is_not_adopted(self):
        real_id = arm_id(
            RG, "Microsoft.DocumentDB/databaseAccounts/jacquidev-cosmos-m4fg23"
                "/sqlDatabases/otherdb")
        drift = attribute(
            "missing_in_azure", SQLDB_TYPE, "jacquidev-cosmos-[86c9cbf6]/appdb",
            [delete_event(real_id, "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete")],
        )
        self.assertIsNone(drift["change_origin"]["changed_by"])
        self.assertEqual(drift["name"], "jacquidev-cosmos-[86c9cbf6]/appdb",
                         "the sibling's event must not rename this resource")

    def test_a_child_of_the_type_is_not_its_own_deletion_event(self):
        """The substring test also matched anything nested UNDER the type - a
        lock's id carries the storage type it hangs off.

        Reached via an id that could not be built at all, because that is the
        path where the name filter cannot run: with no declared name to compare
        against, whatever the type test collects is returned as-is. So the type
        test is the only thing standing between a lock's event and a storage
        account's attribution.
        """
        storage = arm_id(RG, "Microsoft.Storage/storageAccounts/st-real")
        lock = storage + "/providers/Microsoft.Authorization/locks/keep"
        matched = match_activity_for_resource(
            [delete_event(lock, "Microsoft.Authorization/locks/delete"),
             delete_event(storage, "Microsoft.Storage/storageAccounts/delete")],
            "", "Microsoft.Storage/storageAccounts")
        self.assertEqual([e["resource_id"] for e in matched], [storage])


class ProviderPathTests(unittest.TestCase):
    def test_it_interleaves_type_and_name_segments(self):
        self.assertEqual(
            provider_path(PEERING_TYPE, "vnet-hub/hub-to-apps"),
            "Microsoft.Network/virtualNetworks/vnet-hub/virtualNetworkPeerings/hub-to-apps")

    def test_a_flat_type_is_unchanged(self):
        self.assertEqual(
            provider_path("Microsoft.Network/publicIPAddresses", "pip-nat"),
            "Microsoft.Network/publicIPAddresses/pip-nat")

    def test_a_name_with_too_few_segments_yields_no_path(self):
        """Better no id than an impossible one: "" lets the caller fall through
        to type matching, a malformed path silently matches nothing."""
        self.assertEqual(provider_path(SQLDB_TYPE, "just-the-account"), "")

    def test_the_builder_is_the_inverse_of_the_parser(self):
        from tools.activity_log import deployed_name_from_event_id
        for rtype, name in ((PEERING_TYPE, "vnet-hub/hub-to-apps"),
                            (CONTAINER_TYPE, "cosmos/appdb/items"),
                            ("Microsoft.Network/publicIPAddresses", "pip-nat")):
            with self.subTest(rtype):
                self.assertEqual(
                    deployed_name_from_event_id(rtype, arm_id(RG, provider_path(rtype, name))),
                    name)


class FallbackResourceIdTests(unittest.TestCase):
    def test_a_nested_id_interleaves(self):
        drift = {"name": "vnet-hub/hub-to-apps", "details": {"_declared_in_rg": RG}}
        self.assertEqual(
            _fallback_resource_id(SUB, "*", PEERING_TYPE, "vnet-hub/hub-to-apps", drift),
            arm_id(RG, "Microsoft.Network/virtualNetworks/vnet-hub"
                       "/virtualNetworkPeerings/hub-to-apps"))

    def test_an_unbuildable_id_is_empty_not_impossible(self):
        drift = {"name": "just-the-account", "details": {"_declared_in_rg": RG}}
        self.assertEqual(
            _fallback_resource_id(SUB, "*", SQLDB_TYPE, "just-the-account", drift), "")


if __name__ == "__main__":
    unittest.main()
