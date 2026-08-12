"""Live-state collection against payloads a real subscription actually sent.

Every other test of this layer feeds it a payload someone typed, so it asserts
that the code handles what we IMAGINED Azure returns. These run the same code
against `tests/cassettes/lz-prod-subscription.json` - 28 interactions captured
from a deployed landing zone on 2026-08-13, across Resource Graph, the Cosmos
child expansion, RBAC and policy.

Enters through `get_live_state`, the stage ABOVE the collectors, because a test
that calls a collector directly can pass while the pipeline never reaches it -
which this codebase has been burned by twice.
"""

import json
import unittest

from tests.cassette_support import CassetteTestCase
from tools import recording
from tools.live_state import get_live_state
from tools.live_state.common import CollectionGaps


class LiveStateFromRealPayloadsTests(CassetteTestCase):
    CASSETTE = "lz-prod-subscription.json"

    def collect(self):
        gaps = CollectionGaps()
        resources = get_live_state(
            resource_group="jacquiprod-*",
            subscription_id=self.subscription_id,
            scope="subscription",
            gaps=gaps,
        )
        return resources, gaps

    def test_the_whole_estate_is_collected_without_a_gap(self):
        # A gap here means a collector could not read a type, and the declared
        # resources of a gapped type go on to report as unverified rather than
        # deleted - so a corpus that quietly gapped would be testing nothing.
        resources, gaps = self.collect()
        self.assertEqual(dict(gaps.as_dict()), {})
        self.assertEqual(len(resources), 29)

    def test_the_expected_types_come_back(self):
        resources, _ = self.collect()
        types = {(r.get("type") or "").lower() for r in resources}
        for expected in (
            "microsoft.keyvault/vaults",
            "microsoft.documentdb/databaseaccounts",
            "microsoft.network/virtualnetworks",
            "microsoft.network/natgateways",
            "microsoft.network/privateendpoints",
            "microsoft.operationalinsights/workspaces",
            "microsoft.storage/storageaccounts",
        ):
            self.assertIn(expected, types)

    def test_cosmos_children_are_expanded_and_parent_qualified(self):
        # Cosmos SQL databases and containers are not indexed in Resource Graph;
        # they arrive through an ARM REST expansion, and must carry the
        # parent/child name a Bicep child resource compiles to or they can never
        # correspond and double-report as missing AND extra.
        resources, _ = self.collect()
        by_type = {}
        for r in resources:
            by_type.setdefault((r.get("type") or "").lower(), []).append(r)

        dbs = by_type.get("microsoft.documentdb/databaseaccounts/sqldatabases", [])
        containers = by_type.get(
            "microsoft.documentdb/databaseaccounts/sqldatabases/containers", []
        )
        self.assertTrue(dbs, "no Cosmos SQL database was expanded")
        self.assertTrue(containers, "no Cosmos container was expanded")
        self.assertEqual(dbs[0]["name"].count("/"), 1, dbs[0]["name"])
        self.assertEqual(containers[0]["name"].count("/"), 2, containers[0]["name"])

    def test_the_key_vault_carries_the_properties_its_comparator_reads(self):
        # networkAcls and enableRbacAuthorization are the un-blinded Key Vault
        # security properties. Asserting they are PRESENT on a real payload is
        # the point: a comparator cannot detect drift on a property the live
        # state never carries, and that absence is invisible to a hand-written
        # fixture that simply includes them.
        resources, _ = self.collect()
        vaults = [r for r in resources
                  if (r.get("type") or "").lower() == "microsoft.keyvault/vaults"]
        self.assertEqual(len(vaults), 1)
        props = vaults[0].get("properties") or {}
        self.assertIn("networkAcls", props)
        self.assertIn("enableRbacAuthorization", props)

    def test_no_resource_id_lost_its_subscription(self):
        resources, _ = self.collect()
        for r in resources:
            self.assertIn(self.subscription_id, r.get("id", ""), r.get("name"))


class TheCorpusIsLoadBearingTests(CassetteTestCase):
    """Mutation checks.

    Without these, a replayer that returned empty for every request would leave
    every assertion above passing on an empty list, and the corpus would be
    decorative - the same shape as the two backup comparators that shipped dead
    for a month with a green suite.
    """

    CASSETTE = "lz-prod-subscription.json"

    def _replay_mutated(self, mutate):
        """Re-point the session at a doctored copy of the cassette."""
        raw = json.loads(self.cassette_path.read_text())
        mutate(raw)
        doctored = self.cassette_path.parent / "_mutated.tmp.json"
        doctored.write_text(json.dumps(raw))
        self.addCleanup(doctored.unlink)
        recording.stop()
        recording.start_replay(doctored)
        return get_live_state(
            resource_group="jacquiprod-*",
            subscription_id=self.subscription_id,
            scope="subscription",
            gaps=CollectionGaps(),
        )

    def test_removing_the_vault_from_the_payload_removes_it_from_the_result(self):
        def drop_vaults(raw):
            for interaction in raw["interactions"].values():
                body = interaction.get("body") or {}
                if isinstance(body, dict) and isinstance(body.get("data"), list):
                    body["data"] = [
                        row for row in body["data"]
                        if "keyvault" not in str(row.get("type", "")).lower()
                    ]

        resources = self._replay_mutated(drop_vaults)
        types = {(r.get("type") or "").lower() for r in resources}
        self.assertNotIn("microsoft.keyvault/vaults", types)

    def test_renaming_in_the_payload_renames_in_the_result(self):
        def rename(raw):
            for interaction in raw["interactions"].values():
                body = interaction.get("body") or {}
                if isinstance(body, dict) and isinstance(body.get("data"), list):
                    for row in body["data"]:
                        if "natgateway" in str(row.get("type", "")).lower():
                            row["name"] = "renamed-by-the-test"

        resources = self._replay_mutated(rename)
        names = {r.get("name") for r in resources}
        self.assertIn("renamed-by-the-test", names)


if __name__ == "__main__":
    unittest.main()
