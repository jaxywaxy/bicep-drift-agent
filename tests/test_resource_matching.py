"""
Unit tests for ResourceMatcher.match_resources — specifically the single-candidate
fallback guard: a deleted resource's Bicep definition must NOT be paired with an
unrelated, differently-named new resource of the same type (which would hide both
a missing_in_azure and an extra_in_azure).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import DriftDetector, ResourceMatcher


def _res(rtype, name):
    return {"type": rtype, "name": name, "properties": {}}


class SingleCandidateGuardTests(unittest.TestCase):
    ACR = "Microsoft.ContainerRegistry/registries"

    def test_deleted_managed_plus_new_extra_are_not_matched(self):
        # Bicep declares the managed ACR (uniqueString placeholder); the managed one
        # was deleted and an unrelated ACR was created manually.
        bicep = [_res(self.ACR, "acrtestdrift[86c9cbf6]")]
        deployed = [_res(self.ACR, "acrshadow99999")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(matches, [], "unrelated ACR must not be matched to the deleted managed one")

    def test_full_drift_reports_missing_and_extra(self):
        bicep = [_res(self.ACR, "acrtestdrift[86c9cbf6]")]
        deployed = [_res(self.ACR, "acrshadow99999")]
        drifts = DriftDetector.detect_drift(bicep, deployed)
        kinds = {(d.drift_type, d.resource_name) for d in drifts}
        self.assertIn(("missing", "acrtestdrift[86c9cbf6]"), kinds)
        self.assertIn(("extra", "acrshadow99999"), kinds)

    def test_legit_uniquestring_resolution_still_matches(self):
        # The real deployed name shares the static prefix -> must still match.
        bicep = [_res(self.ACR, "acrtestdrift[86c9cbf6]")]
        deployed = [_res(self.ACR, "acrtestdriftac7e6oa6bxbta")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1]["name"], "acrtestdriftac7e6oa6bxbta")

    def test_exact_literal_name_still_matches(self):
        bicep = [_res("Microsoft.Web/serverfarms", "asp-test-drift")]
        deployed = [_res("Microsoft.Web/serverfarms", "asp-test-drift")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(len(matches), 1)


if __name__ == "__main__":
    unittest.main()


class ChildSiblingFuzzyGuardTests(unittest.TestCase):
    """A deleted child's bicep definition must not fuzzy-match a surviving
    SIBLING: siblings share every parent segment, so full-name token overlap
    ('aks-drift-test/userpool' vs 'aks-drift-test/system') clears the fuzzy
    threshold on the parent alone (live repro: deleted userpool paired with the
    system pool, hiding missing_in_azure and fabricating name/mode drift)."""

    POOL = "Microsoft.ContainerService/managedClusters/agentPools"

    def test_deleted_pool_not_matched_to_sibling(self):
        bicep = [_res(self.POOL, "aks-drift-test/userpool")]
        deployed = [_res(self.POOL, "aks-drift-test/system")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(matches, [])

    def test_deletion_reports_missing_and_sibling_extra(self):
        bicep = [_res(self.POOL, "aks-drift-test/userpool")]
        deployed = [_res(self.POOL, "aks-drift-test/system")]
        drifts = DriftDetector.detect_drift(bicep, deployed)
        by_type = {(d.drift_type, d.resource_name) for d in drifts}
        self.assertIn(("missing", "aks-drift-test/userpool"), by_type)
        self.assertIn(("extra", "aks-drift-test/system"), by_type)

    def test_same_leaf_under_placeholder_parent_still_matches(self):
        # eventhub child under a uniqueString-named namespace: parent differs
        # textually (placeholder) but the leaf matches - must still pair.
        EH = "Microsoft.EventHub/namespaces/eventhubs"
        bicep = [_res(EH, "eh-[3a7f9c2b]/drift-hub")]
        deployed = [_res(EH, "eh-3s7c7weddxr3s/drift-hub")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(len(matches), 1)

    def test_cross_parent_same_leaf_not_matched(self):
        # identical leaf under DIFFERENT literal parents is a different resource
        CT = "Microsoft.Storage/storageAccounts/blobServices/containers"
        bicep = [_res(CT, "stalpha/default/data")]
        deployed = [_res(CT, "stbravo/default/data")]
        matches = ResourceMatcher.match_resources(bicep, deployed)
        self.assertEqual(matches, [])
