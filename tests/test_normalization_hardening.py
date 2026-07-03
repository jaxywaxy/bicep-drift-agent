"""
Unit tests for normalization hardening surfaced by scanning a realistic CAF
landing zone: subset comparison of Azure-augmented arrays, unresolved-expression
handling, and case-insensitive smart matching of uniqueString-named resources.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator, DriftDetector
from tools.smart_matching import (
    _has_unresolvable_expression,
    smart_match_resources,
    annotate_drifts_with_matches,
)


def _build_comparison_set(arm, live):
    """Mirror analyze_drift: remap smart-matched (unresolvable-name) bicep
    resources to their live name so their properties are compared."""
    matched, unmatched_bicep, _ = smart_match_resources(arm, live, {})
    return unmatched_bicep + [
        {**m, "name": m.get("matched_to")} for m in matched if m.get("matched_to")
    ]


class SubsetArrayComparisonTests(unittest.TestCase):
    def test_augmented_securityrules_is_not_drift(self):
        # Bicep specifies a subset of fields; Azure returns them plus read-only
        # fields (provisioningState, sourcePortRanges). That is not drift.
        bicep = {"properties": {"securityRules": [
            {"name": "Allow-HTTPS", "properties": {"priority": 100, "access": "Allow",
                                                    "destinationPortRange": "443"}},
        ]}}
        deployed = {"properties": {"securityRules": [
            {"name": "Allow-HTTPS", "properties": {"priority": 100, "access": "Allow",
                                                   "destinationPortRange": "443",
                                                   "sourcePortRanges": [], "provisioningState": "Succeeded"}},
        ]}}
        diffs = PropertyComparator.compare_properties(bicep, deployed)
        self.assertEqual(diffs, [])

    def test_manually_added_route_is_drift(self):
        # Bicep defines one route; someone added 'to-onprem' by hand. Azure never
        # adds elements to these named collections itself, so the extra element
        # is drift even though the bicep-defined element still matches.
        bicep = {"properties": {"routes": [
            {"name": "to-hub", "properties": {"addressPrefix": "10.0.0.0/16"}}]}}
        deployed = {"properties": {"routes": [
            {"name": "to-hub", "properties": {"addressPrefix": "10.0.0.0/16",
                                              "provisioningState": "Succeeded"}},
            {"name": "to-onprem", "properties": {"addressPrefix": "192.168.0.0/16"}},
        ]}}
        diffs = PropertyComparator.compare_properties(bicep, deployed)
        self.assertTrue(any("routes" in d.property_path for d in diffs),
                        "a manually added named element must be drift")

    def test_unnamed_array_extra_elements_stay_subset(self):
        # Unnamed arrays (e.g. natGateway publicIpAddresses by id) keep pure
        # subset semantics - extra deployed entries are not flagged here.
        bicep = {"properties": {"publicIpAddresses": [{"id": "/subscriptions/s/x"}]}}
        deployed = {"properties": {"publicIpAddresses": [
            {"id": "/subscriptions/s/x"}, {"id": "/subscriptions/s/y"}]}}
        self.assertEqual(PropertyComparator.compare_properties(bicep, deployed), [])

    def test_changed_rule_value_is_drift(self):
        bicep = {"properties": {"securityRules": [
            {"name": "Allow-HTTPS", "properties": {"destinationPortRange": "443"}}]}}
        deployed = {"properties": {"securityRules": [
            {"name": "Allow-HTTPS", "properties": {"destinationPortRange": "8443",
                                                   "provisioningState": "Succeeded"}}]}}
        diffs = PropertyComparator.compare_properties(bicep, deployed)
        self.assertTrue(any("securityRules" in d.property_path for d in diffs))

    def test_resource_id_case_insensitive(self):
        b = {"properties": {"subnet": {"id": "/subscriptions/S/resourceGroups/RG/x"}}}
        d = {"properties": {"subnet": {"id": "/subscriptions/s/resourcegroups/rg/x"}}}
        self.assertEqual(PropertyComparator.compare_properties(b, d), [])

    def test_unresolved_nested_id_is_not_drift(self):
        b = {"properties": {"publicIpAddresses": [
            {"id": "resourceId('Microsoft.Network/publicIPAddresses', 'x')"}]}}
        d = {"properties": {"publicIpAddresses": [
            {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/x"}]}}
        self.assertEqual(PropertyComparator.compare_properties(b, d), [])

    def test_none_bicep_value_is_not_drift(self):
        b = {"properties": {"subnet": {"id": None}}}
        d = {"properties": {"subnet": {"id": "/subscriptions/s/rg/.../subnet"}}}
        self.assertEqual(PropertyComparator.compare_properties(b, d), [])


class UnresolvableDetectionTests(unittest.TestCase):
    def test_detects_bare_function_call_without_brackets(self):
        # The analyzer strips [] leaving a bare call - still unresolvable.
        self.assertTrue(_has_unresolvable_expression(
            "jacquidevstgtake(uniqueString(resourceGroup().id), 6)"))
        self.assertTrue(_has_unresolvable_expression(
            "toLower(format('{0}st', parameters('prefix')))"))

    def test_plain_name_is_resolvable(self):
        self.assertFalse(_has_unresolvable_expression("jacquidev-vnet-hub"))


class SmartMatchCaseInsensitiveTests(unittest.TestCase):
    def test_matches_across_type_casing_and_annotates_extra(self):
        # Bicep PascalCase type + uniqueString name; live lowercase type + real name.
        bicep = [{"type": "Microsoft.Storage/storageAccounts",
                  "name": "toLower(format('{0}stg{1}', parameters('prefix'), take(uniqueString(x),6)))"}]
        live = [{"type": "microsoft.storage/storageaccounts", "name": "jacquidevstgm4fg23"}]
        matched, _, _ = smart_match_resources(bicep, live, {})
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["matched_to"], "jacquidevstgm4fg23")

        # The extra_in_azure drift (lowercase type) is annotated away.
        drifts = [{"type": "microsoft.storage/storageaccounts",
                   "name": "jacquidevstgm4fg23", "drift_type": "extra_in_azure"}]
        annotated = annotate_drifts_with_matches(drifts, matched)
        self.assertEqual(annotated[0]["drift_type"], "matched_unresolvable")
        self.assertTrue(annotated[0]["is_matched"])

    def test_best_match_prefers_name_prefix(self):
        # Two storage accounts; general (stg) vs logging (stl) must pair correctly.
        bicep = [
            {"type": "Microsoft.Storage/storageAccounts",
             "name": "jacquidevstgtake(uniqueString(x),6)"},
            {"type": "Microsoft.Storage/storageAccounts",
             "name": "jacquidevstltake(uniqueString(x),6)"},
        ]
        live = [
            {"type": "microsoft.storage/storageaccounts", "name": "jacquidevstla7m6et"},
            {"type": "microsoft.storage/storageaccounts", "name": "jacquidevstgm4fg23"},
        ]
        matched, _, _ = smart_match_resources(bicep, live, {})
        pairs = {m["name"][:12]: m["matched_to"] for m in matched}
        self.assertEqual(pairs["jacquidevstg"], "jacquidevstgm4fg23")
        self.assertEqual(pairs["jacquidevstl"], "jacquidevstla7m6et")


class UniqueStringPropertyDriftTests(unittest.TestCase):
    """A uniqueString-named resource must still be PROPERTY-checked, not just
    existence-matched (else e.g. a storage SKU change goes undetected)."""

    def _storage(self, name, sku):
        return {"type": "Microsoft.Storage/storageAccounts", "name": name,
                "sku": {"name": sku}, "properties": {}}

    def test_sku_change_on_uniquestring_storage_is_detected(self):
        arm = [self._storage(
            "toLower(format('{0}stg{1}', parameters('prefix'), take(uniqueString(x),6)))", "Standard_LRS")]
        live = [{"type": "microsoft.storage/storageaccounts", "name": "jacquidevstgm4fg23",
                 "sku": {"name": "Standard_GRS"}, "properties": {}}]
        comparison = _build_comparison_set(arm, live)
        # The remapped resource now carries the live name.
        self.assertEqual(comparison[-1]["name"], "jacquidevstgm4fg23")
        drifts = DriftDetector.detect_drift(comparison, live)
        modified = [d for d in drifts if d.drift_type == "modified"]
        self.assertTrue(any(
            any("sku" in pd.property_path for pd in d.property_diffs) for d in modified
        ), "storage SKU change on a uniqueString-named account should be detected")

    def test_two_storage_identical_name_expr_no_collision(self):
        # Both storage accounts share the SAME name expression (same module,
        # different purpose) - the pair-based remap must not collide.
        expr = "toLower(format('{0}st{1}', parameters('prefix'), take(uniqueString(x),6)))"
        arm = [self._storage(expr, "Standard_LRS"), self._storage(expr, "Standard_LRS")]
        live = [
            {"type": "microsoft.storage/storageaccounts", "name": "jacquidevstgm4fg23",
             "sku": {"name": "Standard_GRS"}, "properties": {}},
            {"type": "microsoft.storage/storageaccounts", "name": "jacquidevstla7m6et",
             "sku": {"name": "Standard_LRS"}, "properties": {}},
        ]
        comparison = _build_comparison_set(arm, live)
        names = sorted(c["name"] for c in comparison)
        self.assertEqual(names, ["jacquidevstgm4fg23", "jacquidevstla7m6et"])  # both, no collision
        drifts = DriftDetector.detect_drift(comparison, live)
        modified = [d for d in drifts if d.drift_type == "modified"]
        # Exactly the GRS account drifts (the other matches LRS==LRS).
        self.assertEqual(len(modified), 1)


if __name__ == "__main__":
    unittest.main()
