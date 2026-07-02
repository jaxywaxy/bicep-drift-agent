"""
Unit tests for layered ignore profiles (Phase 4): agent baseline + per-LZ repo.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ignore_patterns import IgnorePatternList


def _write(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".drift-ignore", delete=False)
    f.write(text)
    f.close()
    return f.name


class IgnoreLayeringTests(unittest.TestCase):
    def test_from_files_merges_both_profiles(self):
        baseline = _write("ignore:\n  - resource_type: 'Microsoft.Network/networkWatchers'\n    reason: universal\n")
        repo = _write("ignore:\n  - resource_type: 'Microsoft.Network/virtualNetworks'\n    reason: workload LZ\n")
        il = IgnorePatternList.from_files(baseline, repo)
        drifts = [
            {"type": "Microsoft.Network/networkWatchers", "name": "nw", "drift_type": "extra_in_azure"},
            {"type": "Microsoft.Network/virtualNetworks", "name": "vnet", "drift_type": "property_drift",
             "details": {"changed_properties": {"properties.addressSpace": {}}}},
            {"type": "Microsoft.Storage/storageAccounts", "name": "st", "drift_type": "property_drift",
             "details": {"changed_properties": {"properties.accessTier": {}}}},
        ]
        filtered, ignored = il.filter_drifts(drifts)
        ignored_types = {d["type"] for d in ignored}
        self.assertIn("Microsoft.Network/networkWatchers", ignored_types)   # from baseline
        self.assertIn("Microsoft.Network/virtualNetworks", ignored_types)   # from repo profile
        self.assertEqual([d["type"] for d in filtered], ["Microsoft.Storage/storageAccounts"])

    def test_platform_lz_without_network_profile_surfaces_network(self):
        # Baseline only (no per-LZ network ignores) = platform LZ scenario:
        # network drift is NOT ignored -> it surfaces.
        baseline = _write("ignore:\n  - resource_type: 'Microsoft.Network/networkWatchers'\n    reason: universal\n")
        il = IgnorePatternList.from_files(baseline, None)
        drifts = [{"type": "Microsoft.Network/virtualNetworks", "name": "vnet",
                   "drift_type": "property_drift",
                   "details": {"changed_properties": {"properties.addressSpace": {}}}}]
        filtered, ignored = il.filter_drifts(drifts)
        self.assertEqual(len(filtered), 1)   # surfaces
        self.assertEqual(len(ignored), 0)

    def test_missing_files_are_skipped(self):
        il = IgnorePatternList.from_files("/no/such/file", None)
        self.assertEqual(il.patterns, [])


if __name__ == "__main__":
    unittest.main()
