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
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


if __name__ == "__main__":
    unittest.main()
