"""
Unit tests for Recovery Services vault backup drift (Backup Tranche - Phase 1).

vaults/backupconfig is NOT indexed by Resource Graph (confirmed live), so it is
fetched via ARM REST (_query_backup_children) and shaped as '{vault}/vaultconfig'
to match the Bicep child. softDeleteFeatureState is the headline backup security
control: disabling it lets backups be deleted immediately, and it is silent until
a restore is needed - so it and enhancedSecurityState are CRITICAL.

Backup POLICIES (schedule/retention) are Phase 2 and not covered here: the estate
declares no policy, and every vault carries built-in defaults that would need
selective matching to avoid extra_in_azure noise.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator
from tools.get_live_state import _shape_backup_config


def diffs_by_path(diffs):
    return {d.property_path: d for d in diffs}


TYPE = "Microsoft.RecoveryServices/vaults/backupconfig"


def _bicep(**props):
    return {"type": TYPE, "name": "rsv-drift-test/vaultconfig", "properties": props}


def _live(**props):
    # Azure augments with read-only fields; the bicep-keyed compare ignores them.
    base = {
        "softDeleteRetentionPeriodInDays": 14,
        "isSoftDeleteFeatureStateEditable": True,
    }
    base.update(props)
    return {"type": TYPE, "name": "rsv-drift-test/vaultconfig", "properties": base}


class BackupConfigShapeTests(unittest.TestCase):
    def test_shape_names_child_under_vault_and_keeps_props(self):
        payload = {
            "id": "/subscriptions/S/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv/backupconfig/vaultconfig",
            "name": "vaultconfig",
            "type": TYPE,
            "properties": {"softDeleteFeatureState": "Enabled", "enhancedSecurityState": "Enabled"},
        }
        shaped = _shape_backup_config("rsv", "rg", payload)
        self.assertEqual(shaped["name"], "rsv/vaultconfig")
        self.assertEqual(shaped["type"], TYPE)
        self.assertEqual(shaped["resource_group"], "rg")
        self.assertEqual(shaped["properties"]["softDeleteFeatureState"], "Enabled")


class BackupConfigDriftTests(unittest.TestCase):
    def test_clean_when_azure_adds_readonly_fields(self):
        bicep = _bicep(enhancedSecurityState="Enabled", softDeleteFeatureState="Enabled")
        live = _live(enhancedSecurityState="Enabled", softDeleteFeatureState="Enabled")
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_soft_delete_disabled_is_critical(self):
        bicep = _bicep(enhancedSecurityState="Enabled", softDeleteFeatureState="Enabled")
        live = _live(enhancedSecurityState="Enabled", softDeleteFeatureState="Disabled")
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.softDeleteFeatureState", d)
        self.assertEqual(d["properties.softDeleteFeatureState"].severity, "critical")

    def test_enhanced_security_disabled_is_critical(self):
        bicep = _bicep(enhancedSecurityState="Enabled", softDeleteFeatureState="Enabled")
        live = _live(enhancedSecurityState="Disabled", softDeleteFeatureState="Enabled")
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        self.assertIn("properties.enhancedSecurityState", d)
        self.assertEqual(d["properties.enhancedSecurityState"].severity, "critical")

    def test_live_only_retention_field_does_not_false_flag(self):
        # bicep omits softDeleteRetentionPeriodInDays; the live-only value must not drift.
        bicep = _bicep(softDeleteFeatureState="Enabled")
        live = _live(softDeleteFeatureState="Enabled")
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])


if __name__ == "__main__":
    unittest.main()
