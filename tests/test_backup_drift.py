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
from tools.get_live_state import _shape_backup_config, _shape_backup_policy
from tools.diff_states import filter_unmanaged_live_resources


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


POLICY_TYPE = "Microsoft.RecoveryServices/vaults/backupPolicies"


def _policy_live(name, count=30):
    return {
        "type": POLICY_TYPE,
        "name": f"rsv-drift-test/{name}",
        "properties": {
            "backupManagementType": "AzureIaasVM",
            "schedulePolicy": {"scheduleRunFrequency": "Daily"},
            "retentionPolicy": {
                "retentionPolicyType": "LongTermRetentionPolicy",
                "dailySchedule": {"retentionDuration": {"count": count, "durationType": "Days"}},
            },
        },
    }


class BackupPolicySuppressionTests(unittest.TestCase):
    """Built-in default policies (DefaultPolicy/EnhancedPolicy/HourlyLogBackup)
    ship with every vault; only a DECLARED policy should survive to compare."""

    def _defaults_plus(self, *extra_names):
        live = [_policy_live(n) for n in ("DefaultPolicy", "EnhancedPolicy", "HourlyLogBackup")]
        live += [_policy_live(n) for n in extra_names]
        return live

    def test_undeclared_defaults_are_dropped(self):
        live = self._defaults_plus()
        filtered = filter_unmanaged_live_resources(live, filtered_arm=[])  # estate declares no policy
        self.assertEqual([r for r in filtered if r["type"] == POLICY_TYPE], [])

    def test_declared_policy_survives_defaults_dropped(self):
        live = self._defaults_plus("drift-vm-policy")
        bicep = [{"type": POLICY_TYPE, "name": "rsv-drift-test/drift-vm-policy", "properties": {}}]
        filtered = filter_unmanaged_live_resources(live, filtered_arm=bicep)
        kept = [r["name"] for r in filtered if r["type"] == POLICY_TYPE]
        self.assertEqual(kept, ["rsv-drift-test/drift-vm-policy"])


class BackupPolicyDriftTests(unittest.TestCase):
    def _bicep(self, count):
        return {
            "type": POLICY_TYPE,
            "name": "rsv-drift-test/drift-vm-policy",
            "properties": {
                "retentionPolicy": {"dailySchedule": {"retentionDuration": {"count": count, "durationType": "Days"}}},
            },
        }

    def test_retention_shortened_is_critical(self):
        bicep = self._bicep(30)
        live = _policy_live("drift-vm-policy", count=7)   # 30 -> 7 days out of band
        d = diffs_by_path(PropertyComparator.compare_properties(bicep, live))
        path = "properties.retentionPolicy.dailySchedule.retentionDuration.count"
        self.assertIn(path, d)
        self.assertEqual(d[path].severity, "critical")

    def test_clean_policy_no_drift(self):
        bicep = self._bicep(30)
        live = _policy_live("drift-vm-policy", count=30)
        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])

    def test_shape_policy_names_under_vault(self):
        payload = {"name": "drift-vm-policy", "type": POLICY_TYPE,
                   "id": "/subscriptions/S/.../backupPolicies/drift-vm-policy",
                   "properties": {"backupManagementType": "AzureIaasVM"}}
        shaped = _shape_backup_policy("rsv-drift-test", "rg", payload)
        self.assertEqual(shaped["name"], "rsv-drift-test/drift-vm-policy")
        self.assertEqual(shaped["type"], POLICY_TYPE)


if __name__ == "__main__":
    unittest.main()
