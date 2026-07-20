"""
Compute tranche: managed disks, scale sets, availability sets, zone placement.

Three distinct gaps this round closes:

1. DECLARED MANAGED DISKS WERE INVISIBLE. filter_unmanaged_live_resources
   dropped every live Microsoft.Compute/disks row as "created by VMs", so a
   data disk declared as its own bicep resource false-flagged missing_in_azure
   and no out-of-band change to it (resize, networkAccessPolicy opened,
   encryption swapped) could ever be reported. The drop now applies only to
   disks matching no declared disk - a VM's implicit OS disk still stays out.

2. RESILIENCY PROPERTIES RATED AS NOISE. Zone lists and availability-set fault/
   update domain counts are the difference between redundant and not, but they
   scored "warning" alongside cosmetic tag churn.

3. ZONES COMPARED AS A SUBSET. The generic list compare is one-directional, so
   a live zone list that gained or lost entries against a template declaring []
   was invisible - the vacuous-subset trap already fixed for firewall scalar
   lists and Key Vault allowlists.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.diff_states import filter_unmanaged_live_resources
from tools.property_drift import PropertyComparator

DISK_TYPE = "Microsoft.Compute/disks"
VMSS_TYPE = "Microsoft.Compute/virtualMachineScaleSets"
AVSET_TYPE = "Microsoft.Compute/availabilitySets"


def _disk(name, network_access_policy="DenyAll", size=4, zones=None):
    resource = {
        "type": DISK_TYPE,
        "name": name,
        "id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/disks/{name}",
        "properties": {
            "diskSizeGB": size,
            "networkAccessPolicy": network_access_policy,
            "encryption": {"type": "EncryptionAtRestWithPlatformKey"},
        },
    }
    if zones is not None:
        resource["zones"] = zones
    return resource


class DeclaredDiskVisibilityTests(unittest.TestCase):
    """A disk declared in bicep must survive the auto-managed filter."""

    def test_declared_disk_survives(self):
        live = [_disk("disk-drift-data"), _disk("vm-drift-test_OsDisk_1_9f3a")]
        arm = [_disk("disk-drift-data")]

        kept = {r["name"] for r in filter_unmanaged_live_resources(live, arm)}

        self.assertIn("disk-drift-data", kept)

    def test_vm_created_os_disk_still_dropped(self):
        """The implicit OS disk must not become a false extra_in_azure."""
        live = [_disk("disk-drift-data"), _disk("vm-drift-test_OsDisk_1_9f3a")]
        arm = [_disk("disk-drift-data")]

        kept = {r["name"] for r in filter_unmanaged_live_resources(live, arm)}

        self.assertNotIn("vm-drift-test_OsDisk_1_9f3a", kept)

    def test_no_declared_disks_drops_all(self):
        """Unchanged behaviour when the template declares no disks at all."""
        live = [_disk("vm-drift-test_OsDisk_1_9f3a")]

        self.assertEqual(filter_unmanaged_live_resources(live, []), [])

    def test_placeholder_named_disk_matches_by_static_prefix(self):
        """uniqueString-named declarations still claim their live disk."""
        live = [_disk("diskdrifttest86c9cbf6")]
        arm = [_disk("diskdrifttest[86c9cbf6]")]

        kept = {r["name"] for r in filter_unmanaged_live_resources(live, arm)}

        self.assertIn("diskdrifttest86c9cbf6", kept)

    def test_vm_extensions_unaffected_when_disks_declared(self):
        live = [{
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "name": "vm-drift-test/AzureMonitorLinuxAgent",
        }]

        self.assertEqual(filter_unmanaged_live_resources(live, [_disk("d1")]), [])


class DiskPropertyDriftTests(unittest.TestCase):
    def test_network_access_policy_opened_is_critical(self):
        diffs = PropertyComparator.compare_properties(
            _disk("disk-drift-data", network_access_policy="DenyAll"),
            _disk("disk-drift-data", network_access_policy="AllowAll"),
        )

        by_path = {d.property_path: d for d in diffs}
        self.assertIn("properties.networkAccessPolicy", by_path)
        self.assertEqual(by_path["properties.networkAccessPolicy"].severity, "critical")

    def test_encryption_type_change_is_critical(self):
        self.assertEqual(
            PropertyComparator._get_severity("properties.encryption.type"), "critical"
        )

    def test_undeclared_network_access_policy_caught_by_sentinel(self):
        """Template omits the key entirely; `az disk update` adds it live."""
        bicep = {"type": DISK_TYPE, "name": "d", "properties": {"diskSizeGB": 4}}
        live = {
            "type": DISK_TYPE,
            "name": "d",
            "properties": {"diskSizeGB": 4, "networkAccessPolicy": "AllowPrivate"},
        }

        diffs = PropertyComparator.compare_properties(bicep, live)

        sentinel = [d for d in diffs if d.property_path == "properties.networkAccessPolicy"]
        self.assertEqual(len(sentinel), 1)
        self.assertEqual(sentinel[0].change_type, "added")
        self.assertEqual(sentinel[0].severity, "critical")

    def test_sentinel_silent_at_documented_default(self):
        bicep = {"type": DISK_TYPE, "name": "d", "properties": {"diskSizeGB": 4}}
        live = {
            "type": DISK_TYPE,
            "name": "d",
            "properties": {"diskSizeGB": 4, "networkAccessPolicy": "AllowAll"},
        }

        self.assertEqual(PropertyComparator.compare_properties(bicep, live), [])


class ZonePlacementTests(unittest.TestCase):
    """Zones are exact-set: drift in BOTH directions, including from []."""

    def test_zone_removed_is_drift(self):
        diffs = PropertyComparator.compare_properties(
            _disk("d", zones=["1", "2", "3"]), _disk("d", zones=["1"])
        )

        self.assertIn("zones", {d.property_path for d in diffs})

    def test_zone_added_against_empty_declaration_is_drift(self):
        """The vacuous-subset case: [] would 'contain' nothing to miss."""
        diffs = PropertyComparator.compare_properties(
            _disk("d", zones=[]), _disk("d", zones=["2"])
        )

        self.assertIn("zones", {d.property_path for d in diffs})

    def test_matching_zones_are_clean(self):
        diffs = PropertyComparator.compare_properties(
            _disk("d", zones=["1", "2"]), _disk("d", zones=["2", "1"])
        )

        self.assertEqual(diffs, [])

    def test_zones_rate_critical(self):
        self.assertEqual(PropertyComparator._get_severity("zones"), "critical")


class ResiliencySeverityTests(unittest.TestCase):
    def test_availability_set_domain_counts_are_critical(self):
        bicep = {
            "type": AVSET_TYPE,
            "name": "avset-drift-test",
            "properties": {"platformFaultDomainCount": 2, "platformUpdateDomainCount": 5},
        }
        live = {
            "type": AVSET_TYPE,
            "name": "avset-drift-test",
            "properties": {"platformFaultDomainCount": 1, "platformUpdateDomainCount": 5},
        }

        diffs = PropertyComparator.compare_properties(bicep, live)

        by_path = {d.property_path: d for d in diffs}
        self.assertIn("properties.platformFaultDomainCount", by_path)
        self.assertEqual(
            by_path["properties.platformFaultDomainCount"].severity, "critical"
        )

    def test_automatic_repairs_disabled_is_critical(self):
        self.assertEqual(
            PropertyComparator._get_severity("properties.automaticRepairsPolicy.enabled"),
            "critical",
        )


class ScaleSetSeverityTests(unittest.TestCase):
    def test_upgrade_policy_downgrade_is_critical(self):
        bicep = {
            "type": VMSS_TYPE,
            "name": "vmss-drift-test",
            "sku": {"name": "Standard_B1s", "capacity": 0},
            "properties": {"upgradePolicy": {"mode": "Automatic"}},
        }
        live = {
            "type": VMSS_TYPE,
            "name": "vmss-drift-test",
            "sku": {"name": "Standard_B1s", "capacity": 0},
            "properties": {"upgradePolicy": {"mode": "Manual"}},
        }

        diffs = PropertyComparator.compare_properties(bicep, live)

        by_path = {d.property_path: d for d in diffs}
        self.assertEqual(by_path["properties.upgradePolicy.mode"].severity, "critical")

    def test_capacity_change_is_critical(self):
        """Scaling a set out/in is a cost and capacity event."""
        self.assertEqual(PropertyComparator._get_severity("sku.capacity"), "critical")

    def test_encryption_at_host_critical_in_both_declaration_shapes(self):
        for path in (
            "properties.securityProfile.encryptionAtHost",
            "properties.virtualMachineProfile.securityProfile.encryptionAtHost",
        ):
            with self.subTest(path=path):
                self.assertEqual(PropertyComparator._get_severity(path), "critical")

    def test_instance_public_ip_is_critical(self):
        path = (
            "properties.virtualMachineProfile.networkProfile"
            ".networkInterfaceConfigurations[0].ipConfigurations[0]"
            ".publicIPAddressConfiguration.name"
        )

        self.assertEqual(PropertyComparator._get_severity(path), "critical")


if __name__ == "__main__":
    unittest.main()
