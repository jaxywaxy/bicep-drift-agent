"""
tools/property_drift/validators.py

Cross-resource configuration checks that go beyond property-level diff:
orphaned managed disks, VMs with no NICs, VM data-disk add/remove/modify.
These operate over the whole deployed set (not per-match) and emit their own
ResourceDrift records with change_type='critical_config_error' or 'modified'.
"""

from .models import PropertyDiff, ResourceDrift, ResourceIndexer


class ConfigurationValidator:
    """Validate resource configurations for critical issues."""

    @staticmethod
    def check_orphaned_disks(deployed_resources: list[dict]) -> list[ResourceDrift]:
        """Detect orphaned disks (OS and data disks not attached to any VM).

        This is a critical issue because:
        - Orphaned disks consume storage costs
        - They indicate VMs were deleted without proper cleanup
        - They prevent resource group deletion
        """
        drifts = []

        vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")
        disks = ResourceIndexer.filter_by_type(deployed_resources, "Microsoft.Compute/disks")

        for disk in disks:
            disk_name = disk.get("name", "")
            disk_id = disk.get("id", "")

            is_attached = False
            for vm_name, vm in vms.items():
                vm_props = vm.get("properties", {})
                if vm_props.get("storageProfile", {}).get("osDisk", {}).get("managedDisk", {}).get("id") == disk_id:
                    is_attached = True
                    break

                for data_disk in vm_props.get("storageProfile", {}).get("dataDisks", []):
                    if data_disk.get("managedDisk", {}).get("id") == disk_id:
                        is_attached = True
                        break

                if is_attached:
                    break

            if not is_attached:
                drifts.append(
                    ResourceDrift(
                        resource_type="Microsoft.Compute/disks",
                        resource_name=disk_name,
                        bicep_name="",
                        deployed_name=disk_name,
                        drift_type="critical_config_error",
                        property_diffs=[
                            PropertyDiff(
                                property_path="attachment_status",
                                desired_value="attached to VM",
                                actual_value="orphaned",
                                change_type="modified",
                                severity="critical",
                            )
                        ],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def check_vms_without_nics(deployed_resources: list[dict]) -> list[ResourceDrift]:
        """Detect VMs without network interfaces (critical configuration error)."""
        drifts = []

        vms = [r for r in deployed_resources
               if r.get("type") == "Microsoft.Compute/virtualMachines"]
        nic_ids = ResourceIndexer.by_id(deployed_resources, "Microsoft.Network/networkInterfaces")

        for vm in vms:
            vm_name = vm.get("name", "")
            vm_props = vm.get("properties", {})
            nic_refs = vm_props.get("networkProfile", {}).get("networkInterfaces", [])

            has_nics = False
            for nic_ref in nic_refs:
                nic_id = nic_ref.get("id", "")
                if nic_id in nic_ids:
                    has_nics = True
                    break

            if not has_nics:
                drifts.append(
                    ResourceDrift(
                        resource_type="Microsoft.Compute/virtualMachines",
                        resource_name=vm_name,
                        bicep_name="",
                        deployed_name=vm_name,
                        drift_type="critical_config_error",
                        property_diffs=[
                            PropertyDiff(
                                property_path="networkInterfaces",
                                desired_value="at least 1 NIC",
                                actual_value="0 NICs",
                                change_type="modified",
                                severity="critical",
                            )
                        ],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def check_data_disk_changes(
        bicep_resources: list[dict],
        deployed_resources: list[dict],
    ) -> list[ResourceDrift]:
        """Detect data disk additions, removals, and modifications on VMs.

        Data disk changes are important configuration drifts because they affect
        storage capacity and performance. Reports when:
        - Data disks are added to deployed VMs (not in Bicep)
        - Data disks are removed from deployed VMs (in Bicep but not deployed)
        - Data disk properties change (size, caching, etc.)
        """
        drifts = []

        bicep_vms = {r.get("name", ""): r for r in bicep_resources
                     if r.get("type") == "Microsoft.Compute/virtualMachines"}
        deployed_vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")

        for vm_name in set(bicep_vms.keys()) & set(deployed_vms.keys()):
            bicep_vm = bicep_vms[vm_name]
            deployed_vm = deployed_vms[vm_name]

            bicep_disks = bicep_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])
            deployed_disks = deployed_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])

            bicep_by_lun = {d.get("lun"): d for d in bicep_disks if isinstance(d, dict)}
            deployed_by_lun = {d.get("lun"): d for d in deployed_disks if isinstance(d, dict)}

            for lun, deployed_disk in deployed_by_lun.items():
                if lun not in bicep_by_lun:
                    disk_name = deployed_disk.get("name", f"DataDisk-LUN{lun}")
                    disk_size = deployed_disk.get("diskSizeGB", "unknown")
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}]",
                                    desired_value="(not defined in Bicep)",
                                    actual_value=f"{disk_name} ({disk_size}GB, LUN {lun})",
                                    change_type="added",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

            for lun, bicep_disk in bicep_by_lun.items():
                if lun not in deployed_by_lun:
                    disk_name = bicep_disk.get("name", f"DataDisk-LUN{lun}")
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}]",
                                    desired_value=f"{disk_name} (in Bicep)",
                                    actual_value="(not attached)",
                                    change_type="removed",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

            for lun in set(bicep_by_lun.keys()) & set(deployed_by_lun.keys()):
                bicep_disk = bicep_by_lun[lun]
                deployed_disk = deployed_by_lun[lun]

                bicep_size = bicep_disk.get("diskSizeGB")
                deployed_size = deployed_disk.get("diskSizeGB")
                if bicep_size and deployed_size and bicep_size != deployed_size:
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}].diskSizeGB",
                                    desired_value=bicep_size,
                                    actual_value=deployed_size,
                                    change_type="modified",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

        return drifts
