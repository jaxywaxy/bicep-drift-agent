"""
Property-level drift detection.

Compares resource properties between Bicep (desired) and deployed (actual)
to detect configuration changes outside of IaC.
"""

import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class PropertyDiff:
    """A single property difference."""
    property_path: str  # e.g., "properties.sku.name"
    desired_value: Any  # From Bicep
    actual_value: Any   # From Azure
    change_type: str    # "modified", "added", "removed"
    severity: str       # "critical", "warning", "info"


@dataclass
class ResourceDrift:
    """Drift information for a single resource."""
    resource_type: str
    resource_name: str
    bicep_name: str      # Name from Bicep template
    deployed_name: str   # Name of deployed resource
    drift_type: str      # "missing", "extra", "modified", "unchanged"
    property_diffs: List[PropertyDiff]
    match_confidence: float  # 0.0 to 1.0


class PropertyExtractor:
    """Extract properties from resources."""

    @staticmethod
    def extract_bicep_properties(resource: Dict) -> Dict[str, Any]:
        """Extract properties from a Bicep-compiled ARM resource."""
        properties = {}

        # Top-level properties (skip apiVersion — it's ARM template metadata, not a deployment property)
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]

        # Resource-specific properties
        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties

    @staticmethod
    def extract_azure_properties(resource: Dict) -> Dict[str, Any]:
        """Extract properties from an Azure-deployed resource."""
        properties = {}

        # Top-level properties
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "id" in resource:
            properties["id"] = resource["id"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]

        # Resource-specific properties
        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties


class ResourceMatcher:
    """Match Bicep resources to deployed resources using intelligent contextual matching."""

    @staticmethod
    def _find_associated_resource(resource: Dict, bicep_resources: List[Dict], resource_type: str) -> Dict:
        """Find a related resource (e.g., find VM for a NIC by name similarity)."""
        res_name = resource.get("name", "")
        # Extract name tokens from resource (e.g., 'vm-dev-001-nic' → 'vm-dev-001')
        name_tokens = res_name.replace('-nic', '').replace('-nic-', '-')

        # Look for resources of target type with similar names
        for r in bicep_resources:
            if r.get("type") == resource_type:
                r_name = r.get("name", "")
                if name_tokens in r_name or r_name in name_tokens:
                    return r
        return None

    @staticmethod
    def _find_parent_vm(disk_name: str, bicep_resources: List[Dict]) -> Dict:
        """Find parent VM for a managed disk by extracting VM name from disk name.

        Example: vm-prod-002_OsDisk_1_<hash> → extract 'vm-prod-002'
        """
        # Extract VM name from disk (before first underscore)
        vm_name = disk_name.split('_')[0] if '_' in disk_name else None
        if not vm_name:
            return None

        # Find matching VM
        for r in bicep_resources:
            if r.get("type") == "Microsoft.Compute/virtualMachines":
                if r.get("name", "").lower() == vm_name.lower():
                    return r
        return None

    @staticmethod
    def match_resources(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[Tuple[Dict, Dict, float]]:
        """
        Match Bicep resources to deployed resources using intelligent contextual matching.

        Strategy:
        1. Exact name matches (highest confidence)
        2. Contextual matching: for identical-named resources, use related resources
           to disambiguate (e.g., match NICs via their VMs)
        3. Fuzzy token-based matching (parameter-based names)
        4. Positional matching as fallback for true duplicates

        Returns:
            List of (bicep_resource, deployed_resource, confidence) tuples
        """
        matches = []
        deployed_by_type = defaultdict(list)

        # Index deployed resources by type
        for resource in deployed_resources:
            resource_type = resource.get("type", "")
            deployed_by_type[resource_type].append(resource)

        # Track used deployed resources
        used_deployed = set()

        # First pass: exact matches
        for bicep_resource in bicep_resources:
            resource_type = bicep_resource.get("type", "")
            bicep_name = bicep_resource.get("name", "")

            candidates = [r for r in deployed_by_type.get(resource_type, []) if id(r) not in used_deployed]
            if not candidates:
                continue

            exact_match = None
            for deployed in candidates:
                deployed_name = deployed.get("name", "")
                if bicep_name == deployed_name or bicep_name in deployed_name:
                    exact_match = deployed
                    break

            if exact_match:
                matches.append((bicep_resource, exact_match, 0.95))
                used_deployed.add(id(exact_match))

        # Second pass: contextual + fuzzy matching for remaining resources
        bicep_by_type = defaultdict(list)
        for bicep_resource in bicep_resources:
            if id(bicep_resource) not in {id(b) for b, _, _ in matches}:
                bicep_by_type[bicep_resource.get("type", "")].append(bicep_resource)

        for resource_type, bicep_res_list in bicep_by_type.items():
            candidates = [r for r in deployed_by_type.get(resource_type, []) if id(r) not in used_deployed]
            if not candidates:
                continue

            # Check if all bicep resources have identical names (e.g., 4x "parameters('vmName')-nic")
            bicep_names = [r.get("name", "") for r in bicep_res_list]
            all_identical = len(set(bicep_names)) == 1

            for bicep_idx, bicep_resource in enumerate(bicep_res_list):
                bicep_name = bicep_resource.get("name", "")
                best_match = None
                best_score = 0.25
                best_match_idx = -1

                # For identical-named resources, try contextual matching via related resources
                if resource_type == "Microsoft.Compute/disks":
                    # For disks, try to match via parent VM
                    # Extract VM name from disk name (e.g., vm-prod-002_OsDisk_1_<hash> → vm-prod-002)
                    disk_name = bicep_resource.get("name", "")
                    parent_vm = ResourceMatcher._find_parent_vm(disk_name, bicep_resources)
                    if parent_vm:
                        # Find which deployed disk matches this parent VM
                        for cand_idx, candidate in enumerate(candidates):
                            cand_name = candidate.get("name", "")
                            # Check if candidate disk belongs to parent VM
                            vm_name_from_disk = cand_name.split('_')[0] if '_' in cand_name else None
                            if vm_name_from_disk and vm_name_from_disk.lower() == parent_vm.get("name", "").lower():
                                best_match = candidate
                                best_match_idx = cand_idx
                                best_score = 0.95  # High confidence: matched via parent VM
                                break

                if all_identical and resource_type == "Microsoft.Network/networkInterfaces":
                    # Try to match NIC via its associated VM
                    associated_vm = ResourceMatcher._find_associated_resource(bicep_resource, bicep_resources, "Microsoft.Compute/virtualMachines")
                    if associated_vm:
                        # Find the deployed VM this bicep VM matches to
                        for matched_bicep, matched_deployed, _ in matches:
                            if matched_bicep.get("name") == associated_vm.get("name"):
                                # Now find the NIC that matches this deployed VM
                                vm_name = matched_deployed.get("name", "")
                                for cand_idx, candidate in enumerate(candidates):
                                    cand_name = candidate.get("name", "")
                                    if vm_name in cand_name:
                                        best_match = candidate
                                        best_match_idx = cand_idx
                                        best_score = 0.90
                                        break
                                if best_match:
                                    break

                # If contextual matching didn't work, try fuzzy matching
                if not best_match:
                    for cand_idx, deployed in enumerate(candidates):
                        deployed_name = deployed.get("name", "")
                        bicep_clean = bicep_name.replace('[', '').replace(']', '').replace("'", '').replace('parameters(', '').replace(')', '')
                        deployed_clean = deployed_name

                        bicep_tokens = [t for t in bicep_clean.split('-') if len(t) > 1 and t not in ('vmName', 'vaultName', 'name')]
                        deployed_tokens = [t for t in deployed_clean.split('-') if len(t) > 1]

                        if bicep_tokens and deployed_tokens:
                            matches_count = sum(1 for bt in bicep_tokens if any(dt.startswith(bt) or bt in dt for dt in deployed_tokens))
                            score = matches_count / max(len(bicep_tokens), len(deployed_tokens))
                            if score > best_score:
                                best_score = score
                                best_match = deployed
                                best_match_idx = cand_idx

                # Fallback: positional matching for identical-named resources
                if not best_match and all_identical and len(candidates) >= len(bicep_res_list):
                    # Match by position in list
                    best_match = candidates[bicep_idx]
                    best_match_idx = bicep_idx
                    best_score = 0.60

                if best_match:
                    matches.append((bicep_resource, best_match, best_score))
                    used_deployed.add(id(best_match))
                elif len(candidates) == 1:
                    matches.append((bicep_resource, candidates[0], 0.70))
                    used_deployed.add(id(candidates[0]))

        return matches


class PropertyComparator:
    """Compare properties between desired and actual resources."""

    CRITICAL_PROPERTIES = {
        # Location and kind are fundamental
        "location",
        "kind",
        # SKU properties (pricing tier, size, capacity)
        "sku.name",
        "sku.tier",
        "sku.family",
        "sku.size",
        "sku.capacity",
        # VM-specific
        "properties.hardwareProfile.vmSize",
        # Storage-specific
        "properties.accountType",
        "properties.replicationType",
        "properties.accessTier",
        # Database-specific
        "properties.edition",
        "properties.serviceLevelObjective",
        # App Service-specific
        "properties.reserved",
        "properties.workerSize",
    }

    WRITE_ONLY_PROPERTIES = {
        # VM OS profile (not returned by Azure API for security/privacy)
        "properties.osprofile.adminusername",
        "properties.osprofile.adminpassword",
        "properties.osprofile.computername",
        "properties.osprofile.linuxconfiguration.disablepasswordauthentication",
        "properties.osprofile.linuxconfiguration.ssh",
        "properties.osprofile.windowsconfiguration.enableautomaticupdates",
        "properties.osprofile.windowsconfiguration.provisionvmagent",
        # Storage profile (image reference is immutable post-deployment)
        "properties.storageprofile.imagereference.publisher",
        "properties.storageprofile.imagereference.offer",
        "properties.storageprofile.imagereference.sku",
        "properties.storageprofile.imagereference.version",
        # OS disk properties (immutable post-deployment)
        "properties.storageprofile.osdisk.createoption",
        "properties.storageprofile.osdisk.manageddisk.storageaccounttype",
        # Network interfaces (Bicep uses expressions, Azure returns resolved IDs - functionally equivalent)
        "properties.networkprofile.networkinterfaces",
    }

    @staticmethod
    def compare_properties(
        bicep_properties: Dict[str, Any],
        deployed_properties: Dict[str, Any],
    ) -> List[PropertyDiff]:
        """
        Compare properties between Bicep and deployed resources.

        Returns:
            List of PropertyDiff objects
        """
        diffs = []

        # Flatten both property dicts for comparison
        bicep_flat = PropertyComparator._flatten_dict(bicep_properties)
        deployed_flat = PropertyComparator._flatten_dict(deployed_properties)

        # Check for modified properties
        for key, bicep_value in bicep_flat.items():
            if key in deployed_flat:
                # Skip write-only properties (Azure doesn't return these in API responses)
                if PropertyComparator._is_write_only_property(key):
                    continue

                deployed_value = deployed_flat[key]
                if bicep_value != deployed_value:
                    severity = PropertyComparator._get_severity(key)
                    diffs.append(
                        PropertyDiff(
                            property_path=key,
                            desired_value=bicep_value,
                            actual_value=deployed_value,
                            change_type="modified",
                            severity=severity,
                        )
                    )

        # Check for removed properties (in Bicep but not deployed)
        for key, bicep_value in bicep_flat.items():
            if key not in deployed_flat:
                # Skip write-only properties (Azure doesn't return these in API responses)
                if PropertyComparator._is_write_only_property(key):
                    continue

                diffs.append(
                    PropertyDiff(
                        property_path=key,
                        desired_value=bicep_value,
                        actual_value=None,
                        change_type="removed",
                        severity="info",
                    )
                )

        # NOTE: Skip added properties (deployed but not in Bicep)
        # These are optional properties that Azure manages automatically.
        # If not explicitly defined in the Bicep template, they should not
        # be reported as drift. Examples: sku fields, tags added by policies,
        # Azure-managed system properties, etc.
        # Only report properties that are explicitly defined in Bicep template.

        return diffs

    @staticmethod
    def _flatten_dict(d: Dict, parent_key: str = "", sep: str = ".") -> Dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(PropertyComparator._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, (list, tuple)):
                # Skip complex nested structures for now
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)

    @staticmethod
    def _get_severity(property_path: str) -> str:
        """Determine severity of property change."""
        for critical in PropertyComparator.CRITICAL_PROPERTIES:
            if critical in property_path.lower():
                return "critical"
        return "warning"

    @staticmethod
    def _is_write_only_property(property_path: str) -> bool:
        """Check if property is write-only (not returned by Azure API).

        Write-only properties include:
        - Credentials (admin passwords, SSH keys)
        - OS profile settings (Azure returns null)
        - Immutable properties (image reference, disk creation options)
        """
        path_lower = property_path.lower()
        for write_only in PropertyComparator.WRITE_ONLY_PROPERTIES:
            if write_only == path_lower or path_lower.startswith(write_only + "."):
                return True
        return False

    @staticmethod
    def _is_system_property(key: str) -> bool:
        """Check if property is system-generated."""
        system_prefixes = {
            "id",
            "systemData",
            "etag",
            "managedBy",
            "identity.principalId",
            "identity.tenantId",
        }
        return any(key.startswith(prefix) for prefix in system_prefixes)


class ConfigurationValidator:
    """Validate resource configurations for critical issues."""

    @staticmethod
    def check_orphaned_disks(deployed_resources: List[Dict]) -> List[ResourceDrift]:
        """
        Detect orphaned disks (OS and data disks not attached to any VM).

        This is a critical issue because:
        - Orphaned disks consume storage costs
        - They indicate VMs were deleted without proper cleanup
        - They prevent resource group deletion
        """
        drifts = []

        # Get all VMs and disks
        vms = {r.get("name", ""): r for r in deployed_resources
               if r.get("type") == "Microsoft.Compute/virtualMachines"}
        disks = [r for r in deployed_resources
                if r.get("type") == "Microsoft.Compute/disks"]

        for disk in disks:
            disk_name = disk.get("name", "")
            disk_id = disk.get("id", "")

            # Check if disk is attached to any VM
            is_attached = False
            for vm_name, vm in vms.items():
                # Check OS disk
                vm_props = vm.get("properties", {})
                if vm_props.get("storageProfile", {}).get("osDisk", {}).get("managedDisk", {}).get("id") == disk_id:
                    is_attached = True
                    break

                # Check data disks
                for data_disk in vm_props.get("storageProfile", {}).get("dataDisks", []):
                    if data_disk.get("managedDisk", {}).get("id") == disk_id:
                        is_attached = True
                        break

                if is_attached:
                    break

            # If disk is not attached, it's orphaned
            if not is_attached:
                # Determine if it's an OS disk or data disk
                disk_type = "OS disk"
                if "_DataDisk_" in disk_name or "_datadisk_" in disk_name.lower():
                    disk_type = "Data disk"

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
    def check_vms_without_nics(deployed_resources: List[Dict]) -> List[ResourceDrift]:
        """
        Detect VMs without network interfaces (critical configuration error).

        A VM cannot function without at least one NIC. If a VM exists but has
        no NICs attached, it's a critical issue indicating:
        - Manual NIC deletion
        - Network interface failure
        - Incomplete deployment
        """
        drifts = []

        # Get all VMs and NICs
        vms = [r for r in deployed_resources
               if r.get("type") == "Microsoft.Compute/virtualMachines"]
        nic_ids = {r.get("id", ""): r.get("name", "") for r in deployed_resources
                   if r.get("type") == "Microsoft.Network/networkInterfaces"}

        for vm in vms:
            vm_name = vm.get("name", "")
            vm_props = vm.get("properties", {})
            nic_refs = vm_props.get("networkProfile", {}).get("networkInterfaces", [])

            # Check if VM has any NICs
            has_nics = False
            for nic_ref in nic_refs:
                nic_id = nic_ref.get("id", "")
                if nic_id in nic_ids:
                    has_nics = True
                    break

            # If VM has no NICs, it's a critical issue
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
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[ResourceDrift]:
        """
        Detect data disk additions, removals, and modifications on VMs.

        Data disk changes are important configuration drifts because they affect
        storage capacity and performance. Reports when:
        - Data disks are added to deployed VMs (not in Bicep)
        - Data disks are removed from deployed VMs (in Bicep but not deployed)
        - Data disk properties change (size, caching, etc.)
        """
        drifts = []

        # Create lookup maps
        bicep_vms = {r.get("name", ""): r for r in bicep_resources
                     if r.get("type") == "Microsoft.Compute/virtualMachines"}
        deployed_vms = {r.get("name", ""): r for r in deployed_resources
                        if r.get("type") == "Microsoft.Compute/virtualMachines"}

        # Check VMs that exist in both (matched resources)
        for vm_name in set(bicep_vms.keys()) & set(deployed_vms.keys()):
            bicep_vm = bicep_vms[vm_name]
            deployed_vm = deployed_vms[vm_name]

            bicep_disks = bicep_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])
            deployed_disks = deployed_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])

            # Convert to dicts keyed by LUN for comparison
            bicep_by_lun = {d.get("lun"): d for d in bicep_disks if isinstance(d, dict)}
            deployed_by_lun = {d.get("lun"): d for d in deployed_disks if isinstance(d, dict)}

            # Check for added disks (deployed but not in Bicep)
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

            # Check for removed disks (in Bicep but not deployed)
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

            # Check for modified disk properties
            for lun in set(bicep_by_lun.keys()) & set(deployed_by_lun.keys()):
                bicep_disk = bicep_by_lun[lun]
                deployed_disk = deployed_by_lun[lun]

                # Check disk size
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


class DriftDetector:
    """Detect all types of drift."""

    @staticmethod
    def _is_internal_resource(resource: Dict) -> bool:
        """Check if resource is internal/management (not actual infrastructure)."""
        resource_type = resource.get("type", "")
        # Filter out deployment modules and other management resources
        internal_types = {
            "Microsoft.Resources/deployments",
        }
        return resource_type in internal_types

    @staticmethod
    def detect_drift(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[ResourceDrift]:
        """
        Detect all drift between Bicep and deployed resources.

        Includes:
        - Resource matching (missing, extra)
        - Property comparison (modified configs)
        - Critical configuration validation:
          * Orphaned disks (OS and data)
          * VMs without network interfaces

        Returns:
            List of ResourceDrift objects
        """
        drifts = []
        extractor = PropertyExtractor()

        # Filter out internal resources (deployments, etc.)
        bicep_resources = [r for r in bicep_resources if not DriftDetector._is_internal_resource(r)]
        deployed_resources = [r for r in deployed_resources if not DriftDetector._is_internal_resource(r)]

        # Run critical configuration validation checks
        validator = ConfigurationValidator()
        drifts.extend(validator.check_orphaned_disks(deployed_resources))
        drifts.extend(validator.check_vms_without_nics(deployed_resources))
        drifts.extend(validator.check_data_disk_changes(bicep_resources, deployed_resources))

        matches = ResourceMatcher.match_resources(bicep_resources, deployed_resources)
        comparator = PropertyComparator()

        # Track matched resources
        matched_bicep = {id(r) for r, _, _ in matches}
        matched_deployed = {id(r) for _, r, _ in matches}

        # Check matched resources for property drift
        for bicep_res, deployed_res, confidence in matches:
            bicep_props = extractor.extract_bicep_properties(bicep_res)
            deployed_props = extractor.extract_azure_properties(deployed_res)

            diffs = comparator.compare_properties(bicep_props, deployed_props)

            if diffs:
                drifts.append(
                    ResourceDrift(
                        resource_type=bicep_res.get("type", ""),
                        resource_name=bicep_res.get("name", ""),
                        bicep_name=bicep_res.get("name", ""),
                        deployed_name=deployed_res.get("name", ""),
                        drift_type="modified",
                        property_diffs=diffs,
                        match_confidence=confidence,
                    )
                )

        # Check for missing resources (in Bicep, not deployed)
        for bicep_res in bicep_resources:
            if id(bicep_res) not in matched_bicep:
                drifts.append(
                    ResourceDrift(
                        resource_type=bicep_res.get("type", ""),
                        resource_name=bicep_res.get("name", ""),
                        bicep_name=bicep_res.get("name", ""),
                        deployed_name="",
                        drift_type="missing",
                        property_diffs=[],
                        match_confidence=1.0,
                    )
                )

        # Check for extra resources (deployed, not in Bicep)
        for deployed_res in deployed_resources:
            if id(deployed_res) not in matched_deployed:
                drifts.append(
                    ResourceDrift(
                        resource_type=deployed_res.get("type", ""),
                        resource_name=deployed_res.get("name", ""),
                        bicep_name="",
                        deployed_name=deployed_res.get("name", ""),
                        drift_type="extra",
                        property_diffs=[],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def generate_summary(drifts: List[ResourceDrift]) -> Dict[str, int]:
        """Generate summary of drift types."""
        summary = {
            "total": len(drifts),
            "missing": len([d for d in drifts if d.drift_type == "missing"]),
            "extra": len([d for d in drifts if d.drift_type == "extra"]),
            "modified": len([d for d in drifts if d.drift_type == "modified"]),
            "unchanged": len([d for d in drifts if d.drift_type == "unchanged"]),
        }
        return summary
