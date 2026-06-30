"""
Property-level drift detection.

Compares resource properties between Bicep (desired) and deployed (actual)
to detect configuration changes outside of IaC.
"""

import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict


class MatchConfidenceScores:
    """
    Confidence scores for resource matching strategies.

    These thresholds determine how confident we are that a Bicep resource
    matches a deployed resource. Used to handle ambiguous cases where multiple
    deployed resources could match a single Bicep resource.

    Scores range from 0.0 (no match) to 1.0 (perfect match).
    """

    # Exact name match (case-insensitive or substring)
    # Most reliable: resource names match exactly
    EXACT_MATCH = 0.95

    # Contextual matching via parent resource
    # High confidence when we can use related resources to disambiguate
    # Example: matched disk to VM parent, then found deployed disk for that VM
    CONTEXTUAL_MATCH_DISK = 0.95
    CONTEXTUAL_MATCH_NIC = 0.90

    # Prefix match for parameter-based names
    # Example: 'st[uniqueString(...)]' matched to 'st12345abc' by prefix 'st'
    PREFIX_MATCH = 0.85

    # Fuzzy token-based matching
    # Matches by splitting names into tokens and checking overlap
    # Example: 'vm-prod-001' vs 'myvm-prod-001-nic' = high token overlap
    FUZZY_MATCH_THRESHOLD = 0.60

    # Positional matching for truly identical-named resources
    # Last resort: match by position when all else fails
    # Example: 4x resources all named [parameters('vmName')]-nic
    POSITIONAL_MATCH = 0.60

    # Single candidate fallback
    # When only one deployed resource exists for a resource type
    SINGLE_CANDIDATE = 0.70

    # No match / unresolved
    # Placeholder for resources that couldn't be matched
    NO_MATCH = 0.25


class ResourceIndexer:
    """Helper for indexing and grouping resources by type and properties."""

    @staticmethod
    def by_name(resources: List[Dict], resource_type: str) -> Dict[str, Dict]:
        """Index resources by name for a specific type."""
        return {
            r.get("name", ""): r
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def by_id(resources: List[Dict], resource_type: str) -> Dict[str, str]:
        """Index resource names by ID for a specific type."""
        return {
            r.get("id", ""): r.get("name", "")
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def filter_by_type(resources: List[Dict], resource_type: str) -> List[Dict]:
        """Filter resources by type."""
        return [r for r in resources if r.get("type") == resource_type]

    @staticmethod
    def group_by_type(resources: List[Dict]) -> Dict[str, List[Dict]]:
        """Group all resources by type."""
        grouped = defaultdict(list)
        for r in resources:
            grouped[r.get("type", "unknown")].append(r)
        return dict(grouped)


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
    def _normalize_resource_type(resource_type: str) -> str:
        """Normalize resource type to lowercase for consistent comparison.

        Azure SDK may return different casing for the same resource type.
        Example: Microsoft.Web/serverfarms vs Microsoft.Web/serverFarms
        """
        return resource_type.lower() if resource_type else ""

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
    def _match_disks_by_parent_vm(
        bicep_resource: Dict, bicep_resources: List[Dict], candidates: List[Dict], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match a disk to its parent VM's disk.

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        disk_name = bicep_resource.get("name", "")
        parent_vm = ResourceMatcher._find_parent_vm(disk_name, bicep_resources)
        if not parent_vm:
            return None

        for candidate in candidates:
            cand_name = candidate.get("name", "")
            vm_name_from_disk = cand_name.split('_')[0] if '_' in cand_name else None
            if vm_name_from_disk and vm_name_from_disk.lower() == parent_vm.get("name", "").lower():
                return candidate, 0.95  # High confidence: matched via parent VM

        return None

    @staticmethod
    def _match_nics_by_associated_vm(
        bicep_resource: Dict, bicep_resources: List[Dict], candidates: List[Dict],
        matches: List[Tuple[Dict, Dict, float]], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match a NIC to its associated VM's NIC.

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        associated_vm = ResourceMatcher._find_associated_resource(
            bicep_resource, bicep_resources, "Microsoft.Compute/virtualMachines"
        )
        if not associated_vm:
            return None

        # Find the deployed VM this bicep VM matches to
        for matched_bicep, matched_deployed, _ in matches:
            if matched_bicep.get("name") == associated_vm.get("name"):
                vm_name = matched_deployed.get("name", "")
                for candidate in candidates:
                    cand_name = candidate.get("name", "")
                    if vm_name in cand_name:
                        return candidate, 0.90

        return None

    @staticmethod
    def _match_by_fuzzy_tokens(
        bicep_name: str, candidates: List[Dict], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match using fuzzy token-based matching (for parameter-based names).

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        best_match = None
        best_score = current_best_score

        for candidate in candidates:
            deployed_name = candidate.get("name", "")
            bicep_clean = bicep_name.replace('[', '').replace(']', '').replace("'", '').replace('parameters(', '').replace(')', '')

            bicep_tokens = [t for t in bicep_clean.split('-') if len(t) > 1 and t not in ('vmName', 'vaultName', 'name')]
            deployed_tokens = [t for t in deployed_name.split('-') if len(t) > 1]

            if bicep_tokens and deployed_tokens:
                # Optimize fuzzy matching: use set intersection for O(n+m) instead of O(n*m)
                bicep_set = set(bicep_tokens)
                deployed_set = set(deployed_tokens)
                # Exact token matches (e.g., 'prod' in both 'vm-prod-001')
                exact_matches = len(bicep_set & deployed_set)
                # Prefix/substring matches for tokens not found exactly
                prefix_matches = sum(
                    1 for bt in bicep_tokens
                    if bt not in deployed_set and any(dt.startswith(bt) or bt in dt for dt in deployed_tokens)
                )
                matches_count = exact_matches + prefix_matches
                score = matches_count / max(len(bicep_tokens), len(deployed_tokens))
                if score > best_score:
                    best_score = score
                    best_match = candidate

        return (best_match, best_score) if best_match else None

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

        # Index deployed resources by normalized type (lowercase)
        for resource in deployed_resources:
            resource_type = ResourceMatcher._normalize_resource_type(resource.get("type", ""))
            deployed_by_type[resource_type].append(resource)

        # Track used deployed resources
        used_deployed = set()

        # First pass: exact matches
        for bicep_resource in bicep_resources:
            resource_type = ResourceMatcher._normalize_resource_type(bicep_resource.get("type", ""))
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
                matches.append((bicep_resource, exact_match, MatchConfidenceScores.EXACT_MATCH))
                used_deployed.add(id(exact_match))
            else:
                # Try fuzzy matching for unresolvable names like sttestdrift[uniqueString(...)]
                if "[" in bicep_name and "]" in bicep_name:
                    # Extract prefix before the bracket
                    prefix = bicep_name.split("[")[0]
                    if prefix:  # Only if there's a meaningful prefix
                        prefix_matches = [d for d in candidates if d.get("name", "").startswith(prefix)]
                        if len(prefix_matches) == 1:
                            # Exactly one match found via prefix
                            matches.append((bicep_resource, prefix_matches[0], MatchConfidenceScores.PREFIX_MATCH))
                            used_deployed.add(id(prefix_matches[0]))

        # Second pass: contextual + fuzzy matching for remaining resources
        bicep_by_type = defaultdict(list)
        for bicep_resource in bicep_resources:
            if id(bicep_resource) not in {id(b) for b, _, _ in matches}:
                resource_type = ResourceMatcher._normalize_resource_type(bicep_resource.get("type", ""))
                bicep_by_type[resource_type].append(bicep_resource)

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
                best_score = MatchConfidenceScores.NO_MATCH

                # Try contextual matching strategies
                if resource_type == "Microsoft.Compute/disks":
                    result = ResourceMatcher._match_disks_by_parent_vm(
                        bicep_resource, bicep_resources, candidates, best_score
                    )
                    if result:
                        best_match, best_score = result

                elif all_identical and resource_type == "Microsoft.Network/networkInterfaces":
                    result = ResourceMatcher._match_nics_by_associated_vm(
                        bicep_resource, bicep_resources, candidates, matches, best_score
                    )
                    if result:
                        best_match, best_score = result

                # Try fuzzy matching if contextual matching failed
                if not best_match:
                    result = ResourceMatcher._match_by_fuzzy_tokens(
                        bicep_name, candidates, best_score
                    )
                    if result:
                        best_match, best_score = result

                # Fallback: positional matching for identical-named resources
                if not best_match and all_identical and len(candidates) >= len(bicep_res_list):
                    best_match = candidates[bicep_idx]
                    best_score = MatchConfidenceScores.POSITIONAL_MATCH

                # Single candidate fallback
                if not best_match and len(candidates) == 1:
                    best_match = candidates[0]
                    best_score = MatchConfidenceScores.SINGLE_CANDIDATE

                if best_match:
                    matches.append((bicep_resource, best_match, best_score))
                    used_deployed.add(id(best_match))

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
        # App Service Plan properties (not returned by API)
        "properties.reserved",
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

        # Skip detailed comparison if property enrichment failed
        # (deployed_properties have no nested "properties.*" or "sku.*" keys - likely API returned empty)
        has_detailed_deployed_properties = any(
            k.startswith("properties.") or k.startswith("sku.") for k in deployed_flat.keys()
        )
        if not has_detailed_deployed_properties:
            # Property enrichment didn't work for this resource - return empty diffs
            # to avoid false positives from incomplete data (empty properties object)
            return diffs

        # Check for modified properties
        for key, bicep_value in bicep_flat.items():
            if key in deployed_flat:
                # Skip write-only properties (Azure doesn't return these in API responses)
                if PropertyComparator._is_write_only_property(key):
                    continue

                # Skip name property comparisons when the name contains unresolved expressions
                # (e.g., sttestdrift[uniqueString(...)]) - these are matched by prefix
                if key == "name" and isinstance(bicep_value, str):
                    if "[" in bicep_value and "]" in bicep_value:
                        continue

                # Skip unresolved template expressions (resolve at deploy time)
                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                deployed_value = deployed_flat[key]

                # Normalize type comparisons (Azure may return different casing)
                if key == "type" and isinstance(bicep_value, str) and isinstance(deployed_value, str):
                    if bicep_value.lower() == deployed_value.lower():
                        continue

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

                # Skip unresolved template expressions (resolve at deploy time)
                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                # Skip if deployed properties are incomplete (likely property enrichment issue)
                # If deployed_flat is empty or minimal, property querying may have failed
                if len(deployed_flat) < 3:
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
        """Flatten nested dictionary.

        Arrays are serialized as JSON for semantic comparison (not string comparison).
        This prevents false positives from whitespace differences or element reordering.
        Example: [1,2,3] vs [1, 2, 3] will compare equal.
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(PropertyComparator._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, (list, tuple)):
                # Serialize arrays as JSON for semantic comparison
                # This preserves element order and type while avoiding string conversion issues
                items.append((new_key, json.dumps(v, sort_keys=True, default=str)))
            else:
                items.append((new_key, v))
        return dict(items)

    @staticmethod
    def _has_unresolved_expressions(value: Any) -> bool:
        """Check if value contains unresolved Bicep/ARM template expressions.

        Examples: uniqueString(), subscription(), resourceId(), format(), etc.
        These resolve at deployment time and shouldn't be reported as drift.
        """
        if not isinstance(value, str):
            return False

        value_lower = value.lower()
        # Common template functions that resolve at deploy time
        unresolved_markers = [
            'uniquestring(',
            'subscription().',
            'resourceid(',
            'format(',
            'variables(',
            'parameters(',
            'reference(',
            'listkeys(',
            'concat(',
            'string(',
        ]

        return any(marker in value_lower for marker in unresolved_markers)

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
        vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")
        disks = ResourceIndexer.filter_by_type(deployed_resources, "Microsoft.Compute/disks")

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
        nic_ids = ResourceIndexer.by_id(deployed_resources, "Microsoft.Network/networkInterfaces")

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
        deployed_vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")

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
