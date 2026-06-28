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

        # Top-level properties
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "apiVersion" in resource:
            properties["apiVersion"] = resource["apiVersion"]
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

        # Dependencies
        if "dependsOn" in resource:
            properties["dependsOn"] = resource["dependsOn"]

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
        "location",
        "sku.name",
        "sku.tier",
        "kind",
        "properties.accountType",
        "properties.replicationType",
        "properties.accessTier",
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
                diffs.append(
                    PropertyDiff(
                        property_path=key,
                        desired_value=bicep_value,
                        actual_value=None,
                        change_type="removed",
                        severity="info",
                    )
                )

        # Check for added properties (deployed but not in Bicep)
        for key, deployed_value in deployed_flat.items():
            if key not in bicep_flat:
                # Skip system-generated properties
                if not PropertyComparator._is_system_property(key):
                    diffs.append(
                        PropertyDiff(
                            property_path=key,
                            desired_value=None,
                            actual_value=deployed_value,
                            change_type="added",
                            severity="info",
                        )
                    )

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

        Returns:
            List of ResourceDrift objects
        """
        drifts = []
        extractor = PropertyExtractor()

        # Filter out internal resources (deployments, etc.)
        bicep_resources = [r for r in bicep_resources if not DriftDetector._is_internal_resource(r)]
        deployed_resources = [r for r in deployed_resources if not DriftDetector._is_internal_resource(r)]

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
