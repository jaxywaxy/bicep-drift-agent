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
    """Match Bicep resources to deployed resources."""

    @staticmethod
    def match_resources(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[Tuple[Dict, Dict, float]]:
        """
        Match Bicep resources to deployed resources.

        Returns:
            List of (bicep_resource, deployed_resource, confidence) tuples
        """
        matches = []
        deployed_by_type = defaultdict(list)

        # Index deployed resources by type
        for resource in deployed_resources:
            resource_type = resource.get("type", "")
            deployed_by_type[resource_type].append(resource)

        # Match each Bicep resource
        for bicep_resource in bicep_resources:
            resource_type = bicep_resource.get("type", "")
            bicep_name = bicep_resource.get("name", "")

            candidates = deployed_by_type.get(resource_type, [])
            if not candidates:
                continue

            # Try exact match first
            exact_match = None
            for deployed in candidates:
                deployed_name = deployed.get("name", "")
                if bicep_name == deployed_name or bicep_name in deployed_name:
                    exact_match = deployed
                    break

            if exact_match:
                matches.append((bicep_resource, exact_match, 0.95))
                continue

            # Try fuzzy name matching for parameter-based names
            best_match = None
            best_score = 0.4

            for deployed in candidates:
                deployed_name = deployed.get("name", "")
                # Token-based matching: split names by - and compare overlapping parts
                bicep_tokens = set(bicep_name.replace('[', '').replace(']', '').replace("'", '').split('-'))
                deployed_tokens = set(deployed_name.replace('[', '').replace(']', '').replace("'", '').split('-'))

                # Remove parameter noise
                bicep_tokens.discard('parameters')
                bicep_tokens.discard('vmName')
                bicep_tokens.discard('vaultName')
                deployed_tokens.discard('nic')

                if bicep_tokens and deployed_tokens:
                    # Jaccard similarity: intersection / union
                    intersection = bicep_tokens & deployed_tokens
                    union = bicep_tokens | deployed_tokens
                    score = len(intersection) / len(union) if union else 0.0
                    if score > best_score:
                        best_score = score
                        best_match = deployed

            if best_match:
                matches.append((bicep_resource, best_match, best_score))
            elif len(candidates) == 1:
                # Only one resource of this type, likely a match
                matches.append((bicep_resource, candidates[0], 0.70))

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
