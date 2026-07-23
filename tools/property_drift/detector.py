"""
tools/property_drift/detector.py

Top-level drift orchestrator: run cross-resource validators (orphaned disks,
VMs without NICs, VM data-disk changes), match Bicep <-> deployed resources,
property-compare each matched pair, then emit missing/extra ResourceDrifts
for the un-matched sides.
"""

from .comparator import PropertyComparator
from .extractor import PropertyExtractor
from .matcher import ResourceMatcher
from .models import ResourceDrift
from .validators import ConfigurationValidator


class DriftDetector:
    """Detect all types of drift."""

    @staticmethod
    def _is_internal_resource(resource: dict) -> bool:
        """Check if resource is internal/management (not actual infrastructure)."""
        resource_type = resource.get("type", "")
        # Filter out deployment modules and other management resources
        internal_types = {
            "Microsoft.Resources/deployments",
        }
        return resource_type in internal_types

    @staticmethod
    def detect_drift(
        bicep_resources: list[dict],
        deployed_resources: list[dict],
    ) -> list[ResourceDrift]:
        """Detect all drift between Bicep and deployed resources.

        Includes:
        - Resource matching (missing, extra)
        - Property comparison (modified configs)
        - Critical configuration validation:
          * Orphaned disks (OS and data)
          * VMs without network interfaces
        """
        drifts = []
        extractor = PropertyExtractor()

        bicep_resources = [r for r in bicep_resources if not DriftDetector._is_internal_resource(r)]
        deployed_resources = [r for r in deployed_resources if not DriftDetector._is_internal_resource(r)]

        validator = ConfigurationValidator()
        drifts.extend(validator.check_orphaned_disks(deployed_resources))
        drifts.extend(validator.check_vms_without_nics(deployed_resources))
        drifts.extend(validator.check_data_disk_changes(bicep_resources, deployed_resources))

        matches = ResourceMatcher.match_resources(bicep_resources, deployed_resources)
        comparator = PropertyComparator()

        matched_bicep = {id(r) for r, _, _ in matches}
        matched_deployed = {id(r) for _, r, _ in matches}

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
    def generate_summary(drifts: list[ResourceDrift]) -> dict[str, int]:
        """Generate summary of drift types."""
        return {
            "total": len(drifts),
            "missing": len([d for d in drifts if d.drift_type == "missing"]),
            "extra": len([d for d in drifts if d.drift_type == "extra"]),
            "modified": len([d for d in drifts if d.drift_type == "modified"]),
            "unchanged": len([d for d in drifts if d.drift_type == "unchanged"]),
        }
