"""
tools/diff_states.py

Compares desired state (from compiled ARM JSON) against live Azure state.

Uses the normalizer to resolve expressions and flatten resources.
Generates a drift report showing missing, extra, and modified resources.
"""

from dataclasses import dataclass, field
from .normalizer import normalize_live_resources, resource_key
from .property_drift import DriftDetector


@dataclass
class ResourceDrift:
    resource_type: str
    resource_name: str
    drift_type: str          # "missing_in_azure" | "extra_in_azure" | "property_drift"
    details: dict = field(default_factory=dict)

    def summary(self) -> str:
        if self.drift_type == "missing_in_azure":
            return f"[MISSING] {self.resource_type}/{self.resource_name} is in Bicep but not deployed"
        if self.drift_type == "extra_in_azure":
            return f"[EXTRA]   {self.resource_type}/{self.resource_name} is deployed but not in Bicep"
        if self.drift_type == "property_drift":
            changed = list(self.details.get("changed_properties", {}).keys())
            return f"[DRIFT]   {self.resource_type}/{self.resource_name} — properties differ: {', '.join(changed)}"
        return f"[UNKNOWN] {self.resource_type}/{self.resource_name}"


def diff_states(
    arm_resources: list[dict],
    live_resources: list[dict],
    ignore_patterns=None,
) -> list[ResourceDrift]:
    """
    Compare ARM template resources against live Azure resources.

    Uses intelligent resource matching (exact + fuzzy) to handle
    parameter-based resource names in modular Bicep templates.

    Filters out module references and internal resources that don't
    correspond to actual Azure resources.

    Args:
        arm_resources: Normalized resources from extract_resources_from_arm()
        live_resources: Raw resources from get_live_state() (normalized here)

    Returns:
        List of ResourceDrift objects describing what's different.
    """
    drifts = []

    # Filter ARM resources — skip module references and unresolvable ones
    filtered_arm = [r for r in arm_resources if _should_compare_resource(r)]

    # Log what was filtered for debugging
    unresolvable_count = len(arm_resources) - len(filtered_arm)
    if unresolvable_count > 0:
        print(f"  ℹ Filtered {unresolvable_count} resource(s) with unresolvable expressions")

    # Normalize live resources to match ARM shape
    normalized_live = normalize_live_resources(live_resources)

    # Filter out auto-managed resources from live state that can't be in Bicep
    # (These are created and managed by other resources, not separately defined)
    auto_managed_types = {
        "Microsoft.Compute/disks",  # Created by VMs
        "Microsoft.Compute/virtualMachines/extensions",  # Created by VMs
    }
    normalized_live = [r for r in normalized_live if r.get("type") not in auto_managed_types]

    # Use DriftDetector's intelligent matching (handles fuzzy matching for parameter-based names)
    detector_drifts = DriftDetector.detect_drift(filtered_arm, normalized_live)

    # Apply ignore patterns if provided
    drifts_to_convert = detector_drifts
    if ignore_patterns:
        # Convert detector drifts to dict format for filtering
        drifts_as_dicts = [
            {
                "type": d.resource_type,
                "name": d.resource_name,
                "drift_type": d.drift_type,
            }
            for d in detector_drifts
        ]
        filtered_dict_drifts, _ = ignore_patterns.filter_drifts(drifts_as_dicts)

        # Rebuild detector drifts from filtered list
        filtered_names = {(d["type"], d["name"]) for d in filtered_dict_drifts}
        drifts_to_convert = [
            d for d in detector_drifts
            if (d.resource_type, d.resource_name) in filtered_names
        ]

    # Convert detector drifts to our ResourceDrift format
    for d in drifts_to_convert:
        if d.drift_type == "missing":
            drifts.append(ResourceDrift(
                resource_type=d.resource_type,
                resource_name=d.resource_name,
                drift_type="missing_in_azure",
            ))
        elif d.drift_type == "extra":
            drifts.append(ResourceDrift(
                resource_type=d.resource_type,
                resource_name=d.resource_name,
                drift_type="extra_in_azure",
            ))
        elif d.drift_type == "modified":
            property_details = {}
            if d.property_diffs:
                changed_props = {}
                for diff in d.property_diffs:
                    changed_props[diff.property_path] = {
                        "desired": diff.desired_value,
                        "actual": diff.actual_value,
                        "severity": diff.severity,
                    }
                property_details["changed_properties"] = changed_props
            drifts.append(ResourceDrift(
                resource_type=d.resource_type,
                resource_name=d.resource_name,
                drift_type="property_drift",
                details=property_details,
            ))

    return drifts


def _diff_properties(arm_resource: dict, live_resource: dict) -> dict:
    """
    Compare properties between desired and live state.

    Only compares the fields ARM cares about — skips Azure-managed fields
    like provisioningState, createdTime, etc.

    Returns a dict of {property: {desired: x, actual: y}} for anything that differs.
    """
    # Fields ARM defines that we want to compare
    comparable_fields = ["location", "sku", "tags", "kind"]

    diffs = {}

    for field in comparable_fields:
        arm_val = arm_resource.get(field)
        live_val = live_resource.get(field)

        if arm_val is None and live_val is None:
            continue

        if arm_val != live_val:
            diffs[field] = {"desired": arm_val, "actual": live_val}

    return diffs


def _should_compare_resource(resource: dict) -> bool:
    """
    Determine if a resource should be included in drift comparison.

    Skips:
    - Module references (Microsoft.Resources/deployments)
    - Resources with truly unresolvable complex expressions

    Note: DriftDetector now uses fuzzy matching, so resources with
    simple parameter references (like parameters('vmName')) can be matched.

    Args:
        resource: Normalized resource dict

    Returns:
        True if resource should be compared, False otherwise
    """
    res_type = resource.get("type", "").lower()
    res_name = resource.get("name", "")

    # Skip module deployments — these are Bicep syntax, not real resources
    if res_type == "microsoft.resources/deployments":
        return False

    # Skip only truly unresolvable complex expressions
    # Simple parameters() are now handled by fuzzy matching
    complex_unresolvable = [
        "format(",
        "coalesce(",
        "tryget(",
        "guid(",
        "resourceid(",
        "copyindex(",
        "unique-string",
        "copy-index",
        "deployment()",
    ]

    name_lower = res_name.lower()
    if any(indicator in name_lower for indicator in complex_unresolvable):
        return False

    # Skip empty or malformed names
    if not res_name or res_name == "unknown":
        return False

    return True


def format_drift_report(drifts: list[ResourceDrift], resource_group: str) -> str:
    """
    Simple text summary — good enough for Phase 1, the agent will do better later.
    """
    if not drifts:
        return f"✅ No drift detected in resource group '{resource_group}'."

    lines = [
        f"Drift Report — {resource_group}",
        f"{'=' * 50}",
        f"Found {len(drifts)} drift(s):\n",
    ]

    for d in drifts:
        lines.append(f"  {d.summary()}")
        if d.details:
            for prop, change in d.details.get("changed_properties", {}).items():
                lines.append(f"      {prop}:")
                lines.append(f"        desired: {change['desired']}")
                lines.append(f"        actual:  {change['actual']}")

    return "\n".join(lines)
