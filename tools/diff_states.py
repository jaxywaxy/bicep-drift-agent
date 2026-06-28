"""
tools/diff_states.py

Compares desired state (from compiled ARM JSON) against live Azure state.

Uses the normalizer to resolve expressions and flatten resources.
Generates a drift report showing missing, extra, and modified resources.
"""

from dataclasses import dataclass, field
from .normalizer import normalize_live_resources, resource_key


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
) -> list[ResourceDrift]:
    """
    Compare ARM template resources against live Azure resources.

    Both inputs should be normalized (from normalizer module).
    Matching is by (type, name) after normalization.

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

    # Normalize live resources to match ARM shape
    normalized_live = normalize_live_resources(live_resources)

    # Build lookup maps keyed by (normalised_type, normalised_name)
    arm_map = {resource_key(r): r for r in filtered_arm}
    live_map = {resource_key(r): r for r in normalized_live}

    arm_keys = set(arm_map.keys())
    live_keys = set(live_map.keys())

    # Resources in Bicep but not deployed
    for key in arm_keys - live_keys:
        r = arm_map[key]
        drifts.append(ResourceDrift(
            resource_type=r["type"],
            resource_name=r["name"],
            drift_type="missing_in_azure",
        ))

    # Resources deployed but not in Bicep (might be fine — might be shadow IT)
    for key in live_keys - arm_keys:
        r = live_map[key]
        drifts.append(ResourceDrift(
            resource_type=r["type"],
            resource_name=r["name"],
            drift_type="extra_in_azure",
        ))

    # Resources in both — check for property drift
    for key in arm_keys & live_keys:
        arm_r = arm_map[key]
        live_r = live_map[key]
        property_diffs = _diff_properties(arm_r, live_r)

        if property_diffs:
            drifts.append(ResourceDrift(
                resource_type=arm_r["type"],
                resource_name=arm_r["name"],
                drift_type="property_drift",
                details={"changed_properties": property_diffs},
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
    - Resources with unresolved complex expressions
    - Internal Azure-managed resources

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

    # Skip resources with obvious unresolved expressions
    # (These indicate parameter-driven resources we can't match)
    unresolved_indicators = [
        "parameters(",
        "variables(",
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
    if any(indicator in name_lower for indicator in unresolved_indicators):
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
