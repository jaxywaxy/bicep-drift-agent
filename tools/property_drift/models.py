"""
tools/property_drift/models.py

Small dataclasses and lookup helpers shared across the property-drift package.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any


class MatchConfidenceScores:
    """Confidence scores for resource matching strategies.

    These thresholds determine how confident we are that a Bicep resource
    matches a deployed resource. Used to handle ambiguous cases where multiple
    deployed resources could match a single Bicep resource.

    Scores range from 0.0 (no match) to 1.0 (perfect match).
    """

    # Exact name match (case-insensitive or substring)
    EXACT_MATCH = 0.95

    # Contextual matching via parent resource
    CONTEXTUAL_MATCH_DISK = 0.95
    CONTEXTUAL_MATCH_NIC = 0.90

    # Prefix match for parameter-based names
    # Example: 'st[uniqueString(...)]' matched to 'st12345abc' by prefix 'st'
    PREFIX_MATCH = 0.85

    # Fuzzy token-based matching
    FUZZY_MATCH_THRESHOLD = 0.60

    # Positional matching for truly identical-named resources (last resort)
    POSITIONAL_MATCH = 0.60

    # Single candidate fallback (only one deployed resource of that type)
    SINGLE_CANDIDATE = 0.70

    # No match / unresolved
    NO_MATCH = 0.25


class ResourceIndexer:
    """Helper for indexing and grouping resources by type and properties."""

    @staticmethod
    def by_name(resources: list[dict], resource_type: str) -> dict[str, dict]:
        """Index resources by name for a specific type."""
        return {
            r.get("name", ""): r
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def by_id(resources: list[dict], resource_type: str) -> dict[str, str]:
        """Index resource names by ID for a specific type."""
        return {
            r.get("id", ""): r.get("name", "")
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def filter_by_type(resources: list[dict], resource_type: str) -> list[dict]:
        """Filter resources by type."""
        return [r for r in resources if r.get("type") == resource_type]

    @staticmethod
    def group_by_type(resources: list[dict]) -> dict[str, list[dict]]:
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
    property_diffs: list[PropertyDiff]
    match_confidence: float  # 0.0 to 1.0
