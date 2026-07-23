"""
tools/property_drift

Property-level drift detection.

Compares resource properties between Bicep (desired) and deployed (actual)
to detect configuration changes outside of IaC.

Split from the old single-file tools/property_drift.py into a package by
existing class boundaries:
- models: MatchConfidenceScores, PropertyDiff, ResourceDrift, ResourceIndexer
- extractor: PropertyExtractor (Bicep and Azure property extraction)
- matcher: ResourceMatcher (name / prefix / contextual / fuzzy / positional)
- comparator: PropertyComparator (all comparison, severity, sentinel logic)
- validators: ConfigurationValidator (orphaned disks, VMs without NICs, data disks)
- detector: DriftDetector (top-level orchestrator)

The public surface (DriftDetector, PropertyComparator, PropertyExtractor,
ResourceMatcher) is re-exported here so callers keep using
`from tools.property_drift import ...`.
"""

# Re-exports are intentional (tests reach for the classes and some private
# statics via the top-level module). Silence F401 for this facade.
from .comparator import PropertyComparator  # noqa: F401
from .detector import DriftDetector  # noqa: F401
from .extractor import PropertyExtractor  # noqa: F401
from .matcher import ResourceMatcher  # noqa: F401
from .models import (  # noqa: F401
    MatchConfidenceScores,
    PropertyDiff,
    ResourceDrift,
    ResourceIndexer,
)
from .validators import ConfigurationValidator  # noqa: F401

__all__ = [
    "DriftDetector",
    "PropertyComparator",
    "PropertyExtractor",
    "ResourceMatcher",
    "PropertyDiff",
    "ResourceDrift",
    "ConfigurationValidator",
    "ResourceIndexer",
    "MatchConfidenceScores",
]
