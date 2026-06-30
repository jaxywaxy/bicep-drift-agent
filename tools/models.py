"""
Data models for drift analysis.

These define the structures that Phase 1 generates and Phase 2's agent consumes.
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


@dataclass
class Resource:
    """A normalized Azure resource."""
    type: str
    name: str
    location: str = "unknown"
    tags: Optional[Dict[str, str]] = None
    sku: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None
    source: str = "unknown"  # "bicep" or "azure"

    def identifier(self) -> tuple:
        """Get a stable identifier for this resource."""
        return (self.type.lower(), self.name.lower())


@dataclass
class Drift:
    """A detected drift between desired and actual state."""
    resource_type: str
    resource_name: str
    drift_type: str  # "missing", "extra", "modified"
    severity: str = "info"  # "info", "warning", "critical"
    details: Optional[Dict[str, Any]] = None
    suggested_action: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class DriftReport:
    """Complete drift analysis report."""
    bicep_file: str
    resource_group: str
    parameters: Optional[Dict[str, Any]] = None

    # State snapshots
    arm_resources: Optional[List[Resource]] = None
    live_resources: Optional[List[Resource]] = None

    # Analysis results
    drifts: Optional[List[Drift]] = None
    total_missing: int = 0
    total_extra: int = 0
    total_modified: int = 0

    @property
    def total_drift(self) -> int:
        """Total number of drift issues."""
        return self.total_missing + self.total_extra + self.total_modified

    def critical_drifts(self) -> List[Drift]:
        """Return only critical-severity drifts."""
        if not self.drifts:
            return []
        return [d for d in self.drifts if d.severity == "critical"]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "bicep_file": self.bicep_file,
            "resource_group": self.resource_group,
            "parameters": self.parameters,
            "arm_resources": [r.__dict__ for r in (self.arm_resources or [])],
            "live_resources": [r.__dict__ for r in (self.live_resources or [])],
            "drifts": [d.to_dict() for d in (self.drifts or [])],
            "summary": {
                "total_drift": self.total_drift,
                "missing": self.total_missing,
                "extra": self.total_extra,
                "modified": self.total_modified,
            }
        }
