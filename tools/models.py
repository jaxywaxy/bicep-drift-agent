"""
Data models for drift analysis.

These define the structures that Phase 1 generates and Phase 2's agent consumes.
"""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Resource:
    """A normalized Azure resource."""
    type: str
    name: str
    location: str = "unknown"
    tags: dict[str, str] | None = None
    sku: str | None = None
    properties: dict[str, Any] | None = None
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
    details: dict[str, Any] | None = None
    suggested_action: str | None = None
    # ARM resource id and change attribution, when the report carries them.
    # Threaded to the analysis agent so it reasons by id and cites who changed
    # what (from lifecycle/change_origin) instead of asking for Activity Logs.
    resource_id: str | None = None
    change_origin: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class DriftReport:
    """Complete drift analysis report."""
    bicep_file: str
    resource_group: str
    parameters: dict[str, Any] | None = None

    # State snapshots
    arm_resources: list[Resource] | None = None
    live_resources: list[Resource] | None = None

    # Analysis results
    drifts: list[Drift] | None = None
    total_missing: int = 0
    total_extra: int = 0
    total_modified: int = 0

    @property
    def total_drift(self) -> int:
        """Total number of drift issues."""
        return self.total_missing + self.total_extra + self.total_modified

    def critical_drifts(self) -> list[Drift]:
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
