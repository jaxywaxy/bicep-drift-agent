"""
agent/findings.py

Finding data types shared across the agent package: the drift severity /
category / remediation-action enums and the DriftFinding record the
classifier produces and the prompt builder serialises. No behaviour here -
just the vocabulary the mixins and orchestrator agree on.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DriftSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class DriftCategory(str, Enum):
    RESOURCE_DRIFT = "resource_drift"
    CONFIGURATION_DRIFT = "configuration_drift"
    GOVERNANCE_DRIFT = "governance_drift"
    SECURITY_DRIFT = "security_drift"
    COST_DRIFT = "cost_drift"
    UNMANAGED_RESOURCE = "unmanaged_resource"
    SYSTEM_MANAGED = "system_managed"
    UNKNOWN = "unknown"


class RemediationAction(str, Enum):
    REDEPLOY_BICEP = "redeploy_bicep"
    ADD_TO_BICEP = "add_to_bicep"
    DELETE_RESOURCE = "delete_resource"
    UPDATE_PARAMETERS = "update_parameters"
    APPLY_POLICY_REMEDIATION = "apply_policy_remediation"
    INVESTIGATE_MANUAL_CHANGE = "investigate_manual_change"
    IGNORE_SYSTEM_MANAGED = "ignore_system_managed"
    APPROVE_EXCEPTION = "approve_exception"
    NO_ACTION = "no_action"
    UNKNOWN = "unknown"


@dataclass
class DriftFinding:
    resource_type: str
    resource_name: str
    resource_id: str | None
    drift_type: str
    severity: DriftSeverity
    category: DriftCategory
    recommended_action: RemediationAction
    confidence: float
    reason: str
    details: dict[str, Any]
    # Attribution from the report's change_origin (origin, changed_by, category,
    # reason). Given to the agent so it cites who/how instead of re-deriving it.
    change_origin: dict[str, Any] | None = None
    # Sibling properties of the LIVE resource that did not drift (see
    # LIVE_CONTEXT_PROPERTIES). details carries only the CHANGED paths, so
    # without this the analysis cannot see the state that bounds a finding's
    # severity or decides whether a remediation is even possible - and correctly
    # refuses to assert it, producing "unverified" hedges about facts the report
    # already holds.
    live_context: dict[str, Any] | None = None
