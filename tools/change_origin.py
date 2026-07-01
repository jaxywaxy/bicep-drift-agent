"""
Classify drift origin and track resource lifecycle.

Analyzes Activity Log to determine:
- If a drift was caused by policy, manual changes, deployments, or system actions
- Complete resource lifecycle (creation, updates, deletions)
- Who/what made each change and when

This classification is crucial for:
- Reducing false positives (policy changes are expected)
- Complete audit trails (who changed what, when, how)
- Governance (identifying unauthorized changes)
- Compliance (proving policy enforcement and tracking resource history)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ChangeOrigin(str, Enum):
    """Classification of change origin."""
    POLICY_DINE = "policy_dine"
    POLICY_MODIFY = "policy_modify"
    POLICY_REMEDIATION = "policy_remediation"
    MANUAL_CHANGE = "manual_change"
    TERRAFORM_CHANGE = "terraform_change"
    SYSTEM_MANAGED = "system_managed"
    UNKNOWN = "unknown"


class ChangeCategory(str, Enum):
    """Category of change."""
    COMPLIANCE_ENFORCED = "compliance_enforced"
    UNAUTHORIZED = "unauthorized"
    UNMANAGED = "unmanaged"
    UNKNOWN = "unknown"


class ChangeSeverity(str, Enum):
    """Severity of the drift due to its origin."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class OperationType(str, Enum):
    """Type of operation on the resource."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    MODIFY = "modify"
    REMEDIATE = "remediate"
    UNKNOWN = "unknown"


@dataclass
class ResourceLifecycleEvent:
    """A single lifecycle event for a resource."""
    timestamp: datetime
    operation: OperationType
    actor: str
    method: str
    status: str
    reason: str = ""
    origin: ChangeOrigin = ChangeOrigin.UNKNOWN
    policy_name: Optional[str] = None
    policy_id: Optional[str] = None
    deployment_id: Optional[str] = None
    modified_properties: Optional[Dict[str, Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'operation': self.operation.value,
            'actor': self.actor,
            'method': self.method,
            'status': self.status,
            'reason': self.reason,
            'origin': self.origin.value,
            'policy_name': self.policy_name,
            'policy_id': self.policy_id,
            'deployment_id': self.deployment_id,
            'modified_properties': self.modified_properties,
        }


@dataclass
class ResourceLifecycle:
    """Complete lifecycle history of a resource."""
    resource_id: str
    events: List[ResourceLifecycleEvent] = field(default_factory=list)
    created_at: Optional[datetime] = None
    created_by: Optional[str] = None
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None
    last_modified_at: Optional[datetime] = None
    last_modified_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'resource_id': self.resource_id,
            'events': [e.to_dict() for e in self.events],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'deleted_at': self.deleted_at.isoformat() if self.deleted_at else None,
            'deleted_by': self.deleted_by,
            'last_modified_at': self.last_modified_at.isoformat() if self.last_modified_at else None,
            'last_modified_by': self.last_modified_by,
        }


@dataclass
class ChangeOriginInfo:
    """Information about a change's origin."""
    origin: ChangeOrigin
    category: ChangeCategory
    severity: ChangeSeverity
    expected: bool
    timestamp: Optional[datetime] = None
    changed_by: Optional[str] = None
    method: Optional[str] = None
    policy_name: Optional[str] = None
    policy_id: Optional[str] = None
    modified_properties: Optional[Dict[str, Dict[str, Any]]] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'origin': self.origin.value,
            'category': self.category.value,
            'severity': self.severity.value,
            'expected': self.expected,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'changed_by': self.changed_by,
            'method': self.method,
            'policy_name': self.policy_name,
            'policy_id': self.policy_id,
            'modified_properties': self.modified_properties,
            'reason': self.reason,
        }


def select_relevant_activity(
    activity_logs: Optional[List[Dict[str, Any]]],
    drift_type: str,
) -> List[Dict[str, Any]]:
    """
    Narrow a resource's Activity Log entries down to the ones that explain THIS drift.

    A resource group query returns every event for the resource type. We only want
    the operation that actually caused the observed drift:
      - missing_in_azure  -> the DELETE that removed the resource
      - property/modified -> the WRITE/action that changed it (ignore reads/list/deletes)

    Returns the single most-recent relevant entry (as a 1-item list), or [] if none
    match. Entries are matched on the operation name suffix.
    """
    if not activity_logs:
        return []

    drift_type = (drift_type or "").lower()
    is_missing = "missing" in drift_type or "delete" in drift_type

    def op_of(entry: Dict[str, Any]) -> str:
        return (entry.get("operation") or "").lower()

    def is_delete(entry: Dict[str, Any]) -> bool:
        return op_of(entry).endswith("/delete") or op_of(entry).endswith("delete")

    def is_write(entry: Dict[str, Any]) -> bool:
        op = op_of(entry)
        # writes/updates that mutate config; exclude reads, lists, and deletes
        return (op.endswith("/write") or "modify" in op or "update" in op
                or "remediat" in op) and not is_delete(entry)

    if is_missing:
        candidates = [e for e in activity_logs if is_delete(e)]
    else:
        candidates = [e for e in activity_logs if is_write(e)]

    # Fallback: if nothing matched the expected operation, keep any non-read event
    if not candidates:
        candidates = [e for e in activity_logs if "read" not in op_of(e) and "list" not in op_of(e)]

    if not candidates:
        return []

    # Most recent first
    candidates.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    return [candidates[0]]


def classify_change_origin(
    activity_logs: Optional[List[Dict[str, Any]]]
) -> ChangeOriginInfo:
    """
    Classify the origin of a drift based on Activity Log entries.

    Args:
        activity_logs: Activity log entries from query_activity_log()

    Returns:
        ChangeOriginInfo with classification and metadata
    """
    if not activity_logs or len(activity_logs) == 0:
        return ChangeOriginInfo(
            origin=ChangeOrigin.UNKNOWN,
            category=ChangeCategory.UNKNOWN,
            severity=ChangeSeverity.MEDIUM,
            expected=False,
            reason="No activity log entries found (logs may have expired)",
        )

    # Get most recent entry
    latest = activity_logs[0]
    caller = latest.get('caller', '').lower()
    operation = latest.get('operation', '').lower()
    props = latest.get('properties', {})
    status = latest.get('status', 'Unknown')

    # Check for policy-enforced changes
    if "azure policy" in caller or "policy" in operation:
        return _classify_policy_change(latest, activity_logs)

    # Check for Azure service changes
    if _is_system_managed(caller):
        return ChangeOriginInfo(
            origin=ChangeOrigin.SYSTEM_MANAGED,
            category=ChangeCategory.COMPLIANCE_ENFORCED,
            severity=ChangeSeverity.LOW,
            expected=True,
            timestamp=latest.get('timestamp'),
            changed_by=caller,
            reason=f"System-managed resource modified by {caller}",
        )

    # Check for Terraform
    if "terraform" in caller or "terraform" in operation:
        return ChangeOriginInfo(
            origin=ChangeOrigin.TERRAFORM_CHANGE,
            category=ChangeCategory.UNAUTHORIZED,
            severity=ChangeSeverity.HIGH,
            expected=False,
            timestamp=latest.get('timestamp'),
            changed_by=caller,
            method="Terraform",
            reason="Resource modified by Terraform (external IaC tool, not bicep)",
        )

    # Manual change
    return ChangeOriginInfo(
        origin=ChangeOrigin.MANUAL_CHANGE,
        category=ChangeCategory.UNAUTHORIZED,
        severity=ChangeSeverity.HIGH,
        expected=False,
        timestamp=latest.get('timestamp'),
        changed_by=caller,
        method=latest.get('method', 'Unknown'),
        reason=f"Manual change by {caller} via {latest.get('method', 'Unknown')} (unauthorized)",
    )


def _classify_policy_change(
    entry: Dict[str, Any],
    all_entries: List[Dict[str, Any]]
) -> ChangeOriginInfo:
    """Classify Azure Policy-enforced changes."""
    operation = entry.get('operation', '').lower()
    props = entry.get('properties', {})
    timestamp = entry.get('timestamp')

    # DEPLOYIFNOTEXISTS - creates resources
    if "deployifnotexists" in operation:
        policy_name = _extract_policy_name(props)
        return ChangeOriginInfo(
            origin=ChangeOrigin.POLICY_DINE,
            category=ChangeCategory.COMPLIANCE_ENFORCED,
            severity=ChangeSeverity.LOW,
            expected=True,
            timestamp=timestamp,
            changed_by="Azure Policy (DINE)",
            policy_name=policy_name,
            policy_id=props.get('policyAssignmentId'),
            reason=f"Auto-deployed by Azure Policy DINE: {policy_name}",
        )

    # MODIFY - changes properties
    if "modify" in operation or "resourceManagementProcesses" in operation:
        modified = props.get('modifiedProperties', {})

        if modified:
            policy_name = _extract_policy_name(props)
            modified_list = list(modified.keys())
            return ChangeOriginInfo(
                origin=ChangeOrigin.POLICY_MODIFY,
                category=ChangeCategory.COMPLIANCE_ENFORCED,
                severity=ChangeSeverity.LOW,
                expected=True,
                timestamp=timestamp,
                changed_by="Azure Policy (Modify)",
                policy_name=policy_name,
                policy_id=props.get('policyAssignmentId'),
                modified_properties=modified,
                reason=f"Policy modified: {', '.join(modified_list)}",
            )

    # REMEDIATION - fixes non-compliant resources
    if "remediationtasks" in operation or "remediation" in operation:
        policy_name = _extract_policy_name(props)
        num_remediated = props.get('numRemediatedResources', 1)
        return ChangeOriginInfo(
            origin=ChangeOrigin.POLICY_REMEDIATION,
            category=ChangeCategory.COMPLIANCE_ENFORCED,
            severity=ChangeSeverity.LOW,
            expected=True,
            timestamp=timestamp,
            changed_by="Azure Policy (Remediation)",
            policy_name=policy_name,
            policy_id=props.get('policyAssignmentId'),
            reason=f"Auto-remediated by Azure Policy ({num_remediated} resource(s))",
        )

    # Unknown policy action
    return ChangeOriginInfo(
        origin=ChangeOrigin.UNKNOWN,
        category=ChangeCategory.UNKNOWN,
        severity=ChangeSeverity.MEDIUM,
        expected=False,
        timestamp=timestamp,
        changed_by="Azure Policy (unknown effect)",
        reason="Policy-related change but couldn't determine effect type",
    )


def _extract_policy_name(props: Dict[str, Any]) -> str:
    """Extract policy name from Activity Log properties."""
    policy_id = props.get('policyAssignmentId', '')
    if policy_id:
        # Format: /subscriptions/.../policyAssignments/PolicyName
        return policy_id.split('/')[-1]
    return "Unknown Policy"


def _is_system_managed(caller: str) -> bool:
    """Check if caller is a system-managed service."""
    system_callers = [
        "system",
        "microsoft.",
        "azure",
        "appservice",
        "functionapp",
        "cosmosdb",
        "sql",
        "storage",
    ]
    return any(sys in caller for sys in system_callers)


def build_resource_lifecycle(
    resource_id: str,
    activity_logs: Optional[List[Dict[str, Any]]]
) -> ResourceLifecycle:
    """
    Build complete resource lifecycle from Activity Log entries.

    Returns all events in chronological order (oldest first).
    """
    lifecycle = ResourceLifecycle(resource_id=resource_id)

    if not activity_logs:
        return lifecycle

    # Sort chronologically (oldest first)
    sorted_logs = sorted(activity_logs, key=lambda x: x.get('timestamp', ''), reverse=False)

    for entry in sorted_logs:
        event = _create_lifecycle_event(entry)
        if event:
            lifecycle.events.append(event)

            # Track lifecycle milestones
            if event.operation == OperationType.CREATE:
                lifecycle.created_at = event.timestamp
                lifecycle.created_by = event.actor
            elif event.operation == OperationType.DELETE:
                lifecycle.deleted_at = event.timestamp
                lifecycle.deleted_by = event.actor
            elif event.operation in (OperationType.UPDATE, OperationType.MODIFY):
                lifecycle.last_modified_at = event.timestamp
                lifecycle.last_modified_by = event.actor

    return lifecycle


def _create_lifecycle_event(entry: Dict[str, Any]) -> Optional[ResourceLifecycleEvent]:
    """Create a lifecycle event from an Activity Log entry."""
    try:
        timestamp = entry.get('timestamp')
        caller = entry.get('caller', 'Unknown').lower()
        operation_name = entry.get('operation', 'Unknown').lower()
        status = entry.get('status', 'Unknown')
        props = entry.get('properties', {})

        # Determine operation type
        op_type = _classify_operation_type(operation_name)

        # Determine origin and context
        origin, policy_info = _classify_origin_context(caller, operation_name, props)

        # Extract method
        method = _extract_method(caller, operation_name, props)

        # Extract deployment ID if available
        deployment_id = _extract_deployment_id(props)

        # Extract modified properties for UPDATE operations
        modified_props = None
        if op_type in (OperationType.UPDATE, OperationType.MODIFY):
            modified_props = props.get('modifiedProperties')

        reason = _build_event_reason(op_type, origin, caller, policy_info)

        return ResourceLifecycleEvent(
            timestamp=timestamp,
            operation=op_type,
            actor=caller,
            method=method,
            status=status,
            reason=reason,
            origin=origin,
            policy_name=policy_info.get('policy_name'),
            policy_id=policy_info.get('policy_id'),
            deployment_id=deployment_id,
            modified_properties=modified_props,
        )
    except Exception as e:
        logger.debug(f"Failed to create lifecycle event: {e}")
        return None


def _classify_operation_type(operation_name: str) -> OperationType:
    """Classify the operation type from activity log operation name."""
    op_lower = operation_name.lower()

    if any(x in op_lower for x in ["create", "write", "deploy", "put"]):
        return OperationType.CREATE
    elif any(x in op_lower for x in ["delete", "remove"]):
        return OperationType.DELETE
    elif any(x in op_lower for x in ["modify", "patch", "update"]):
        return OperationType.MODIFY
    elif any(x in op_lower for x in ["remediate", "remediation"]):
        return OperationType.REMEDIATE
    else:
        return OperationType.UNKNOWN


def _classify_origin_context(
    caller: str,
    operation_name: str,
    props: Dict[str, Any]
) -> tuple[ChangeOrigin, Dict[str, str]]:
    """
    Classify origin and extract context.

    Returns (origin, policy_info_dict)
    """
    op_lower = operation_name.lower()
    caller_lower = caller.lower()
    policy_info = {}

    # Azure Policy
    if "azure policy" in caller_lower or "policy" in op_lower:
        if "deployifnotexists" in op_lower:
            origin = ChangeOrigin.POLICY_DINE
        elif "modify" in op_lower or "resourceManagementProcesses" in op_lower:
            origin = ChangeOrigin.POLICY_MODIFY
        elif "remediat" in op_lower:
            origin = ChangeOrigin.POLICY_REMEDIATION
        else:
            origin = ChangeOrigin.UNKNOWN

        # Extract policy info
        policy_id = props.get('policyAssignmentId')
        if policy_id:
            policy_info['policy_id'] = policy_id
            policy_info['policy_name'] = policy_id.split('/')[-1]
        return origin, policy_info

    # System managed
    if _is_system_managed(caller):
        return ChangeOrigin.SYSTEM_MANAGED, {}

    # Terraform
    if "terraform" in caller_lower or "terraform" in op_lower:
        return ChangeOrigin.TERRAFORM_CHANGE, {}

    # ARM deployment
    if "deployment" in caller_lower or "microsoft.resources/deployments" in op_lower:
        origin = ChangeOrigin.UNKNOWN  # Was deployed but check props for more info
        deployment_id = _extract_deployment_id(props)
        if deployment_id:
            policy_info['deployment_id'] = deployment_id
        return origin, policy_info

    # Default to manual
    return ChangeOrigin.MANUAL_CHANGE, {}


def _extract_method(caller: str, operation_name: str, props: Dict[str, Any]) -> str:
    """Extract the method (Portal, CLI, SDK, ARM template, etc.)."""
    op_lower = operation_name.lower()

    if "portal" in props.get('method', '').lower():
        return "Azure Portal"
    elif "cli" in props.get('method', '').lower() or "cli" in caller.lower():
        return "Azure CLI"
    elif "powershell" in props.get('method', '').lower():
        return "PowerShell"
    elif "sdk" in props.get('method', '').lower():
        return "Azure SDK"
    elif "terraform" in caller.lower():
        return "Terraform"
    elif "deployment" in op_lower or "arm" in op_lower:
        return "ARM Deployment"
    else:
        return props.get('method', 'Unknown')


def _extract_deployment_id(props: Dict[str, Any]) -> Optional[str]:
    """Extract ARM deployment ID from properties."""
    deployment_id = props.get('deploymentId')
    if not deployment_id:
        deployment_id = props.get('correlationId')
    return deployment_id


def _build_event_reason(
    op_type: OperationType,
    origin: ChangeOrigin,
    actor: str,
    policy_info: Dict[str, str]
) -> str:
    """Build a human-readable reason for the event."""
    if origin == ChangeOrigin.POLICY_DINE:
        policy_name = policy_info.get('policy_name', 'Unknown Policy')
        return f"Auto-deployed by Azure Policy DINE ({policy_name})"
    elif origin == ChangeOrigin.POLICY_MODIFY:
        policy_name = policy_info.get('policy_name', 'Unknown Policy')
        return f"Properties modified by Azure Policy ({policy_name})"
    elif origin == ChangeOrigin.POLICY_REMEDIATION:
        policy_name = policy_info.get('policy_name', 'Unknown Policy')
        return f"Auto-remediated by Azure Policy ({policy_name})"
    elif origin == ChangeOrigin.SYSTEM_MANAGED:
        return f"System-managed change by {actor}"
    elif origin == ChangeOrigin.TERRAFORM_CHANGE:
        return "Modified by Terraform (external IaC)"
    elif origin == ChangeOrigin.MANUAL_CHANGE:
        return f"Manual change by {actor}"
    else:
        return f"{op_type.value.title()} operation by {actor}"


def format_change_origin_for_display(info: ChangeOriginInfo) -> Dict[str, str]:
    """Format change origin info for display in reports."""
    status_icon = "✅" if info.expected else "🔴"
    severity_color = "low" if info.severity == ChangeSeverity.LOW else "high"

    return {
        'icon': status_icon,
        'origin': info.origin.value.replace('_', ' ').title(),
        'changed_by': info.changed_by or "Unknown",
        'method': info.method or "Unknown",
        'timestamp': info.timestamp.isoformat() if info.timestamp else "Unknown",
        'policy_name': info.policy_name or "N/A",
        'severity': info.severity.value.upper(),
        'expected': "Yes" if info.expected else "No",
        'reason': info.reason,
        'action': "None (auto-enforced)" if info.expected else "Review & Remediate",
    }


def format_lifecycle_for_display(lifecycle: ResourceLifecycle) -> Dict[str, Any]:
    """Format lifecycle for HTML display."""
    return {
        'created_at': lifecycle.created_at.isoformat() if lifecycle.created_at else None,
        'created_by': lifecycle.created_by,
        'deleted_at': lifecycle.deleted_at.isoformat() if lifecycle.deleted_at else None,
        'deleted_by': lifecycle.deleted_by,
        'last_modified_at': lifecycle.last_modified_at.isoformat() if lifecycle.last_modified_at else None,
        'last_modified_by': lifecycle.last_modified_by,
        'events': [
            {
                'timestamp': e.timestamp.isoformat() if e.timestamp else None,
                'operation': e.operation.value,
                'actor': e.actor,
                'method': e.method,
                'status': e.status,
                'reason': e.reason,
                'origin': e.origin.value,
                'policy_name': e.policy_name,
            }
            for e in lifecycle.events
        ],
    }
