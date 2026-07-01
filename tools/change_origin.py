"""
Classify drift origin: Policy-enforced vs Manual changes.

Analyzes Activity Log to determine if a drift was caused by:
- Azure Policy DINE (DeployIfNotExists) - auto-deployed resources
- Azure Policy Modify - auto-modified properties
- Azure Policy Remediation - auto-remediated resources
- Manual changes - unauthorized out-of-band changes

This classification is crucial for:
- Reducing false positives (policy changes are expected)
- Audit trails (who changed what, when, how)
- Governance (identifying unauthorized changes)
- Compliance (proving policy enforcement)
"""

import logging
from dataclasses import dataclass
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
