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
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ChangeOrigin(str, Enum):
    """Classification of change origin."""
    POLICY_DINE = "policy_dine"
    POLICY_MODIFY = "policy_modify"
    POLICY_REMEDIATION = "policy_remediation"
    MANUAL_CHANGE = "manual_change"
    TERRAFORM_CHANGE = "terraform_change"
    SYSTEM_MANAGED = "system_managed"
    AUTHORIZED_DEPLOYMENT = "authorized_deployment"
    UNKNOWN = "unknown"


class ChangeCategory(str, Enum):
    """Category of change."""
    COMPLIANCE_ENFORCED = "compliance_enforced"
    # A change made outside the IaC pipeline (manual portal/CLI edit, or an
    # external tool like Terraform). "out_of_band" - not necessarily
    # illegitimate; the operator may have every right to make it. It flags that
    # the change bypassed the declared pipeline, which is what drift detection
    # is for. Deliberately NOT "unauthorized", which reads as an accusation.
    OUT_OF_BAND = "out_of_band"
    UNMANAGED = "unmanaged"
    AUTHORIZED = "authorized"
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
    # ARM's /write covers create AND update; the operation name cannot separate
    # them. _classify_operation_type returns this, and build_resource_lifecycle
    # resolves every WRITE to CREATE or MODIFY, so it never reaches a report.
    WRITE = "write"
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
    policy_name: str | None = None
    policy_id: str | None = None
    deployment_id: str | None = None
    modified_properties: dict[str, dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
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
    events: list[ResourceLifecycleEvent] = field(default_factory=list)
    created_at: datetime | None = None
    created_by: str | None = None
    deleted_at: datetime | None = None
    deleted_by: str | None = None
    last_modified_at: datetime | None = None
    last_modified_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
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
    timestamp: datetime | None = None
    changed_by: str | None = None
    method: str | None = None
    policy_name: str | None = None
    policy_id: str | None = None
    modified_properties: dict[str, dict[str, Any]] | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
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
    activity_logs: list[dict[str, Any]] | None,
    drift_type: str,
) -> list[dict[str, Any]]:
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

    def op_of(entry: dict[str, Any]) -> str:
        return (entry.get("operation") or "").lower()

    def is_delete(entry: dict[str, Any]) -> bool:
        return op_of(entry).endswith("/delete") or op_of(entry).endswith("delete")

    def is_write(entry: dict[str, Any]) -> bool:
        op = op_of(entry)
        # Writes/updates that mutate config; exclude reads, lists, and deletes.
        #
        # Match on PATH SEGMENTS, not substrings. A substring test for "update"
        # also matches 'Microsoft.Resourcehealth/healthevent/Updated/action' -
        # platform health telemetry that every VM and scale-set instance emits
        # continuously, carrying caller=None. Being newer than the user's own
        # write, it won the latest-first sort and a real out-of-band change was
        # reported with NO actor (live, 2026-08-02, VMSS capacity 0->1).
        segments = op.split("/")
        return (
            op.endswith("/write")
            or "update" in segments
            or "modify" in segments
            or any(s.startswith("remediat") for s in segments)
        ) and not is_delete(entry)

    def latest(entries):
        # Prefer an operation that took effect. Azure logs several records per
        # operation, and picking purely by timestamp let a status="Failed"
        # record outrank the Succeeded one that actually did the work.
        effective = [e for e in entries if event_succeeded(e)]
        entries = effective or entries
        return max(entries, key=lambda e: str(e.get("timestamp") or "")) if entries else None

    if is_missing:
        deletes = [e for e in activity_logs if is_delete(e)]
        writes = [e for e in activity_logs if is_write(e)]
        latest_delete = latest(deletes)
        latest_write = latest(writes)

        # Stale-delete guard: names are deterministic (uniqueString is stable per RG),
        # so a resource deleted and later re-created shares the same name and both
        # events show up. If a create/write is NEWER than the delete, the resource
        # was recreated and is NOT actually gone - don't report it as deleted.
        # A recreate that FAILED recreated nothing, so it does not clear the
        # delete: taking it suppressed the real deletion and left the drift
        # reading "unknown" instead of naming who removed the resource.
        if latest_delete and latest_write and event_succeeded(latest_write):
            if str(latest_write.get("timestamp") or "") > str(latest_delete.get("timestamp") or ""):
                return [latest_write]
        if latest_delete:
            return [latest_delete]
        candidates = writes
    else:
        candidates = [e for e in activity_logs if is_write(e)]

    # Fallback: if nothing matched the expected operation, keep any non-read event
    if not candidates:
        candidates = [e for e in activity_logs if "read" not in op_of(e) and "list" not in op_of(e)]

    if not candidates:
        return []

    # Most recent first, an effective operation ahead of a failed one, and - only
    # to break an exact tie - an event that NAMES SOMEONE ahead of one that names
    # no one, since "manual change by <nobody>" is not an attribution.
    #
    # Caller-presence is deliberately the LAST key, not the first. Ranking it
    # above recency would let an older named event outrank the newer one that
    # actually set current state - the #337 failure mode (good history, false
    # cause). Excluding platform telemetry is is_write's job, not the sort's.
    candidates.sort(
        key=lambda e: (
            event_succeeded(e),
            str(e.get("timestamp") or ""),
            bool(e.get("caller")),
        ),
        reverse=True,
    )
    return [candidates[0]]


#: Activity Log statuses that mean the operation did not take effect. Anything
#: else - Succeeded, Started, Accepted, Unknown - is treated as possibly
#: effective: a delete logged only as "Started" against a resource that is
#: demonstrably gone is ingestion lag, not a non-event, and rejecting it would
#: drop attribution the report already gets right.
_UNEFFECTIVE_STATUSES = frozenset({"failed", "failure", "canceled", "cancelled"})


def event_succeeded(event: dict[str, Any] | None) -> bool:
    """Did this Activity Log entry's operation actually take effect?"""
    if not event:
        return False
    return (event.get("status") or "").strip().lower() not in _UNEFFECTIVE_STATUSES


def event_explains_drift(event: dict[str, Any] | None, drift_type: str) -> bool:
    """Could this event have CAUSED the observed drift?

    select_relevant_activity returns a best-effort event so the lifecycle
    timeline keeps its context, falling back to a write when no delete exists.
    That fallback is useful history and a false cause: a create or update cannot
    account for a resource being GONE. Attributing one anyway produced findings
    reading "Deployed by authorized pipeline identity" for resources that no
    longer exist (four of them in the 2026-07-28 teardown run), and, on a
    freshly-changed resource whose write had not yet reached the Activity Log,
    reported an out-of-band edit as an authorized deployment (issue #337).
    """
    if not event:
        return False
    # An operation that did not succeed changed nothing. Both App Service Plans
    # in the 2026-07-28 teardown were attributed to one status="Failed" delete -
    # which also means at most one of them could have been its subject.
    if not event_succeeded(event):
        return False
    op = (event.get("operation") or "").lower()
    if "missing" in (drift_type or "").lower():
        return op.endswith("delete") or op == "delete"
    # Property/config drift: a write is the explanation; a delete is not.
    return not (op.endswith("delete") or op == "delete")


def classify_change_origin(
    activity_logs: list[dict[str, Any]] | None,
    policy_principal_ids: set | None = None,
    authorized_deployers: set | None = None,
    explained: bool = True,
) -> ChangeOriginInfo:
    """
    Classify the origin of a drift based on Activity Log entries.

    Args:
        activity_logs: Activity log entries from query_activity_log()
        policy_principal_ids: managed-identity principalIds belonging to policy
            assignments. A change whose caller is one of these is policy-enforced
            (DINE/Modify act through the assignment's identity - the caller is a
            GUID, not "Azure Policy", and the resource write often lacks a
            policyAssignmentId).
        authorized_deployers: lowercased identity aliases (object ids, appIds,
            UPNs) of IaC pipeline identities - the scanning identity plus any
            DRIFT_AUTHORIZED_DEPLOYERS config. A change by one of these is an
            authorized deployment, not a manual/unauthorized change. NOTE:
            expected stays False - the DRIFT is still actionable (a
            pipeline-created orphan is still drift); only the attribution and
            severity change, so authorized deploys don't scream "unauthorized".

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

    # Events exist but none of them could have caused this drift. Say that,
    # rather than binding the newest unrelated one: a confident wrong actor is
    # worse than an admitted gap, and UNKNOWN already rates MEDIUM so a
    # genuinely unattributed change outranks a falsely reassuring
    # "authorized_deployment / low".
    if not explained:
        return ChangeOriginInfo(
            origin=ChangeOrigin.UNKNOWN,
            category=ChangeCategory.UNKNOWN,
            severity=ChangeSeverity.MEDIUM,
            expected=False,
            reason=(
                "No Activity Log event accounts for this change - the events on "
                "this resource predate it or describe a different operation. The "
                "log may not have ingested it yet; the timeline still shows what "
                "was found."
            ),
        )

    # Get most recent entry
    latest = activity_logs[0]
    caller = (latest.get('caller') or '').lower()
    operation = (latest.get('operation') or '').lower()

    # Check for policy-enforced changes. Besides caller/operation text, the most
    # reliable signal is a policyAssignmentId/policyDefinitionId in the event
    # properties - present on Modify/DINE remediation writes even when the caller
    # is the policy's managed identity (a GUID) rather than the string "Azure Policy".
    _props = latest.get('properties', {}) or {}
    has_policy_prop = isinstance(_props, dict) and bool(
        _props.get('policyAssignmentId') or _props.get('policyDefinitionId')
    )
    caller_is_policy_msi = bool(policy_principal_ids) and caller in policy_principal_ids
    # If we matched via the MSI principal map, we also know the policy's display name.
    policy_name_hint = None
    if isinstance(policy_principal_ids, dict):
        policy_name_hint = policy_principal_ids.get(caller)
    # Writing TO a policy assignment/exemption/definition is a governance change
    # BY someone (human or pipeline) - not a change ENFORCED by policy. Without
    # this exclusion, 'policy' in the operation name mis-attributes an
    # out-of-band policy assignment as policy-enforced (expected), silently
    # moving it out of the actionable drift set.
    is_governance_object_write = operation.startswith("microsoft.authorization/policy")
    op_signals_policy_effect = "policy" in operation and not is_governance_object_write
    if ("azure policy" in caller or op_signals_policy_effect or has_policy_prop
            or caller_is_policy_msi):
        return _classify_policy_change(latest, policy_name_hint)

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

    # Check for authorized deployer identities (the scanning identity and any
    # configured DRIFT_AUTHORIZED_DEPLOYERS). Checked AFTER policy/system (a
    # policy MSI write stays policy-attributed) and BEFORE terraform/manual
    # (an allowlisted deployer wins). expected=False keeps the drift in the
    # actionable set - only attribution and severity change.
    if authorized_deployers and caller in authorized_deployers:
        return ChangeOriginInfo(
            origin=ChangeOrigin.AUTHORIZED_DEPLOYMENT,
            category=ChangeCategory.AUTHORIZED,
            severity=ChangeSeverity.LOW,
            expected=False,
            timestamp=latest.get('timestamp'),
            changed_by=caller,
            method=latest.get('method', 'Unknown'),
            reason=f"Deployed by authorized pipeline identity {caller}",
        )

    # Check for Terraform
    if "terraform" in caller or "terraform" in operation:
        return ChangeOriginInfo(
            origin=ChangeOrigin.TERRAFORM_CHANGE,
            category=ChangeCategory.OUT_OF_BAND,
            severity=ChangeSeverity.HIGH,
            expected=False,
            timestamp=latest.get('timestamp'),
            changed_by=caller,
            method="Terraform",
            reason="Resource modified by Terraform (external IaC tool, not bicep)",
        )

    # Manual change - made outside the IaC pipeline ("out-of-band"), not
    # necessarily illegitimate. Only name the method when we actually know it;
    # a null/Unknown method rendered "via None"/"via Unknown", which is noise.
    method = latest.get('method') or 'Unknown'
    via = f" via {method}" if method not in ('Unknown', 'None') else ''
    return ChangeOriginInfo(
        origin=ChangeOrigin.MANUAL_CHANGE,
        category=ChangeCategory.OUT_OF_BAND,
        severity=ChangeSeverity.HIGH,
        expected=False,
        timestamp=latest.get('timestamp'),
        changed_by=caller,
        method=method,
        reason=f"Manual change by {caller}{via} (out-of-band)",
    )


def _classify_policy_change(
    entry: dict[str, Any],
    policy_name_hint: str | None = None,
) -> ChangeOriginInfo:
    """Classify Azure Policy-enforced changes. policy_name_hint names the policy
    when known from the assignment's managed identity (the resource write itself
    usually lacks a policyAssignmentId)."""
    operation = (entry.get('operation') or '').lower()
    props = entry.get('properties', {})
    timestamp = entry.get('timestamp')

    def _name(p):
        n = _extract_policy_name(p)
        return policy_name_hint if (n == "Unknown Policy" and policy_name_hint) else n

    # DEPLOYIFNOTEXISTS - creates resources
    if "deployifnotexists" in operation:
        policy_name = _name(props)
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
            policy_name = _name(props)
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
        policy_name = _name(props)
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

    # Confirmed policy-driven (policy caller or policyAssignmentId present) but the
    # operation string didn't match a specific effect - e.g. a Modify remediation
    # that writes '.../tags/write'. It is still policy-enforced, so treat it as a
    # generic POLICY_MODIFY (expected) rather than unknown/actionable.
    policy_name = _name(props)
    return ChangeOriginInfo(
        origin=ChangeOrigin.POLICY_MODIFY,
        category=ChangeCategory.COMPLIANCE_ENFORCED,
        severity=ChangeSeverity.LOW,
        expected=True,
        timestamp=timestamp,
        changed_by="Azure Policy",
        policy_name=policy_name,
        policy_id=props.get('policyAssignmentId') if isinstance(props, dict) else None,
        reason=f"Policy-enforced change ({policy_name})" if policy_name != "Unknown Policy" else "Policy-enforced change",
    )


def _extract_policy_name(props: dict[str, Any]) -> str:
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


def _resolve_write(drift_type: str | None, seen_write: bool) -> OperationType:
    """Decide whether an ARM /write was a creation or a modification.

    The drift type is the authoritative signal and beats event ordering:
    select_relevant_activity has ALREADY narrowed the log to the one operation
    that explains this drift, so on a property drift the resource demonstrably
    exists and its write is a modification; on an extra_in_azure drift the write
    genuinely is the creation of something undeclared.

    Ordering is only the fallback for callers with no drift context (first write
    in the window creates, later ones modify). That fallback alone was not
    enough: production hands this a ONE-event list, so every write looked like a
    first write and therefore a create.
    """
    dt = (drift_type or "").lower()
    if "property" in dt or "modified" in dt:
        return OperationType.MODIFY
    if "extra" in dt:
        return OperationType.CREATE
    return OperationType.MODIFY if seen_write else OperationType.CREATE


def build_resource_lifecycle(
    resource_id: str,
    activity_logs: list[dict[str, Any]] | None,
    authorized_deployers: set | None = None,
    drift_type: str | None = None,
) -> ResourceLifecycle:
    """
    Build complete resource lifecycle from Activity Log entries.

    Returns all events in chronological order (oldest first). `drift_type` is
    what the drift record says happened; it resolves ARM's create-or-update
    /write ambiguity (see _resolve_write) and is optional so callers without it
    still get the ordering-based reading.
    """
    lifecycle = ResourceLifecycle(resource_id=resource_id)

    if not activity_logs:
        return lifecycle

    # Sort chronologically (oldest first)
    sorted_logs = sorted(activity_logs, key=lambda x: x.get('timestamp', ''), reverse=False)

    seen_write = False
    for entry in sorted_logs:
        event = _create_lifecycle_event(entry, authorized_deployers)
        if not event:
            continue

        if event.operation == OperationType.WRITE:
            event.operation = _resolve_write(drift_type, seen_write)
            seen_write = True

        lifecycle.events.append(event)

        # A failed operation stays in the timeline as context but sets no
        # milestone: deleted_at/deleted_by taken from a status="Failed" delete
        # asserts a deletion that never happened, and contradicts the
        # change_origin the same event is now rejected from explaining.
        if not event_succeeded(entry):
            continue

        # Track lifecycle milestones. created_at is only taken from the FIRST
        # create so a later event cannot move it.
        if event.operation == OperationType.CREATE:
            if lifecycle.created_at is None:
                lifecycle.created_at = event.timestamp
                lifecycle.created_by = event.actor
        elif event.operation == OperationType.DELETE:
            lifecycle.deleted_at = event.timestamp
            lifecycle.deleted_by = event.actor
        elif event.operation in (OperationType.UPDATE, OperationType.MODIFY):
            lifecycle.last_modified_at = event.timestamp
            lifecycle.last_modified_by = event.actor

    return lifecycle


def _create_lifecycle_event(
    entry: dict[str, Any],
    authorized_deployers: set | None = None,
) -> ResourceLifecycleEvent | None:
    """Create a lifecycle event from an Activity Log entry."""
    try:
        timestamp = entry.get('timestamp')
        caller = (entry.get('caller') or 'Unknown').lower()
        operation_name = (entry.get('operation') or 'Unknown').lower()
        status = entry.get('status', 'Unknown')
        props = entry.get('properties', {})

        # Determine operation type
        op_type = _classify_operation_type(operation_name)

        # Determine origin and context
        origin, policy_info = _classify_origin_context(
            caller, operation_name, props, authorized_deployers
        )

        # Extract method
        method = _extract_method(caller, operation_name, props)

        # Extract deployment ID if available
        deployment_id = _extract_deployment_id(props)

        # Extract modified properties for anything that mutates in place. WRITE
        # is included: it is resolved to CREATE/MODIFY by the caller, and an
        # ARM /write that turns out to be an update carries them.
        modified_props = None
        if op_type in (OperationType.UPDATE, OperationType.MODIFY, OperationType.WRITE):
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
    """Classify the operation type from an activity log operation name.

    ARM operation names are '{provider}/{type}[/{child}]/{action}' and only the
    LAST segment is the verb, so the verb match is anchored there. Substring
    -matching the whole string silently mis-fires: 'Microsoft.Compute/...'
    contains 'put', which classified every Compute DELETE (VM, disk, VMSS,
    availability set) as a create - so deleted_at/deleted_by never populated and
    the lifecycle read 'created by' for a resource that had just been removed.

    'remediation' is matched against the whole name because it identifies the
    resource TYPE (Microsoft.PolicyInsights/remediations/write), not the verb.
    """
    op_lower = (operation_name or "").lower()
    if "remediat" in op_lower:
        return OperationType.REMEDIATE

    action = op_lower.rsplit("/", 1)[-1].strip()
    if action in ("delete", "remove"):
        return OperationType.DELETE
    if action in ("create", "put", "deploy"):
        return OperationType.CREATE
    if action in ("modify", "patch", "update"):
        return OperationType.MODIFY
    if action == "write":
        # ARM uses /write for BOTH create and update, so the name alone cannot
        # tell them apart. build_resource_lifecycle resolves it positionally;
        # see OperationType.WRITE.
        return OperationType.WRITE
    return OperationType.UNKNOWN


def _classify_origin_context(
    caller: str,
    operation_name: str,
    props: dict[str, Any],
    authorized_deployers: set | None = None,
) -> tuple[ChangeOrigin, dict[str, str]]:
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

    # Authorized deployer (scanning identity / DRIFT_AUTHORIZED_DEPLOYERS)
    if authorized_deployers and caller_lower in authorized_deployers:
        return ChangeOrigin.AUTHORIZED_DEPLOYMENT, {}

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


def _extract_method(caller: str, operation_name: str, props: dict[str, Any]) -> str:
    """Extract the method (Portal, CLI, SDK, ARM template, etc.).

    An ARM deployment is identified by the operation's resource TYPE
    (Microsoft.Resources/deployments/write), never by its verb, so that test
    matches whole type segments. Substring-matching the whole operation name
    reported every Microsoft.Web/serverf(arm)s operation as an ARM deployment -
    both App Service Plans in the 2026-07-28 teardown carried
    method "ARM Deployment" for what were manual deletions. Same trap
    _classify_operation_type documents for 'put' inside 'Microsoft.Compute';
    the fix there is the same one - anchor on segments, not substrings.
    """
    op_lower = operation_name.lower()
    # Everything but the trailing verb is the type chain.
    type_segments = [s for s in op_lower.split("/") if s][:-1]

    if "portal" in (props.get('method') or '').lower():
        return "Azure Portal"
    elif "cli" in (props.get('method') or '').lower() or "cli" in caller.lower():
        return "Azure CLI"
    elif "powershell" in (props.get('method') or '').lower():
        return "PowerShell"
    elif "sdk" in (props.get('method') or '').lower():
        return "Azure SDK"
    elif "terraform" in caller.lower():
        return "Terraform"
    elif "deployments" in type_segments:
        return "ARM Deployment"
    else:
        return props.get('method', 'Unknown')


def _extract_deployment_id(props: dict[str, Any]) -> str | None:
    """Extract ARM deployment ID from properties."""
    deployment_id = props.get('deploymentId')
    if not deployment_id:
        deployment_id = props.get('correlationId')
    return deployment_id


def _build_event_reason(
    op_type: OperationType,
    origin: ChangeOrigin,
    actor: str,
    policy_info: dict[str, str]
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
    elif origin == ChangeOrigin.AUTHORIZED_DEPLOYMENT:
        return f"Deployed by authorized pipeline identity {actor}"
    elif origin == ChangeOrigin.MANUAL_CHANGE:
        return f"Manual change by {actor}"
    else:
        # WRITE is create-or-update and is resolved by the caller; naming the
        # verb here would contradict the resolved operation.
        verb = "Change" if op_type == OperationType.WRITE else op_type.value.title()
        return f"{verb} operation by {actor}"
