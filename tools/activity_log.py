"""
Query Azure Activity Log to determine change origin and history.

Activity Log provides audit trails for all Azure API calls, allowing us to
determine who made changes, when, how (via what method), and if it was
policy-enforced (DINE, Modify, Remediation) or manual.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)


def get_change_history(
    resource_id: str,
    subscription_id: str,
    days: int = 30,
    resource_type: Optional[str] = None,
    resource_group: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Query Activity Log for changes to a specific resource.

    For deleted resources, provide resource_type and resource_group for broader search.

    Args:
        resource_id: Full Azure resource ID
        subscription_id: Azure subscription ID
        days: Look back this many days in activity log
        resource_type: Resource type (e.g., Microsoft.OperationalInsights/workspaces) for fallback search
        resource_group: Resource group name for fallback search

    Returns:
        List of activity log entries (most recent first), or None if query fails
    """
    # Query the Azure Monitor Activity Log via the management REST API.
    # (We do NOT use Log Analytics here - that requires a workspace ID and diagnostic
    #  settings routing Activity Log to a workspace, which isn't guaranteed. The
    #  management Activity Log is always available for the subscription.)
    return query_activity_log_via_rest(
        resource_id,
        subscription_id,
        days,
        resource_type=resource_type,
        resource_group=resource_group,
    )


def query_activity_log_via_rest(
    resource_id: str,
    subscription_id: str,
    days: int = 30,
    resource_type: Optional[str] = None,
    resource_group: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Query the Azure Monitor Activity Log using the management REST API.

    The Activity Log $filter only supports eventTimestamp + resourceGroupName
    (and a few others) combined with 'and'. We filter by RG + time, then match
    the specific resource (or resource type, for deleted resources) client-side.
    """
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        credential = DefaultAzureCredential()
        client = MonitorManagementClient(credential, subscription_id)

        # Determine resource group for the query filter.
        # The Activity Log REST API $filter ONLY supports a very limited set of fields
        # (eventTimestamp, resourceGroupName, resourceId, resourceProvider, correlationId)
        # combined with 'and' ONLY. It does NOT support 'status', 'resourceType', or 'or'.
        # So we filter by eventTimestamp + resourceGroupName and match everything else client-side.
        rg_for_filter = resource_group or _extract_rg_from_resource_id(resource_id)
        start_time = datetime.utcnow() - timedelta(days=days)

        if not rg_for_filter:
            logger.warning(f"Could not determine resource group for {resource_id}; skipping activity log")
            return []

        filter_str = (
            f"eventTimestamp ge '{start_time.isoformat()}Z' "
            f"and resourceGroupName eq '{rg_for_filter}'"
        )

        logger.info(f"[Activity Log Query]")
        logger.info(f"  Subscription: {subscription_id}")
        logger.info(f"  Resource ID (target): {resource_id}")
        logger.info(f"  Resource Group (filter): {rg_for_filter}")
        logger.info(f"  Filter: {filter_str}")
        logger.info(f"  Days: {days}")

        activity_logs = client.activity_logs.list(filter=filter_str)

        # Collect all RG events, then match client-side.
        resource_id_lower = resource_id.lower()
        resource_type_lower = (resource_type or "").lower()
        matched = []
        total_seen = 0
        for log in activity_logs:
            total_seen += 1
            log_resource_id = (log.resource_id or "")
            log_resource_id_lower = log_resource_id.lower()

            # Match strategy:
            # 1. Exact/substring resource ID match (case-insensitive) - handles live resources
            # 2. For missing/deleted resources: match by resource type in the resource ID
            is_match = False
            if resource_id_lower and (
                log_resource_id_lower == resource_id_lower
                or log_resource_id_lower.startswith(resource_id_lower)
                or resource_id_lower.startswith(log_resource_id_lower)
            ):
                is_match = True
            elif resource_type_lower and resource_type_lower in log_resource_id_lower:
                # broader match for deleted resources (resource ID no longer resolvable)
                is_match = True

            if not is_match:
                continue

            matched.append({
                'timestamp': log.event_timestamp,
                'caller': log.caller,
                'operation': log.operation_name.value if log.operation_name else "Unknown",
                'status': log.status.value if log.status else "Unknown",
                'properties': log.properties if log.properties else {},
                'resource_id': log.resource_id,
                'method': log.properties.get('method') if log.properties else None,
                'authorization': log.authorization if hasattr(log, 'authorization') else None,
            })
            if len(matched) <= 10:
                logger.debug(
                    f"  Matched: {log.event_timestamp} | {log.caller} | "
                    f"{log.operation_name.value if log.operation_name else '?'} | {log_resource_id}"
                )

        logger.info(f"  Scanned {total_seen} RG event(s), matched {len(matched)} for target resource")
        entries = matched

        logger.info(f"Found {len(entries)} activity log entries via REST API for {resource_id}")
        return entries

    except Exception as e:
        logger.error(f"Failed to query Activity Log via REST API: {e}")
        return None


def _extract_rg_from_resource_id(resource_id: str) -> Optional[str]:
    """Extract the resource group name from an Azure resource ID (case-insensitive)."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def extract_policy_info(activity_entry: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Extract Azure Policy information from activity log entry.

    Returns policy assignment ID, definition ID, and policy name if available.
    """
    try:
        props = activity_entry.get('properties', {})

        policy_id = props.get('policyAssignmentId')
        policy_def_id = props.get('policyDefinitionId')

        if policy_id:
            # Extract policy name from ID path
            # Format: /subscriptions/.../policyAssignments/PolicyName
            policy_name = policy_id.split('/')[-1]

            return {
                'policy_assignment_id': policy_id,
                'policy_definition_id': policy_def_id,
                'policy_name': policy_name,
            }
    except Exception as e:
        logger.debug(f"Failed to extract policy info: {e}")

    return None


def extract_modified_properties(activity_entry: Dict[str, Any]) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Extract list of properties that were modified by a policy.

    Returns dict of {property_name: {old_value, new_value}}
    """
    try:
        props = activity_entry.get('properties', {})
        modified = props.get('modifiedProperties', {})

        if modified:
            return modified
    except Exception as e:
        logger.debug(f"Failed to extract modified properties: {e}")

    return None
