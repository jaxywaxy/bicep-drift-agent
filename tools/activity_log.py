"""
Query Azure Activity Log to determine change origin and history.

Activity Log provides audit trails for all Azure API calls, allowing us to
determine who made changes, when, how (via what method), and if it was
policy-enforced (DINE, Modify, Remediation) or manual.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)


def fetch_policy_principal_ids(subscription_id: str, resource_group: Optional[str] = None) -> dict:
    """
    Return a map of managed-identity principalId -> policy display name for all
    policy assignments in the subscription.

    DeployIfNotExists / Modify policies act through the assignment's managed
    identity, so the Activity Log 'caller' for a policy-driven change is that
    identity's GUID (not the string 'Azure Policy', and often without a
    policyAssignmentId on the resource write). Mapping principalId -> policy name
    lets us both attribute the change to policy AND name the responsible policy.
    Keys are lowercased GUIDs. Never raises (returns {} on failure).
    """
    import json as _json
    import urllib.request

    try:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.load(resp)
        mapping = {}
        for a in data.get("value", []):
            pid = (a.get("identity") or {}).get("principalId")
            if pid:
                props = a.get("properties", {}) or {}
                name = props.get("displayName") or a.get("name") or "Azure Policy"
                mapping[pid.lower()] = name
        logger.info(f"Found {len(mapping)} policy-assignment managed identity principal(s)")
        return mapping
    except Exception as e:
        logger.warning(f"Could not fetch policy assignment principals: {e}")
        return {}


def fetch_resource_group_activity(
    subscription_id: str,
    resource_group: str,
    days: int = 30,
    credential: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch ALL Azure Monitor Activity Log events for a resource group, once.

    The Activity Log $filter only supports a limited set of fields
    (eventTimestamp, resourceGroupName, resourceId, resourceProvider, correlationId)
    combined with 'and' ONLY - no 'status', 'resourceType', or 'or'. So we pull the
    whole RG window here and let callers match individual resources in memory
    (see match_activity_for_resource) instead of issuing one API query per drift.

    Returns a list of normalized entry dicts (may be empty). Never raises.
    """
    if not resource_group:
        logger.warning("No resource group provided; skipping activity log fetch")
        return []
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        credential = credential or DefaultAzureCredential()
        client = MonitorManagementClient(credential, subscription_id)

        # Timezone-aware UTC (datetime.utcnow() is deprecated in Python 3.12+).
        start_time = datetime.now(timezone.utc) - timedelta(days=days)
        filter_str = (
            f"eventTimestamp ge '{start_time.isoformat()}' "
            f"and resourceGroupName eq '{resource_group}'"
        )
        logger.debug(f"Activity Log query: rg={resource_group}, days={days}, filter={filter_str}")

        entries = [_entry_from_log(log) for log in client.activity_logs.list(filter=filter_str)]
        logger.info(f"Activity Log: fetched {len(entries)} event(s) for resource group '{resource_group}'")
        return entries
    except Exception as e:
        logger.error(f"Failed to fetch Activity Log for '{resource_group}': {e}")
        return []


def match_activity_for_resource(
    rg_events: List[Dict[str, Any]],
    resource_id: str,
    resource_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    From a pre-fetched list of RG activity events, return the ones for a resource.

    Matching:
      1. exact / prefix resource-ID match (case-insensitive) - live resources
      2. resource-type substring - deleted resources whose exact ID can't be built
    """
    resource_id_lower = (resource_id or "").lower()
    resource_type_lower = (resource_type or "").lower()

    # Primary: events for THIS resource or its sub-resources (exact id, or the
    # event id is a child path 'id/...'). We do NOT match the reverse direction
    # (our id starts with the event id) - that would wrongly match a child
    # resource (e.g. a lock) to its parent's events (the storage account writes).
    matched = [
        e for e in rg_events
        if resource_id_lower and (
            (e.get("resource_id") or "").lower() == resource_id_lower
            or (e.get("resource_id") or "").lower().startswith(resource_id_lower + "/")
        )
    ]
    if matched:
        return matched

    # Fallback ONLY for resources with no id match (e.g. deleted resources whose
    # exact id can't be resolved): match by resource type substring.
    if resource_type_lower:
        return [e for e in rg_events if resource_type_lower in (e.get("resource_id") or "").lower()]
    return []


def get_change_history(
    resource_id: str,
    subscription_id: str,
    days: int = 30,
    resource_type: Optional[str] = None,
    resource_group: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Convenience single-resource query (fetches the RG window, then matches).

    Prefer fetch_resource_group_activity() + match_activity_for_resource() when
    processing multiple resources in the same RG to avoid repeated API scans.
    """
    rg = resource_group or _extract_rg_from_resource_id(resource_id)
    if not rg:
        logger.warning(f"Could not determine resource group for {resource_id}; skipping activity log")
        return []
    rg_events = fetch_resource_group_activity(subscription_id, rg, days)
    return match_activity_for_resource(rg_events, resource_id, resource_type)


def _entry_from_log(log: Any) -> Dict[str, Any]:
    """Normalize an Azure Monitor activity-log record into our dict shape."""
    props = log.properties if log.properties else {}
    return {
        'timestamp': log.event_timestamp,
        'caller': log.caller,
        'operation': log.operation_name.value if log.operation_name else "Unknown",
        'status': log.status.value if log.status else "Unknown",
        'properties': props,
        'resource_id': log.resource_id,
        'method': props.get('method') if isinstance(props, dict) else None,
        'authorization': log.authorization if hasattr(log, 'authorization') else None,
    }


def _extract_rg_from_resource_id(resource_id: str) -> Optional[str]:
    """Extract the resource group name from an Azure resource ID (case-insensitive)."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None
