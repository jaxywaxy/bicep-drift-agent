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
from azure.monitor.query import LogsQueryClient

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
    try:
        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)

        start_time = datetime.utcnow() - timedelta(days=days)

        # KQL query for activity log
        query = f"""
        AzureActivity
        | where TimeGenerated >= ago({days}d)
        | where ResourceId =~ "{resource_id}"
        | where ActivityStatus == "Succeeded" or ActivityStatus == "Failed"
        | project
            TimeGenerated,
            Caller,
            OperationName,
            ActivityStatus,
            Properties,
            ResourceId,
            SubscriptionId
        | order by TimeGenerated desc
        | limit 100
        """

        # Query Log Analytics workspace
        # Note: This requires Activity Logs to be sent to Log Analytics
        # Alternative: Use REST API directly (see fallback below)
        try:
            response = client.query_workspace(
                workspace_id=subscription_id,  # This will be the workspace ID in practice
                query=query,
                timespan=(start_time, datetime.utcnow()),
            )

            if response.status == "Success":
                entries = []
                for row in response.tables[0].rows:
                    entries.append({
                        'timestamp': row[0],
                        'caller': row[1],
                        'operation': row[2],
                        'status': row[3],
                        'properties': row[4],
                        'resource_id': row[5],
                    })
                logger.info(f"Found {len(entries)} activity log entries for {resource_id}")
                return entries
        except Exception as e:
            logger.debug(f"Log Analytics query failed: {e}, falling back to REST API")
            return query_activity_log_via_rest(resource_id, subscription_id, days)

    except Exception as e:
        logger.error(f"Failed to query activity log: {e}")
        return None


def query_activity_log_via_rest(
    resource_id: str,
    subscription_id: str,
    days: int = 30,
) -> Optional[List[Dict[str, Any]]]:
    """
    Fallback: Query Activity Log using Azure REST API directly.

    This is more reliable than Log Analytics since Activity Log is always available,
    though less flexible.
    """
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        credential = DefaultAzureCredential()
        client = MonitorManagementClient(credential, subscription_id)

        # Build OData filter
        start_time = datetime.utcnow() - timedelta(days=days)
        filter_str = (
            f"eventTimestamp ge '{start_time.isoformat()}Z' "
            f"and resourceId eq '{resource_id}' "
            f"and (status eq 'Succeeded' or status eq 'Failed')"
        )

        logger.info(f"[Activity Log Query]")
        logger.info(f"  Subscription: {subscription_id}")
        logger.info(f"  Resource ID: {resource_id}")
        logger.info(f"  Filter: {filter_str}")
        logger.info(f"  Days: {days}")

        activity_logs = client.activity_logs.list(filter=filter_str)

        entries = []
        log_count = 0
        for log in activity_logs:
            log_count += 1
            logger.debug(f"  Log entry {log_count}:")
            logger.debug(f"    Timestamp: {log.event_timestamp}")
            logger.debug(f"    Caller: {log.caller}")
            logger.debug(f"    Operation: {log.operation_name.value if log.operation_name else 'Unknown'}")
            logger.debug(f"    Status: {log.status.value if log.status else 'Unknown'}")
            logger.debug(f"    Resource ID: {log.resource_id}")

            entries.append({
                'timestamp': log.event_timestamp,
                'caller': log.caller,
                'operation': log.operation_name.value if log.operation_name else "Unknown",
                'status': log.status.value if log.status else "Unknown",
                'properties': log.properties if log.properties else {},
                'resource_id': log.resource_id,
                'method': log.properties.get('method') if log.properties else None,
                'authorization': log.authorization if hasattr(log, 'authorization') else None,
            })

        logger.info(f"  Result: {len(entries)} entries found")

        # If no entries found and resource_type provided, try broader search (for deleted resources)
        if len(entries) == 0 and resource_type and resource_group:
            logger.info(f"[Activity Log Fallback Search]")
            logger.info(f"  No results for specific resource ID, trying broader search...")
            logger.info(f"  Resource Type: {resource_type}")
            logger.info(f"  Resource Group: {resource_group}")

            # Use resourceGroup and resourceProviderName instead for broader matching
            filter_str_broad = (
                f"eventTimestamp ge '{start_time.isoformat()}Z' "
                f"and resourceGroup eq '{resource_group}'"
            )
            logger.info(f"  Broader Filter: {filter_str_broad}")

            activity_logs = client.activity_logs.list(filter=filter_str_broad)

            fallback_count = 0
            for log in activity_logs:
                fallback_count += 1
                if fallback_count <= 5:  # Log first 5 for debugging
                    logger.debug(f"  Fallback log {fallback_count}: {log.resource_id} - {log.caller}")

                entries.append({
                    'timestamp': log.event_timestamp,
                    'caller': log.caller,
                    'operation': log.operation_name.value if log.operation_name else "Unknown",
                    'status': log.status.value if log.status else "Unknown",
                    'properties': log.properties if log.properties else {},
                    'resource_id': log.resource_id,
                    'method': log.properties.get('method') if log.properties else None,
                    'authorization': log.authorization if hasattr(log, 'authorization') else None,
                })
            logger.info(f"  Fallback result: {len(entries)} entries found")

        logger.info(f"Found {len(entries)} activity log entries via REST API for {resource_id}")
        return entries

    except Exception as e:
        logger.error(f"Failed to query Activity Log via REST API: {e}")
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
