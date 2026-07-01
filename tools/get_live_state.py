"""
tools/get_live_state.py

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import os
import json
import logging
import time
from typing import Optional, List, Dict, Callable, TypeVar, Any
from functools import wraps
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)

try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
    HAS_RESOURCE_GRAPH = True
except ImportError:
    logger.warning("azure-mgmt-resourcegraph not installed, will fall back to ResourceManagementClient")
    HAS_RESOURCE_GRAPH = False

T = TypeVar('T')


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0) -> Callable:
    """Decorator to retry Azure SDK calls with exponential backoff.

    Retries on transient HTTP errors (5xx, 429 rate limiting).
    Logs each retry attempt and final failure.

    Args:
        max_retries: Maximum number of retry attempts (default 3)
        initial_delay: Initial delay in seconds (default 1.0, doubles each retry)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            last_error = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except HttpResponseError as e:
                    last_error = e
                    # Only retry on transient errors (5xx, 429)
                    if e.status_code not in (429, 500, 502, 503, 504):
                        raise
                    if attempt < max_retries:
                        logger.debug(
                            f"Transient error in {func.__name__} (attempt {attempt + 1}/{max_retries}): "
                            f"HTTP {e.status_code}, retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        logger.warning(
                            f"Failed after {max_retries + 1} attempts in {func.__name__}: {e}"
                        )
                except Exception as e:
                    # Non-transient errors, fail immediately
                    raise

            # Should not reach here, but just in case
            if last_error:
                raise last_error
            return func(*args, **kwargs)

        return wrapper
    return decorator




def get_live_state(
    resource_group: str = None,
    subscription_id: Optional[str] = None,
    scope: str = "resource_group"
) -> List[Dict]:
    """
    Query resources using Azure Resource Graph (fast and efficient).

    Supports both resource group and subscription scopes.

    Uses DefaultAzureCredential, which tries (in order):
      - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
      - Managed Identity
      - Azure CLI (`az login`)

    Args:
        resource_group: Name of the Azure resource group (required for RG scope).
        subscription_id: Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.
        scope: "resource_group" (default) or "subscription"

    Returns:
        List of resource dicts with type, name, location, and properties.
    """
    sub_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise ValueError(
            "No subscription_id provided and AZURE_SUBSCRIPTION_ID not set in environment."
        )

    if not HAS_RESOURCE_GRAPH:
        logger.warning("Resource Graph not available, falling back to ResourceManagementClient")
        return _get_live_state_fallback(resource_group, sub_id, scope)

    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)

    # Build KQL query based on scope
    # Note: Resource Graph doesn't have a separate AuthorizationResources table
    # Query resources in resource group, explicitly including locks and Log Analytics
    if scope == "resource_group":
        if not resource_group:
            raise ValueError("resource_group required for resource_group scope")
        # Query resources AND locks AND workspaces - use proper precedence with parentheses
        kql_query = (
            f"Resources "
            f"| where resourceGroup =~ '{resource_group}' "
            f"| union (Resources | where type =~ 'Microsoft.Authorization/locks' and resourceGroup =~ '{resource_group}') "
            f"| union (Resources | where type =~ 'Microsoft.OperationalInsights/workspaces' and resourceGroup =~ '{resource_group}')"
        )
    else:
        # Query all resources in subscription
        if resource_group:
            kql_query = (
                f"Resources "
                f"| where resourceGroup =~ '{resource_group}' "
                f"| union (Resources | where type =~ 'Microsoft.Authorization/locks' and resourceGroup =~ '{resource_group}') "
                f"| union (Resources | where type =~ 'Microsoft.OperationalInsights/workspaces' and resourceGroup =~ '{resource_group}')"
            )
        else:
            kql_query = (
                "Resources "
                "| union (Resources | where type =~ 'Microsoft.Authorization/locks') "
                "| union (Resources | where type =~ 'Microsoft.OperationalInsights/workspaces')"
            )

    logger.info(f"Querying Azure Resource Graph: {kql_query}")
    start_time = time.time()

    try:
        request = QueryRequest(subscriptions=[sub_id], query=kql_query)
        response = client.resources(request)
    except Exception as e:
        logger.error(f"Resource Graph query failed: {e}, falling back to ResourceManagementClient")
        return _get_live_state_fallback(resource_group, sub_id, scope)

    elapsed = time.time() - start_time
    logger.info(f"Resource Graph query completed in {elapsed:.2f}s")

    # Transform results to match expected format
    resources = []
    if response.data:
        for item in response.data:
            resource_dict = {
                "type": item.get("type"),
                "name": item.get("name"),
                "location": item.get("location"),
                "tags": item.get("tags", {}),
                "sku": item.get("sku"),
                "kind": item.get("kind"),
                "properties": item.get("properties", {}),
                "id": item.get("id"),
                "resource_group": item.get("resourceGroup"),
            }
            resources.append(resource_dict)

    # Query locks separately (Resource Graph doesn't index them)
    try:
        locks = _query_locks(resource_group, sub_id, scope)
        resources.extend(locks)
        logger.info(f"Found {len(resources)} total resource(s) via Resource Graph + locks")
    except Exception as e:
        logger.warning(f"Failed to query locks: {e}")
        logger.info(f"Found {len(resources)} resource(s) via Resource Graph (locks unavailable)")

    return resources


def _get_live_state_fallback(resource_group: str, sub_id: str, scope: str) -> List[Dict]:
    """Fallback: query resources using ResourceManagementClient when Resource Graph is unavailable."""
    logger.warning(f"Using ResourceManagementClient fallback (slower than Resource Graph)")
    from azure.mgmt.resource.resources import ResourceManagementClient

    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, sub_id)

    resources = []
    start_time = time.time()

    # Query resources
    if scope == "resource_group":
        if not resource_group:
            raise ValueError("resource_group required for resource_group scope")
        resource_iterator = client.resources.list_by_resource_group(resource_group, expand="properties")
    else:
        resource_iterator = client.resources.list(expand="properties")

    # Process resources
    for resource in resource_iterator:
        if scope == "subscription" and resource_group:
            rg_from_id = _extract_resource_group_from_id(resource.id)
            if rg_from_id and rg_from_id.lower() != resource_group.lower():
                continue

        resource_dict = {
            "type": resource.type,
            "name": resource.name,
            "location": resource.location,
            "tags": resource.tags or {},
            "sku": {"name": resource.sku.name} if resource.sku else None,
            "kind": resource.kind,
            "properties": resource.properties if resource.properties else {},
            "id": resource.id,
            "resource_group": _extract_resource_group_from_id(resource.id),
        }
        resources.append(resource_dict)

    # Query locks separately (not returned by Resource Graph or resource list)
    try:
        locks = _query_locks(resource_group, sub_id, scope)
        resources.extend(locks)
        logger.info(f"Added {len(locks)} lock(s) to results")
    except Exception as e:
        logger.warning(f"Failed to query locks: {e}")

    elapsed = time.time() - start_time
    logger.info(f"ResourceManagementClient query completed in {elapsed:.2f}s (slower than Resource Graph)")
    return resources


def _query_locks(resource_group: Optional[str], sub_id: str, scope: str) -> List[Dict]:
    """Query management locks (not returned by Resource Graph or resource list APIs)."""
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        credential = DefaultAzureCredential()
        client = AuthorizationManagementClient(credential, sub_id)

        locks = []

        if scope == "resource_group" and resource_group:
            # Query locks in specific resource group
            try:
                lock_iterator = client.management_locks.list_at_resource_group_level(resource_group)
                for lock in lock_iterator:
                    lock_dict = {
                        "type": "Microsoft.Authorization/locks",
                        "name": lock.name,
                        "location": "unknown",
                        "tags": {},
                        "sku": None,
                        "kind": None,
                        "properties": {"level": lock.level, "notes": lock.notes} if hasattr(lock, 'notes') else {"level": lock.level},
                        "id": lock.id,
                        "resource_group": resource_group,
                    }
                    locks.append(lock_dict)
            except Exception as e:
                logger.debug(f"Failed to query resource group locks: {e}")
        else:
            # Query all locks in subscription
            try:
                lock_iterator = client.management_locks.list_at_subscription_level()
                for lock in lock_iterator:
                    rg = _extract_resource_group_from_id(lock.id)
                    if scope == "subscription" and resource_group and rg and rg.lower() != resource_group.lower():
                        continue

                    lock_dict = {
                        "type": "Microsoft.Authorization/locks",
                        "name": lock.name,
                        "location": "unknown",
                        "tags": {},
                        "sku": None,
                        "kind": None,
                        "properties": {"level": lock.level, "notes": lock.notes} if hasattr(lock, 'notes') else {"level": lock.level},
                        "id": lock.id,
                        "resource_group": rg,
                    }
                    locks.append(lock_dict)
            except Exception as e:
                logger.debug(f"Failed to query subscription locks: {e}")

        return locks
    except Exception as e:
        logger.warning(f"Could not query locks: {e}")
        return []


def _extract_resource_group_from_id(resource_id: str) -> Optional[str]:
    """Extract resource group name from Azure resource ID.

    Example: /subscriptions/SUB_ID/resourceGroups/MY_RG/providers/... → MY_RG
    """
    if not resource_id:
        return None

    parts = resource_id.lower().split('/')
    try:
        rg_index = parts.index('resourcegroups')
        if rg_index + 1 < len(parts):
            return parts[rg_index + 1]
    except (ValueError, IndexError):
        pass
    return None
    """Enrich Storage Account properties using StorageManagementClient."""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
    except Exception:
        logger.debug("StorageManagementClient initialization failed. Skipping storage property enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.Storage/storageAccounts":
            account_name = resource["name"]
            try:
                account = storage_client.storage_accounts.get_properties(resource_group, account_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                # Azure SDK returns models with _data dict attribute
                data = account._data if hasattr(account, "_data") else account
                props = data.get("properties", {}) if isinstance(data, dict) else {}

                if props:
                    resource["properties"].update({
                        "accessTier": str(props.get("accessTier", "")).split(".")[-1],
                        "minimumTlsVersion": str(props.get("minimumTlsVersion", "")).split(".")[-1],
                        "supportsHttpsTrafficOnly": props.get("supportsHttpsTrafficOnly"),
                        "publicNetworkAccess": props.get("publicNetworkAccess"),
                    })
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


if __name__ == "__main__":
    import sys
    import json
    from pathlib import Path
    from dotenv import load_dotenv
    try:
        from .logger import setup_logging
    except ImportError:
        # When run as standalone script, add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent))
        from logger import setup_logging

    load_dotenv()
    setup_logging(level="INFO")

    if len(sys.argv) < 2:
        logger.error("Usage: python get_live_state.py <resource-group-name>")
        sys.exit(1)

    rg = sys.argv[1]
    logger.info(f"Querying live state for resource group: {rg}")

    resources = get_live_state(rg)

    logger.info(f"Found {len(resources)} resource(s)")
    for r in resources:
        sku_info = f" [{r['sku']['name']}]" if r.get("sku") else ""
        logger.info(f"  {r['type']} — {r['name']}{sku_info}")

    logger.debug("Full live state (first resource):")
    if resources:
        logger.debug(json.dumps(resources[0], indent=2, default=str))
