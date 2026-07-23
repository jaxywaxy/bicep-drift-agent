"""
tools/live_state/resource_graph.py

The primary live-state query (Azure Resource Graph) with a slower
ResourceManagementClient fallback, plus the orchestrator that augments the
base list with everything the collectors add: locks, cosmos children, backup,
cognitive, data-plane children, App Service config, extensions, VNet peerings,
plus post-processing (dedupe, child-name qualification, ACI/Cosmos normalisation).
"""

import logging
import os
import time
from typing import Any

from azure.identity import DefaultAzureCredential

from .collectors.aci import _normalize_aci_container_groups
from .collectors.appservice import _expand_appservice_config
from .collectors.backup import _query_backup_children, _query_backup_policies
from .collectors.cognitive import _query_cognitive_deployments
from .collectors.cosmos import _normalize_cosmos_account_locations, _query_cosmos_children
from .collectors.data_plane import _expand_data_plane_children
from .collectors.extensions import _expand_extension_resources
from .collectors.locks import _query_locks
from .collectors.peerings import _expand_vnet_peerings
from .common import (
    _ALL_RG_SELECTORS,
    _dedupe_resources_by_id,
    _extract_resource_group_from_id,
    _filter_by_rg_selector,
    _is_rg_glob,
    _kql_rg_filter,
    _qualify_child_resource_names,
)

logger = logging.getLogger(__name__)

try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
    HAS_RESOURCE_GRAPH = True
except ImportError:
    logger.warning("azure-mgmt-resourcegraph not installed, will fall back to ResourceManagementClient")
    HAS_RESOURCE_GRAPH = False


def get_live_state(
    resource_group: str = None,
    subscription_id: str | None = None,
    scope: str = "resource_group",
) -> list[dict]:
    """Query resources using Azure Resource Graph (fast and efficient).

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

    # Build KQL query based on scope.
    # NOTE: The Resources table already returns all normal resources (including
    # OperationalInsights workspaces) for the RG. Do NOT union them again - that
    # produces duplicate rows. Management locks are NOT in the Resources table at
    # all, so they are queried separately via the ARM REST API in _query_locks().
    if scope == "resource_group":
        if not resource_group:
            raise ValueError("resource_group required for resource_group scope")
        kql_query = _kql_rg_filter(resource_group)
    else:
        # Subscription scope (landing zones). The selector can be:
        #   None/''/'*'  -> whole subscription
        #   a glob        -> query broad, filter to matching RGs in Python (below)
        #   an exact name -> filter to that one RG in KQL
        if resource_group in _ALL_RG_SELECTORS or _is_rg_glob(resource_group):
            kql_query = "Resources"
        else:
            kql_query = _kql_rg_filter(resource_group)

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

    resources = []
    if response.data:
        for item in response.data:
            resources.append({
                "type": item.get("type"),
                "name": item.get("name"),
                "location": item.get("location"),
                "tags": item.get("tags", {}),
                "sku": item.get("sku"),
                "kind": item.get("kind"),
                # Availability zones are their own top-level column, not part of
                # properties. Without this the comparator sees no live zones at
                # all and zone placement can never be compared.
                "zones": item.get("zones"),
                "properties": item.get("properties", {}),
                "id": item.get("id"),
                "resource_group": item.get("resourceGroup"),
            })

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential)
    if scope == "subscription":
        resources = _filter_by_rg_selector(resources, resource_group)
    logger.info(f"Found {len(resources)} total resource(s) (Resource Graph + locks + cosmos children)")
    return resources


def _get_live_state_fallback(resource_group: str, sub_id: str, scope: str) -> list[dict]:
    """Fallback: query resources using ResourceManagementClient when Resource Graph is unavailable."""
    logger.warning("Using ResourceManagementClient fallback (slower than Resource Graph)")
    from azure.mgmt.resource.resources import ResourceManagementClient

    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, sub_id)

    resources = []
    start_time = time.time()

    if scope == "resource_group":
        if not resource_group:
            raise ValueError("resource_group required for resource_group scope")
        resource_iterator = client.resources.list_by_resource_group(resource_group, expand="properties")
    else:
        resource_iterator = client.resources.list(expand="properties")

    for resource in resource_iterator:
        # Sub scope with an exact RG name: filter to it. Globs/'*'/None are
        # handled by _filter_by_rg_selector after augmentation (below).
        if (
            scope == "subscription"
            and resource_group not in _ALL_RG_SELECTORS
            and not _is_rg_glob(resource_group)
        ):
            rg_from_id = _extract_resource_group_from_id(resource.id)
            if rg_from_id and rg_from_id.lower() != resource_group.lower():
                continue

        resources.append({
            "type": resource.type,
            "name": resource.name,
            "location": resource.location,
            "tags": resource.tags or {},
            "sku": {"name": resource.sku.name} if resource.sku else None,
            "kind": resource.kind,
            "properties": resource.properties if resource.properties else {},
            "id": resource.id,
            "resource_group": _extract_resource_group_from_id(resource.id),
        })

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential)
    if scope == "subscription":
        resources = _filter_by_rg_selector(resources, resource_group)
    elapsed = time.time() - start_time
    logger.info(f"ResourceManagementClient query completed in {elapsed:.2f}s (slower than Resource Graph)")
    return resources


def _augment_untracked_resources(
    resources: list[dict],
    resource_group: str | None,
    sub_id: str,
    scope: str,
    credential: Any | None = None,
) -> None:
    """Add resources not indexed by Resource Graph / the resource list API, and
    normalise known false-positive properties. Mutates `resources` in place.

    - Management locks (Microsoft.Authorization/locks) via ARM REST
    - Recovery Services vault backupconfig + backupPolicies via ARM REST
    - Cosmos DB SQL databases/containers via ARM REST
    - Cognitive Services / Foundry children via ARM REST
    - Generic data-plane children (storage/servicebus/eventhub/DNS/AKS pools/FW/...)
    - App Service config (config/web + config/appsettings)
    - Extension resources (diagnostic settings, DCR associations)
    - VNet peerings (embedded in vnet properties)
    - Cosmos account location normalization
    - ACI container-group normalization
    - Child-name qualification and id-level dedupe
    """
    # Share one credential+token across the ARM REST helpers instead of each
    # creating its own (avoids repeated auth round-trips). Callers that already
    # authenticated pass their credential in.
    try:
        credential = credential or DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for untracked-resource queries: {e}")
        token = None

    # Each collector logs-and-skips on failure so a single ARM outage never
    # sinks the whole scan; that's the documented "sidecar" contract.
    _extend_swallowing(resources, lambda: _query_locks(resource_group, sub_id, scope, token=token),
                       "locks")
    _extend_swallowing(resources, lambda: _query_cosmos_children(resources, sub_id, token=token),
                       "Cosmos child resources")
    _extend_swallowing(resources, lambda: _query_backup_children(resources, sub_id, token=token),
                       "vault backup config")
    _extend_swallowing(resources, lambda: _query_backup_policies(resources, sub_id, token=token),
                       "vault backup policies")
    _extend_swallowing(resources, lambda: _query_cognitive_deployments(resources, token=token),
                       "Cognitive Services deployments")
    _extend_swallowing(resources, lambda: _expand_data_plane_children(resources, token=token),
                       "data-plane children")
    _extend_swallowing(resources, lambda: _expand_appservice_config(resources, token=token),
                       "App Service config")
    _extend_swallowing(resources, lambda: _expand_extension_resources(resources, token=token),
                       "extension resources")

    _normalize_cosmos_account_locations(resources)
    _normalize_aci_container_groups(resources)
    _expand_vnet_peerings(resources)
    _qualify_child_resource_names(resources)
    _dedupe_resources_by_id(resources)


def _extend_swallowing(resources: list[dict], call, label: str) -> None:
    """Extend `resources` with the collector's output, swallowing exceptions.

    Matches the prior behaviour: a single collector failure logs a warning
    ("Failed to query ${label}: ...") and the scan continues.
    """
    try:
        resources.extend(call())
    except Exception as e:
        logger.warning(f"Failed to query {label}: {e}")
