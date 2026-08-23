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
from .collectors.private_dns import query_private_dns_zone_groups
from .collectors.cognitive import _query_cognitive_deployments
from .collectors.cosmos import _normalize_cosmos_account_locations, _query_cosmos_children
from .collectors.data_plane import _expand_data_plane_children
from .collectors.extensions import _expand_extension_resources
from .collectors.locks import _query_locks
from .collectors.peerings import _expand_vnet_peerings
from .collectors.resource_groups import query_resource_groups
from .common import (
    _ALL_RG_SELECTORS,
    CollectionGaps,
    _dedupe_resources_by_id,
    _extract_resource_group_from_id,
    _filter_by_rg_selector,
    _is_rg_glob,
    _kql_rg_filter,
    _qualify_child_resource_names,
    retry_with_backoff,
)

logger = logging.getLogger(__name__)


@retry_with_backoff()
def _run_resource_graph_query(client, request):
    """Execute the Resource Graph query, retrying transient 429/5xx. Isolated so
    the retry wraps only the SDK call (idempotent read), not the result handling
    or the ResourceManagementClient fallback."""
    return client.resources(request)


def _ordered_for_paging(kql: str) -> str:
    """Append a deterministic sort unless the query already carries one.

    Resource Graph's paging is only consistent when the query sorts on a unique
    column. Without it the service may repeat a row on one page and omit another
    entirely. A repeat is survivable - `_dedupe_resources_by_id` already exists -
    but an omission is a resource missing from live state, which reads as
    `missing_in_azure`. Both queries paged here project `id`.
    """
    return kql if "order by" in kql.lower() else f"{kql} | order by id asc"


def _run_paginated_query(client, sub_id: str, kql: str) -> list[dict]:
    """Every row the query matches, following Resource Graph's `skip_token`.

    Resource Graph bounds a response and hands back a continuation token for the
    remainder, so a single call returns only the FIRST page. Paging is therefore
    correctness, not throughput: rows never read do not enter live state, and a
    declared resource with no live counterpart is `missing_in_azure`. An
    unpaginated read of an over-bound estate produces a confident report that
    most of it has been deleted - no error, green run.

    It is invisible below the bound, which is where every verification estate
    sits by construction (docs/ARCHITECTURE.md, "Assumed estate size"), so no
    fixture round can catch it.
    """
    rows: list[dict] = []
    query = _ordered_for_paging(kql)
    skip_token = None
    pages = 0

    while True:
        request = QueryRequest(
            subscriptions=[sub_id],
            query=query,
            options={"skip_token": skip_token} if skip_token else None,
        )
        response = _run_resource_graph_query(client, request)
        rows.extend(response.data or [])
        pages += 1
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            break

    # Truncation the service will not let us page past: the rows are simply
    # gone, so the report is WRONG rather than merely short. Say so loudly -
    # this is the one signal that distinguishes "the estate is small" from
    # "we only read part of it".
    truncated = getattr(response, "result_truncated", None)
    if str(getattr(truncated, "value", truncated) or "").lower() == "true":
        logger.warning(
            "Resource Graph reported the result TRUNCATED after %d page(s) with "
            "no continuation token: %d row(s) read, an unknown number dropped. "
            "Declared resources beyond that point will read as missing_in_azure "
            "- treat this report as INCOMPLETE, not as drift.",
            pages, len(rows),
        )
    if pages > 1:
        logger.info(
            "Resource Graph returned %d row(s) across %d pages", len(rows), pages
        )
    return rows

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
    gaps: CollectionGaps | None = None,
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
        gaps: optional CollectionGaps the collectors record into when a type
            cannot be read. Without it a failed collector is indistinguishable
            from an empty one, and its declared resources false-flag missing.

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
        return _get_live_state_fallback(resource_group, sub_id, scope, gaps=gaps)

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
        rows = _run_paginated_query(client, sub_id, kql_query)
    except Exception as e:
        logger.error(f"Resource Graph query failed: {e}, falling back to ResourceManagementClient")
        return _get_live_state_fallback(resource_group, sub_id, scope, gaps=gaps)

    elapsed = time.time() - start_time
    logger.info(f"Resource Graph query completed in {elapsed:.2f}s")

    resources = []
    if rows:
        for item in rows:
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

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential, gaps=gaps)
    if scope == "subscription":
        resources.extend(query_resource_groups(
            lambda kql: _run_paginated_query(client, sub_id, kql),
            sub_id, gaps=gaps))
        resources = _filter_by_rg_selector(resources, resource_group)
    logger.info(f"Found {len(resources)} total resource(s) (Resource Graph + locks + cosmos children)")
    return resources


def _get_live_state_fallback(
    resource_group: str, sub_id: str, scope: str, gaps: CollectionGaps | None = None,
) -> list[dict]:
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

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential, gaps=gaps)
    if scope == "subscription":
        resources = _filter_by_rg_selector(resources, resource_group)
    elapsed = time.time() - start_time
    logger.info(f"ResourceManagementClient query completed in {elapsed:.2f}s (slower than Resource Graph)")
    return resources


#: Types whose ONLY source is an ARM REST collector below - if the shared token
#: cannot be acquired, none of them are gathered and every declared instance
#: would otherwise read as deleted.
_COSMOS_CHILD_TYPES = (
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers",
)
_COGNITIVE_CHILD_TYPES = (
    "Microsoft.CognitiveServices/accounts/deployments",
    "Microsoft.CognitiveServices/accounts/raiPolicies",
)
_EXTENSION_TYPES = (
    "Microsoft.Insights/diagnosticSettings",
    "Microsoft.Insights/dataCollectionRuleAssociations",
)
_AUGMENTED_TYPES = (
    "Microsoft.Authorization/locks",
    "Microsoft.RecoveryServices/vaults/backupconfig",
    "Microsoft.RecoveryServices/vaults/backupPolicies",
    "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
    "Microsoft.Web/sites/config",
    *_COSMOS_CHILD_TYPES,
    *_COGNITIVE_CHILD_TYPES,
    *_EXTENSION_TYPES,
)


def _augment_untracked_resources(
    resources: list[dict],
    resource_group: str | None,
    sub_id: str,
    scope: str,
    credential: Any | None = None,
    gaps: CollectionGaps | None = None,
) -> None:
    """Add resources not indexed by Resource Graph / the resource list API, and
    normalise known false-positive properties. Mutates `resources` in place.

    - Management locks (Microsoft.Authorization/locks) via ARM REST
    - Recovery Services vault backupconfig + backupPolicies via ARM REST
    - Private endpoint DNS zone groups via ARM REST
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

    # A token we could not acquire fails EVERY collector below, so the whole
    # augmented set is unverified rather than absent.
    if token is None and gaps is not None:
        gaps.record_all(_AUGMENTED_TYPES, "no ARM token could be acquired for this run")

    # Each collector logs-and-skips on failure so a single ARM outage never
    # sinks the whole scan; that's the documented "sidecar" contract. `types=`
    # is what it costs: the failure is recorded against the types that collector
    # owns, so their declared resources read "could not verify" instead of
    # "missing". Fan-out collectors pass no types and record their own, per
    # listing - marking all twenty of the data-plane types because one failed
    # would bury real deletions.
    _extend_swallowing(resources, lambda: _query_locks(resource_group, sub_id, scope, token=token),
                       "locks", gaps, ("Microsoft.Authorization/locks",))
    _extend_swallowing(resources, lambda: _query_cosmos_children(resources, sub_id, token=token),
                       "Cosmos child resources", gaps, _COSMOS_CHILD_TYPES)
    _extend_swallowing(resources, lambda: _query_backup_children(resources, sub_id, token=token, gaps=gaps),
                       "vault backup config", gaps, ("Microsoft.RecoveryServices/vaults/backupconfig",))
    _extend_swallowing(resources, lambda: _query_backup_policies(resources, sub_id, token=token, gaps=gaps),
                       "vault backup policies", gaps, ("Microsoft.RecoveryServices/vaults/backupPolicies",))
    _extend_swallowing(resources, lambda: query_private_dns_zone_groups(resources, sub_id, token=token, gaps=gaps),
                       "private DNS zone groups", gaps,
                       ("Microsoft.Network/privateEndpoints/privateDnsZoneGroups",))
    _extend_swallowing(resources, lambda: _query_cognitive_deployments(resources, token=token),
                       "Cognitive Services deployments", gaps, _COGNITIVE_CHILD_TYPES)
    _extend_swallowing(resources, lambda: _expand_data_plane_children(resources, token=token, gaps=gaps),
                       "data-plane children", gaps)
    _extend_swallowing(resources, lambda: _expand_appservice_config(resources, token=token),
                       "App Service config", gaps, ("Microsoft.Web/sites/config",))
    _extend_swallowing(resources, lambda: _expand_extension_resources(resources, token=token),
                       "extension resources", gaps, _EXTENSION_TYPES)

    _normalize_cosmos_account_locations(resources)
    _normalize_aci_container_groups(resources)
    _expand_vnet_peerings(resources)
    _qualify_child_resource_names(resources)
    _dedupe_resources_by_id(resources)


def _extend_swallowing(
    resources: list[dict],
    call,
    label: str,
    gaps: CollectionGaps | None = None,
    types: tuple[str, ...] = (),
) -> None:
    """Extend `resources` with the collector's output, swallowing exceptions.

    Matches the prior behaviour: a single collector failure logs a warning
    ("Failed to query ${label}: ...") and the scan continues - but the types it
    owns are recorded as ungathered, so the diff cannot read their absence as
    deletion.
    """
    try:
        resources.extend(call())
    except Exception as e:
        logger.warning(f"Failed to query {label}: {e}")
        if gaps is not None:
            gaps.record_all(types, f"{label} could not be collected: {e}")
