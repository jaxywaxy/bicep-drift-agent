"""
tools/get_live_state.py

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import os
import json
import logging
import re
import time
import fnmatch
from typing import Any, Optional, List, Dict, Callable, TypeVar
from functools import wraps
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)

# Resource-group selectors that mean "the whole subscription" (no filter).
_ALL_RG_SELECTORS = {None, "", "*"}

# Legal Azure resource-group name: alphanumerics, underscores, parentheses,
# hyphens, periods (can't end in a period). Anything else is rejected before
# being interpolated into a KQL query - RG names arrive from LZ configs and
# workflow inputs, so this closes the KQL-injection surface.
_RG_NAME_RE = re.compile(r"^[\w\-\.\(\)]{1,90}$")


def _kql_rg_filter(resource_group: str) -> str:
    """Build the KQL RG filter clause, validating the name first."""
    if not _RG_NAME_RE.match(resource_group or ""):
        raise ValueError(
            f"Invalid resource group name for query: {resource_group!r} "
            "(allowed: alphanumerics, '_', '-', '.', '(', ')')"
        )
    return f"Resources | where resourceGroup =~ '{resource_group}'"


def _is_rg_glob(selector: Optional[str]) -> bool:
    """True if the selector is a glob (e.g. 'jacquidev-*') needing multi-RG match."""
    return bool(selector) and any(c in selector for c in "*?[")


def _rg_of(resource: Dict) -> str:
    """Return a resource's resource-group name (from the field or its id)."""
    rg = resource.get("resource_group")
    if rg:
        return rg
    return _extract_resource_group_from_id(resource.get("id", "")) or ""


def _filter_by_rg_selector(resources: List[Dict], selector: Optional[str]) -> List[Dict]:
    """Keep only resources whose RG matches a glob selector (case-insensitive).

    Used for a subscription-scoped scan restricted to a set of RGs (e.g. one
    landing-zone instance, 'jacquidev-*'). A None/'*'/exact selector is handled
    by the KQL query itself, so this is a no-op for those.
    """
    if not _is_rg_glob(selector):
        return resources
    sel = selector.lower()
    return [r for r in resources if fnmatch.fnmatch(_rg_of(r).lower(), sel)]

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
                except Exception:
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

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential)
    if scope == "subscription":
        resources = _filter_by_rg_selector(resources, resource_group)
    logger.info(f"Found {len(resources)} total resource(s) (Resource Graph + locks + cosmos children)")
    return resources


def _get_live_state_fallback(resource_group: str, sub_id: str, scope: str) -> List[Dict]:
    """Fallback: query resources using ResourceManagementClient when Resource Graph is unavailable."""
    logger.warning("Using ResourceManagementClient fallback (slower than Resource Graph)")
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

    _augment_untracked_resources(resources, resource_group, sub_id, scope, credential=credential)
    if scope == "subscription":
        resources = _filter_by_rg_selector(resources, resource_group)
    elapsed = time.time() - start_time
    logger.info(f"ResourceManagementClient query completed in {elapsed:.2f}s (slower than Resource Graph)")
    return resources


def _augment_untracked_resources(
    resources: List[Dict],
    resource_group: Optional[str],
    sub_id: str,
    scope: str,
    credential: Optional[Any] = None,
) -> None:
    """
    Add resources not indexed by Resource Graph / the resource list API, and
    normalize known false-positive properties. Mutates `resources` in place.

    - Management locks (Microsoft.Authorization/locks) via ARM REST
    - Cosmos DB SQL databases/containers via ARM REST
    - Cosmos account location normalization
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

    try:
        resources.extend(_query_locks(resource_group, sub_id, scope, token=token))
    except Exception as e:
        logger.warning(f"Failed to query locks: {e}")
    try:
        resources.extend(_query_cosmos_children(resources, sub_id, token=token))
    except Exception as e:
        logger.warning(f"Failed to query Cosmos child resources: {e}")
    try:
        resources.extend(_query_cognitive_deployments(resources, token=token))
    except Exception as e:
        logger.warning(f"Failed to query Cognitive Services deployments: {e}")
    try:
        resources.extend(_expand_data_plane_children(resources, token=token))
    except Exception as e:
        logger.warning(f"Failed to expand data-plane children: {e}")
    try:
        resources.extend(_expand_appservice_config(resources, token=token))
    except Exception as e:
        logger.warning(f"Failed to expand App Service config: {e}")
    try:
        resources.extend(_expand_extension_resources(resources, token=token))
    except Exception as e:
        logger.warning(f"Failed to expand extension resources: {e}")
    _normalize_cosmos_account_locations(resources)
    _normalize_aci_container_groups(resources)
    _expand_vnet_peerings(resources)
    _qualify_child_resource_names(resources)
    _dedupe_resources_by_id(resources)


def _dedupe_resources_by_id(resources: List[Dict]) -> None:
    """Drop rows whose resource id duplicates an earlier one (mutates in place).

    Resource Graph is progressively indexing child types (Cognitive Services
    projects, virtualNetworkLinks, ...), so an ARM-REST expansion can add a
    second copy of a row the base query already returned. First-seen wins:
    base Resource Graph rows precede expansion rows, and Graph rows carry
    richer properties. Rows without an id are always kept (nothing to key on).
    """
    seen: set = set()
    deduped: List[Dict] = []
    dropped = 0
    for r in resources:
        rid = str(r.get("id") or "").lower()
        if rid and rid in seen:
            dropped += 1
            continue
        if rid:
            seen.add(rid)
        deduped.append(r)
    if dropped:
        logger.info(f"Deduped {dropped} duplicate live resource row(s) by id")
    resources[:] = deduped


def _qualify_child_resource_names(resources: List[Dict]) -> None:
    """Give Resource-Graph-indexed child resources their parent-qualified name.

    Resource Graph returns some child rows (SQL databases, ...) with the BARE
    child name ('driftdb'), while bicep child resources compile to
    'parent/child' ('sqlserver1/driftdb') - so they can never match and
    double-report as missing + extra. A child type has more segments than its
    name; rebuild the full name from the resource id's path (which alternates
    type/name segments after the provider namespace). Mutates in place.
    """
    for r in resources:
        rtype = r.get("type") or ""
        name = r.get("name") or ""
        expected_segments = len(rtype.split("/")) - 1  # e.g. servers/databases -> 2
        if expected_segments < 2 or name.count("/") == expected_segments - 1:
            continue
        rid = r.get("id") or ""
        marker = "/providers/"
        idx = rid.lower().rfind(marker)
        if idx < 0:
            continue
        segs = rid[idx + len(marker):].split("/")  # [namespace, typeA, nameA, typeB, nameB, ...]
        names = segs[2::2]
        if len(names) == expected_segments:
            r["name"] = "/".join(names)


def _expand_vnet_peerings(resources: List[Dict]) -> None:
    """Expand VNet peerings into child resources (mutates `resources` in place).

    Peerings are NOT separate rows in Resource Graph - they're embedded in the
    vnet's properties.virtualNetworkPeerings. Bicep declares them as child
    resources ('vnet/peering'), so without expansion they can never be matched:
    they show as missing and their properties (allowForwardedTraffic, etc.) are
    never compared. No extra API call - the data is already in the vnet.
    """
    children = []
    for r in resources:
        if (r.get("type") or "").lower() != "microsoft.network/virtualnetworks":
            continue
        vnet_name = r.get("name", "")
        for p in (r.get("properties") or {}).get("virtualNetworkPeerings", []) or []:
            children.append({
                "type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                "name": f"{vnet_name}/{p.get('name', '')}",
                "location": None,  # peerings have no location; None is skipped by the comparator
                "tags": {},
                "sku": None,
                "kind": None,
                "properties": p.get("properties", {}),
                "id": p.get("id"),
                "resource_group": r.get("resource_group"),
            })
    if children:
        logger.info(f"Expanded {len(children)} VNet peering child resource(s)")
        resources.extend(children)


def fetch_cross_subscription_resources(arm_resources: List[Dict]) -> List[Dict]:
    """Fetch bicep resources whose module targets ANOTHER subscription.

    A vending template can deploy cross-scope (e.g. hub-side peering created by
    the spoke template via scope: resourceGroup(hubSub, hubRg)). The normalizer
    stamps those with _target_subscription/_target_rg; here each is fetched by
    point ARM GET from its own subscription (api-version from the bicep) and
    returned in live-resource shape, so normal matching + property comparison
    apply. Unresolvable ids and fetch failures are skipped (the resource then
    surfaces as missing - correct if it genuinely isn't there).
    """
    import urllib.request
    import urllib.error

    targets = [r for r in arm_resources if r.get("_target_subscription")]
    if not targets:
        return []
    scanned_sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    fetched: List[Dict] = []
    token = None
    for r in targets:
        sub = r["_target_subscription"]
        rg = r.get("_target_rg")
        name = r.get("name", "")
        rtype = r.get("type", "")
        api = r.get("apiVersion", "2023-04-01")
        if not rg or not sub or sub == scanned_sub or _has_unresolved(sub) or _has_unresolved(name):
            continue
        # Build the resource id: type Ns/typeA/typeB + name segA/segB
        ns, _, type_path = rtype.partition("/")
        type_segs = type_path.split("/")
        name_segs = name.split("/")
        if len(type_segs) != len(name_segs):
            continue
        path = "/".join(f"{t}/{n}" for t, n in zip(type_segs, name_segs))
        url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
               f"/providers/{ns}/{path}?api-version={api}")
        try:
            if not token:
                token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
            fetched.append({
                "type": rtype, "name": name, "location": data.get("location"),
                "tags": data.get("tags", {}), "sku": data.get("sku"), "kind": data.get("kind"),
                "properties": data.get("properties", {}), "id": data.get("id"),
                "resource_group": rg, "_cross_subscription": sub,
            })
            logger.info(f"Cross-sub verified: {rtype}/{name} in {sub[:8]}...")
        except Exception as e:
            logger.warning(f"Cross-sub fetch failed for {rtype}/{name} in {sub}: {e}")
    return fetched


def _has_unresolved(value: str) -> bool:
    """True if a value still contains unresolved template expression markers."""
    v = (value or "").lower()
    return any(m in v for m in ("(", "[", "subscription-id", "parameters"))


def _query_locks(resource_group: Optional[str], sub_id: str, scope: str, token: Optional[str] = None) -> List[Dict]:
    """
    Query management locks via the ARM REST API.

    Locks are NOT indexed in Resource Graph, and the management_locks operations
    have been moved/removed across azure-mgmt-* SDK versions. The ARM REST endpoint
    is stable and version-independent, so we call it directly with the credential
    token we already have. A shared token may be passed in to avoid re-auth.
    """
    import json as _json
    import urllib.request
    import urllib.error

    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token

        if scope == "resource_group" and resource_group:
            url = (
                f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
            )
        else:
            url = (
                f"https://management.azure.com/subscriptions/{sub_id}/providers/"
                f"Microsoft.Authorization/locks?api-version=2016-09-01"
            )

        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.load(resp)

        locks = []
        for lk in data.get("value", []):
            lock_id = lk.get("id", "")
            rg = _extract_resource_group_from_id(lock_id) or resource_group
            # When scoped to a subscription-wide query, keep only requested RG
            if scope == "subscription" and resource_group and rg and rg.lower() != resource_group.lower():
                continue
            props = lk.get("properties", {}) or {}
            locks.append({
                "type": "Microsoft.Authorization/locks",
                "name": lk.get("name"),
                "location": "unknown",
                "tags": {},
                "sku": None,
                "kind": None,
                "properties": {"level": props.get("level"), "notes": props.get("notes")},
                "id": lock_id,
                "resource_group": rg,
            })

        logger.info(f"Found {len(locks)} management lock(s) via ARM REST API")
        return locks
    except Exception as e:
        logger.warning(f"Could not query locks: {e}")
        return []


def _query_cosmos_children(resources: List[Dict], sub_id: str, token: Optional[str] = None) -> List[Dict]:
    """
    Query Cosmos DB SQL databases and containers via the ARM REST API.

    Resource Graph does not index Cosmos SQL databases/containers, so they never
    appear in the base query and get falsely flagged as missing. We enumerate them
    from each Cosmos account already found, naming them '{account}/{db}' and
    '{account}/{db}/{container}' to match the Bicep resource naming.
    A shared token may be passed in to avoid re-auth.
    """
    import json as _json
    import urllib.request

    api_version = "2023-11-15"
    accounts = [
        r for r in resources
        if (r.get("type") or "").lower() == "microsoft.documentdb/databaseaccounts"
    ]
    if not accounts:
        return []

    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for Cosmos query: {e}")
        return []

    def _get(url: str) -> Dict:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.load(resp)

    children: List[Dict] = []
    for acct in accounts:
        acct_id = acct.get("id", "")
        acct_name = acct.get("name", "")
        rg = acct.get("resource_group") or _extract_resource_group_from_id(acct_id)
        if not acct_id or not acct_name:
            continue
        try:
            dbs = _get(f"https://management.azure.com{acct_id}/sqlDatabases?api-version={api_version}")
        except Exception as e:
            logger.debug(f"Could not list Cosmos databases for {acct_name}: {e}")
            continue

        for db in dbs.get("value", []):
            db_name = (db.get("properties", {}) or {}).get("resource", {}).get("id") or db.get("name")
            db_id = db.get("id", "")
            children.append({
                "type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases",
                "name": f"{acct_name}/{db_name}",
                "location": "unknown",
                "tags": {},
                "sku": None,
                "kind": None,
                "properties": db.get("properties", {}) or {},
                "id": db_id,
                "resource_group": rg,
            })

            try:
                containers = _get(f"https://management.azure.com{db_id}/containers?api-version={api_version}")
            except Exception as e:
                logger.debug(f"Could not list Cosmos containers for {acct_name}/{db_name}: {e}")
                continue

            for c in containers.get("value", []):
                c_id = c.get("id", "")
                c_props = c.get("properties", {}) or {}
                c_name = c_props.get("resource", {}).get("id") or c.get("name")

                # Normalize indexingMode casing: Azure returns lowercase ("consistent")
                # while Bicep declares it capitalized ("Consistent"). Cosmos treats it
                # case-insensitively, so align casing to avoid a false property drift.
                idx = c_props.get("resource", {}).get("indexingPolicy", {})
                if isinstance(idx, dict) and isinstance(idx.get("indexingMode"), str):
                    idx["indexingMode"] = idx["indexingMode"].capitalize()

                # Throughput is not returned by the container GET - it lives at the
                # throughputSettings sub-resource. Fetch it so Bicep's options.throughput
                # can be compared instead of always showing as drift.
                try:
                    th = _get(
                        f"https://management.azure.com{c_id}/throughputSettings/default"
                        f"?api-version={api_version}"
                    )
                    th_res = (th.get("properties", {}) or {}).get("resource", {}) or {}
                    if th_res.get("throughput") is not None:
                        c_props.setdefault("options", {})["throughput"] = th_res["throughput"]
                    elif (th_res.get("autoscaleSettings") or {}).get("maxThroughput") is not None:
                        c_props.setdefault("options", {}).setdefault("autoscaleSettings", {})[
                            "maxThroughput"
                        ] = th_res["autoscaleSettings"]["maxThroughput"]
                except Exception as e:
                    logger.debug(f"Could not fetch throughput for {acct_name}/{db_name}/{c_name}: {e}")

                children.append({
                    "type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers",
                    "name": f"{acct_name}/{db_name}/{c_name}",
                    "location": "unknown",
                    "tags": {},
                    "sku": None,
                    "kind": None,
                    "properties": c_props,
                    "id": c_id,
                    "resource_group": rg,
                })

    logger.info(f"Found {len(children)} Cosmos SQL database/container resource(s) via ARM REST API")
    return children


def _cognitive_deployment_child(acct_name: str, rg: Optional[str], dep: Dict) -> Dict:
    """Shape an AI model deployment as a live child resource ('{account}/{dep}').

    sku is kept (name + capacity): capacity is the TPM quota, the classic
    out-of-band bump. Azure-only augmentation in properties (capabilities,
    rateLimits, provisioningState, ...) is tolerated by the bicep-driven
    subset comparison, so properties pass through unmodified.
    """
    return {
        "type": "Microsoft.CognitiveServices/accounts/deployments",
        "name": f"{acct_name}/{dep.get('name', '')}",
        "location": None,  # deployments carry no location; None is skipped by the comparator
        "tags": {},
        "sku": dep.get("sku"),
        "kind": None,
        "properties": dep.get("properties", {}) or {},
        "id": dep.get("id"),
        "resource_group": rg,
    }


def _is_system_managed_rai_policy(item: Dict) -> bool:
    """Built-in content filter policies (Microsoft.Default*) are SystemManaged;
    only UserManaged (custom) policies are bicep-comparable state."""
    ptype = str((item.get("properties", {}) or {}).get("type", "")).lower()
    return ptype == "systemmanaged"


def _query_cognitive_deployments(resources: List[Dict], token: Optional[str] = None) -> List[Dict]:
    """Expand AI (Azure OpenAI / AI Services / Foundry) child resources via ARM REST.

    Resource Graph indexes NONE of these children, so without expansion the
    estate's most drift-prone AI state is never compared:
      * accounts/deployments  - model name/VERSION, sku.capacity (TPM quota)
      * accounts/raiPolicies  - custom content filters (UserManaged only;
        the Microsoft.Default* built-ins are SystemManaged noise)
      * accounts/projects     - Foundry projects
      * accounts/connections and projects/connections - Foundry connections
        (out-of-band additions = new data channels; the list API returns
        metadata only - category/target/authType - never credentials)
    Same pattern as the Cosmos children expansion.
    """
    import json as _json
    import urllib.request

    api_version = "2025-06-01"
    accounts = [
        r for r in resources
        if (r.get("type") or "").lower() == "microsoft.cognitiveservices/accounts"
    ]
    if not accounts:
        return []

    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for Cognitive Services query: {e}")
        return []

    def _list(parent_id: str, child: str) -> List[Dict]:
        req = urllib.request.Request(
            f"https://management.azure.com{parent_id}/{child}?api-version={api_version}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.load(resp).get("value", [])

    children: List[Dict] = []
    counts = {"deployments": 0, "raiPolicies": 0, "projects": 0, "connections": 0}
    for acct in accounts:
        acct_id = acct.get("id", "")
        acct_name = acct.get("name", "")
        rg = acct.get("resource_group") or _extract_resource_group_from_id(acct_id)
        if not acct_id or not acct_name:
            continue

        try:
            for dep in _list(acct_id, "deployments"):
                children.append(_cognitive_deployment_child(acct_name, rg, dep))
                counts["deployments"] += 1
        except Exception as e:
            logger.debug(f"Could not list deployments for {acct_name}: {e}")

        try:
            for pol in _list(acct_id, "raiPolicies"):
                if _is_system_managed_rai_policy(pol):
                    continue
                children.append(_cognitive_child(
                    "Microsoft.CognitiveServices/accounts/raiPolicies", acct_name, rg, pol
                ))
                counts["raiPolicies"] += 1
        except Exception as e:
            logger.debug(f"Could not list raiPolicies for {acct_name}: {e}")

        try:
            for conn in _list(acct_id, "connections"):
                children.append(_cognitive_child(
                    "Microsoft.CognitiveServices/accounts/connections", acct_name, rg, conn
                ))
                counts["connections"] += 1
        except Exception as e:
            logger.debug(f"Could not list connections for {acct_name}: {e}")

        try:
            projects = _list(acct_id, "projects")
        except Exception as e:
            logger.debug(f"Could not list projects for {acct_name}: {e}")
            projects = []
        for proj in projects:
            proj_name = proj.get("name", "")
            children.append({
                **_cognitive_child(
                    "Microsoft.CognitiveServices/accounts/projects", acct_name, rg, proj
                ),
                "location": proj.get("location"),  # projects DO carry a location
            })
            counts["projects"] += 1
            try:
                for conn in _list(proj.get("id", ""), "connections"):
                    children.append(_cognitive_child(
                        "Microsoft.CognitiveServices/accounts/projects/connections",
                        f"{acct_name}/{proj_name}", rg, conn,
                    ))
                    counts["connections"] += 1
            except Exception as e:
                logger.debug(f"Could not list connections for project {proj_name}: {e}")

    if children:
        summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
        logger.info(f"Expanded AI children via ARM REST API: {summary}")
    return children


# ---------------------------------------------------------------------------
# Generic data-plane child expansion.
#
# Resource Graph's Resources table only indexes top-level (and a few child)
# resource types. Everything below is invisible without an ARM REST listing -
# and these children are where high-value drift lives: a blob container made
# public, a hand-added DNS record, a new federated credential on an identity.
# Each spec: (parent type, list path under the parent, api-version, child
# type, optional per-item skip predicate).
# ---------------------------------------------------------------------------

def _skip_default_consumer_group(item: Dict) -> bool:
    return (item.get("name") or "") == "$Default"  # auto-created on every event hub


def _skip_apex_ns_soa(item: Dict) -> bool:
    """Zone-apex NS and SOA record sets are auto-created with the zone."""
    rtype = (item.get("type") or "").upper()
    return (item.get("name") or "") == "@" and (rtype.endswith("/NS") or rtype.endswith("/SOA"))


_CHILD_EXPANSION_SPECS = [
    # (parent_type_lower, list_path, api_version, child_type, skip_predicate)
    # The 'default' blob/file service rows themselves (soft-delete/versioning
    # policies live here, and bicep declares them as parents of containers).
    ("microsoft.storage/storageaccounts", "blobServices",
     "2023-01-01", "Microsoft.Storage/storageAccounts/blobServices", None),
    ("microsoft.storage/storageaccounts", "fileServices",
     "2023-01-01", "Microsoft.Storage/storageAccounts/fileServices", None),
    ("microsoft.storage/storageaccounts", "blobServices/default/containers",
     "2023-01-01", "Microsoft.Storage/storageAccounts/blobServices/containers", None),
    ("microsoft.storage/storageaccounts", "fileServices/default/shares",
     "2023-01-01", "Microsoft.Storage/storageAccounts/fileServices/shares", None),
    ("microsoft.servicebus/namespaces", "queues",
     "2021-11-01", "Microsoft.ServiceBus/namespaces/queues", None),
    ("microsoft.servicebus/namespaces", "topics",
     "2021-11-01", "Microsoft.ServiceBus/namespaces/topics", None),
    ("microsoft.eventhub/namespaces", "eventhubs",
     "2021-11-01", "Microsoft.EventHub/namespaces/eventhubs", None),
    ("microsoft.network/privatednszones", "virtualNetworkLinks",
     "2020-06-01", "Microsoft.Network/privateDnsZones/virtualNetworkLinks", None),
    ("microsoft.managedidentity/userassignedidentities", "federatedIdentityCredentials",
     "2023-01-31", "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials", None),
    # SQL server firewall rules: a hand-added rule (esp. an AllowAll 0.0.0.0
    # range) opening a prod database to the internet is the classic drift.
    ("microsoft.sql/servers", "firewallRules",
     "2023-08-01-preview", "Microsoft.Sql/servers/firewallRules", None),
    # Front Door Standard/Premium (Microsoft.Cdn/profiles) children. Drift here
    # redirects traffic (origins), changes routing/TLS (routes), or detaches the
    # WAF (securityPolicies). Origins/routes are grandchildren (below).
    ("microsoft.cdn/profiles", "afdEndpoints",
     "2023-05-01", "Microsoft.Cdn/profiles/afdEndpoints", None),
    ("microsoft.cdn/profiles", "originGroups",
     "2023-05-01", "Microsoft.Cdn/profiles/originGroups", None),
    ("microsoft.cdn/profiles", "securityPolicies",
     "2023-05-01", "Microsoft.Cdn/profiles/securityPolicies", None),
    ("microsoft.cdn/profiles", "ruleSets",
     "2023-05-01", "Microsoft.Cdn/profiles/ruleSets", None),
    # Event Grid subscriptions are extension resources under a topic/system topic;
    # a changed destination (re-routing events elsewhere) or filter is quiet, high-
    # value drift. Custom-topic subs list under a nested provider segment; system-
    # topic subs are a plain child. Both parents are base Resource Graph rows.
    ("microsoft.eventgrid/topics", "providers/Microsoft.EventGrid/eventSubscriptions",
     "2023-12-15-preview", "Microsoft.EventGrid/topics/eventSubscriptions", None),
    ("microsoft.eventgrid/systemtopics", "eventSubscriptions",
     "2023-12-15-preview", "Microsoft.EventGrid/systemTopics/eventSubscriptions", None),
]

# Record sets list with their concrete type in the response (…/dnszones/A etc.);
# the spec's child_type of None means "use the item's own type".
_RECORDSET_SPECS = [
    ("microsoft.network/dnszones", "recordsets", "2018-05-01", None, _skip_apex_ns_soa),
    ("microsoft.network/privatednszones", "ALL", "2020-06-01", None, _skip_apex_ns_soa),
]

# Children of children, expanded from the first pass's results.
_GRANDCHILD_EXPANSION_SPECS = [
    ("microsoft.eventhub/namespaces/eventhubs", "consumergroups",
     "2021-11-01", "Microsoft.EventHub/namespaces/eventhubs/consumergroups",
     _skip_default_consumer_group),
    ("microsoft.eventhub/namespaces/eventhubs", "authorizationRules",
     "2021-11-01", "Microsoft.EventHub/namespaces/eventhubs/authorizationRules", None),
    # Front Door origins live under origin groups; routes under endpoints. An
    # added origin is a traffic-redirect (exfil) vector; a route's TLS/forwarding
    # change is a downgrade risk.
    ("microsoft.cdn/profiles/origingroups", "origins",
     "2023-05-01", "Microsoft.Cdn/profiles/originGroups/origins", None),
    ("microsoft.cdn/profiles/afdendpoints", "routes",
     "2023-05-01", "Microsoft.Cdn/profiles/afdEndpoints/routes", None),
]


def _expand_data_plane_children(resources: List[Dict], token: Optional[str] = None) -> List[Dict]:
    """Expand ARM-REST-only children per _CHILD_EXPANSION_SPECS (see above)."""
    import json as _json
    import urllib.request

    parent_types = {s[0] for s in _CHILD_EXPANSION_SPECS + _RECORDSET_SPECS}
    if not any((r.get("type") or "").lower() in parent_types for r in resources):
        return []

    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for child expansion: {e}")
        return []

    def _list(parent_id: str, path: str, api: str) -> List[Dict]:
        req = urllib.request.Request(
            f"https://management.azure.com{parent_id}/{path}?api-version={api}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.load(resp).get("value", [])

    # Some child types ARE Resource Graph rows in some cases (virtualNetworkLinks,
    # for one) - dedupe by resource id so expansion never duplicates a row the
    # base query already returned (a duplicate live row becomes a false extra).
    seen_ids = {str(r.get("id") or "").lower() for r in resources if r.get("id")}

    def _expand(pool: List[Dict], specs) -> List[Dict]:
        out: List[Dict] = []
        for parent_type, path, api, child_type, skip in specs:
            for parent in [r for r in pool if (r.get("type") or "").lower() == parent_type]:
                pid, pname = parent.get("id", ""), parent.get("name", "")
                if not pid or not pname:
                    continue
                try:
                    items = _list(pid, path, api)
                except Exception as e:
                    logger.debug(f"Could not list {path} for {pname}: {e}")
                    continue
                for item in items:
                    if skip and skip(item):
                        continue
                    item_id = str(item.get("id") or "").lower()
                    if item_id and item_id in seen_ids:
                        continue
                    if item_id:
                        seen_ids.add(item_id)
                    # blobServices/fileServices paths inject the implicit
                    # 'default' segment bicep child names carry.
                    infix = "default/" if "/default/" in f"/{path}/" else ""
                    out.append({
                        "type": child_type or item.get("type"),
                        "name": f"{pname}/{infix}{item.get('name', '')}",
                        "location": None,
                        "tags": {},
                        "sku": item.get("sku"),
                        "kind": None,
                        "properties": item.get("properties", {}) or {},
                        "id": item.get("id"),
                        "resource_group": parent.get("resource_group"),
                    })
        return out

    children = _expand(resources, _CHILD_EXPANSION_SPECS + _RECORDSET_SPECS)
    # Grandchild parents (AFD afdEndpoints/originGroups) can come from EITHER the
    # child expansion above OR the base Resource Graph query — afdEndpoints is
    # returned as a base row, so the first pass dedups it out of `children` (its id
    # is already seen). Expand grandchildren over BOTH pools, otherwise AFD routes
    # (whose parent endpoint came from the base query) are never fetched and every
    # route false-flags as missing_in_azure. seen_ids still prevents duplicate rows.
    children.extend(_expand(resources + children, _GRANDCHILD_EXPANSION_SPECS))
    if children:
        by_type = {}
        for c in children:
            key = (c["type"] or "").split("/")[-1]
            by_type[key] = by_type.get(key, 0) + 1
        logger.info("Expanded data-plane children via ARM REST: "
                    + ", ".join(f"{v} {k}" for k, v in sorted(by_type.items())))
    return children


def _expand_appservice_config(resources: List[Dict], token: Optional[str] = None) -> List[Dict]:
    """Expand App Service config children: config/web + config/appsettings.

    config/web (GET) carries the non-secret runtime surface: TLS minimum,
    ftpsState, http20Enabled, alwaysOn - portal setting flips are the canonical
    workload drift. App settings VALUES are secrets: the appsettings child is
    shaped with its raw properties here, and the comparator reduces both sides
    to KEY SETS (values are never compared or written to a report).
    """
    import json as _json
    import urllib.request

    api = "2023-01-01"
    sites = [r for r in resources if (r.get("type") or "").lower() == "microsoft.web/sites"]
    if not sites:
        return []
    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for App Service config: {e}")
        return []

    def _call(url: str, method: str = "GET") -> Dict:
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}", "Content-Length": "0"},
            method=method, data=b"" if method == "POST" else None,
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.load(resp)

    children: List[Dict] = []
    for site in sites:
        sid, sname = site.get("id", ""), site.get("name", "")
        if not sid or not sname:
            continue
        try:
            web = _call(f"https://management.azure.com{sid}/config/web?api-version={api}")
            children.append({
                "type": "Microsoft.Web/sites/config", "name": f"{sname}/web",
                "location": None, "tags": {}, "sku": None, "kind": None,
                "properties": web.get("properties", {}) or {},
                "id": web.get("id"), "resource_group": site.get("resource_group"),
            })
        except Exception as e:
            logger.debug(f"Could not fetch config/web for {sname}: {e}")
        try:
            apps = _call(f"https://management.azure.com{sid}/config/appsettings/list?api-version={api}",
                         method="POST")
            children.append({
                "type": "Microsoft.Web/sites/config", "name": f"{sname}/appsettings",
                "location": None, "tags": {}, "sku": None, "kind": None,
                "properties": apps.get("properties", {}) or {},  # comparator reduces to keys
                "id": apps.get("id"), "resource_group": site.get("resource_group"),
            })
        except Exception as e:
            logger.debug(f"Could not fetch appsettings for {sname}: {e}")
    if children:
        logger.info(f"Expanded {len(children)} App Service config object(s)")
    return children


# Types that commonly carry diagnostic settings - queried per resource (N calls),
# so scoped to a curated set rather than every row.
_DIAGNOSTIC_PARENT_TYPES = {
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.web/sites",
    "microsoft.sql/servers/databases",
    "microsoft.eventhub/namespaces",
    "microsoft.servicebus/namespaces",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.cognitiveservices/accounts",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/azurefirewalls",
    "microsoft.network/applicationgateways",
    "microsoft.containerservice/managedclusters",
    "microsoft.operationalinsights/workspaces",
    "microsoft.logic/workflows",
}


# Data Collection Rule associations link a DCR to a monitored resource (chiefly
# VMs/VMSS). A deleted association silences guest telemetry - the modern
# equivalent of a deleted diagnostic setting.
_DCR_ASSOCIATION_PARENT_TYPES = {
    "microsoft.compute/virtualmachines",
    "microsoft.compute/virtualmachinescalesets",
    "microsoft.hybridcompute/machines",  # Arc-enabled servers
}

# Extension-resource types the agent expands per-resource, keyed by the child
# type: (parent-type set, provider-relative list path, api-version, log label).
_EXTENSION_EXPANSION_SPECS = {
    "Microsoft.Insights/diagnosticSettings": (
        _DIAGNOSTIC_PARENT_TYPES, "providers/Microsoft.Insights/diagnosticSettings",
        "2021-05-01-preview", "diagnostic setting"),
    "Microsoft.Insights/dataCollectionRuleAssociations": (
        _DCR_ASSOCIATION_PARENT_TYPES, "providers/Microsoft.Insights/dataCollectionRuleAssociations",
        "2022-06-01", "DCR association"),
}

# The extension types whose bicep resources carry a 'scope' field to qualify.
_EXTENSION_TYPES_LOWER = {t.lower() for t in _EXTENSION_EXPANSION_SPECS}


def _expand_extension_resources(resources: List[Dict], token: Optional[str] = None) -> List[Dict]:
    """Expand per-resource extension children (diagnostic settings, DCR
    associations) named '{resource}/{name}'.

    These are attached to a target resource and are NOT Resource Graph rows; a
    deleted one is a silenced audit/telemetry feed - the drift that must page
    someone. Bicep declares them as extension resources with a 'scope';
    qualify_extension_resource_names() aligns those to the same name form.
    """
    import json as _json
    import urllib.request

    active = {
        child_type: spec for child_type, spec in _EXTENSION_EXPANSION_SPECS.items()
        if any((r.get("type") or "").lower() in spec[0] for r in resources)
    }
    if not active:
        return []
    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for extension-resource expansion: {e}")
        return []

    children: List[Dict] = []
    for child_type, (parent_types, path, api, label) in active.items():
        parents = [
            r for r in resources
            if (r.get("type") or "").lower() in parent_types and r.get("id")
        ]
        count = 0
        for parent in parents[:60]:  # hard cap on the N+1 fan-out
            pid, pname = parent["id"], parent.get("name", "")
            try:
                req = urllib.request.Request(
                    f"https://management.azure.com{pid}/{path}?api-version={api}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    items = _json.load(resp).get("value", [])
            except Exception as e:
                logger.debug(f"Could not list {label} for {pname}: {e}")
                continue
            for item in items:
                children.append({
                    "type": child_type,
                    "name": f"{pname}/{item.get('name', '')}",
                    "location": None, "tags": {}, "sku": None, "kind": None,
                    "properties": item.get("properties", {}) or {},
                    "id": item.get("id"), "resource_group": parent.get("resource_group"),
                })
                count += 1
        if count:
            logger.info(f"Expanded {count} {label}(s)")
    return children


# Back-compat alias (used by tests and callers that expanded diag settings only).
def _expand_diagnostic_settings(resources: List[Dict], token: Optional[str] = None) -> List[Dict]:
    return _expand_extension_resources(resources, token=token)


def qualify_extension_resource_names(arm_resources: List[Dict]) -> None:
    """Rewrite bicep extension resources (diagnostic settings, DCR associations)
    to '{scope-leaf}/{name}' so they match the live expansion form.

    A bicep extension resource compiles with a plain name plus a 'scope' field
    ('Microsoft.Storage/storageAccounts/stX'); live expansion names them
    '{resourceName}/{settingName}'. Mutates in place.
    """
    for r in arm_resources:
        if (r.get("type") or "").lower() not in _EXTENSION_TYPES_LOWER:
            continue
        scope = str(r.get("scope") or "")
        if not scope or "/" in (r.get("name") or ""):
            continue
        scope_leaf = scope.split("/")[-1]
        if scope_leaf:
            r["name"] = f"{scope_leaf}/{r['name']}"


# Back-compat alias.
qualify_diagnostic_setting_names = qualify_extension_resource_names


def fetch_declared_defender_pricings(arm_resources: List[Dict], sub_id: str,
                                     token: Optional[str] = None) -> List[Dict]:
    """Fetch Defender for Cloud pricing tiers - ONLY those the bicep declares.

    Every subscription has a pricing row for every plan (default Free), so
    surfacing undeclared ones would flood extras; this is bicep-driven only:
    a declared 'Standard' plan downgraded to Free IS drift, silence about
    plans the template doesn't manage is intentional.
    """
    import json as _json
    import urllib.request

    declared = {
        (r.get("name") or "").split("/")[-1].lower()
        for r in arm_resources
        if (r.get("type") or "").lower() == "microsoft.security/pricings"
    }
    declared.discard("")
    if not declared:
        return []
    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
        req = urllib.request.Request(
            f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            items = _json.load(resp).get("value", [])
    except Exception as e:
        logger.warning(f"Could not fetch Defender pricings: {e}")
        return []

    rows = []
    for item in items:
        if (item.get("name") or "").lower() not in declared:
            continue
        rows.append({
            "type": "Microsoft.Security/pricings", "name": item.get("name"),
            "location": None, "tags": {}, "sku": None, "kind": None,
            "properties": item.get("properties", {}) or {},
            "id": item.get("id"), "resource_group": None,
        })
    if rows:
        logger.info(f"Fetched {len(rows)} declared Defender pricing plan(s)")
    return rows


def _cognitive_child(rtype: str, parent_name: str, rg: Optional[str], item: Dict) -> Dict:
    """Shape a Cognitive Services child resource as '{parent}/{name}' live state.

    Some list APIs (projects) already return parent-qualified names
    ('account/project') while others (deployments, raiPolicies) return bare
    names - prefix only when needed, or the name double-prefixes.
    """
    raw_name = item.get("name", "")
    qualified = raw_name if raw_name.startswith(f"{parent_name}/") else f"{parent_name}/{raw_name}"
    return {
        "type": rtype,
        "name": qualified,
        "location": None,  # child resources carry no location; None is skipped
        "tags": {},
        "sku": item.get("sku"),
        "kind": None,
        "properties": item.get("properties", {}) or {},
        "id": item.get("id"),
        "resource_group": rg,
    }


def _normalize_cosmos_account_locations(resources: List[Dict]) -> None:
    """
    Normalize Cosmos DB account 'properties.locations' in-place to avoid false drift.

    Bicep declares locations as e.g. {locationName: 'australiaeast', failoverPriority: 0,
    isZoneRedundant: false}. Azure returns the display-form region name ('Australia East')
    plus service-injected fields (id, documentEndpoint, provisioningState). We reduce each
    live location to the Bicep-relevant fields and normalize locationName (lowercase, no
    spaces) so 'Australia East' == 'australiaeast' and only genuine changes are flagged.
    """
    for r in resources:
        if (r.get("type") or "").lower() != "microsoft.documentdb/databaseaccounts":
            continue
        props = r.get("properties")
        if not isinstance(props, dict):
            continue
        locs = props.get("locations")
        if not isinstance(locs, list):
            continue
        normalized = []
        for loc in locs:
            if not isinstance(loc, dict):
                normalized.append(loc)
                continue
            name = loc.get("locationName", "")
            normalized.append({
                "locationName": name.replace(" ", "").lower() if isinstance(name, str) else name,
                "failoverPriority": loc.get("failoverPriority"),
                "isZoneRedundant": loc.get("isZoneRedundant"),
            })
        props["locations"] = normalized


def _normalize_aci_container_groups(resources: List[Dict]) -> None:
    """
    Normalize Container Instance 'properties.containers' in-place to avoid false drift.

    Azure injects runtime-only fields into each container that Bicep never declares
    (instanceView, empty configMap/environmentVariables/ports/volumeMounts) and returns
    cpu/memoryInGB as floats (1.0) where Bicep uses ints (1). We strip the runtime noise
    and coerce whole-number requests to int, so a genuine change (e.g. image tag or
    cpu/memory) still surfaces while cosmetic differences do not.
    """
    RUNTIME_ONLY = ("instanceView",)
    DROP_IF_EMPTY = ("configMap", "environmentVariables", "ports", "volumeMounts", "command")

    for r in resources:
        if (r.get("type") or "").lower() != "microsoft.containerinstance/containergroups":
            continue
        props = r.get("properties")
        if not isinstance(props, dict):
            continue
        containers = props.get("containers")
        if not isinstance(containers, list):
            continue
        for c in containers:
            cprops = c.get("properties") if isinstance(c, dict) else None
            if not isinstance(cprops, dict):
                continue
            for key in RUNTIME_ONLY:
                cprops.pop(key, None)
            for key in DROP_IF_EMPTY:
                if key in cprops and cprops[key] in ([], {}, None):
                    cprops.pop(key, None)
            # configMap comes back as {"keyValuePairs": {}} when unset - drop that too
            cm = cprops.get("configMap")
            if isinstance(cm, dict) and not cm.get("keyValuePairs"):
                cprops.pop("configMap", None)
            requests = (cprops.get("resources") or {}).get("requests")
            if isinstance(requests, dict):
                for key in ("cpu", "memoryInGB"):
                    v = requests.get(key)
                    if isinstance(v, float) and v.is_integer():
                        requests[key] = int(v)


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


if __name__ == "__main__":
    import sys
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
