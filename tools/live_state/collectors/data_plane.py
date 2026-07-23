"""Generic data-plane child expansion via ARM REST.

Resource Graph's Resources table only indexes top-level (and a few child)
resource types. Everything below is invisible without an ARM REST listing -
and these children are where high-value drift lives: a blob container made
public, a hand-added DNS record, a new federated credential on an identity.
"""

import json as _json
import logging
import time
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked

logger = logging.getLogger(__name__)


def _skip_default_consumer_group(item: dict) -> bool:
    return (item.get("name") or "") == "$Default"  # auto-created on every event hub


def _skip_apex_ns_soa(item: dict) -> bool:
    """Zone-apex NS and SOA record sets are auto-created with the zone."""
    rtype = (item.get("type") or "").upper()
    return (item.get("name") or "") == "@" and (rtype.endswith("/NS") or rtype.endswith("/SOA"))


def _skip_builtin_hub_route_table(item: dict) -> bool:
    """defaultRouteTable and noneRouteTable ship with every Virtual Hub; no
    template declares them, so an undeclared one is not drift. Same detect-then-
    drop trade-off as backup DefaultPolicy / storage default containers: a route
    added out-of-band to the built-in defaultRouteTable is not surfaced."""
    return (item.get("name") or "") in ("defaultRouteTable", "noneRouteTable")


# (parent_type_lower, list_path, api_version, child_type, skip_predicate)
_CHILD_EXPANSION_SPECS = [
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
    # AKS agent pools: pools declared as separate agentPools children are invisible
    # to Resource Graph, so without this a declared pool false-flags missing_in_azure
    # (and a deleted/scaled pool goes undetected). Inline system pools surface as
    # extras and are suppressed by the extra_in_azure-scoped ignore.
    ("microsoft.containerservice/managedclusters", "agentPools",
     "2024-02-01", "Microsoft.ContainerService/managedClusters/agentPools", None),
    # Event Grid subscriptions are extension resources under a topic/system topic;
    # a changed destination (re-routing events elsewhere) or filter is quiet, high-
    # value drift. Custom-topic subs list under a nested provider segment; system-
    # topic subs are a plain child. Both parents are base Resource Graph rows.
    ("microsoft.eventgrid/topics", "providers/Microsoft.EventGrid/eventSubscriptions",
     "2023-12-15-preview", "Microsoft.EventGrid/topics/eventSubscriptions", None),
    ("microsoft.eventgrid/systemtopics", "eventSubscriptions",
     "2023-12-15-preview", "Microsoft.EventGrid/systemTopics/eventSubscriptions", None),
    # Azure Firewall Policy rule collection groups hold the actual firewall
    # rules; the policy row itself is nearly empty. Invisible to Resource
    # Graph, so without expansion declared RCGs false-flag missing_in_azure
    # and an out-of-band allow rule (THE classic firewall drift) goes
    # undetected.
    ("microsoft.network/firewallpolicies", "ruleCollectionGroups",
     "2023-09-01", "Microsoft.Network/firewallPolicies/ruleCollectionGroups", None),
    # Virtual Hub routing. The virtualHubs row itself is a base Resource Graph
    # row, but its routing lives in children that Resource Graph does not index.
    # routingIntent is the security control - its routingPolicies force
    # Internet/PrivateTraffic to the Azure Firewall next hop; remove or repoint
    # it and spoke traffic silently bypasses inspection. hubRouteTables carry the
    # explicit routes (nextHop/destinations). Without expansion a declared route
    # table / routing intent false-flags missing_in_azure and an out-of-band
    # bypass goes undetected.
    ("microsoft.network/virtualhubs", "routingIntent",
     "2023-09-01", "Microsoft.Network/virtualHubs/routingIntent", None),
    ("microsoft.network/virtualhubs", "hubRouteTables",
     "2023-09-01", "Microsoft.Network/virtualHubs/hubRouteTables", _skip_builtin_hub_route_table),
    # Hub VNet connections: how a spoke attaches to the hub. Not a Resource Graph
    # row; a changed routingConfiguration (associated/propagated route tables,
    # labels) re-routes the spoke. Connecting a VNet also auto-creates a
    # RemoteVnetToHubPeering on the spoke - filtered in _expand_vnet_peerings.
    ("microsoft.network/virtualhubs", "hubVirtualNetworkConnections",
     "2023-09-01", "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections", None),
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


def _expand_data_plane_children(resources: list[dict], token: str | None = None) -> list[dict]:
    """Expand ARM-REST-only children per _CHILD_EXPANSION_SPECS (see above)."""
    parent_types = {s[0] for s in _CHILD_EXPANSION_SPECS + _RECORDSET_SPECS}
    if not any((r.get("type") or "").lower() in parent_types for r in resources):
        return []

    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for child expansion: {e}")
        return []

    def _list(parent_id: str, path: str, api: str) -> list[dict]:
        req = urllib.request.Request(
            f"https://management.azure.com{parent_id}/{path}?api-version={api}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urlopen_checked(req, timeout=30) as resp:
            return _json.load(resp).get("value", [])

    # Some child types ARE Resource Graph rows in some cases (virtualNetworkLinks,
    # for one) - dedupe by resource id so expansion never duplicates a row the
    # base query already returned (a duplicate live row becomes a false extra).
    seen_ids = {str(r.get("id") or "").lower() for r in resources if r.get("id")}

    def _expand(pool: list[dict], specs) -> list[dict]:
        out: list[dict] = []
        for parent_type, path, api, child_type, skip in specs:
            for parent in [r for r in pool if (r.get("type") or "").lower() == parent_type]:
                pid, pname = parent.get("id", ""), parent.get("name", "")
                if not pid or not pname:
                    continue
                # A failed listing must NOT silently yield "no children": every
                # declared child of this parent would false-flag missing_in_azure
                # (seen live: a transient agentPools failure while an AKS cluster
                # reconciled reported a healthy declared pool as deleted). Retry
                # once, then WARN so the gap is visible in the run log.
                try:
                    items = _list(pid, path, api)
                except Exception:
                    try:
                        time.sleep(2)
                        items = _list(pid, path, api)
                    except Exception as e:
                        logger.warning(
                            f"Could not list {path} for {pname} after retry: {e} - "
                            f"declared {child_type or path} children may false-flag as missing"
                        )
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
        by_type: dict = {}
        for c in children:
            key = (c["type"] or "").split("/")[-1]
            by_type[key] = by_type.get(key, 0) + 1
        logger.info("Expanded data-plane children via ARM REST: "
                    + ", ".join(f"{v} {k}" for k, v in sorted(by_type.items())))
    return children
