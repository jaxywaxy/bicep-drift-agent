"""Expand VNet peerings from their parent VNet's properties into child rows.

Peerings are NOT separate rows in Resource Graph - they're embedded in the
vnet's properties.virtualNetworkPeerings. Bicep declares them as child
resources ('vnet/peering'), so without expansion they can never be matched.
No extra API call - the data is already in the vnet.
"""

import logging

logger = logging.getLogger(__name__)


def _expand_vnet_peerings(resources: list[dict]) -> None:
    """Expand VNet peerings into child resources (mutates `resources` in place)."""
    children = []
    for r in resources:
        if (r.get("type") or "").lower() != "microsoft.network/virtualnetworks":
            continue
        vnet_name = r.get("name", "")
        for p in (r.get("properties") or {}).get("virtualNetworkPeerings", []) or []:
            # Connecting a VNet to a Virtual Hub auto-creates a platform-managed
            # peering (RemoteVnetToHubPeering_<guid> on the spoke, HubToRemoteVnet
            # the other way). No template declares it, so it would false-flag as an
            # extra - skip it, the hubVirtualNetworkConnection is the real resource.
            pname = p.get("name", "") or ""
            if pname.startswith("RemoteVnetToHubPeering") or pname.startswith("HubToRemoteVnetPeering"):
                continue
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
