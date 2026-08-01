"""Private endpoint DNS zone groups via ARM REST. Not indexed by Resource Graph.

A zone group is what makes a private endpoint resolvable by its own name. Delete
it, or point its privateDnsZoneConfigs at the wrong zone, and clients silently
fall back to public DNS - traffic meant to traverse Private Link goes out the
front door, with no error anywhere. Until this collector existed the declared
group was permanently reported missing and the false positive was suppressed by
a .drift-ignore rule, so the real thing was invisible too (issue #329).

Listed rather than bicep-driven (unlike defender.py): a private endpoint carries
at most a handful of groups, so the payload is small, and an UNDECLARED group is
itself worth seeing - something added the DNS integration out of band.
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ..common import _extract_resource_group_from_id
from ..common import arm_urlopen

logger = logging.getLogger(__name__)

_API_VERSION = "2023-09-01"


def _shape_zone_group(pe_name: str, rg: str | None, payload: dict) -> dict:
    """Shape a privateDnsZoneGroups payload as '{privateEndpoint}/{group}' to
    match the Bicep child name."""
    return {
        "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
        "name": f"{pe_name}/{payload.get('name') or ''}",
        "location": "unknown",
        "tags": {},
        "sku": None,
        "kind": None,
        "properties": payload.get("properties", {}) or {},
        "id": payload.get("id", ""),
        "resource_group": rg,
    }


def query_private_dns_zone_groups(
    resources: list[dict], sub_id: str, token: str | None = None, gaps=None,
) -> list[dict]:
    """Fetch the DNS zone groups of every private endpoint already found."""
    endpoints = [
        r for r in resources
        if (r.get("type") or "").lower() == "microsoft.network/privateendpoints"
    ]
    if not endpoints:
        return []
    if not token:
        token = DefaultAzureCredential().get_token(
            "https://management.azure.com/.default").token

    out: list[dict] = []
    for pe in endpoints:
        pe_id = pe.get("id", "")
        pe_name = pe.get("name")
        rg = pe.get("resource_group") or _extract_resource_group_from_id(pe_id)
        url = (f"https://management.azure.com{pe_id}/privateDnsZoneGroups"
               f"?api-version={_API_VERSION}")
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with arm_urlopen(req, timeout=30) as resp:
                data = _json.load(resp)
        except Exception as e:
            logger.warning(f"Could not query DNS zone groups for endpoint {pe_name}: {e}")
            if gaps is not None:
                gaps.record("Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
                            f"zone groups for {pe_name} could not be read: {e}")
            continue
        for group in data.get("value", []):
            out.append(_shape_zone_group(pe_name, rg, group))

    logger.info(f"Found {len(out)} private DNS zone group(s) via ARM REST API")
    return out
