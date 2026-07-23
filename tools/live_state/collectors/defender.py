"""Defender for Cloud pricing plans - fetch ONLY those the bicep declares.

Every subscription has a pricing row for every plan (default Free); surfacing
undeclared ones would flood extras. Bicep-driven: a declared 'Standard' plan
downgraded to Free IS drift, silence about plans the template doesn't manage
is intentional.
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked

logger = logging.getLogger(__name__)


def fetch_declared_defender_pricings(
    arm_resources: list[dict],
    sub_id: str,
    token: str | None = None,
) -> list[dict]:
    """Fetch Defender for Cloud pricing tiers - ONLY those the bicep declares."""
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
        with urlopen_checked(req, timeout=30) as resp:
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
