"""Cross-subscription resource fetches for bicep modules targeting another sub.

A vending template can deploy cross-scope (e.g. hub-side peering created by
the spoke template via scope: resourceGroup(hubSub, hubRg)). The normalizer
stamps those with _target_subscription/_target_rg; here each is fetched by
point ARM GET from its own subscription and returned in live-resource shape.
"""

import json
import logging
import os
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked
from ..common import _has_unresolved

logger = logging.getLogger(__name__)


def fetch_cross_subscription_resources(arm_resources: list[dict]) -> list[dict]:
    """Fetch bicep resources whose module targets ANOTHER subscription."""
    targets = [r for r in arm_resources if r.get("_target_subscription")]
    if not targets:
        return []
    scanned_sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    fetched: list[dict] = []
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
            with urlopen_checked(req, timeout=30) as resp:
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
