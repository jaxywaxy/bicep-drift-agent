"""Management locks (Microsoft.Authorization/locks) via ARM REST.

Locks are NOT indexed in Resource Graph, and the management_locks operations
have been moved/removed across azure-mgmt-* SDK versions. The ARM REST endpoint
is stable and version-independent, so we call it directly with the credential
token we already have.
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked
from ..common import _extract_resource_group_from_id

logger = logging.getLogger(__name__)


def _query_locks(
    resource_group: str | None,
    sub_id: str,
    scope: str,
    token: str | None = None,
) -> list[dict]:
    """Query management locks via the ARM REST API. A shared token may be passed in."""
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
        with urlopen_checked(req, timeout=30) as resp:
            data = _json.load(resp)

        locks = []
        for lk in data.get("value", []):
            lock_id = lk.get("id", "")
            rg = _extract_resource_group_from_id(lock_id) or resource_group
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
