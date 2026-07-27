"""Log Analytics workspace tables via ARM REST. Not indexed by Resource Graph.

Bicep-driven, for the same reason as defender.py: a workspace carries the full
built-in table catalogue - 679 on the drift-test workspace, 2.8 MB of JSON -
and listing them all to keep the one the template declares would flood the
report's live_resources with rows that get dropped again at diff time. So we ask
for the declared tables by name instead: one small GET each, and a declared
table that returns 404 is simply absent from live state, which is exactly the
missing_in_azure signal we want (issue #329).

Matched by LEAF name across every live workspace, not by full name: the declared
parent is usually a uniqueString() placeholder ('log-[86c9cbf6]/CustomLog_CL'),
so the workspace half cannot be resolved at compile time.

Built-in tables are declarable too - setting retentionInDays on Heartbeat is a
normal retention-management pattern - so this deliberately does not filter to
custom '_CL' tables. Whatever the template names is what we fetch.
"""

import json as _json
import logging
import urllib.error
import urllib.request

from azure.identity import DefaultAzureCredential

from ..common import _extract_resource_group_from_id
from ..common import arm_urlopen

logger = logging.getLogger(__name__)

_API_VERSION = "2022-10-01"
_TABLE_TYPE = "microsoft.operationalinsights/workspaces/tables"


def _declared_table_leaves(arm_resources: list[dict]) -> set[str]:
    leaves = {
        (r.get("name") or "").split("/")[-1]
        for r in arm_resources
        if (r.get("type") or "").lower() == _TABLE_TYPE
    }
    leaves.discard("")
    return leaves


def _shape_table(workspace_name: str, rg: str | None, payload: dict) -> dict:
    """Shape a workspace table payload as '{workspace}/{table}' to match the
    Bicep child name."""
    return {
        "type": "Microsoft.OperationalInsights/workspaces/tables",
        "name": f"{workspace_name}/{payload.get('name') or ''}",
        "location": "unknown",
        "tags": {},
        "sku": None,
        "kind": None,
        "properties": payload.get("properties", {}) or {},
        "id": payload.get("id", ""),
        "resource_group": rg,
    }


def fetch_declared_workspace_tables(
    arm_resources: list[dict],
    live_resources: list[dict],
    token: str | None = None,
) -> list[dict]:
    """Fetch the workspace tables the bicep declares - only those."""
    leaves = _declared_table_leaves(arm_resources)
    if not leaves:
        return []
    workspaces = [
        r for r in live_resources
        if (r.get("type") or "").lower() == "microsoft.operationalinsights/workspaces"
    ]
    if not workspaces:
        return []
    if not token:
        try:
            token = DefaultAzureCredential().get_token(
                "https://management.azure.com/.default").token
        except Exception as e:
            logger.warning(f"Could not acquire token for workspace tables: {e}")
            return []

    out: list[dict] = []
    for ws in workspaces:
        ws_id = ws.get("id", "")
        ws_name = ws.get("name")
        rg = ws.get("resource_group") or _extract_resource_group_from_id(ws_id)
        for leaf in sorted(leaves):
            url = (f"https://management.azure.com{ws_id}/tables/{leaf}"
                   f"?api-version={_API_VERSION}")
            try:
                req = urllib.request.Request(
                    url, headers={"Authorization": f"Bearer {token}"})
                with arm_urlopen(req, timeout=30) as resp:
                    payload = _json.load(resp)
            except urllib.error.HTTPError as e:
                # 404 is not an error here - it is the answer. A declared table
                # that does not exist must stay ABSENT from live state so the
                # diff reports it missing; logging it as a failure would train
                # the reader to ignore the one line that matters.
                if e.code != 404:
                    logger.warning(
                        f"Could not query table {leaf} on workspace {ws_name}: {e}")
                continue
            except Exception as e:
                logger.warning(
                    f"Could not query table {leaf} on workspace {ws_name}: {e}")
                continue
            out.append(_shape_table(ws_name, rg, payload))

    logger.info(f"Found {len(out)} declared workspace table(s) via ARM REST API")
    return out
