"""Cosmos DB SQL databases and containers via ARM REST; Cosmos account location
normalisation. Resource Graph does not index these children."""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked
from ..common import _extract_resource_group_from_id

logger = logging.getLogger(__name__)


def _query_cosmos_children(resources: list[dict], sub_id: str, token: str | None = None) -> list[dict]:
    """Query Cosmos DB SQL databases and containers via the ARM REST API.

    Resource Graph does not index Cosmos SQL databases/containers, so they never
    appear in the base query and get falsely flagged as missing. We enumerate them
    from each Cosmos account already found, naming them '{account}/{db}' and
    '{account}/{db}/{container}' to match the Bicep resource naming.
    """
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

    def _get(url: str) -> dict:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urlopen_checked(req, timeout=30) as resp:
            return _json.load(resp)

    children: list[dict] = []
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


def _normalize_cosmos_account_locations(resources: list[dict]) -> None:
    """Normalize Cosmos DB account 'properties.locations' in-place to avoid false drift.

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
