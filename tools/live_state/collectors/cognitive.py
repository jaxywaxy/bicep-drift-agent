"""Cognitive Services / Azure OpenAI / Foundry children via ARM REST.

Resource Graph indexes NONE of these children, so without expansion the estate's
most drift-prone AI state is never compared:
  * accounts/deployments  - model name/VERSION, sku.capacity (TPM quota)
  * accounts/raiPolicies  - custom content filters (UserManaged only)
  * accounts/projects     - Foundry projects
  * accounts/connections and projects/connections - Foundry connections
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked
from ..common import _extract_resource_group_from_id

logger = logging.getLogger(__name__)


def _cognitive_deployment_child(acct_name: str, rg: str | None, dep: dict) -> dict:
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


def _is_system_managed_rai_policy(item: dict) -> bool:
    """Built-in content filter policies (Microsoft.Default*) are SystemManaged;
    only UserManaged (custom) policies are bicep-comparable state."""
    ptype = str((item.get("properties", {}) or {}).get("type", "")).lower()
    return ptype == "systemmanaged"


def _cognitive_child(rtype: str, parent_name: str, rg: str | None, item: dict) -> dict:
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


def _query_cognitive_deployments(resources: list[dict], token: str | None = None) -> list[dict]:
    """Expand AI (Azure OpenAI / AI Services / Foundry) child resources via ARM REST."""
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

    def _list(parent_id: str, child: str) -> list[dict]:
        req = urllib.request.Request(
            f"https://management.azure.com{parent_id}/{child}?api-version={api_version}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urlopen_checked(req, timeout=30) as resp:
            return _json.load(resp).get("value", [])

    children: list[dict] = []
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
