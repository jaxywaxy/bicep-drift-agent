"""Recovery Services vault child resources (backupconfig + backupPolicies) via
ARM REST. Neither is indexed by Resource Graph."""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked
from ..common import _extract_resource_group_from_id

logger = logging.getLogger(__name__)


def _shape_backup_config(vault_name: str, rg: str | None, payload: dict) -> dict:
    """Shape a Recovery Services vault backupconfig ARM REST payload into a
    resource dict named '{vault}/vaultconfig' to match the Bicep child name.
    Live-only fields (softDeleteRetentionPeriodInDays, isSoftDeleteFeatureStateEditable)
    are kept as-is; the bicep-keyed comparator only checks declared properties."""
    cfg_name = payload.get("name") or "vaultconfig"
    return {
        "type": "Microsoft.RecoveryServices/vaults/backupconfig",
        "name": f"{vault_name}/{cfg_name}",
        "location": "unknown",
        "tags": {},
        "sku": None,
        "kind": None,
        "properties": payload.get("properties", {}) or {},
        "id": payload.get("id", ""),
        "resource_group": rg,
    }


def _query_backup_children(resources: list[dict], sub_id: str, token: str | None = None) -> list[dict]:
    """Query Recovery Services vault backup config via the ARM REST API.

    Resource Graph does NOT index vaults/backupconfig (confirmed: a graph query
    returns zero rows), so a declared backupconfig never matches and gets falsely
    flagged missing. softDeleteFeatureState is the headline backup security
    control - disabling it lets backups be deleted immediately - so we fetch the
    vaultconfig for each vault already found and name it '{vault}/vaultconfig'.
    """
    api_version = "2023-06-01"
    vaults = [
        r for r in resources
        if (r.get("type") or "").lower() == "microsoft.recoveryservices/vaults"
    ]
    if not vaults:
        return []
    if not token:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token

    out: list[dict] = []
    for v in vaults:
        vault_id = v.get("id", "")
        vault_name = v.get("name")
        rg = v.get("resource_group") or _extract_resource_group_from_id(vault_id)
        url = f"https://management.azure.com{vault_id}/backupconfig/vaultconfig?api-version={api_version}"
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urlopen_checked(req, timeout=30) as resp:
                payload = _json.load(resp)
        except Exception as e:
            logger.warning(f"Could not query backupconfig for vault {vault_name}: {e}")
            continue
        out.append(_shape_backup_config(vault_name, rg, payload))

    logger.info(f"Found {len(out)} vault backup config(s) via ARM REST API")
    return out


def _shape_backup_policy(vault_name: str, rg: str | None, payload: dict) -> dict:
    """Shape a Recovery Services vault backupPolicies ARM REST payload into a
    resource dict named '{vault}/{policyName}' to match the Bicep child."""
    pol_name = payload.get("name") or ""
    return {
        "type": "Microsoft.RecoveryServices/vaults/backupPolicies",
        "name": f"{vault_name}/{pol_name}",
        "location": "unknown",
        "tags": {},
        "sku": None,
        "kind": None,
        "properties": payload.get("properties", {}) or {},
        "id": payload.get("id", ""),
        "resource_group": rg,
    }


def _query_backup_policies(resources: list[dict], sub_id: str, token: str | None = None) -> list[dict]:
    """Query Recovery Services vault backup POLICIES via the ARM REST API.

    Not indexed by Resource Graph (confirmed). Every vault also ships built-in
    default policies (DefaultPolicy, EnhancedPolicy, HourlyLogBackup) with no
    protected items - filter_unmanaged_live_resources drops the ones the template
    does not declare, so a declared policy property-compares (retention/schedule)
    while the Azure-managed defaults are not false extras.
    """
    api_version = "2023-06-01"
    vaults = [
        r for r in resources
        if (r.get("type") or "").lower() == "microsoft.recoveryservices/vaults"
    ]
    if not vaults:
        return []
    if not token:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token

    out: list[dict] = []
    for v in vaults:
        vault_id = v.get("id", "")
        vault_name = v.get("name")
        rg = v.get("resource_group") or _extract_resource_group_from_id(vault_id)
        url = f"https://management.azure.com{vault_id}/backupPolicies?api-version={api_version}"
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urlopen_checked(req, timeout=30) as resp:
                data = _json.load(resp)
        except Exception as e:
            logger.warning(f"Could not query backup policies for vault {vault_name}: {e}")
            continue
        for pol in data.get("value", []):
            out.append(_shape_backup_policy(vault_name, rg, pol))

    logger.info(f"Found {len(out)} vault backup policy(ies) via ARM REST API")
    return out
