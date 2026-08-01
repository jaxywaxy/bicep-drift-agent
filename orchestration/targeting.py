"""
orchestration/targeting.py

Resolve WHICH resource groups a scan targets: discover them from a
subscription-scoped template, resolve a configured selector/glob against the live
RG list, and locate the per-repo .drift-ignore. See docs/RESOURCE_GROUP_TARGETING.
"""

import os
import sys

from pathlib import Path
from tools.compile_bicep import compile_bicep, detect_deployment_scope
from tools.logger import get_logger

logger = get_logger(__name__)


def _find_repo_ignore(bicep_file: str):
    """Walk up from the bicep file to find the repo's .drift-ignore.

    The bicep isn't always at <repo>/bicep/main.bicep - a landing zone may keep
    it at envs/dev/main.bicep, etc. Search ancestor directories (stopping at a
    .git dir or the filesystem root) so the per-LZ ignore profile is found
    regardless of nesting depth.
    """
    d = Path(bicep_file).resolve().parent
    for _ in range(8):
        candidate = d / ".drift-ignore"
        if candidate.exists():
            return candidate
        if (d / ".git").exists() or d.parent == d:
            break
        d = d.parent
    return None


def discover_resource_groups():
    """Query Azure for all resource groups in the current subscription.

    Uses the Resource Graph SDK (same auth/client as get_live_state) rather than
    shelling out to `az graph query`, which required the az 'graph' CLI extension.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        client = ResourceGraphClient(DefaultAzureCredential())
        request = QueryRequest(
            subscriptions=[sub_id] if sub_id else [],
            query="Resources | distinct resourceGroup",
        )
        response = client.resources(request)
        rgs = [row["resourceGroup"] for row in (response.data or []) if row.get("resourceGroup")]
        return sorted(rgs)
    except Exception as e:
        logger.error(f"Failed to discover resource groups: {e}")
        return []


def _resolve_target_resource_groups(bicep_file: str, resource_group: str) -> list:
    """Resolve which resource group(s) this invocation should scan.

    A subscription-scoped landing zone spans several RGs from ONE template and is
    scanned as a SINGLE pass (optionally filtered to an RG glob like 'contosodev-*').
    Only an RG-scoped template treats '*' as "discover and scan each RG separately".
    """
    try:
        is_sub_scoped = detect_deployment_scope(compile_bicep(bicep_file)) == "subscription"
    except Exception as e:
        logger.warning(f"Could not detect deployment scope ({e}); assuming resource-group scope")
        is_sub_scoped = False

    if resource_group == "*" and not is_sub_scoped:
        logger.info(f"Processing: {bicep_file} (discovering all resource groups in subscription)")
        discovered_rgs = discover_resource_groups()
        if not discovered_rgs:
            logger.error("No resource groups found in subscription")
            sys.exit(1)
        logger.info(f"Found {len(discovered_rgs)} resource group(s): {', '.join(discovered_rgs)}")
        return discovered_rgs

    if is_sub_scoped:
        logger.info(
            f"Processing: {bicep_file} (subscription-scoped landing zone; "
            f"RG selector: {resource_group})"
        )
    else:
        logger.info(f"Processing: {bicep_file} (resource group: {resource_group})")
    return [resource_group]
