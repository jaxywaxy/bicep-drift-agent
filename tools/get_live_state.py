"""
tools/get_live_state.py

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import os
import json
import subprocess
import logging
import time
from typing import Optional, List, Dict, Callable, TypeVar, Any
from functools import wraps
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.eventhub import EventHubManagementClient

T = TypeVar('T')


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0) -> Callable:
    """Decorator to retry Azure SDK calls with exponential backoff.

    Retries on transient HTTP errors (5xx, 429 rate limiting).
    Logs each retry attempt and final failure.

    Args:
        max_retries: Maximum number of retry attempts (default 3)
        initial_delay: Initial delay in seconds (default 1.0, doubles each retry)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            last_error = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except HttpResponseError as e:
                    last_error = e
                    # Only retry on transient errors (5xx, 429)
                    if e.status_code not in (429, 500, 502, 503, 504):
                        raise
                    if attempt < max_retries:
                        logger.debug(
                            f"Transient error in {func.__name__} (attempt {attempt + 1}/{max_retries}): "
                            f"HTTP {e.status_code}, retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        logger.warning(
                            f"Failed after {max_retries + 1} attempts in {func.__name__}: {e}"
                        )
                except Exception as e:
                    # Non-transient errors, fail immediately
                    raise

            # Should not reach here, but just in case
            if last_error:
                raise last_error
            return func(*args, **kwargs)

        return wrapper
    return decorator


def export_deployed_arm_template(resource_group: str) -> Dict[str, Any]:
    """Export deployed ARM template from resource group.

    Exports all resources in the resource group to an ARM template format,
    showing exactly what's deployed with resolved names and properties.

    Args:
        resource_group: Name of the resource group

    Returns:
        Parsed ARM template JSON as dict

    Raises:
        RuntimeError: If export fails
    """
    try:
        logger.info(f"Exporting deployed ARM template from {resource_group}...")
        result = subprocess.run(
            ["az", "group", "export", "--resource-group", resource_group],
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # 5 minutes - group export can be slow
        )

        deployed_arm = json.loads(result.stdout)
        logger.info(f"✓ Exported ARM template with {len(deployed_arm.get('resources', []))} resource(s)")
        return deployed_arm

    except subprocess.TimeoutExpired:
        logger.warning(f"ARM export timed out after 300s, falling back to individual resource queries...")
        # Fall back to querying resources individually
        return _build_arm_template_from_resources(resource_group)
    except subprocess.CalledProcessError as e:
        logger.warning(f"ARM export failed: {e.stderr}, falling back to individual resource queries...")
        return _build_arm_template_from_resources(resource_group)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse exported ARM template: {e}")
        raise RuntimeError(f"Invalid ARM template JSON: {e}")
    except Exception as e:
        logger.error(f"Unexpected error exporting ARM template: {e}")
        raise RuntimeError(f"ARM export error: {e}")


def _build_arm_template_from_resources(resource_group: str) -> Dict[str, Any]:
    """Build ARM template from individual resource queries (fallback approach).

    Used when az group export times out. Queries resources individually
    and builds an ARM-like template structure.
    """
    logger.info(f"Querying resources individually for {resource_group}...")
    live_resources = get_live_state(resource_group=resource_group, scope="resource_group")

    # Build a minimal ARM template structure
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": live_resources
    }


def get_live_state(
    resource_group: str = None,
    subscription_id: Optional[str] = None,
    scope: str = "resource_group"
) -> List[Dict]:
    """
    Query resources and return their live state.

    Supports both resource group and subscription scopes.

    Uses DefaultAzureCredential, which tries (in order):
      - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
      - Managed Identity
      - Azure CLI (`az login`)

    So if you're logged in via az login, this just works.

    Args:
        resource_group: Name of the Azure resource group (required for RG scope).
        subscription_id: Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.
        scope: "resource_group" (default) or "subscription"

    Returns:
        List of resource dicts with type, name, location, and properties.
    """
    sub_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise ValueError(
            "No subscription_id provided and AZURE_SUBSCRIPTION_ID not set in environment."
        )

    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, sub_id)

    resources = []

    # Determine which resources to query
    if scope == "resource_group":
        if not resource_group:
            raise ValueError("resource_group required for resource_group scope")
        resource_iterator = client.resources.list_by_resource_group(resource_group, expand="properties")
        target_rg = resource_group
    else:  # subscription scope
        resource_iterator = client.resources.list(expand="properties")
        target_rg = resource_group  # May be None if not filtering

    # Process resources with unified logic
    for resource in resource_iterator:
        # Extract resource group if needed (for subscription scope queries)
        if scope == "subscription":
            rg_from_id = _extract_resource_group_from_id(resource.id)
            # Filter to target RG if specified
            if target_rg and rg_from_id and rg_from_id.lower() != target_rg.lower():
                continue
            res_rg = rg_from_id
        else:
            res_rg = target_rg

        # Build resource dict
        resource_dict = {
            "type": resource.type,
            "name": resource.name,
            "location": resource.location,
            "tags": resource.tags or {},
            "sku": _extract_sku(resource),
            "kind": resource.kind,
            "properties": _safe_properties(resource),
            "id": resource.id,
            "resource_group": res_rg,
        }
        resources.append(resource_dict)

    # Enrich resource properties with type-specific clients
    if resource_group:
        _enrich_storage_accounts(credential, sub_id, resource_group, resources)
        _enrich_app_services(credential, sub_id, resource_group, resources)
        _enrich_key_vaults(credential, sub_id, resource_group, resources)
        _enrich_logic_apps(credential, sub_id, resource_group, resources)
        _enrich_log_analytics(credential, sub_id, resource_group, resources)
        _enrich_event_hub_namespaces(credential, sub_id, resource_group, resources)
        _enrich_vm_properties(credential, sub_id, resource_group, resources)

    return resources


def _extract_resource_group_from_id(resource_id: str) -> Optional[str]:
    """Extract resource group name from Azure resource ID.

    Example: /subscriptions/SUB_ID/resourceGroups/MY_RG/providers/... → MY_RG
    """
    if not resource_id:
        return None

    parts = resource_id.lower().split('/')
    try:
        rg_index = parts.index('resourcegroups')
        if rg_index + 1 < len(parts):
            return parts[rg_index + 1]
    except (ValueError, IndexError):
        pass
    return None


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_storage_accounts(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Storage Account properties using StorageManagementClient."""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
    except Exception:
        logger.debug("StorageManagementClient initialization failed. Skipping storage property enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.Storage/storageAccounts":
            account_name = resource["name"]
            try:
                account = storage_client.storage_accounts.get_properties(resource_group, account_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                # Azure SDK returns models with _data dict attribute
                data = account._data if hasattr(account, "_data") else account
                props = data.get("properties", {}) if isinstance(data, dict) else {}

                if props:
                    resource["properties"].update({
                        "accessTier": str(props.get("accessTier", "")).split(".")[-1],
                        "minimumTlsVersion": str(props.get("minimumTlsVersion", "")).split(".")[-1],
                        "supportsHttpsTrafficOnly": props.get("supportsHttpsTrafficOnly"),
                        "publicNetworkAccess": props.get("publicNetworkAccess"),
                    })
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_app_services(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich App Service and App Service Plan properties using WebSiteManagementClient."""
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
    except Exception:
        logger.debug("WebSiteManagementClient initialization failed. Skipping App Service enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.Web/sites":
            site_name = resource["name"]
            try:
                site = web_client.web_apps.get(resource_group, site_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                # Azure SDK returns models with _data dict attribute
                data = site._data if hasattr(site, "_data") else site
                site_props = data.get("properties", {}) if isinstance(data, dict) else {}

                if site_props:
                    resource["properties"].update({
                        "serverFarmId": site_props.get("appServicePlanId"),
                        "httpsOnly": site_props.get("httpsOnly"),
                    })

                # Get site config separately
                try:
                    config = web_client.web_apps.get_configuration(resource_group, site_name)
                    data = config._data if hasattr(config, "_data") else config
                    config_props = data.get("properties", {}) if isinstance(data, dict) else {}

                    if config_props:
                        resource["properties"]["siteConfig"] = {
                            "linuxFxVersion": config_props.get("linuxFxVersion"),
                            "alwaysOn": config_props.get("alwaysOn"),
                            "minTlsVersion": config_props.get("minTlsVersion"),
                            "http20Enabled": config_props.get("http20Enabled"),
                        }
                except Exception:
                    logger.debug("Exception during property enrichment.", exc_info=True)
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)

        elif resource["type"] == "Microsoft.Web/serverfarms":
            plan_name = resource["name"]
            try:
                plan = web_client.app_service_plans.get(resource_group, plan_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                # Extract SKU info (name, tier, family, size, capacity)
                if hasattr(plan, "sku") and plan.sku:
                    resource["sku"] = {
                        "name": getattr(plan.sku, "name", None),
                        "tier": getattr(plan.sku, "tier", None),
                        "family": getattr(plan.sku, "family", None),
                        "size": getattr(plan.sku, "size", None),
                        "capacity": getattr(plan.sku, "capacity", None),
                    }

                # Extract plan properties
                if hasattr(plan, "properties"):
                    data = plan._data if hasattr(plan, "_data") else plan
                    plan_props = data.get("properties", {}) if isinstance(data, dict) else {}

                    if plan_props:
                        resource["properties"].update({
                            "reserved": plan_props.get("reserved"),
                            "workerSize": plan_props.get("workerSize"),
                            "numberOfWorkers": plan_props.get("numberOfWorkers"),
                            "isPremiumApp": plan_props.get("isPremiumApp"),
                        })
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_key_vaults(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Key Vault properties using KeyVaultManagementClient."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
    except Exception:
        logger.debug("KeyVaultManagementClient initialization failed. Skipping Key Vault enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.KeyVault/vaults":
            vault_name = resource["name"]
            try:
                vault = kv_client.vaults.get(resource_group, vault_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                # Azure SDK returns models with _data dict attribute
                data = vault._data if hasattr(vault, "_data") else vault
                vault_props = data.get("properties", {}) if isinstance(data, dict) else {}

                if vault_props:
                    resource["properties"].update({
                        "tenantId": str(vault_props.get("tenantId", "")),
                        "enableRbacAuthorization": vault_props.get("enableRbacAuthorization"),
                        "enableSoftDelete": vault_props.get("enableSoftDelete"),
                        "softDeleteRetentionInDays": vault_props.get("softDeleteRetentionInDays"),
                        "publicNetworkAccess": vault_props.get("publicNetworkAccess"),
                    })
                    sku = vault_props.get("sku", {})
                    if sku:
                        resource["properties"]["sku"] = {
                            "family": sku.get("family"),
                            "name": sku.get("name"),
                        }
                    acls = vault_props.get("networkAcls", {})
                    if acls:
                        resource["properties"]["networkAcls"] = {
                            "defaultAction": acls.get("defaultAction"),
                            "bypass": acls.get("bypass"),
                        }
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_logic_apps(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Logic App properties using LogicManagementClient."""
    try:
        logic_client = LogicManagementClient(credential, subscription_id)
    except Exception:
        logger.debug("LogicManagementClient initialization failed. Skipping Logic App enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.Logic/workflows":
            workflow_name = resource["name"]
            try:
                workflow = logic_client.workflows.get(resource_group, workflow_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                data = workflow._data if hasattr(workflow, "_data") else workflow
                workflow_props = data.get("properties", {}) if isinstance(data, dict) else {}

                if workflow_props:
                    resource["properties"].update({
                        "state": workflow_props.get("state"),
                        "definition": workflow_props.get("definition"),
                    })
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_log_analytics(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Log Analytics Workspace properties using LogAnalyticsManagementClient."""
    try:
        analytics_client = LogAnalyticsManagementClient(credential, subscription_id)
    except Exception:
        return

    for resource in resources:
        if resource["type"] == "Microsoft.OperationalInsights/workspaces":
            workspace_name = resource["name"]
            try:
                workspace = analytics_client.workspaces.get(resource_group, workspace_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                data = workspace._data if hasattr(workspace, "_data") else workspace
                workspace_props = data.get("properties", {}) if isinstance(data, dict) else {}

                if workspace_props:
                    resource["properties"].update({
                        "sku": workspace_props.get("sku"),
                        "retentionInDays": workspace_props.get("retentionInDays"),
                        "publicNetworkAccessForIngestion": workspace_props.get("publicNetworkAccessForIngestion"),
                        "publicNetworkAccessForQuery": workspace_props.get("publicNetworkAccessForQuery"),
                    })
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_event_hub_namespaces(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Event Hub Namespace properties using EventHubManagementClient."""
    try:
        eventhub_client = EventHubManagementClient(credential, subscription_id)
    except Exception:
        return

    for resource in resources:
        if resource["type"] == "Microsoft.EventHub/namespaces":
            namespace_name = resource["name"]
            try:
                namespace = eventhub_client.namespaces.get(resource_group, namespace_name)
                if "properties" not in resource:
                    resource["properties"] = {}

                data = namespace._data if hasattr(namespace, "_data") else namespace
                ns_props = data.get("properties", {}) if isinstance(data, dict) else {}

                if ns_props:
                    resource["properties"].update({
                        "capacity": ns_props.get("capacity"),
                        "isAutoInflateEnabled": ns_props.get("isAutoInflateEnabled"),
                        "maximumThroughputUnits": ns_props.get("maximumThroughputUnits"),
                        "kafkaEnabled": ns_props.get("kafkaEnabled"),
                        "zoneRedundant": ns_props.get("zoneRedundant"),
                    })
                    sku = ns_props.get("sku", {})
                    if sku:
                        resource["properties"]["sku"] = {
                            "name": sku.get("name"),
                            "tier": sku.get("tier"),
                            "capacity": sku.get("capacity"),
                        }
            except Exception:
                logger.debug("Exception during property enrichment.", exc_info=True)
                pass


@retry_with_backoff(max_retries=3, initial_delay=1.0)
def _enrich_vm_properties(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich VM resources with detailed properties via ComputeManagementClient.

    The generic ResourceManagementClient doesn't return detailed VM properties.
    This function fetches hardware profile, storage profile (data disks), and network profile.

    Modifies resources list in place. Errors are logged but don't block enrichment for other VMs.
    """
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)
    except Exception as e:
        logger.warning(f"ComputeManagementClient initialization failed: {type(e).__name__}. Skipping VM property enrichment.", exc_info=True)
        return

    for resource in resources:
        if resource["type"] == "Microsoft.Compute/virtualMachines":
            vm_name = resource["name"]
            try:
                vm = compute_client.virtual_machines.get(resource_group, vm_name, expand="instanceView")

                if "properties" not in resource:
                    resource["properties"] = {}

                # Hardware profile (vmSize)
                if vm.hardware_profile:
                    resource["properties"]["hardwareProfile"] = {
                        "vmSize": vm.hardware_profile.vm_size
                    }

                # Storage profile (data disks, OS disk)
                if vm.storage_profile:
                    storage = {}
                    if vm.storage_profile.data_disks:
                        storage["dataDisks"] = [
                            {
                                "lun": disk.lun,
                                "name": disk.name,
                                "caching": disk.caching,
                                "diskSizeGB": disk.disk_size_gb,
                                "managedDisk": {
                                    "id": disk.managed_disk.id if disk.managed_disk else None
                                } if disk.managed_disk else None,
                            }
                            for disk in vm.storage_profile.data_disks
                        ]
                    if vm.storage_profile.os_disk:
                        storage["osDisk"] = {
                            "name": vm.storage_profile.os_disk.name,
                            "caching": vm.storage_profile.os_disk.caching,
                            "diskSizeGB": vm.storage_profile.os_disk.disk_size_gb,
                            "managedDisk": {
                                "id": vm.storage_profile.os_disk.managed_disk.id
                            } if vm.storage_profile.os_disk.managed_disk else None,
                        }
                    if storage:
                        resource["properties"]["storageProfile"] = storage

                # Network profile (NICs)
                if vm.network_profile and vm.network_profile.network_interfaces:
                    resource["properties"]["networkProfile"] = {
                        "networkInterfaces": [
                            {"id": nic.id} for nic in vm.network_profile.network_interfaces
                        ]
                    }
            except Exception as e:
                logger.warning(f"Failed to enrich VM {vm_name}: {type(e).__name__}. Continuing with partial properties.", exc_info=True)


def _extract_sku(resource) -> dict | None:
    """Pull SKU info if present — relevant for VMs, storage, etc."""
    if resource.sku is None:
        return None
    return {
        "name": resource.sku.name,
        "tier": resource.sku.tier,
        "size": resource.sku.size,
        "family": resource.sku.family,
        "capacity": resource.sku.capacity,
    }


def _safe_properties(resource) -> dict:
    """
    Extract properties safely.

    The ARM API returns properties as an opaque dict via `additional_properties`.
    Not all resource types expose them equally — some need type-specific SDK clients
    (e.g., ComputeManagementClient for VMs). 
    
    For Phase 1, we grab what the generic client gives us.
    Phase 2 will add type-specific enrichment.
    """
    try:
        props = resource.properties
        if props is None:
            return {}
        if isinstance(props, dict):
            return props
        # Some SDKs return objects — convert to dict if possible
        if hasattr(props, "__dict__"):
            return {k: v for k, v in props.__dict__.items() if not k.startswith("_")}
        return {}
    except Exception:

        logger.debug("Exception during initialization.", exc_info=True)
        return {}


if __name__ == "__main__":
    import sys
    import json
    from pathlib import Path
    from dotenv import load_dotenv
    try:
        from .logger import setup_logging
    except ImportError:
        # When run as standalone script, add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent))
        from logger import setup_logging

    load_dotenv()
    setup_logging(level="INFO")

    if len(sys.argv) < 2:
        logger.error("Usage: python get_live_state.py <resource-group-name>")
        sys.exit(1)

    rg = sys.argv[1]
    logger.info(f"Querying live state for resource group: {rg}")

    resources = get_live_state(rg)

    logger.info(f"Found {len(resources)} resource(s)")
    for r in resources:
        sku_info = f" [{r['sku']['name']}]" if r.get("sku") else ""
        logger.info(f"  {r['type']} — {r['name']}{sku_info}")

    logger.debug("Full live state (first resource):")
    if resources:
        logger.debug(json.dumps(resources[0], indent=2, default=str))
