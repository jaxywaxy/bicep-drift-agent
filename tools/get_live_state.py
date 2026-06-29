"""
tools/get_live_state.py

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient


def get_live_state(
    resource_group: str = None,
    subscription_id: str | None = None,
    scope: str = "resource_group"
) -> list[dict]:
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
        _enrich_vm_properties(credential, sub_id, resource_group, resources)

    return resources


def _extract_resource_group_from_id(resource_id: str) -> str | None:
    """Extract resource group name from Azure resource ID.

    Example: /subscriptions/SUB_ID/resourceGroups/MY_RG/providers/... → MY_RG
    """
    parts = resource_id.lower().split('/')
    try:
        rg_index = parts.index('resourcegroups')
        if rg_index + 1 < len(parts):
            return parts[rg_index + 1]
    except (ValueError, IndexError):
        pass
    return None


def _enrich_storage_accounts(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Storage Account properties using StorageManagementClient."""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
    except Exception:
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
                pass


def _enrich_app_services(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich App Service properties using WebSiteManagementClient."""
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
    except Exception:
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
                    pass
            except Exception:
                pass


def _enrich_key_vaults(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich Key Vault properties using KeyVaultManagementClient."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
    except Exception:
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
                pass


def _enrich_vm_properties(credential, subscription_id: str, resource_group: str, resources: list[dict]) -> None:
    """Enrich VM resources with detailed properties via ComputeManagementClient.

    The generic ResourceManagementClient doesn't return detailed VM properties.
    This function fetches hardware profile, storage profile (data disks), and network profile.

    Modifies resources list in place. Errors are logged but don't block enrichment for other VMs.
    """
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)
    except Exception as e:
        print(f"  ⚠ ComputeManagementClient initialization failed: {type(e).__name__}. Skipping VM property enrichment.")
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
                print(f"  ⚠ Failed to enrich VM {vm_name}: {type(e).__name__}. Continuing with partial properties.")


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
        return {}


if __name__ == "__main__":
    import sys
    import json
    from dotenv import load_dotenv

    load_dotenv()

    if len(sys.argv) < 2:
        print("Usage: python get_live_state.py <resource-group-name>")
        sys.exit(1)

    rg = sys.argv[1]
    print(f"\nQuerying live state for resource group: {rg}\n")

    resources = get_live_state(rg)

    print(f"Found {len(resources)} resource(s):\n")
    for r in resources:
        sku_info = f" [{r['sku']['name']}]" if r.get("sku") else ""
        print(f"  {r['type']} — {r['name']}{sku_info}")

    print("\nFull live state (first resource):")
    if resources:
        print(json.dumps(resources[0], indent=2, default=str))
