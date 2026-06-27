"""
tools/get_live_state.py

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources import ResourceManagementClient


def get_live_state(resource_group: str, subscription_id: str | None = None) -> list[dict]:
    """
    Query all resources in a resource group and return their live state.

    Uses DefaultAzureCredential, which tries (in order):
      - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
      - Managed Identity
      - Azure CLI (`az login`)
    
    So if you're logged in via az login, this just works.

    Args:
        resource_group: Name of the Azure resource group.
        subscription_id: Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.

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

    # List all resources in the resource group
    for resource in client.resources.list_by_resource_group(resource_group, expand="properties"):
        resource_dict = {
            "type": resource.type,
            "name": resource.name,
            "location": resource.location,
            "tags": resource.tags or {},
            "sku": _extract_sku(resource),
            "kind": resource.kind,
            "properties": _safe_properties(resource),
            # Keep the raw id for reference
            "id": resource.id,
        }
        resources.append(resource_dict)

    return resources


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
