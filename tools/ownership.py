"""
Owner classification for drift findings (Phase 4).

In a CAF/ALZ model, different teams own different resources: the platform team
owns the network fabric (VNets, subnets, peering, NSG resources, route tables),
while application teams own their workload resources. Drift should be routed to
whoever owns the resource, not blanket-ignored.

This module maps a drift finding to an owner so the report can group by owner
and notifications can route per owner.

Nuance handled:
- An NSG *resource* is platform-owned, but its *security rules*
  (Microsoft.Network/networkSecurityGroups/securityRules, or the
  properties.securityRules property) are typically app-team owned. So a rule
  change is attributed to WORKLOAD even though the NSG is PLATFORM.
"""

from typing import Optional, Dict, Any, Iterable

PLATFORM = "platform"
WORKLOAD = "workload"

# Default platform-owned resource types (the network fabric a platform team
# deploys via subscription vending / connectivity). Lowercased for comparison.
DEFAULT_PLATFORM_TYPES = {
    "microsoft.network/virtualnetworks",
    "microsoft.network/virtualnetworks/subnets",
    "microsoft.network/virtualnetworks/virtualnetworkpeerings",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/routetables",
    "microsoft.network/azurefirewalls",
    "microsoft.network/virtualnetworkgateways",
    "microsoft.network/bastionhosts",
    "microsoft.network/privatednszones",
    "microsoft.network/ddosprotectionplans",
    "microsoft.network/ipgroups",
    "microsoft.network/firewallpolicies",
    "microsoft.network/natgateways",
    # Public IPs in a connectivity/platform LZ front platform egress/ingress
    # (NAT gateway, firewall, bastion, VPN/ER gateway). A workload rarely owns a
    # standalone public IP (it fronts via App Gateway/Front Door), so default
    # platform. Override via config platform_types if a workload LZ owns PIPs.
    "microsoft.network/publicipaddresses",
}

# Types that look platform (nested under a platform resource) but whose drift is
# actually owned by the app team - overrides the platform match above.
WORKLOAD_OVERRIDE_TYPES = {
    "microsoft.network/networksecuritygroups/securityrules",
}

# Property paths that, when they are the drifting property, flip ownership to the
# app team even though the parent resource is platform-owned.
WORKLOAD_OVERRIDE_PROPERTIES = (
    "properties.securityrules",
)


def classify_owner(
    resource_type: str,
    drift: Optional[Dict[str, Any]] = None,
    platform_types: Optional[Iterable[str]] = None,
) -> str:
    """
    Return the owner ("platform" or "workload") for a drift finding.

    Args:
        resource_type: Azure resource type (e.g. "Microsoft.Network/virtualNetworks").
        drift: the full drift dict (used to inspect changed properties for the
            NSG-rules nuance). Optional.
        platform_types: optional override/extension of the platform-owned type set
            (from config). If provided, replaces the default set.

    Rules (in order):
      1. NSG securityRules (child type) -> workload.
      2. If the drift is a property change and the only/again changed properties
         are NSG securityRules -> workload.
      3. Resource type in the platform set -> platform.
      4. Otherwise -> workload (default; app teams own their resources).
    """
    rtype = (resource_type or "").lower()
    types = {t.lower() for t in platform_types} if platform_types else DEFAULT_PLATFORM_TYPES

    # 1. Child security-rule resources are app-owned even though the NSG isn't.
    if rtype in WORKLOAD_OVERRIDE_TYPES:
        return WORKLOAD

    # 2. Property-level override: an NSG (platform) whose *rules* changed -> app.
    if rtype == "microsoft.network/networksecuritygroups" and drift:
        changed = list(
            ((drift.get("details") or {}).get("changed_properties") or {}).keys()
        )
        if changed and all(
            any(c.lower().startswith(p) for p in WORKLOAD_OVERRIDE_PROPERTIES)
            for c in changed
        ):
            return WORKLOAD

    # 3. Platform-owned fabric.
    if rtype in types:
        return PLATFORM

    # 4. Default: workload/app team.
    return WORKLOAD
