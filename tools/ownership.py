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

import fnmatch
from collections.abc import Iterable
from typing import Any

PLATFORM = "platform"
WORKLOAD = "workload"


def _owner_for_module(module: str | None, module_owners: dict | None) -> str | None:
    """Owner for the module a resource was declared in, or None if unmapped.

    LONGEST pattern wins, so `apps/*` can carve an exception out of `*` without
    depending on dict order. Ties are broken alphabetically purely so the result
    is deterministic - two equally-specific patterns disagreeing is a config
    error, and a stable answer makes it a reproducible one.
    """
    if not module or not module_owners:
        return None
    matches = [
        (pattern, owner) for pattern, owner in module_owners.items()
        if fnmatch.fnmatch(module.lower(), str(pattern).lower())
    ]
    if not matches:
        return None
    pattern, owner = sorted(matches, key=lambda kv: (-len(kv[0]), kv[0]))[0]
    return str(owner).lower()

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
    # A firewall policy's rule collection groups ARE the central egress rules the
    # platform team manages - unlike NSG securityRules (delegated to app teams),
    # firewall rules stay platform-owned, so this child follows its parent policy.
    "microsoft.network/firewallpolicies/rulecollectiongroups",
    "microsoft.network/natgateways",
    # Virtual WAN hub routing is platform connectivity fabric. The route tables
    # and routing intent decide whether spoke traffic is forced through the hub
    # firewall - a platform team's call, same as firewall rule collection groups.
    "microsoft.network/virtualhubs",
    "microsoft.network/virtualhubs/hubroutetables",
    "microsoft.network/virtualhubs/routingintent",
    # Load balancers and Application Gateways (+ its WAF policy) are shared
    # ingress/egress fabric a platform team typically owns.
    "microsoft.network/loadbalancers",
    "microsoft.network/applicationgateways",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
    # Front Door (Standard/Premium = Microsoft.Cdn/profiles) + its WAF policy
    # are shared edge/ingress fabric, same as App Gateway.
    "microsoft.cdn/profiles",
    "microsoft.network/frontdoorwebapplicationfirewallpolicies",
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
    drift: dict[str, Any] | None = None,
    platform_types: Iterable[str] | None = None,
    module: str | None = None,
    module_owners: dict | None = None,
    default_owner: str = WORKLOAD,
) -> str:
    """
    Return the owner ("platform" or "workload") for a drift finding.

    Args:
        resource_type: Azure resource type (e.g. "Microsoft.Network/virtualNetworks").
        drift: the full drift dict (used to inspect changed properties for the
            NSG-rules nuance). Optional.
        platform_types: optional override/extension of the platform-owned type set
            (from config). If provided, replaces the default set.
        module: the Bicep module the resource was declared in (`_module`).
        module_owners: per-LZ mapping of module glob -> owner.
        default_owner: what to return when nothing else decides. Workload
            preserves historical behaviour; a platform landing zone sets this to
            "platform", where the app-team default is simply false.

    Rules (in order):
      0. Module mapping, when the operator configured one -> that owner.
      1. Structural cases: policy assignments, deployment stacks, role
         assignments (which follow what they grant access TO).
      2. NSG securityRules, by type or by changed property -> workload.
      3. Resource type in the platform set -> platform.
      4. Otherwise -> `default_owner`.

    Rule 0 is FIRST because it is the only rule backed by evidence rather than
    inference. Resource type cannot decide ownership on its own: the same Key
    Vault is platform-owned in a connectivity subscription and workload-owned in
    an app team's spoke, so a type list is a guess that no amount of curation
    makes right in both places. The module a resource is declared in is a
    statement about which codebase owns it, which is what ownership means.
    """
    rtype = (resource_type or "").lower()
    types = {t.lower() for t in platform_types} if platform_types else DEFAULT_PLATFORM_TYPES

    # 0. Explicit operator configuration beats every heuristic below, including
    #    the deliberate carve-outs. An LZ that maps its networking module to
    #    platform is saying its own NSG rules are not delegated, and it is in a
    #    better position to know that than a default written here.
    configured = _owner_for_module(module, module_owners)
    if configured:
        return configured

    # 0a. Policy assignments/exemptions are governance, full stop - platform.
    if rtype in (
        "microsoft.authorization/policyassignments",
        "microsoft.authorization/policyexemptions",
    ):
        return PLATFORM

    # 0b. The deployment stack itself is the IaC control plane - its deny
    #     settings and unmanage behaviour are the platform team's to answer for,
    #     whatever workload the stack happens to deploy.
    if rtype == "microsoft.resources/deploymentstacks":
        return PLATFORM

    # 0. Role assignments are owned by whoever owns what they grant access TO:
    #    subscription-level grants are governance (platform); a grant scoped to
    #    a resource follows that resource's owner (a grant on a VNet -> platform,
    #    on a storage account -> workload). RG-level grants default to workload
    #    (app teams grant their identities access to their own RG).
    if rtype == "microsoft.authorization/roleassignments":
        scope = str(((drift or {}).get("details") or {}).get("scope") or "").lower()
        if "/resourcegroups/" not in scope:
            return PLATFORM  # subscription (or unknown) scope: governance drift
        from .rbac import _scope_target_type
        target_type = _scope_target_type(scope)
        if target_type:
            return classify_owner(target_type, None, platform_types,
                                  default_owner=default_owner)
        # An RG-scoped grant on nothing more specific. "App teams grant their own
        # identities access to their own RG" is a DEFAULT, not a fact, so it
        # follows default_owner - in a platform LZ every RG is platform's.
        return default_owner

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

    # 4. Nothing decided. Historically this was always "workload", which reads
    #    the whole estate as an app team's - exactly backwards for a platform
    #    landing zone, where every resource group, vault and workspace belongs to
    #    the platform team and the app-team default routes their drift to a team
    #    that cannot act on it.
    return default_owner
