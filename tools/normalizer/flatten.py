"""
tools/normalizer/flatten.py

Flatten ARM template resources into a common shape. Handles nested
deployments (their resources are hoisted, with the module's own
parameter defaults respected and cross-scope module targets stamped).
Also normalises live Azure resources into the same shape.
"""

from typing import Any

from .expressions import (
    _eval_embedded_formats,
    resolve_expression,
)
from .template import (
    _extract_nested_parameters,
    extract_parameters,
    extract_variables,
)


def _resolve_value(value: Any, parameters: dict, variables: dict) -> Any:
    """Recursively resolve parameter/variable expressions in a value.

    Handles strings (expressions), dicts (nested objects), and lists.
    """
    if isinstance(value, str):
        return resolve_expression(value, parameters, variables)
    elif isinstance(value, dict):
        return {k: _resolve_value(v, parameters, variables) for k, v in value.items()}
    elif isinstance(value, list):
        return [_resolve_value(item, parameters, variables) for item in value]
    else:
        return value


def _normalize_resource(resource: dict, parameters: dict, variables: dict = None) -> dict:
    """Normalize a single resource, resolving expression-based fields."""
    if variables is None:
        variables = {}

    normalized = {
        "type": resource.get("type", ""),
        "name": _eval_embedded_formats(
            resolve_expression(resource.get("name", ""), parameters, variables),
            parameters, variables,
        ),
        "location": resolve_expression(resource.get("location"), parameters, variables) or "unknown",
        "apiVersion": resource.get("apiVersion", ""),
        "tags": _resolve_value(resource.get("tags") or {}, parameters, variables),
        "sku": _resolve_value(resource.get("sku"), parameters, variables),
        "kind": resource.get("kind"),
        # Availability zones are a TOP-LEVEL ARM key, not a property. Without
        # carrying them here they never reach the comparator at all, so zone
        # placement drift (a resource silently no longer zone-redundant) is
        # invisible no matter how the comparison treats it.
        "zones": _resolve_value(resource.get("zones"), parameters, variables),
        "properties": _resolve_value(resource.get("properties"), parameters, variables),
    }

    # Extension resources (diagnostic settings, locks) carry the resource they
    # attach to in 'scope' - needed to qualify their names for matching.
    if resource.get("scope"):
        normalized["scope"] = resolve_expression(resource.get("scope"), parameters, variables)

    # Keep original resource for debugging if needed
    normalized["_raw"] = resource

    return normalized


def flatten_resources(arm_template: dict, parameters: dict = None, variables: dict = None) -> list[dict]:
    """Flatten ARM template resources, handling nested deployments and copy loops.

    - Extract top-level resources.
    - Recursively flatten nested deployments.
    - Resolve expression-based names using parameters and variables.
    - Skip resources whose `condition` resolves to a definitive false.
    """
    if parameters is None:
        parameters = extract_parameters(arm_template)
    if variables is None:
        variables = extract_variables(arm_template)

    flattened = []
    resources = arm_template.get("resources", [])

    # Handle both array format [{}] and dict format {name: {}}
    if isinstance(resources, dict):
        resource_list = list(resources.values())
    elif isinstance(resources, list):
        resource_list = resources
    else:
        resource_list = []

    for resource in resource_list:
        if not isinstance(resource, dict):
            continue

        resource_type = resource.get("type", "")

        # Skip infrastructure resources (not drift-checked)
        if resource_type == "Microsoft.Resources/resourceGroups":
            continue

        # Conditional resources: a module/resource gated behind `if (...)` whose
        # condition resolves to false is NOT deployed - comparing it would flag
        # every gated-off module as missing_in_azure. Only a condition that
        # resolves to a definitive false skips; an unresolvable expression keeps
        # the resource (conservative - matches previous behavior).
        condition = resource.get("condition")
        if condition is not None:
            resolved = _resolve_value(condition, parameters, variables)
            if resolved is False or (isinstance(resolved, str) and resolved.lower() == "false"):
                continue

        if resource_type == "Microsoft.Resources/deployments":
            nested_template = resource.get("properties", {}).get("template", {})
            if nested_template:
                # Start from the nested template's own parameter DEFAULTS, then
                # overlay what the parent passes. A module param the parent omits
                # (e.g. postgres adminUsername defaulting to 'pgadmin') otherwise
                # never resolves and falls back to its NAME, flagging false
                # property drift against the live value.
                nested_params = extract_parameters(nested_template)
                passed_params = _extract_nested_parameters(
                    resource.get("properties", {}), parameters, variables
                )
                for pname, pval in passed_params.items():
                    if pval is not None:
                        nested_params[pname] = pval
                    else:
                        nested_params.setdefault(pname, None)
                # Resolve the module's variables against the params the PARENT
                # passed, not just the module's own defaults. A module variable
                # built from a required param with no default (e.g.
                # 'driftAppPlan${suffix}', suffix passed from a parent
                # uniqueString) otherwise resolves against suffix=None and bakes
                # in the literal 'driftAppPlanNone', which then false-flags as a
                # missing/extra pair. Names wrapped in toLower() dodged this only
                # because the resolver can't evaluate toLower and left them
                # unresolvable; this makes the bare-format case behave the same.
                nested_vars = extract_variables(nested_template, nested_params)
                nested_resources = flatten_resources(nested_template, nested_params, nested_vars)
                # Cross-scope module (scope: resourceGroup(otherSub, rg)): stamp the
                # target so the scan can verify these resources in THEIR subscription
                # instead of flagging them missing in the scanned one.
                target_sub = resource.get("subscriptionId")
                target_rg = resource.get("resourceGroup")
                if target_sub:
                    target_sub = _resolve_value(target_sub, parameters, variables)
                    target_rg = _resolve_value(target_rg, parameters, variables) if target_rg else None
                    for nr in nested_resources:
                        nr.setdefault("_target_subscription", target_sub)
                        if target_rg:
                            nr.setdefault("_target_rg", target_rg)
                flattened.extend(nested_resources)
        else:
            normalized = _normalize_resource(resource, parameters, variables)
            flattened.append(normalized)

    return flattened


def normalize_live_resources(live_resources: list[dict]) -> list[dict]:
    """Normalize live Azure resources to match ARM template shape."""
    normalized = []

    for resource in live_resources:
        normalized.append({
            "type": resource.get("type", ""),
            "name": resource.get("name", ""),
            "location": resource.get("location", "unknown"),
            "tags": resource.get("tags") or {},
            "sku": resource.get("sku"),
            "kind": resource.get("kind"),
            "zones": resource.get("zones"),  # top-level key; see normalize side
            "apiVersion": "",  # Not available in live state
            "properties": resource.get("properties"),
            "_raw": resource,
        })

    return normalized


def resource_key(resource: dict) -> tuple[str, str]:
    """Generate a stable (type, name) key for resource matching, lowercased."""
    res_type = resource.get("type", "").lower().strip()
    res_name = resource.get("name", "").lower().strip()
    return (res_type, res_name)
