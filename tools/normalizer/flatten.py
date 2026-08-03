"""
tools/normalizer/flatten.py

Flatten ARM template resources into a common shape. Handles nested
deployments (their resources are hoisted, with the module's own
parameter defaults respected and cross-scope module targets stamped).
Also normalises live Azure resources into the same shape.
"""

import re
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

_PARAM_REF_RE = re.compile(r"parameters\(\s*'([^']+)'\s*\)")


def _declared_types(resource: dict) -> set[str]:
    """Every resource TYPE this declaration would deploy.

    A gated MODULE is a Microsoft.Resources/deployments resource, so recording
    its own type tells you nothing about what went undeclared - the types that
    matter are inside its nested template. Descends so a skipped
    `if (deployAks)` module reports Microsoft.ContainerService/managedClusters,
    which is what a live cluster's `extra_in_azure` row can be matched against.
    """
    resource_type = resource.get("type", "")
    if resource_type != "Microsoft.Resources/deployments":
        return {resource_type} if resource_type else set()

    nested = (resource.get("properties", {}) or {}).get("template", {}) or {}
    inner = nested.get("resources", [])
    inner = list(inner.values()) if isinstance(inner, dict) else (inner or [])
    types: set[str] = set()
    for child in inner:
        if isinstance(child, dict):
            types |= _declared_types(child)
    return types


class SkippedDeclarations:
    """Declarations dropped because their `condition` resolved false.

    Discarding them outright loses the one fact that explains the resulting
    report: a deployed resource whose declaration was gated off comes back as
    `extra_in_azure` -> "unmanaged resource, consider deleting". That is the
    tool recommending you delete something you deploy on purpose. It cost a live
    round on 2026-07-21, when a scan run with default params (deployAks=false)
    reported the real cluster as unmanaged.

    The condition evaluated false against THIS scan's parameters, which is not
    the same as the resource being undeclared - it usually means the scan and
    the deployment were given different parameters.
    """

    def __init__(self) -> None:
        self._by_type: dict[str, dict] = {}

    def record(self, resource: dict, condition: Any, parameters: dict) -> None:
        drivers = sorted(set(_PARAM_REF_RE.findall(str(condition))))
        for resource_type in _declared_types(resource):
            self._by_type.setdefault(resource_type.lower(), {
                "type": resource_type,
                "condition": str(condition),
                "parameters": {p: parameters.get(p) for p in drivers},
            })

    def covers(self, resource_type: str | None) -> bool:
        return bool(resource_type) and str(resource_type).lower() in self._by_type

    def entry_for(self, resource_type: str | None) -> dict | None:
        return self._by_type.get(str(resource_type or "").lower())

    def as_list(self) -> list[dict]:
        """Sorted so a report artifact is byte-stable across runs."""
        return [self._by_type[k] for k in sorted(self._by_type)]

    def __bool__(self) -> bool:
        return bool(self._by_type)

    def __len__(self) -> int:
        return len(self._by_type)


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


def flatten_resources(arm_template: dict, parameters: dict = None, variables: dict = None,
                      skipped: SkippedDeclarations | None = None,
                      subscription_scoped: bool = False) -> list[dict]:
    """Flatten ARM template resources, handling nested deployments and copy loops.

    - Extract top-level resources.
    - Recursively flatten nested deployments.
    - Resolve expression-based names using parameters and variables.
    - Skip resources whose `condition` resolves to a definitive false, recording
      them in `skipped` so a gated-off declaration can still explain a live
      resource that would otherwise read as unmanaged.

    `subscription_scoped` is decided ONCE by the caller from the top-level
    template and threaded down: nested templates carry an RG-scoped schema of
    their own, so re-detecting per level would classify a platform LZ's own
    modules as resource-group scoped.
    """
    if parameters is None:
        parameters = extract_parameters(arm_template)
    if variables is None:
        # Resolve against the parameters we were handed, not the template alone.
        # A landing zone names its resource groups the ordinary way -
        #   var loggingRgName = '${prefix}-rg-logging'
        # - and extracting variables without parameters baked in the literal
        # 'None-rg-logging', which matches no real group, so `_target_rg` never
        # tied an orphan back to the group that vanished. The nested path below
        # already resolves against the parent's params (see the
        # 'driftAppPlanNone' comment); this is the same bug at the top level.
        variables = extract_variables(arm_template, parameters)

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

        # At RG scope the resource group is the FRAME of the scan, not a thing
        # inside it - an RG-scoped template cannot even declare one, and its
        # absence is a targeting failure handled before the diff
        # (run_drift_check._guard_unverifiable_scope).
        #
        # At SUBSCRIPTION scope it is a declared resource like any other, and in
        # a CAF platform landing zone it is part of what the template owns.
        # Skipping it there hid the single most consequential event that can
        # happen to a landing zone: the RG's disappearance was silent while
        # every resource it contained fired as an independent deletion.
        if resource_type == "Microsoft.Resources/resourceGroups" and not subscription_scoped:
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
                if skipped is not None:
                    skipped.record(resource, condition, parameters)
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
                nested_resources = flatten_resources(
                    nested_template, nested_params, nested_vars, skipped=skipped,
                    subscription_scoped=subscription_scoped)
                # Cross-scope module (scope: resourceGroup(otherSub, rg)): stamp the
                # target so the scan can verify these resources in THEIR subscription
                # instead of flagging them missing in the scanned one.
                target_sub = resource.get("subscriptionId")
                target_rg = resource.get("resourceGroup")
                if target_sub:
                    target_sub = _resolve_value(target_sub, parameters, variables)
                # The target RG is stamped for SAME-subscription modules too, not
                # just cross-subscription ones. It is how an orphaned resource is
                # tied back to the resource group that vanished: without it a
                # deleted RG reads as N unrelated deletions with nothing naming
                # the cause. (cross_sub.py selects on _target_subscription, so
                # widening this does not pull same-sub resources into that path.)
                if target_rg:
                    target_rg = _resolve_value(target_rg, parameters, variables)
                for nr in nested_resources:
                    if target_sub:
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
