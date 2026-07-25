"""
tools/property_drift/monitoring.py

Cross-reference (linkage) comparison for alert resources: metric/activity-log/
scheduled-query alerts point at what they watch (scopes) and what they notify
(actions.actionGroups). This compares those refs by identity so a de-scoped
alert or a severed notification path surfaces as drift. Sits on primitives +
severity.
"""

import re as _re
from typing import Any

from .models import PropertyDiff
from . import primitives as _primitives
from . import severity as _severity


LINKAGE_TYPES = frozenset({
    "microsoft.insights/metricalerts",
    "microsoft.insights/activitylogalerts",
    "microsoft.insights/scheduledqueryrules",
})

LINKAGE_PATHS = frozenset({
    "properties.scopes",
    "properties.actions",
    "properties.actions.actiongroups",
})

def ref_identity(ref: Any) -> str | None:
    """Canonical trailing-name identity for a scope / action-group reference,
    or None when the ref is OPAQUE (an unresolved cross-module expression
    with no literal name to extract - e.g. reference(...).outputs.x.value).

    Makes the two spellings of the same target comparable:
      live   '/subscriptions/../actionGroups/ag-drift-test' -> 'ag-drift-test'
      bicep  "resourceId('..','ag-drift-test')"             -> 'ag-drift-test'
    """
    if not isinstance(ref, str):
        return None
    s = ref.strip()
    low = s.lower()
    # A live ARM resource id: identity is the last path segment.
    if low.startswith("/subscriptions/"):
        return s.rstrip("/").rsplit("/", 1)[-1].lower()
    # Bicep resourceId('type','name'[, ...]): last string literal is the name.
    if low.startswith("resourceid("):
        lits = _re.findall(r"'([^']*)'", s)
        return lits[-1].lower() if lits else None
    # Any other unresolved expression (reference()/parameters()/module .id)
    # has no literal name - opaque.
    if _primitives.has_unresolved_expressions(s):
        return None
    # A bare literal id or name (already resolved): trailing segment.
    return s.rstrip("/").rsplit("/", 1)[-1].lower()


def linkage_refs(value: Any) -> list[Any]:
    """Pull the raw reference strings out of a scopes / actions value.
    Handles all three shapes: bare-string scopes, {actionGroupId: ref} dicts
    (metric + activity), and bare-string action-group ids (query rules)."""
    out: list[Any] = []
    if not isinstance(value, (list, tuple)):
        return out
    for el in value:
        if isinstance(el, dict):
            agid = next(
                (v for k, v in el.items() if k.lower() == "actiongroupid"), None
            )
            if agid is not None:
                out.append(agid)
        elif isinstance(el, str):
            out.append(el)
    return out


def compare_monitoring_refs(
    resource_type: str, key: str, bicep_value: Any, deployed_value: Any
) -> list["PropertyDiff"] | None:
    """Exact-set comparison for alert cross-references, so a severed or
    re-pointed linkage surfaces even though the ids are template expressions.

    Owns these paths entirely (returns [] or a diff; the caller then
    continues, skipping the generic subset compare). Resolvable bicep links
    must still be present live; unresolved bicep refs become OPAQUE SLOTS
    that absorb one live link each (so a clean module build - one
    reference() scope vs one live scope - stays zero-drift). A live link
    beyond what those slots cover, or fewer live links than declared, is
    drift. LIMIT: an opaque->opaque re-point (both sides unresolved, same
    count) is invisible - there is no literal name on either side to compare.
    """
    if resource_type not in LINKAGE_TYPES:
        return None
    if key.lower() not in LINKAGE_PATHS:
        return None

    bicep_refs = linkage_refs(bicep_value)
    deployed_refs = linkage_refs(deployed_value)

    b_names: list[str] = []
    b_opaque = 0
    for r in bicep_refs:
        ident = ref_identity(r)
        if ident is None:
            b_opaque += 1
        else:
            b_names.append(ident)
    d_names = [n for n in (ref_identity(r) for r in deployed_refs)
               if n is not None]

    drift = False
    remaining = list(d_names)
    for bn in b_names:
        if bn in remaining:
            remaining.remove(bn)          # declared link still present live
        else:
            drift = True                  # declared link removed or re-pointed
    # Live links beyond what opaque bicep slots can absorb (added out-of-band).
    if len(remaining) > b_opaque:
        drift = True
    # A link/scope was severed: fewer live references than the template declares.
    if len(deployed_refs) < len(b_names) + b_opaque:
        drift = True

    if drift:
        return [PropertyDiff(
            property_path=key,
            desired_value=bicep_value,
            actual_value=deployed_value,
            change_type="modified",
            severity=_severity.get_severity(key),
        )]
    return []
