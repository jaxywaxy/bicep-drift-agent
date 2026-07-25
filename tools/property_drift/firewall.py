"""
tools/property_drift/firewall.py

Granular Azure Firewall policy diffing: ruleCollections -> rules -> fields,
keyed by name so paths read like properties.ruleCollections[net-deny].action.type
(a reviewer sees "Deny->Allow" directly). Scalar rule lists (ports/addresses/
fqdns) use exact-set semantics - a live-added member IS drift. Sits on primitives
(scalar_equal, has_unresolved_expressions) and severity (get_severity).
"""

from typing import Any
from .models import PropertyDiff
from . import primitives as _primitives
from . import severity as _severity


def compare_rule_collections(
    key: str, bicep_value: Any, deployed_value: Any
) -> list["PropertyDiff"] | None:
    """Granular diff for Azure Firewall policy ``ruleCollections``.

    Returns a list of PropertyDiff pinpointing the exact collection, rule,
    and field that changed (empty when nothing material differs), or None to
    fall through to the generic comparison when this isn't a ruleCollections
    property or the shapes aren't both lists.

    Paths read like ``properties.ruleCollections[net-deny-smb].action.type``
    and ``...[net-allow].rules[allow-https-out].destinationPorts`` so a
    reviewer sees "Deny->Allow" / "port 3389 added" directly instead of two
    full-array dumps. Scalar rule lists (ports, addresses, fqdns) compare as
    exact sets: a live-added element IS drift, unlike the vacuous subset
    match the generic path applies.
    """
    if not key.lower().endswith(".rulecollections"):
        return None
    if not (isinstance(bicep_value, list) and isinstance(deployed_value, list)):
        return None

    sev = _severity.get_severity(key)  # "critical" (ruleCollections)

    def name_of(el: Any) -> str:
        return str(el.get("name", "")).lower() if isinstance(el, dict) else ""

    diffs: list[PropertyDiff] = []
    deployed_by_name = {name_of(c): c for c in deployed_value if isinstance(c, dict)}
    bicep_names = set()

    for b in bicep_value:
        if not isinstance(b, dict):
            continue
        bname = name_of(b)
        bicep_names.add(bname)
        cpath = f"{key}[{b.get('name', '')}]"
        d = deployed_by_name.get(bname)
        if d is None:
            diffs.append(PropertyDiff(cpath, b, None, "removed", sev))
            continue

        # action.type (Deny->Allow inversion is the classic tamper).
        b_action = (b.get("action") or {}).get("type")
        d_action = (d.get("action") or {}).get("type")
        if (
            b_action is not None
            and d_action is not None
            and not _primitives.scalar_equal(b_action, d_action)
        ):
            diffs.append(
                PropertyDiff(f"{cpath}.action.type", b_action, d_action, "modified", sev)
            )

        # Remaining collection-scalar fields (priority, ruleCollectionType).
        diffs.extend(
            compare_fw_fields(
                cpath, b, d, sev, skip={"name", "action", "rules"}
            )
        )

        # Rules within the collection.
        diffs.extend(
            compare_fw_rules(
                f"{cpath}.rules", b.get("rules") or [], d.get("rules") or [], sev
            )
        )

    # Whole collections added out-of-band (a rogue rule-collection group
    # inside the policy, not just a rule).
    for d in deployed_value:
        if isinstance(d, dict) and name_of(d) not in bicep_names:
            diffs.append(
                PropertyDiff(f"{key}[{d.get('name', '')}]", None, d, "added", sev)
            )

    return diffs


def compare_fw_rules(
    base_path: str, bicep_rules: list, deployed_rules: list, severity: str
) -> list["PropertyDiff"]:
    """Per-rule / per-field firewall rule diffs, keyed by rule name."""
    def name_of(el: Any) -> str:
        return str(el.get("name", "")).lower() if isinstance(el, dict) else ""

    diffs: list[PropertyDiff] = []
    deployed_by_name = {name_of(r): r for r in deployed_rules if isinstance(r, dict)}
    bicep_names = set()

    for b in bicep_rules:
        if not isinstance(b, dict):
            continue
        bname = name_of(b)
        bicep_names.add(bname)
        rpath = f"{base_path}[{b.get('name', '')}]"
        d = deployed_by_name.get(bname)
        if d is None:
            diffs.append(PropertyDiff(rpath, b, None, "removed", severity))
            continue
        diffs.extend(
            compare_fw_fields(rpath, b, d, severity, skip={"name"})
        )

    # Rules added out-of-band (the allow-all-outbound exfil path).
    for d in deployed_rules:
        if isinstance(d, dict) and name_of(d) not in bicep_names:
            diffs.append(
                PropertyDiff(f"{base_path}[{d.get('name', '')}]", None, d, "added", severity)
            )

    return diffs


def compare_fw_fields(
    base_path: str, bicep_el: dict, deployed_el: dict, severity: str, skip: set
) -> list["PropertyDiff"]:
    """Compare the bicep-declared fields of one firewall element.

    Scalar lists (destinationPorts, sourceAddresses, targetFqdns, ...) use
    exact-set semantics - a widened/removed member is drift. Everything else
    keeps subset semantics so Azure's read-only field augmentation
    (ipv6Rule, sourceIpGroups: [], fqdnTags: [], ...) is not flagged.
    """
    diffs: list[PropertyDiff] = []
    deployed_by_lower = {k.lower(): k for k in deployed_el}

    for fk, fv in bicep_el.items():
        if fk.lower() in {s.lower() for s in skip}:
            continue
        if _primitives.has_unresolved_expressions(fv):
            continue
        dk = deployed_by_lower.get(fk.lower())
        dv = deployed_el.get(dk) if dk is not None else None
        if dv is None:
            # Azure omits the field; only an explicit non-empty bicep value drifts.
            if fv in (None, "", [], {}):
                continue
            diffs.append(PropertyDiff(f"{base_path}.{fk}", fv, None, "modified", severity))
            continue

        if (
            isinstance(fv, list)
            and isinstance(dv, list)
            and all(not isinstance(x, (dict, list)) for x in fv)
            and all(not isinstance(x, (dict, list)) for x in dv)
        ):
            # Exact-set on scalar lists: order-insensitive, case-insensitive.
            if sorted(str(x).lower() for x in fv) != sorted(str(x).lower() for x in dv):
                diffs.append(PropertyDiff(f"{base_path}.{fk}", fv, dv, "modified", severity))
        elif not _primitives.value_matches(fv, dv):
            diffs.append(PropertyDiff(f"{base_path}.{fk}", fv, dv, "modified", severity))

    return diffs
