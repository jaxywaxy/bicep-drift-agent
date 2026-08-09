"""
tools/property_drift/primitives.py

Generic value-matching primitives shared by every comparator: deep SUBSET
matching (bicep specifies a floor, Azure may augment with read-only fields),
case-insensitive resource-id equality, uniqueString placeholder matching, dict
flattening, and unresolved-expression detection. Depend on nothing else in the
package, so the domain comparators and comparator.py can all sit on top without
a cycle. comparator.py keeps thin aliases (PropertyComparator._value_matches
etc.) so existing call sites are unchanged.
"""

import re as _re
from typing import Any


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dictionary.

    Arrays are serialized as JSON for semantic comparison (not string comparison).
    This prevents false positives from whitespace differences or element reordering.
    Example: [1,2,3] vs [1, 2, 3] will compare equal.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, (list, tuple)):
            # Keep arrays as native lists so they can be compared with SUBSET
            # semantics (see _value_matches). Azure augments array-of-object
            # properties (securityRules, subnets, routes) with read-only fields
            # (provisioningState, etc.); serializing to JSON here would make the
            # bicep array never equal the augmented live array (false drift).
            items.append((new_key, list(v)))
        else:
            items.append((new_key, v))
    return dict(items)


# The placeholder the normalizer emits for an unresolvable uniqueString() inside
# a value, e.g. 'aidrift[86c9cbf6]'. The resource NAME gets smart-match remapped,
# but the same placeholder inside a PROPERTY value (a customSubDomainName set to
# the resource name) reaches the comparator as-is and must not be compared
# literally against the resolved live value.
def placeholder_value_matches(bicep_val: str, deployed_val: str) -> bool:
    """True when a placeholder-bearing bicep string is consistent with the
    deployed value: the fixed parts around each [hex] placeholder must
    appear in order, with the placeholders spanning arbitrary generated
    characters. 'aidrift[86c9cbf6]' matches 'aidrift3s7c7weddxr3s'."""
    parts = _re.split(r"\[[0-9a-fA-F]{6,}\]", bicep_val)
    if len(parts) < 2:
        return False  # no placeholder present
    pattern = "".join(_re.escape(p) + ("[a-z0-9]*" if i < len(parts) - 1 else "")
                      for i, p in enumerate(parts))
    return _re.fullmatch(pattern, deployed_val, _re.IGNORECASE) is not None


def scalar_equal(bicep_val: Any, deployed_val: Any) -> bool:
    """Compare two scalars, treating Azure resource IDs case-insensitively.

    Azure returns resource IDs with inconsistent casing (e.g. '/resourceGroups/'
    vs '/resourcegroups/'), which is not real drift.
    """
    if isinstance(bicep_val, str) and isinstance(deployed_val, str):
        if "/subscriptions/" in bicep_val.lower() and "/subscriptions/" in deployed_val.lower():
            return bicep_val.lower() == deployed_val.lower()
        if "[" in bicep_val and placeholder_value_matches(bicep_val, deployed_val):
            return True
    return bicep_val == deployed_val


def value_matches(bicep_val: Any, deployed_val: Any) -> bool:
    """Deep SUBSET match: every field the bicep specifies must be present and
    equal in the deployed value. Deployed-only fields (Azure read-only
    augmentation like provisioningState) are ignored.
    """
    # An unresolved bicep expression (resourceId(), uniqueString(), etc.,
    # often a NESTED id like publicIpAddresses[].id) resolves at deploy time
    # and can't be compared - treat as a match rather than false drift.
    if has_unresolved_expressions(bicep_val):
        return True
    if isinstance(bicep_val, dict) and isinstance(deployed_val, dict):
        for k, v in bicep_val.items():
            match_key = k if k in deployed_val else next(
                (dk for dk in deployed_val if dk.lower() == k.lower()), None
            )
            if match_key is None:
                if v in (None, "", {}, []):
                    continue
                return False
            if not value_matches(v, deployed_val[match_key]):
                return False
        return True
    if isinstance(bicep_val, list) and isinstance(deployed_val, list):
        return list_is_subset(bicep_val, deployed_val)
    return scalar_equal(bicep_val, deployed_val)


def list_is_subset(bicep_list: list, deployed_list: list) -> bool:
    """Compare arrays with subset semantics on FIELDS but not on ELEMENTS.

    Elements with a 'name' (NSG rules, subnets, routes) are matched by name
    and each must field-subset-match its deployed counterpart (Azure augments
    elements with read-only fields like provisioningState - not drift).

    For a NAMED collection, deployed elements that aren't in the bicep ARE
    drift: Azure never adds elements to these user-managed arrays itself
    (default NSG rules live in the separate defaultSecurityRules property),
    so an extra element means someone added a route/rule/subnet by hand.
    Only enforced when the bicep side establishes the named convention (has
    at least one named element), so unnamed/empty arrays keep pure subset.

    Unnamed elements must subset-match some deployed element positionally.
    """
    bicep_named = [b for b in bicep_list if isinstance(b, dict) and "name" in b]
    for b in bicep_list:
        if isinstance(b, dict) and "name" in b:
            bname = str(b.get("name", "")).lower()
            cand = next(
                (d for d in deployed_list
                 if isinstance(d, dict) and str(d.get("name", "")).lower() == bname),
                None,
            )
            if cand is None or not value_matches(b, cand):
                return False
        else:
            if not any(value_matches(b, d) for d in deployed_list):
                return False

    # Named collection: flag manually-ADDED elements (deployed name not in bicep).
    if bicep_named:
        bicep_names = {str(b.get("name", "")).lower() for b in bicep_named}
        for d in deployed_list:
            if isinstance(d, dict) and "name" in d:
                if str(d.get("name", "")).lower() not in bicep_names:
                    return False
    return True


def has_unresolved_expressions(value: Any) -> bool:
    """Check if value contains unresolved Bicep/ARM template expressions.

    Examples: uniqueString(), subscription(), resourceId(), format(), etc.
    These resolve at deployment time and shouldn't be reported as drift.
    """
    if not isinstance(value, str):
        return False

    value_lower = value.lower()
    unresolved_markers = [
        'uniquestring(',
        'subscription().',
        # Placeholder tokens emitted by resolve_expression when a
        # subscription()/tenant()/deployment() or cross-module reference can't
        # be resolved at analysis time (e.g. a subnet id from another module).
        'subscription-tenant-id',
        'subscription-id',
        'subscription-context',
        'deployment-location',
        'tenant(',
        'resourceid(',
        'format(',
        'variables(',
        'parameters(',
        'reference(',
        'listkeys(',
        'concat(',
        'string(',
        'take(',
        # json('<literal>') is resolved in the normalizer; a json(...) that
        # survives here wraps a non-literal arg and can't be compared.
        'json(',
    ]

    return any(marker in value_lower for marker in unresolved_markers)


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
    if has_unresolved_expressions(s):
        return None
    # A bare literal id or name (already resolved): trailing segment.
    return s.rstrip("/").rsplit("/", 1)[-1].lower()
