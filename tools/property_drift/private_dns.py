"""Private endpoint DNS zone group configs - exact-set comparison.

Same failure mode monitoring.py owns for alert linkages, on a different type.
The bicep side is `resourceId('Microsoft.Network/privateDnsZones', '<zone>')`
and the live side is a full ARM id, so the generic subset compare treats the
unresolved expression as a match: it catches the config being REMOVED but never
a RE-POINT. Re-pointing is the dangerous one - clients then resolve the private
endpoint through the wrong zone, fall back to public DNS, and the Private Link
bypass succeeds silently.

Verified live 2026-07-28: with the collector landed and no comparator, swapping
privateDnsZoneId to a completely different zone produced ZERO diffs.

Identity comes from primitives.ref_identity, which already collapses both
spellings to a trailing name.
"""

from typing import TYPE_CHECKING, Any

from . import primitives as _primitives
from . import severity as _severity

if TYPE_CHECKING:
    from .models import PropertyDiff

_ZONE_GROUP_TYPE = "microsoft.network/privateendpoints/privatednszonegroups"
_CONFIGS_PATH = "properties.privatednszoneconfigs"


def _configs_by_name(value: Any) -> tuple[dict[str, str | None], int]:
    """{config name -> zone identity} plus a count of configs whose zone ref is
    OPAQUE (an unresolved expression with no literal name, e.g. a module
    output). Opaque entries are counted, not compared - there is nothing to
    compare them against."""
    by_name: dict[str, str | None] = {}
    opaque = 0
    if not isinstance(value, (list, tuple)):
        return by_name, opaque
    for el in value:
        if not isinstance(el, dict):
            continue
        name = str(el.get("name") or "").lower()
        zone_id = ((el.get("properties") or {}) if isinstance(el.get("properties"), dict)
                   else {}).get("privateDnsZoneId")
        ident = _primitives.ref_identity(zone_id)
        if ident is None and zone_id is not None:
            opaque += 1
        by_name[name] = ident
    return by_name, opaque


def compare_zone_group_configs(
    resource_type: str, key: str, bicep_value: Any, deployed_value: Any
) -> list["PropertyDiff"] | None:
    """Own `properties.privateDnsZoneConfigs` outright: returns [] or a diff so
    the caller skips the generic subset compare that cannot see a re-point.

    Drift when a declared config is missing live, when its zone identity
    changed, or when live carries a config the template never declared (DNS
    integration added out of band).

    LIMIT, as in monitoring: a config whose declared zone is opaque on both
    sides cannot be checked for a re-point - there is no literal name to
    compare. Its presence is still checked.
    """
    if resource_type != _ZONE_GROUP_TYPE or key.lower() != _CONFIGS_PATH:
        return None

    from .models import PropertyDiff

    declared, _ = _configs_by_name(bicep_value)
    live, _ = _configs_by_name(deployed_value)

    drift = False
    for name, want in declared.items():
        if name not in live:
            drift = True                      # declared config gone
        elif want is not None and live[name] != want:
            drift = True                      # zone re-pointed
    if set(live) - set(declared):
        drift = True                          # undeclared config added live

    if not drift:
        return []
    return [PropertyDiff(
        property_path=key,
        desired_value=bicep_value,
        actual_value=deployed_value,
        change_type="modified",
        severity=_severity.get_severity(key),
    )]
