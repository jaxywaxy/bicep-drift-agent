"""
tools/property_drift/comparator.py

Property-level comparison between Bicep (desired) and Azure (actual). All
comparison logic - severity policy, sentinel checks, subset-vs-exact set
semantics, firewall/rule-collection granularity, Key Vault access-policy
identity matching, App Service appsettings key-only compare, monitoring
linkage refs, elevation of severity for monitoring/backup - lives in the
single `PropertyComparator` class. Keeping the class intact preserves the
`PropertyComparator._foo` call sites the test suite relies on.
"""

import re as _re
from typing import Any

from .models import PropertyDiff
from . import severity as _severity
from . import security as _security
from . import firewall as _firewall
from . import primitives as _primitives


class PropertyComparator:
    """Compare properties between desired and actual resources."""

    # Severity policy, write-only + never-projected classification live in
    # severity.py. These aliases preserve the PropertyComparator._foo call
    # sites the test suite binds to.
    CRITICAL_PROPERTIES = _severity.CRITICAL_PROPERTIES
    WRITE_ONLY_PROPERTIES = _severity.WRITE_ONLY_PROPERTIES
    NEVER_PROJECTED_BY_TYPE = _severity.NEVER_PROJECTED_BY_TYPE
    _get_severity = staticmethod(_severity.get_severity)
    _elevate_monitoring_severity = staticmethod(_severity.elevate_monitoring_severity)
    _elevate_backup_severity = staticmethod(_severity.elevate_backup_severity)
    _is_write_only_property = staticmethod(_severity.is_write_only_property)
    _is_unprojected_property = staticmethod(_severity.is_unprojected_property)
    # security: extracted to security.py; aliases preserve call sites.
    _NETWORK_ACL_DEFAULT_TYPES = _security.NETWORK_ACL_DEFAULT_TYPES
    _DEFAULT_OPEN_NETWORK_ACLS = _security.DEFAULT_OPEN_NETWORK_ACLS
    SECURITY_SENTINELS = _security.SECURITY_SENTINELS
    _check_security_sentinels = staticmethod(_security.check_security_sentinels)
    _inject_default_network_acls = staticmethod(_security.inject_default_network_acls)
    _compare_security_list = staticmethod(_security.compare_security_list)
    _allowlist_matches = staticmethod(_security.allowlist_matches)
    _access_policies_match = staticmethod(_security.access_policies_match)
    # firewall: extracted to firewall.py; aliases preserve call sites.
    _compare_rule_collections = staticmethod(_firewall.compare_rule_collections)
    _compare_fw_rules = staticmethod(_firewall.compare_fw_rules)
    _compare_fw_fields = staticmethod(_firewall.compare_fw_fields)
    # primitives: extracted to primitives.py; aliases preserve call sites.
    _flatten_dict = staticmethod(_primitives.flatten_dict)
    _placeholder_value_matches = staticmethod(_primitives.placeholder_value_matches)
    _scalar_equal = staticmethod(_primitives.scalar_equal)
    _value_matches = staticmethod(_primitives.value_matches)
    _list_is_subset = staticmethod(_primitives.list_is_subset)
    _has_unresolved_expressions = staticmethod(_primitives.has_unresolved_expressions)

    # Types whose networkAcls default to open when never configured: Azure
    # returns null/absent, while templates commonly spell out the equivalent
    # explicit default. Injecting the default on the DEPLOYED side (only) makes
    # those compare equal without suppressing real ACL drift. Bicep-side is
    # never injected: an unspecified bicep property is simply not compared.

    # Security sentinels: properties whose ABSENCE from the template is itself a
    # security posture ("no authorized IP ranges", "local accounts enabled"). The
    # generic comparison iterates bicep keys only, so a key someone sets on the
    # live resource out-of-band is invisible when the template omits it — e.g.
    # API server authorizedIPRanges added via `az aks update`. For these paths,
    # an omitted template key is treated as demanding the documented Azure
    # default, and a live value deviating from that default is drift. Paths are
    # matched case-insensitively against the flattened dicts; a path the
    # template DOES declare (itself or any child) is left to the generic
    # comparison. Keyed by lowercased resource type -> {lowercased path: default}.


    # Properties Resource Graph does not project for a SPECIFIC type, so they
    # always diff as desired-vs-null. Type-scoped (unlike WRITE_ONLY_PROPERTIES)
    # because the path is too generic to suppress globally: e.g. a Virtual WAN's
    # `properties.type` (Standard/Basic) is absent from the Resource Graph
    # projection, but a bare "properties.type" would wrongly swallow it on any
    # other resource type. Keyed by lowercased resource type.

    @staticmethod
    def compare_properties(
        bicep_properties: dict[str, Any],
        deployed_properties: dict[str, Any],
    ) -> list[PropertyDiff]:
        """Compare properties between Bicep and deployed resources."""
        diffs = []
        rtype = str(bicep_properties.get("type", "")).lower()

        # App settings VALUES are secrets. Reduce both sides to KEY SETS before
        # any flattening - flattened per-key comparison would put the values
        # into PropertyDiff desired/actual and leak them into reports.
        if (
            str(bicep_properties.get("type", "")).lower() == "microsoft.web/sites/config"
            and str(bicep_properties.get("name", "")).lower().endswith("appsettings")
        ):
            b_keys = sorted((bicep_properties.get("properties") or {}).keys())
            d_keys = sorted((deployed_properties.get("properties") or {}).keys())
            if b_keys != d_keys:
                return [PropertyDiff(
                    property_path="properties.appSettingKeys",
                    desired_value=b_keys,
                    actual_value=d_keys,
                    change_type="modified",
                    severity="warning",
                )]
            return []

        # Null networkAcls on a vault/storage account means "default open" -
        # materialize that default on the deployed side so a template spelling
        # out the same default doesn't false-drift (and so a template demanding
        # Deny DOES drift against a never-configured-open live resource).
        deployed_properties = PropertyComparator._inject_default_network_acls(deployed_properties)

        bicep_flat = PropertyComparator._flatten_dict(bicep_properties)
        deployed_flat = PropertyComparator._flatten_dict(deployed_properties)

        # Skip detailed comparison if property enrichment failed
        # (deployed_properties have no nested "properties.*" or "sku.*" keys - likely API returned empty)
        has_detailed_deployed_properties = any(
            k.startswith("properties.") or k.startswith("sku.") for k in deployed_flat.keys()
        )
        if not has_detailed_deployed_properties:
            return diffs

        # Check for modified properties
        for key, bicep_value in bicep_flat.items():
            if key in deployed_flat:
                if PropertyComparator._is_write_only_property(key):
                    continue

                # Skip name property comparisons when the name contains unresolved expressions
                # (e.g., sttestdrift[uniqueString(...)]) - these are matched by prefix
                if key == "name" and isinstance(bicep_value, str):
                    if "[" in bicep_value and "]" in bicep_value:
                        continue

                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                deployed_value = deployed_flat[key]

                # Monitoring alert cross-references (scopes + action-group links):
                # exact-set compare so a severed/re-pointed link surfaces. The
                # generic subset compare treats the unresolved bicep ids as a
                # match (see _value_matches), so it catches a full removal but
                # NEVER a re-point. This owns the linkage paths outright.
                mon = PropertyComparator._compare_monitoring_refs(
                    rtype, key, bicep_value, deployed_value
                )
                if mon is not None:
                    diffs.extend(mon)
                    continue

                # Security-list properties (KV access policies, networkAcls
                # allowlists) get exact-set semantics: the generic subset
                # comparison would never flag a LIVE-ADDED element (an
                # out-of-band access grant or firewall opening) because it only
                # checks that bicep elements exist in the deployed list.
                semantic = PropertyComparator._compare_security_list(key, bicep_value, deployed_value)
                if semantic is not None:
                    if not semantic:
                        diffs.append(
                            PropertyDiff(
                                property_path=key,
                                desired_value=bicep_value,
                                actual_value=deployed_value,
                                change_type="modified",
                                severity=PropertyComparator._get_severity(key),
                            )
                        )
                    continue

                # Azure Firewall ruleCollections: emit GRANULAR per-collection /
                # per-rule / per-field diffs instead of one opaque whole-array
                # replacement. The generic subset compare only says "the array
                # differs" and dumps both full arrays, which (a) buries the actual
                # change under Azure's read-only field augmentation and (b) MISSES
                # a scalar-list widening on its own - [443] is a subset of
                # [443, 3389], so an added port is invisible unless some sibling
                # (an action flip, an added rule) independently fails the match.
                # The granular differ uses exact-set semantics on scalar rule
                # lists so an out-of-band opening is caught by itself.
                fw = PropertyComparator._compare_rule_collections(
                    key, bicep_value, deployed_value
                )
                if fw is not None:
                    diffs.extend(fw)
                    continue

                # Skip properties where Azure returns None (not exposed by API)
                if deployed_value is None:
                    continue

                # Skip when the bicep value is None - typically an unresolved
                # cross-module reference (e.g. a nested subnet id passed from
                # another module's output that the analyzer can't resolve). Can't
                # meaningfully compare None against a live value.
                if bicep_value is None:
                    continue

                # Skip null vs empty string comparisons (functionally equivalent)
                if (bicep_value is None and deployed_value == "") or (bicep_value == "" and deployed_value is None):
                    continue

                # Skip empty object/dict comparisons (null vs {})
                if isinstance(bicep_value, dict) and isinstance(deployed_value, dict):
                    if not bicep_value and not deployed_value:
                        continue

                # Normalize type/location comparisons (Azure normalizes casing:
                # an action group's 'Global' comes back 'global')
                if key in ("type", "location") and isinstance(bicep_value, str) and isinstance(deployed_value, str):
                    if bicep_value.lower() == deployed_value.lower():
                        continue

                # networkAcls enums compare case-insensitively ('Allow' vs 'allow'),
                # and bypass is a comma-separated set ('AzureServices, Logging' ==
                # 'Logging,AzureServices').
                if ".networkacls." in key.lower() and isinstance(bicep_value, str) and isinstance(deployed_value, str):
                    canon = lambda v: {p.strip().lower() for p in v.split(",") if p.strip()}
                    if canon(bicep_value) == canon(deployed_value):
                        continue

                # Skip if both values are empty (null, empty string, empty list, etc.)
                if not bicep_value and not deployed_value:
                    continue

                # Arrays of objects (securityRules, subnets, routes) and nested
                # dicts are compared with SUBSET semantics: Azure augments them with
                # read-only fields, so only the fields the bicep specifies must
                # match. Scalars compare directly (IDs case-insensitively).
                if isinstance(bicep_value, (list, dict)) and isinstance(deployed_value, (list, dict)):
                    is_drift = not PropertyComparator._value_matches(bicep_value, deployed_value)
                else:
                    is_drift = not PropertyComparator._scalar_equal(bicep_value, deployed_value)

                if is_drift:
                    severity = PropertyComparator._get_severity(key)
                    diffs.append(
                        PropertyDiff(
                            property_path=key,
                            desired_value=bicep_value,
                            actual_value=deployed_value,
                            change_type="modified",
                            severity=severity,
                        )
                    )

        # Check for removed properties (in Bicep but not deployed)
        for key, bicep_value in bicep_flat.items():
            if key not in deployed_flat:
                if PropertyComparator._is_write_only_property(key):
                    continue

                # Skip properties Resource Graph never projects for this type
                # (e.g. Virtual WAN properties.type) - always a desired-vs-null FP.
                if PropertyComparator._is_unprojected_property(rtype, key):
                    continue

                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                # Skip if deployed properties are incomplete (likely property enrichment issue)
                if len(deployed_flat) < 3:
                    continue

                # Skip if Bicep value is essentially empty (optional property not set)
                if not bicep_value or (isinstance(bicep_value, (dict, list)) and len(bicep_value) == 0):
                    continue

                diffs.append(
                    PropertyDiff(
                        property_path=key,
                        desired_value=bicep_value,
                        actual_value=None,
                        change_type="removed",
                        severity="info",
                    )
                )

        # NOTE: Skip added properties (deployed but not in Bicep)
        # These are optional properties that Azure manages automatically.
        # If not explicitly defined in the Bicep template, they should not
        # be reported as drift. Examples: sku fields, tags added by policies,
        # Azure-managed system properties, etc.
        # Only report properties that are explicitly defined in Bicep template.
        # EXCEPTION: security sentinels (SECURITY_SENTINELS) - for those paths a
        # live-added key IS the drift (e.g. authorizedIPRanges set out-of-band).
        diffs.extend(
            PropertyComparator._check_security_sentinels(
                bicep_properties, bicep_flat, deployed_flat
            )
        )

        diffs = PropertyComparator._elevate_monitoring_severity(rtype, diffs)
        return PropertyComparator._elevate_backup_severity(rtype, diffs)










    # Placeholder the normalizer emits for an unresolvable uniqueString() inside
    # a value, e.g. 'aidrift[86c9cbf6]'. The resource NAME gets smart-match
    # remapped, but the same placeholder inside a PROPERTY value (a
    # customSubDomainName set to the resource name) reaches the comparator
    # as-is and must not be compared literally against the resolved live value.






    # Alert/action-group resources are "silent failure" types: a disabled alert
    # or a severed notification path looks fine until an incident. These paths
    # are critical ONLY for these types, so they cannot go in the global
    # substring CRITICAL_PROPERTIES - e.g. "properties.enabled" would also match
    # Key Vault's "properties.enabledForDeployment".



    # Alert types whose linkage (scopes + action-group refs) is a cross-resource
    # reference. metricAlerts/activityLogAlerts/scheduledQueryRules point at the
    # thing they watch (scopes) and the thing they notify (actions.actionGroups);
    # actionGroups/components have no such outward links, so they are excluded.
    _LINKAGE_TYPES = frozenset({
        "microsoft.insights/metricalerts",
        "microsoft.insights/activitylogalerts",
        "microsoft.insights/scheduledqueryrules",
    })
    # Flattened property paths that carry those references. actions is a plain
    # list on metricAlerts and a dict (actions.actionGroups) on activity/query.
    _LINKAGE_PATHS = frozenset({
        "properties.scopes",
        "properties.actions",
        "properties.actions.actiongroups",
    })

    @staticmethod
    def _ref_identity(ref: Any) -> str | None:
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
        if PropertyComparator._has_unresolved_expressions(s):
            return None
        # A bare literal id or name (already resolved): trailing segment.
        return s.rstrip("/").rsplit("/", 1)[-1].lower()

    @staticmethod
    def _linkage_refs(value: Any) -> list[Any]:
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

    @staticmethod
    def _compare_monitoring_refs(
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
        if resource_type not in PropertyComparator._LINKAGE_TYPES:
            return None
        if key.lower() not in PropertyComparator._LINKAGE_PATHS:
            return None

        bicep_refs = PropertyComparator._linkage_refs(bicep_value)
        deployed_refs = PropertyComparator._linkage_refs(deployed_value)

        b_names: list[str] = []
        b_opaque = 0
        for r in bicep_refs:
            ident = PropertyComparator._ref_identity(r)
            if ident is None:
                b_opaque += 1
            else:
                b_names.append(ident)
        d_names = [n for n in (PropertyComparator._ref_identity(r) for r in deployed_refs)
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
                severity=PropertyComparator._get_severity(key),
            )]
        return []


