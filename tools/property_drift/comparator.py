"""
tools/property_drift/comparator.py

Property-level comparison between Bicep (desired) and Azure (actual).
`PropertyComparator.compare_properties` is the orchestrator; the comparison
logic lives in focused sibling modules it delegates to:

    primitives  - generic value matching (subset, scalar, placeholder, flatten)
    severity    - critical-property policy + monitoring/backup elevation
    firewall    - Azure Firewall ruleCollections -> rules -> fields diffing
    security    - sentinels, network-ACL defaults, allowlists, access policies
    monitoring  - alert linkage (scopes / action-group) cross-references

The class keeps thin `staticmethod` aliases (PropertyComparator._foo) delegating
to those modules, preserving every call site the test suite binds to.
"""

from typing import Any

from .models import PropertyDiff
from . import severity as _severity
from . import monitoring as _monitoring
from . import security as _security
from . import firewall as _firewall
from . import primitives as _primitives
from . import private_dns as _private_dns


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
    _elevate_workspace_table_severity = staticmethod(_severity.elevate_workspace_table_severity)
    _is_write_only_property = staticmethod(_severity.is_write_only_property)
    _is_unprojected_property = staticmethod(_severity.is_unprojected_property)
    # monitoring: extracted to monitoring.py; aliases preserve call sites.
    _LINKAGE_TYPES = _monitoring.LINKAGE_TYPES
    _LINKAGE_PATHS = _monitoring.LINKAGE_PATHS
    _ref_identity = staticmethod(_monitoring.ref_identity)
    _linkage_refs = staticmethod(_monitoring.linkage_refs)
    _compare_monitoring_refs = staticmethod(_monitoring.compare_monitoring_refs)
    _compare_zone_group_configs = staticmethod(_private_dns.compare_zone_group_configs)
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

                # Private endpoint DNS zone configs: identical shape to the
                # linkage paths above (bicep resourceId() vs a live ARM id), so
                # the same exact-set treatment. Without this the generic compare
                # matches the unresolved expression and a re-pointed zone - the
                # one that silently sends traffic to the public endpoint - is
                # invisible.
                zone_cfg = PropertyComparator._compare_zone_group_configs(
                    rtype, key, bicep_value, deployed_value
                )
                if zone_cfg is not None:
                    diffs.extend(zone_cfg)
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

                # Tags are the exception to the blanket 'info'. That default
                # hedges against properties Azure simply does not return, but
                # Azure reports the tag map faithfully - a declared key absent
                # from it really was deleted, so there is no FP to hedge.
                # Deleting a tag the template asserts is at least as serious as
                # changing its value (mandatory tag sets are usually policy-
                # enforced), so it scores the same instead of landing at the
                # bottom of the report.
                is_tag = key == "tags" or key.startswith("tags.")

                diffs.append(
                    PropertyDiff(
                        property_path=key,
                        desired_value=bicep_value,
                        actual_value=None,
                        change_type="removed",
                        severity=(
                            PropertyComparator._get_severity(key) if is_tag else "info"
                        ),
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
        diffs = PropertyComparator._elevate_backup_severity(rtype, diffs)
        return PropertyComparator._elevate_workspace_table_severity(rtype, diffs)
