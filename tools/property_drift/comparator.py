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
    _NETWORK_ACL_DEFAULT_TYPES = {
        "microsoft.keyvault/vaults",
        "microsoft.storage/storageaccounts",
        # AI/OpenAI accounts share the same null-means-default-open semantics.
        "microsoft.cognitiveservices/accounts",
    }
    _DEFAULT_OPEN_NETWORK_ACLS = {
        "bypass": "AzureServices",
        "defaultAction": "Allow",
        "ipRules": [],
        "virtualNetworkRules": [],
    }

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
    SECURITY_SENTINELS = {
        "microsoft.containerservice/managedclusters": {
            "properties.apiserveraccessprofile.authorizedipranges": [],
            "properties.apiserveraccessprofile.enableprivatecluster": False,
            "properties.disablelocalaccounts": False,
            "properties.enablerbac": True,
        },
        # NOTE: minimumTlsVersion/minimalTlsVersion are deliberately NOT
        # sentinels: the absent-default is CREATION-API-VERSION-DEPENDENT
        # (live-observed: a fresh EventHub namespace @2021-11-01 materializes
        # '1.0' while ServiceBus @2022-10-01-preview materializes '1.2'), so no
        # single default is FP-free. A template-DECLARED TLS floor weakened
        # out-of-band is still caught by the generic comparison, as critical.
        "microsoft.sql/servers": {
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.storage/storageaccounts": {
            "properties.allowblobpublicaccess": False,
            "properties.allowsharedkeyaccess": True,
            "properties.supportshttpstrafficonly": True,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.keyvault/vaults": {
            "properties.enablesoftdelete": True,
            "properties.enablepurgeprotection": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.web/sites": {
            "properties.httpsonly": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.containerregistry/registries": {
            "properties.adminuserenabled": False,
            "properties.anonymouspullenabled": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.cognitiveservices/accounts": {
            "properties.publicnetworkaccess": "Enabled",
            "properties.disablelocalauth": False,
        },
        "microsoft.servicebus/namespaces": {
            "properties.disablelocalauth": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.eventhub/namespaces": {
            "properties.disablelocalauth": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.documentdb/databaseaccounts": {
            "properties.publicnetworkaccess": "Enabled",
            "properties.disablelocalauth": False,
        },
        "microsoft.compute/disks": {
            "properties.networkaccesspolicy": "AllowAll",
            "properties.publicnetworkaccess": "Enabled",
        },
        # NOTE: no VMSS/VM securityProfile sentinel. Unlike the AKS and storage
        # defaults, encryptionAtHost/Trusted Launch absent-defaults vary by
        # image, VM size and creation API version (a Gen2 image can materialize
        # securityType 'TrustedLaunch' with no template involvement), which is
        # the same trap documented above for TLS floors. Declared values are
        # still generic-compared, as critical.
    }


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

    @staticmethod
    def _check_security_sentinels(
        bicep_properties: dict, bicep_flat: dict, deployed_flat: dict
    ) -> list[PropertyDiff]:
        """Flag live values on sentinel paths the template omits.

        For each SECURITY_SENTINELS path of this resource type that the
        template does not declare (neither the path itself nor any child),
        compare the live value against the documented absent-default; a
        deviation is reported as change_type "added" - the key was introduced
        on the live resource out-of-band.
        """
        rtype = str(bicep_properties.get("type", "")).lower()
        sentinels = PropertyComparator.SECURITY_SENTINELS.get(rtype)
        if not sentinels:
            return []

        bicep_keys = {k.lower() for k in bicep_flat}
        deployed_by_lower = {k.lower(): k for k in deployed_flat}
        diffs = []
        for path, default in sentinels.items():
            if path in bicep_keys or any(k.startswith(path + ".") for k in bicep_keys):
                continue  # template declares it - generic comparison owns it
            deployed_key = deployed_by_lower.get(path)
            if deployed_key is None:
                continue  # absent live-side too
            live_value = deployed_flat[deployed_key]
            if live_value is None or live_value == "":
                # null/"" both mean "never materialized" - i.e. the default.
                continue
            if isinstance(default, list) and isinstance(live_value, list):
                matches = sorted(str(v).lower() for v in live_value) == sorted(
                    str(v).lower() for v in default
                )
            elif isinstance(default, str) and isinstance(live_value, str):
                # Enum-valued strings ('Enabled', 'TLS1_2') - Azure varies casing.
                matches = live_value.lower() == default.lower()
            else:
                matches = live_value == default
            if not matches:
                diffs.append(
                    PropertyDiff(
                        property_path=deployed_key,
                        desired_value=default,
                        actual_value=live_value,
                        change_type="added",
                        severity=PropertyComparator._get_severity(deployed_key),
                    )
                )
        return diffs

    @staticmethod
    def _inject_default_network_acls(deployed_properties: dict) -> dict:
        """Return a copy with default-open networkAcls when the live value is null.

        Only for vault/storage types, only on the deployed side (see
        _NETWORK_ACL_DEFAULT_TYPES). Does not mutate the input.
        """
        rtype = str(deployed_properties.get("type", "")).lower()
        if rtype not in PropertyComparator._NETWORK_ACL_DEFAULT_TYPES:
            return deployed_properties
        props = deployed_properties.get("properties")
        if not isinstance(props, dict) or props.get("networkAcls") is not None:
            return deployed_properties
        return {
            **deployed_properties,
            "properties": {
                **props,
                "networkAcls": dict(PropertyComparator._DEFAULT_OPEN_NETWORK_ACLS),
            },
        }

    @staticmethod
    def _compare_security_list(key: str, bicep_value: Any, deployed_value: Any):
        """Exact-set comparison for security-sensitive list properties.

        Returns True/False (match / drift) when the key is one of the handled
        properties and both sides are lists; None to fall through to the
        generic comparison. Handled:
          * properties.accessPolicies        (Key Vault) - keyed by principal
          * properties.networkAcls.ipRules / .virtualNetworkRules - allowlists
        """
        if not (isinstance(bicep_value, list) and isinstance(deployed_value, list)):
            return None
        kl = key.lower()
        if kl.endswith("properties.accesspolicies"):
            return PropertyComparator._access_policies_match(bicep_value, deployed_value)
        if ".networkacls." in kl and (
            kl.endswith(".iprules")
            or kl.endswith(".virtualnetworkrules")
            or kl.endswith(".resourceaccessrules")
        ):
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        # AI content filters: entries repeat names across sources (Hate/Prompt,
        # Hate/Completion), so the generic name-keyed matcher pairs them wrongly
        # - and a filter loosened out-of-band must be drift.
        if kl.endswith("properties.contentfilters"):
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        # Azure Firewall plain-string lists. Elements carry no 'name', so the
        # generic subset compare is vacuous when the bicep side is empty - an
        # out-of-band threat-intel whitelist entry (exempting an IP/FQDN from
        # TI) or an added custom DNS server (resolution hijack) would be
        # invisible. Exact-set semantics make live-added entries drift.
        if (kl.endswith(".threatintelwhitelist.ipaddresses")
                or kl.endswith(".threatintelwhitelist.fqdns")
                or kl.endswith(".dnssettings.servers")):
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        # Availability zones: a bare list of zone numbers, so the generic subset
        # compare is one-directional - ["1","2","3"] shrunk to ["1"] IS caught
        # (bicep elements go missing), but a live-side zone list that gained an
        # entry the template never asked for is invisible, and a template
        # declaring [] excuses anything. Zone membership is a placement fact
        # that must match exactly in both directions.
        if kl == "zones":
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        # AKS cluster-admin groups: a bare list of AAD group object IDs, and the
        # single highest-privilege grant on the cluster. Same vacuous-subset
        # trap as the firewall lists and worse - the common declaration is an
        # EMPTY adminGroupObjectIDs, and [] is a subset of every list, so adding
        # a group out-of-band (instant cluster-admin for its members) compared
        # clean. Exact set, both directions.
        if kl.endswith("aadprofile.admingroupobjectids"):
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        # Azure Monitor action-group receivers: each *Receivers array is keyed
        # by receiver name. The generic bicep-keyed loop MISSES a receiver
        # deleted entirely (its flattened key just vanishes from the deployed
        # side) and a live-ADDED one, so exact-set both directions - a removed
        # receiver is a broken notification path, an added one an out-of-band
        # alerting change. Covers emailReceivers/smsReceivers/webhookReceivers/
        # armRoleReceivers/... (all end in "receivers").
        if kl.startswith("properties.") and kl.endswith("receivers"):
            return PropertyComparator._allowlist_matches(bicep_value, deployed_value)
        return None

    @staticmethod
    def _allowlist_matches(bicep_list: list, deployed_list: list) -> bool:
        """Match firewall allowlists (ipRules / virtualNetworkRules) as exact sets.

        Element identity is its 'value' (CIDR) or 'id' (subnet), compared
        case-insensitively; other fields subset-match (Azure augments with
        state/action defaults). Unlike the generic subset compare, a deployed
        element with no bicep counterpart IS drift - that's a firewall opening
        someone added by hand. Bicep elements whose identity is an unresolved
        expression (a subnet id from another module) each excuse one otherwise
        unmatched deployed element.
        """
        def identity_and_keys(el: Any):
            """(identity string, keys that formed it). Identity keys are matched
            here (with canonicalization), so they're excluded from the per-pair
            field-subset check - re-comparing them literally would reintroduce
            the '1.2.3.4/32' vs '1.2.3.4' false positive."""
            if not isinstance(el, dict):
                return str(el).lower(), ()
            v = el.get("value") or el.get("id")
            if v is not None:
                s = str(v).lower()
                # Azure returns single-IP rules WITHOUT the /32 suffix that
                # templates conventionally declare ("1.2.3.4/32" -> "1.2.3.4").
                return (s.removesuffix("/32")), ("value", "id")
            # AI contentFilters: names repeat across sources (Hate/Prompt vs
            # Hate/Completion) - identity is the (name, source) pair.
            if "name" in el and "source" in el:
                return (
                    f"{str(el.get('name', '')).lower()}|{str(el.get('source', '')).lower()}",
                    ("name", "source"),
                )
            # Monitor action-group receivers (and similar name-keyed elements):
            # identity is the receiver 'name'; the type-specific fields
            # (emailAddress, serviceUri, ...) subset-match, so Azure-added
            # status / useCommonAlertSchema on the live side don't false-flag.
            if "name" in el:
                return str(el.get("name", "")).lower(), ("name",)
            # storage resourceAccessRules have no value/id - identity is the
            # (tenantId, resourceId) pair, joined so unresolved-expression
            # markers in either part stay detectable by the caller.
            return (
                f"{str(el.get('tenantId', '')).lower()}|{str(el.get('resourceId', '')).lower()}",
                ("tenantid", "resourceid"),
            )

        def identity(el: Any) -> str:
            return identity_and_keys(el)[0]

        def non_identity_fields(el: Any) -> Any:
            if not isinstance(el, dict):
                return el
            _, used = identity_and_keys(el)
            return {k: v for k, v in el.items() if k.lower() not in used}

        unresolved_slots = 0
        unmatched_deployed = list(deployed_list)
        for b in bicep_list:
            b_id = identity(b)
            if PropertyComparator._has_unresolved_expressions(b_id):
                unresolved_slots += 1
                continue
            hit = next((d for d in unmatched_deployed if identity(d) == b_id), None)
            if hit is None or not PropertyComparator._value_matches(non_identity_fields(b), hit):
                return False  # a bicep-declared rule is gone or altered
            unmatched_deployed.remove(hit)
        # Every leftover deployed rule must be covered by an unresolved slot;
        # anything beyond that was added out-of-band.
        return len(unmatched_deployed) <= unresolved_slots

    @staticmethod
    def _compare_rule_collections(
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

        sev = PropertyComparator._get_severity(key)  # "critical" (ruleCollections)

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
                and not PropertyComparator._scalar_equal(b_action, d_action)
            ):
                diffs.append(
                    PropertyDiff(f"{cpath}.action.type", b_action, d_action, "modified", sev)
                )

            # Remaining collection-scalar fields (priority, ruleCollectionType).
            diffs.extend(
                PropertyComparator._compare_fw_fields(
                    cpath, b, d, sev, skip={"name", "action", "rules"}
                )
            )

            # Rules within the collection.
            diffs.extend(
                PropertyComparator._compare_fw_rules(
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

    @staticmethod
    def _compare_fw_rules(
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
                PropertyComparator._compare_fw_fields(rpath, b, d, severity, skip={"name"})
            )

        # Rules added out-of-band (the allow-all-outbound exfil path).
        for d in deployed_rules:
            if isinstance(d, dict) and name_of(d) not in bicep_names:
                diffs.append(
                    PropertyDiff(f"{base_path}[{d.get('name', '')}]", None, d, "added", severity)
                )

        return diffs

    @staticmethod
    def _compare_fw_fields(
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
            if PropertyComparator._has_unresolved_expressions(fv):
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
            elif not PropertyComparator._value_matches(fv, dv):
                diffs.append(PropertyDiff(f"{base_path}.{fk}", fv, dv, "modified", severity))

        return diffs

    @staticmethod
    def _access_policies_match(bicep_list: list, deployed_list: list) -> bool:
        """Match Key Vault accessPolicies keyed by principal, permissions as sets.

        Identity is (objectId, applicationId), case-insensitive. Permissions
        compare as case-insensitive sets across ALL four categories (keys/
        secrets/certificates/storage) - a category the bicep omits is an empty
        set, so a permission granted out-of-band in any category is drift.
        A bicep policy whose objectId is a runtime expression (a managed
        identity's principalId) excuses one otherwise unmatched deployed
        policy, permissions unchecked - best-effort, like smart matching.
        """
        def perm_sets(policy: dict) -> dict[str, frozenset]:
            perms = policy.get("permissions") or {}
            if not isinstance(perms, dict):
                perms = {}
            return {
                cat: frozenset(str(p).lower() for p in (perms.get(cat) or []))
                for cat in ("keys", "secrets", "certificates", "storage")
            }

        def identity(policy: dict) -> tuple:
            return (
                str(policy.get("objectId") or "").lower(),
                str(policy.get("applicationId") or "").lower(),
            )

        unresolved_slots = 0
        unmatched_deployed = [p for p in deployed_list if isinstance(p, dict)]
        if len(unmatched_deployed) != len(deployed_list):
            return False  # malformed live data - surface it rather than guess

        for b in bicep_list:
            if not isinstance(b, dict):
                return False
            obj_id = str(b.get("objectId") or "")
            if PropertyComparator._has_unresolved_expressions(obj_id):
                unresolved_slots += 1
                continue
            b_ident = identity(b)
            hit = next((d for d in unmatched_deployed if identity(d) == b_ident), None)
            if hit is None:
                return False  # bicep-declared policy revoked
            if perm_sets(b) != perm_sets(hit):
                return False  # permissions changed (granted or revoked)
            unmatched_deployed.remove(hit)

        return len(unmatched_deployed) <= unresolved_slots


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


