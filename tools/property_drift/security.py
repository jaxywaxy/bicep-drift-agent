"""
tools/property_drift/security.py

Security-sensitive comparators: SECURITY_SENTINELS (live-added keys on
template-omitted security paths), default network-ACL injection so an omitted
networkAcls block is compared against Azure's effective default, exact-set
allowlist compare (ipRules/virtualNetworkRules - an added entry IS drift), and
Key Vault access-policy identity matching. Sits on primitives + severity.
"""

from typing import Any
from .models import PropertyDiff
from . import primitives as _primitives
from . import severity as _severity


# Types whose networkAcls default to open when never configured: Azure returns
# null/absent, while templates commonly spell out the equivalent explicit
# default. Injecting the default on the DEPLOYED side (only) makes those compare
# equal without suppressing real ACL drift. Bicep-side is never injected: an
# unspecified bicep property is simply not compared.
NETWORK_ACL_DEFAULT_TYPES = {
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    # AI/OpenAI accounts share the same null-means-default-open semantics.
    "microsoft.cognitiveservices/accounts",
}

DEFAULT_OPEN_NETWORK_ACLS = {
    "bypass": "AzureServices",
    "defaultAction": "Allow",
    "ipRules": [],
    "virtualNetworkRules": [],
}

# Properties whose ABSENCE from the template is itself a security posture ("no
# authorized IP ranges", "local accounts enabled"). The generic comparison
# iterates bicep keys only, so a key someone sets on the live resource
# out-of-band is invisible when the template omits it - e.g. API server
# authorizedIPRanges added via `az aks update`. For these paths, an omitted
# template key is treated as demanding the documented Azure default, and a live
# value deviating from that default is drift. Paths are matched
# case-insensitively against the flattened dicts; a path the template DOES
# declare (itself or any child) is left to the generic comparison. Keyed by
# lowercased resource type -> {lowercased path: default}.
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

def check_security_sentinels(
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
    sentinels = SECURITY_SENTINELS.get(rtype)
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
                    severity=_severity.get_severity(deployed_key),
                )
            )
    return diffs


def inject_default_network_acls(deployed_properties: dict) -> dict:
    """Return a copy with default-open networkAcls when the live value is null.

    Only for vault/storage types, only on the deployed side (see
    _NETWORK_ACL_DEFAULT_TYPES). Does not mutate the input.
    """
    rtype = str(deployed_properties.get("type", "")).lower()
    if rtype not in NETWORK_ACL_DEFAULT_TYPES:
        return deployed_properties
    props = deployed_properties.get("properties")
    if not isinstance(props, dict) or props.get("networkAcls") is not None:
        return deployed_properties
    return {
        **deployed_properties,
        "properties": {
            **props,
            "networkAcls": dict(DEFAULT_OPEN_NETWORK_ACLS),
        },
    }


def compare_security_list(key: str, bicep_value: Any, deployed_value: Any):
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
        return access_policies_match(bicep_value, deployed_value)
    if ".networkacls." in kl and (
        kl.endswith(".iprules")
        or kl.endswith(".virtualnetworkrules")
        or kl.endswith(".resourceaccessrules")
    ):
        return allowlist_matches(bicep_value, deployed_value)
    # AI content filters: entries repeat names across sources (Hate/Prompt,
    # Hate/Completion), so the generic name-keyed matcher pairs them wrongly
    # - and a filter loosened out-of-band must be drift.
    if kl.endswith("properties.contentfilters"):
        return allowlist_matches(bicep_value, deployed_value)
    # Azure Firewall plain-string lists. Elements carry no 'name', so the
    # generic subset compare is vacuous when the bicep side is empty - an
    # out-of-band threat-intel whitelist entry (exempting an IP/FQDN from
    # TI) or an added custom DNS server (resolution hijack) would be
    # invisible. Exact-set semantics make live-added entries drift.
    if (kl.endswith(".threatintelwhitelist.ipaddresses")
            or kl.endswith(".threatintelwhitelist.fqdns")
            or kl.endswith(".dnssettings.servers")):
        return allowlist_matches(bicep_value, deployed_value)
    # Availability zones: a bare list of zone numbers, so the generic subset
    # compare is one-directional - ["1","2","3"] shrunk to ["1"] IS caught
    # (bicep elements go missing), but a live-side zone list that gained an
    # entry the template never asked for is invisible, and a template
    # declaring [] excuses anything. Zone membership is a placement fact
    # that must match exactly in both directions.
    if kl == "zones":
        return allowlist_matches(bicep_value, deployed_value)
    # AKS cluster-admin groups: a bare list of AAD group object IDs, and the
    # single highest-privilege grant on the cluster. Same vacuous-subset
    # trap as the firewall lists and worse - the common declaration is an
    # EMPTY adminGroupObjectIDs, and [] is a subset of every list, so adding
    # a group out-of-band (instant cluster-admin for its members) compared
    # clean. Exact set, both directions.
    if kl.endswith("aadprofile.admingroupobjectids"):
        return allowlist_matches(bicep_value, deployed_value)
    # Azure Monitor action-group receivers: each *Receivers array is keyed
    # by receiver name. The generic bicep-keyed loop MISSES a receiver
    # deleted entirely (its flattened key just vanishes from the deployed
    # side) and a live-ADDED one, so exact-set both directions - a removed
    # receiver is a broken notification path, an added one an out-of-band
    # alerting change. Covers emailReceivers/smsReceivers/webhookReceivers/
    # armRoleReceivers/... (all end in "receivers").
    if kl.startswith("properties.") and kl.endswith("receivers"):
        return allowlist_matches(bicep_value, deployed_value)
    return None


def allowlist_matches(bicep_list: list, deployed_list: list) -> bool:
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
        if _primitives.has_unresolved_expressions(b_id):
            unresolved_slots += 1
            continue
        hit = next((d for d in unmatched_deployed if identity(d) == b_id), None)
        if hit is None or not _primitives.value_matches(non_identity_fields(b), hit):
            return False  # a bicep-declared rule is gone or altered
        unmatched_deployed.remove(hit)
    # Every leftover deployed rule must be covered by an unresolved slot;
    # anything beyond that was added out-of-band.
    return len(unmatched_deployed) <= unresolved_slots


def access_policies_match(bicep_list: list, deployed_list: list) -> bool:
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
        if _primitives.has_unresolved_expressions(obj_id):
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
