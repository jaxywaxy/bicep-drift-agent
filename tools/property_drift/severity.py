"""
tools/property_drift/severity.py

Severity policy for property drift: the critical-property substring set,
monitoring/backup severity elevation (type-scoped), and the write-only /
never-projected property classifiers. Extracted from PropertyComparator so
the severity rules are testable in isolation; comparator.py keeps thin
staticmethod aliases (PropertyComparator._get_severity etc.) that delegate
here, preserving every existing call site.

The hand-maintained tables below are the primary source. `tools/schema/`
supplies type-scoped facts derived from the published Azure type definitions,
which ADD to them - see is_write_only_for_type for why they cannot replace them.
"""


from .models import PropertyDiff  # noqa: F401
from tools.schema import flags as _schema


CRITICAL_PROPERTIES = {
    # Location and kind are fundamental
    "location",
    "kind",
    # SKU properties (pricing tier, size, capacity)
    "sku.name",
    "sku.tier",
    "sku.family",
    "sku.size",
    "sku.capacity",
    # VM-specific
    "properties.hardwareProfile.vmSize",
    # Storage-specific
    "properties.accountType",
    "properties.replicationType",
    "properties.accessTier",
    # Database-specific
    "properties.edition",
    "properties.serviceLevelObjective",
    # App Service-specific
    "properties.reserved",
    "properties.workerSize",
    # Data-plane exposure (Key Vault / storage firewalls, vault access grants).
    # NOTE: _get_severity matches these against a LOWERCASED path, so they
    # must be lowercase here.
    "properties.networkacls",
    "properties.accesspolicies",
    "properties.enablerbacauthorization",
    "properties.publicnetworkaccess",
    # Recovery Services vault backup controls (backupconfig). Disabling soft
    # delete lets backups be deleted immediately; weakening enhanced security
    # removes MUA/critical-operation protection. Both are silent until you
    # need a restore. Substrings are unique to vaults/backupconfig.
    "properties.softdeletefeaturestate",
    "properties.softdeletestate",
    "properties.enhancedsecuritystate",
    # Private endpoint DNS zone group wiring. The zone group is what makes a
    # private endpoint resolvable by its own name; repoint privateDnsZoneId at
    # the wrong zone (or drop the config) and clients silently fall back to
    # public DNS - the Private Link bypass succeeds, so nothing errors and
    # nothing looks broken. Substring is unique to privateDnsZoneGroups.
    "properties.privatednszoneconfigs",
    # Credential / anonymous-access exposure (ACR admin account, anonymous
    # pull, storage public blobs, key-based auth left enabled).
    "properties.adminuserenabled",
    "properties.anonymouspullenabled",
    "properties.allowblobpublicaccess",
    # The blob CONTAINER's own switch (None/Blob/Container). allowBlobPublicAccess
    # only permits anonymous access; this is what actually turns it on, so a
    # container flipped to Blob is the same exposure class as the account flag
    # and must not fall through to the default "warning".
    "properties.publicaccess",
    "properties.allowsharedkeyaccess",
    "properties.disablelocalauth",
    # Transport security (TLS floor / https enforcement).
    "properties.supportshttpstrafficonly",
    "properties.minimumtlsversion",
    "properties.minimaltlsversion",
    "properties.httpsonly",
    # App Service / Function App transport, in BOTH declaration shapes:
    # inline on the site ("properties.siteConfig.ftpsState") and on the
    # config/web child ("properties.ftpsState"). Bare substrings cover both;
    # only Microsoft.Web/sites(+/config) carry them. ftpsState=AllAllowed
    # means FTP credentials in PLAINTEXT while the site still reports
    # httpsOnly=true; "mintlsversion" also picks up scmMinTlsVersion, the
    # Kudu/SCM endpoint's floor. (Declared TLS floors are generic-compared
    # as critical - they are never security SENTINELS, because the
    # absent-default is creation-API-version-dependent.)
    "ftpsstate",
    "mintlsversion",
    # Key Vault data-destruction protection.
    "properties.enablesoftdelete",
    # AI content filters - loosening one is a governance event
    "properties.contentfilters",
    # Network security: NSG rule tampering (an out-of-band allow-any
    # inbound rule) and route changes (next hop flipped off the firewall
    # appliance = inspection bypass) are the classic unauthorized changes.
    # properties.routes also covers Virtual Hub route tables
    # (virtualHubs/hubRouteTables), whose routes carry the same nextHop.
    "properties.securityrules",
    "properties.routes",
    # Virtual Hub routing intent: routingPolicies force Internet/Private
    # traffic to the Azure Firewall (or NVA) next hop. Repointing the nextHop
    # off the firewall, or narrowing destinations, silently drops spoke
    # traffic out of inspection while the hub still reads healthy - the vWAN
    # equivalent of a route-table bypass. Only virtualHubs/routingIntent
    # carries this path.
    "properties.routingpolicies",
    # Workload-identity federation trust boundary: repointing a federated
    # credential's subject or issuer lets a DIFFERENT external repo/branch/
    # IdP mint tokens as this managed identity - a persistence / supply-
    # chain escalation, not a config tweak. Only federatedIdentityCredentials
    # carry properties.subject / properties.issuer in the estate.
    "properties.subject",
    "properties.issuer",
    # Application Gateway / WAF security posture: WAF mode flip
    # (Prevention->Detection), disabling the WAF, or weakening the min TLS
    # version are all security-critical.
    "properties.policysettings.mode",
    "properties.policysettings.state",
    # WAF detection COVERAGE, not just its mode: the managed rule sets ARE
    # the WAF's attack detection (an OWASP version downgrade silently drops
    # rules), and requestBodyCheck=false stops payload inspection entirely
    # (SQLi/XSS in POST bodies sail through) while the WAF still reads as
    # Enabled/Prevention. Only WAF policies carry these paths.
    "properties.managedrules",
    "properties.policysettings.requestbodycheck",
    "properties.sslpolicy.minprotocolversion",
    "properties.webapplicationfirewallconfiguration.enabled",
    "properties.webapplicationfirewallconfiguration.firewallmode",
    # Azure Firewall (policy + classic). The rule collections ARE the
    # firewall: an out-of-band allow rule, an action flip, or a priority
    # reshuffle silently opens traffic paths - the NSG securityRules
    # equivalent. threatIntelMode Alert/Deny->Off disables threat
    # intelligence while the firewall still reads healthy; whitelisting an
    # IP/FQDN exempts it from TI; DNS settings changes (proxy off, custom
    # servers) redirect name resolution; intrusionDetection covers Premium
    # IDPS mode downgrades. Classic (non-policy) firewalls carry the three
    # inline *RuleCollections paths instead.
    "properties.rulecollections",
    "properties.threatintelmode",
    "properties.threatintelwhitelist",
    "properties.dnssettings",
    "properties.intrusiondetection",
    "properties.applicationrulecollections",
    "properties.networkrulecollections",
    "properties.natrulecollections",
    # Detaching/swapping the policy on the firewall resource re-bases its
    # entire rule set.
    "properties.firewallpolicy",
    # Container Apps ingress exposure: turning ingress public or allowing
    # insecure (http) traffic is a security posture change.
    "properties.configuration.ingress.external",
    "properties.configuration.ingress.allowinsecure",
    # Front Door route TLS posture: forwarding to origins over HttpOnly, or
    # dropping the HTTP->HTTPS redirect, is a downgrade.
    "properties.forwardingprotocol",
    "properties.httpsredirect",
    # Event Grid subscription destination: re-pointing a subscription sends the
    # event stream to a different sink (data exfiltration / interception).
    "properties.destination",
    # AKS security posture: disabling RBAC, opening the API server (private
    # cluster off / authorized IP ranges dropped), re-enabling local accounts,
    # or removing the network policy engine are all security-critical changes.
    "properties.enablerbac",
    "properties.apiserveraccessprofile",
    "properties.disablelocalaccounts",
    "properties.networkprofile.networkpolicy",
    # AKS identity + governance, the second tranche. These are DECLARED-path
    # entries only: severity applies when the template declares the property
    # and live differs, so there is no absent-default to guess and no FP
    # surface (contrast the SECURITY_SENTINELS table, where an absent-default
    # that turns out to be API-version-dependent manufactures drift - see the
    # TLS note there).
    #   aadProfile: enableAzureRBAC off drops Kubernetes authorization back to
    #   cluster-local RBAC, and adminGroupObjectIDs is a direct grant of
    #   cluster-admin - both are privilege changes, not config tweaks.
    "properties.aadprofile",
    #   The policy add-on is how Azure Policy reaches INTO the cluster;
    #   omsagent is the cluster's audit/telemetry path. Switching either off
    #   leaves the estate looking compliant and observed while it is neither.
    "properties.addonprofiles.azurepolicy",
    "properties.addonprofiles.omsagent",
    #   upgradeChannel 'none' does not break anything today - it silently
    #   stops the cluster receiving patches, which is exactly the drift that
    #   no dashboard shows until a CVE lands.
    "properties.autoupgradeprofile",
    #   Defender for Containers off = runtime threat detection gone.
    "properties.securityprofile.defender",
    #   OIDC issuer is the dependency for workload identity; turning it off
    #   breaks federated auth and pushes workloads back to secrets. Scoped to
    #   `.enabled` on purpose: the sibling `issuerUrl` is an Azure-GENERATED
    #   output, so a subtree entry made a read-only value critical (caught by
    #   test_eventgrid_filter_subject_not_falsely_critical, which already
    #   pinned it as warning).
    "properties.oidcissuerprofile.enabled",
    # Resiliency: the zone list a resource is pinned to, and the fault/update
    # domain counts of an availability set. Shrinking any of these is a
    # silent availability downgrade that nothing else surfaces - the resource
    # still reads healthy while it has stopped being redundant. `zones` is a
    # top-level ARM key (not under properties), hence the bare entry.
    "zones",
    "properties.platformfaultdomaincount",
    "properties.platformupdatedomaincount",
    "properties.zonebalance",
    # Self-healing: automatic instance repair off means unhealthy VMSS
    # instances are never replaced.
    "properties.automaticrepairspolicy",
    # Managed disk exposure and data-at-rest protection. networkAccessPolicy
    # /publicNetworkAccess opened lets a disk be exported over the internet
    # via SAS; the encryption block is the CMK-vs-platform-key choice and
    # encryptionSettingsCollection is host/ADE encryption.
    "properties.networkaccesspolicy",
    "properties.encryption.type",
    "properties.encryptionsettingscollection",
    # Host-level encryption + Trusted Launch (secure boot / vTPM) on VMs and
    # scale sets. Both declaration shapes: inline on a VM
    # ("properties.securityProfile") and under a scale set's
    # ("properties.virtualMachineProfile.securityProfile").
    "securityprofile.encryptionathost",
    "securityprofile.uefisettings",
    "securityprofile.securitytype",
    # VMSS patching: upgradePolicy Manual means published model changes
    # (including security patches) never reach running instances.
    "properties.upgradepolicy.mode",
    # A scale set instance given its own public IP is directly internet-
    # reachable, bypassing the load balancer and its NSG posture.
    "publicipaddressconfiguration",
}

WRITE_ONLY_PROPERTIES = {
    # SQL server admin password (never returned; comparing it would also
    # LEAK the desired value into the drift report)
    "properties.administratorloginpassword",
    # VM OS profile (not returned by Azure API for security/privacy)
    "properties.osprofile.adminusername",
    "properties.osprofile.adminpassword",
    "properties.osprofile.computername",
    "properties.osprofile.linuxconfiguration.disablepasswordauthentication",
    "properties.osprofile.linuxconfiguration.ssh",
    "properties.osprofile.windowsconfiguration.enableautomaticupdates",
    "properties.osprofile.windowsconfiguration.provisionvmagent",
    # Storage profile (image reference is immutable post-deployment)
    "properties.storageprofile.imagereference.publisher",
    "properties.storageprofile.imagereference.offer",
    "properties.storageprofile.imagereference.sku",
    "properties.storageprofile.imagereference.version",
    # OS disk properties (immutable post-deployment)
    "properties.storageprofile.osdisk.createoption",
    "properties.storageprofile.osdisk.manageddisk.storageaccounttype",
    # Network interfaces (Bicep uses expressions, Azure returns resolved IDs - functionally equivalent)
    "properties.networkprofile.networkinterfaces",
    # App Service Plan properties (not returned by API)
    "properties.reserved",
    # Provisioning-mode inputs (PostgreSQL/MySQL flexible servers, Cosmos
    # restores, etc.) — consumed at create time, never returned by the API,
    # so they always diff as desired-vs-null.
    "properties.createmode",
}

# Properties Resource Graph does not project for a SPECIFIC type, so they always
# diff as desired-vs-null. Type-scoped (unlike WRITE_ONLY_PROPERTIES) because the
# path is too generic to suppress globally: e.g. a Virtual WAN's
# `properties.type` (Standard/Basic) is absent from the Resource Graph
# projection, but a bare "properties.type" would wrongly swallow it on any other
# resource type. Keyed by lowercased resource type.
NEVER_PROJECTED_BY_TYPE = {
    "microsoft.network/virtualwans": ("properties.type",),
}

MONITORING_TYPES = frozenset({
    "microsoft.insights/metricalerts",
    "microsoft.insights/activitylogalerts",
    "microsoft.insights/scheduledqueryrules",
    "microsoft.insights/actiongroups",
    "microsoft.insights/components",
})

# Alert/action-group resources are "silent failure" types: a disabled alert or a
# severed notification path looks fine until an incident. These paths are
# critical ONLY for these types, so they cannot go in the global substring
# CRITICAL_PROPERTIES - e.g. "properties.enabled" would also match Key Vault's
# "properties.enabledForDeployment".
MONITORING_CRITICAL_SUBSTRINGS = (
    "properties.enabled",           # alert / action group switched off
    "receivers",                    # a notification path removed or changed
    "properties.criteria",          # metric/query threshold loosened
    "properties.condition",         # activity-log condition narrowed
    "properties.retentionindays",   # data retention shortened
    "publicnetworkaccessfor",       # App Insights ingestion/query opened
    "properties.disableipmasking",  # client IPs un-masked
    "properties.scopes",            # alert de-scoped (stops watching a target)
    "properties.actions",           # notification link severed/re-pointed
)

def get_severity(property_path: str) -> str:
    """Determine severity of property change."""
    for critical in CRITICAL_PROPERTIES:
        if critical in property_path.lower():
            return "critical"
    return "warning"


def elevate_monitoring_severity(
    resource_type: str, diffs: list["PropertyDiff"]
) -> list["PropertyDiff"]:
    """Raise severity to critical for silent-failure paths on monitoring
    types. Type-scoped so the substrings cannot over-match other resources."""
    if resource_type not in MONITORING_TYPES:
        return diffs
    for d in diffs:
        path = d.property_path.lower()
        if any(s in path for s in MONITORING_CRITICAL_SUBSTRINGS):
            d.severity = "critical"
    return diffs


def elevate_backup_severity(
    resource_type: str, diffs: list["PropertyDiff"]
) -> list["PropertyDiff"]:
    """Raise severity to critical for backup-policy retention/schedule paths.
    Shortening retention or loosening the schedule silently shrinks how far
    back you can restore. Type-scoped to vaults/backupPolicies so 'retention'
    does not collide with diagnostic-settings retentionPolicy on other types."""
    if resource_type != "microsoft.recoveryservices/vaults/backuppolicies":
        return diffs
    for d in diffs:
        path = d.property_path.lower()
        if "retention" in path or "schedule" in path:
            d.severity = "critical"
    return diffs


def elevate_workspace_table_severity(
    resource_type: str, diffs: list["PropertyDiff"]
) -> list["PropertyDiff"]:
    """Raise severity to critical for workspace-table retention and plan.

    Shortening retention silently shrinks how far back you can query, and
    switching plan Analytics -> Basic drops most query capability on the table;
    both are discovered during an incident, which is the worst time. Same class
    as backup retention, and type-scoped for the same reason: 'retentionindays'
    also appears on the WORKSPACE itself, on ACR retention policies and on
    diagnostic settings, where the default warning is right.
    """
    if resource_type != "microsoft.operationalinsights/workspaces/tables":
        return diffs
    for d in diffs:
        path = d.property_path.lower()
        if "retention" in path or path.endswith("plan"):
            d.severity = "critical"
    return diffs


def is_write_only_property(property_path: str) -> bool:
    """Check if property is write-only (not returned by Azure API).

    Write-only properties include:
    - Credentials (admin passwords, SSH keys)
    - OS profile settings (Azure returns null)
    - Immutable properties (image reference, disk creation options)
    """
    path_lower = property_path.lower()
    for write_only in WRITE_ONLY_PROPERTIES:
        if write_only == path_lower or path_lower.startswith(write_only + "."):
            return True
    return False


def is_unprojected_property(rtype: str, property_path: str) -> bool:
    """True if Resource Graph never projects this property for this type, so
    a desired value always diffs against null (see NEVER_PROJECTED_BY_TYPE)."""
    props = NEVER_PROJECTED_BY_TYPE.get((rtype or "").lower())
    if not props:
        return False
    p = property_path.lower()
    return any(p == wp or p.startswith(wp + ".") for wp in props)


def is_write_only_for_type(rtype: str, api_version: str | None, property_path: str) -> bool:
    """Write-only per the hand list OR per the type's own published schema.

    The two sources answer different questions and neither subsumes the other.
    WRITE_ONLY_PROPERTIES is EMPIRICAL - paths Azure was observed not to return,
    curated to be safe as global substrings. The schema flag is CONTRACTUAL - an
    RP author annotated the REST spec. Measured across the 73 types this repo
    has opinions about, the flag reproduces only 2 of the 17 hand-listed paths
    (Microsoft.Compute annotates none of the osProfile family at any API version
    tried, 2021-07-01 through 2024-11-01), so the schema is added to the hand
    list, never substituted for it.

    The schema half is type-scoped because it was never curated for global use:
    Microsoft.Resources/deployments marks `identity` write-only, and suppressing
    `identity` estate-wide would blind managed-identity drift on every resource.
    """
    if is_write_only_property(property_path):
        return True
    return _schema.is_write_only(rtype, api_version, property_path)


def is_absent_from_api_version(rtype: str, api_version: str | None, property_path: str) -> bool:
    """True only when the type's schema for THIS apiVersion positively does not
    declare the property.

    A template can declare a property its target API version does not have -
    `az bicep build` warns (BCP037) but still compiles, and ARM drops it at
    deploy time. The property is then absent from every live payload forever,
    which the removed-property branch would otherwise report as drift on every
    single scan, with no action that could ever clear it.

    Deliberately conservative: `property_declared` returns None for an
    uncovered type@apiVersion and for anything under a free-form map, an
    untyped `any`, an array element, or a truncated branch. Only an explicit
    False suppresses, so partial coverage costs nothing but the check itself.
    """
    return _schema.property_declared(rtype, api_version, property_path) is False
