"""
Property-level drift detection.

Compares resource properties between Bicep (desired) and deployed (actual)
to detect configuration changes outside of IaC.
"""

import logging
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


class MatchConfidenceScores:
    """
    Confidence scores for resource matching strategies.

    These thresholds determine how confident we are that a Bicep resource
    matches a deployed resource. Used to handle ambiguous cases where multiple
    deployed resources could match a single Bicep resource.

    Scores range from 0.0 (no match) to 1.0 (perfect match).
    """

    # Exact name match (case-insensitive or substring)
    # Most reliable: resource names match exactly
    EXACT_MATCH = 0.95

    # Contextual matching via parent resource
    # High confidence when we can use related resources to disambiguate
    # Example: matched disk to VM parent, then found deployed disk for that VM
    CONTEXTUAL_MATCH_DISK = 0.95
    CONTEXTUAL_MATCH_NIC = 0.90

    # Prefix match for parameter-based names
    # Example: 'st[uniqueString(...)]' matched to 'st12345abc' by prefix 'st'
    PREFIX_MATCH = 0.85

    # Fuzzy token-based matching
    # Matches by splitting names into tokens and checking overlap
    # Example: 'vm-prod-001' vs 'myvm-prod-001-nic' = high token overlap
    FUZZY_MATCH_THRESHOLD = 0.60

    # Positional matching for truly identical-named resources
    # Last resort: match by position when all else fails
    # Example: 4x resources all named [parameters('vmName')]-nic
    POSITIONAL_MATCH = 0.60

    # Single candidate fallback
    # When only one deployed resource exists for a resource type
    SINGLE_CANDIDATE = 0.70

    # No match / unresolved
    # Placeholder for resources that couldn't be matched
    NO_MATCH = 0.25


class ResourceIndexer:
    """Helper for indexing and grouping resources by type and properties."""

    @staticmethod
    def by_name(resources: List[Dict], resource_type: str) -> Dict[str, Dict]:
        """Index resources by name for a specific type."""
        return {
            r.get("name", ""): r
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def by_id(resources: List[Dict], resource_type: str) -> Dict[str, str]:
        """Index resource names by ID for a specific type."""
        return {
            r.get("id", ""): r.get("name", "")
            for r in resources
            if r.get("type") == resource_type
        }

    @staticmethod
    def filter_by_type(resources: List[Dict], resource_type: str) -> List[Dict]:
        """Filter resources by type."""
        return [r for r in resources if r.get("type") == resource_type]

    @staticmethod
    def group_by_type(resources: List[Dict]) -> Dict[str, List[Dict]]:
        """Group all resources by type."""
        grouped = defaultdict(list)
        for r in resources:
            grouped[r.get("type", "unknown")].append(r)
        return dict(grouped)


@dataclass
class PropertyDiff:
    """A single property difference."""
    property_path: str  # e.g., "properties.sku.name"
    desired_value: Any  # From Bicep
    actual_value: Any   # From Azure
    change_type: str    # "modified", "added", "removed"
    severity: str       # "critical", "warning", "info"


@dataclass
class ResourceDrift:
    """Drift information for a single resource."""
    resource_type: str
    resource_name: str
    bicep_name: str      # Name from Bicep template
    deployed_name: str   # Name of deployed resource
    drift_type: str      # "missing", "extra", "modified", "unchanged"
    property_diffs: List[PropertyDiff]
    match_confidence: float  # 0.0 to 1.0


class PropertyExtractor:
    """Extract properties from resources."""

    @staticmethod
    def extract_bicep_properties(resource: Dict) -> Dict[str, Any]:
        """Extract properties from a Bicep-compiled ARM resource."""
        properties = {}

        # Top-level properties (skip apiVersion — it's ARM template metadata, not a deployment property)
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]

        # Resource-specific properties
        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties

    @staticmethod
    def extract_azure_properties(resource: Dict) -> Dict[str, Any]:
        """Extract properties from an Azure-deployed resource."""
        properties = {}

        # Top-level properties
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "id" in resource:
            properties["id"] = resource["id"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]

        # Resource-specific properties
        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties


class ResourceMatcher:
    """Match Bicep resources to deployed resources using intelligent contextual matching."""

    @staticmethod
    def _normalize_resource_type(resource_type: str) -> str:
        """Normalize resource type to lowercase for consistent comparison.

        Azure SDK may return different casing for the same resource type.
        Example: Microsoft.Web/serverfarms vs Microsoft.Web/serverFarms
        """
        return resource_type.lower() if resource_type else ""

    @staticmethod
    def _find_associated_resource(resource: Dict, bicep_resources: List[Dict], resource_type: str) -> Dict:
        """Find a related resource (e.g., find VM for a NIC by name similarity)."""
        res_name = resource.get("name", "")
        # Extract name tokens from resource (e.g., 'vm-dev-001-nic' → 'vm-dev-001')
        name_tokens = res_name.replace('-nic', '').replace('-nic-', '-')

        # Look for resources of target type with similar names
        for r in bicep_resources:
            if r.get("type") == resource_type:
                r_name = r.get("name", "")
                if name_tokens in r_name or r_name in name_tokens:
                    return r
        return None

    @staticmethod
    def _find_parent_vm(disk_name: str, bicep_resources: List[Dict]) -> Dict:
        """Find parent VM for a managed disk by extracting VM name from disk name.

        Example: vm-prod-002_OsDisk_1_<hash> → extract 'vm-prod-002'
        """
        # Extract VM name from disk (before first underscore)
        vm_name = disk_name.split('_')[0] if '_' in disk_name else None
        if not vm_name:
            return None

        # Find matching VM
        for r in bicep_resources:
            if r.get("type") == "Microsoft.Compute/virtualMachines":
                if r.get("name", "").lower() == vm_name.lower():
                    return r
        return None

    @staticmethod
    def _match_disks_by_parent_vm(
        bicep_resource: Dict, bicep_resources: List[Dict], candidates: List[Dict], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match a disk to its parent VM's disk.

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        disk_name = bicep_resource.get("name", "")
        parent_vm = ResourceMatcher._find_parent_vm(disk_name, bicep_resources)
        if not parent_vm:
            return None

        for candidate in candidates:
            cand_name = candidate.get("name", "")
            vm_name_from_disk = cand_name.split('_')[0] if '_' in cand_name else None
            if vm_name_from_disk and vm_name_from_disk.lower() == parent_vm.get("name", "").lower():
                return candidate, 0.95  # High confidence: matched via parent VM

        return None

    @staticmethod
    def _match_nics_by_associated_vm(
        bicep_resource: Dict, bicep_resources: List[Dict], candidates: List[Dict],
        matches: List[Tuple[Dict, Dict, float]], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match a NIC to its associated VM's NIC.

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        associated_vm = ResourceMatcher._find_associated_resource(
            bicep_resource, bicep_resources, "Microsoft.Compute/virtualMachines"
        )
        if not associated_vm:
            return None

        # Find the deployed VM this bicep VM matches to
        for matched_bicep, matched_deployed, _ in matches:
            if matched_bicep.get("name") == associated_vm.get("name"):
                vm_name = matched_deployed.get("name", "")
                for candidate in candidates:
                    cand_name = candidate.get("name", "")
                    if vm_name in cand_name:
                        return candidate, 0.90

        return None

    @staticmethod
    def _match_by_fuzzy_tokens(
        bicep_name: str, candidates: List[Dict], current_best_score: float
    ) -> Tuple[Dict, float]:
        """Match using fuzzy token-based matching (for parameter-based names).

        Returns:
            Tuple of (matched_resource, confidence_score) or None if no match found
        """
        best_match = None
        best_score = current_best_score

        for candidate in candidates:
            deployed_name = candidate.get("name", "")

            # Child resources ('parent/child'): siblings share every parent
            # segment, so full-name token overlap ('aks-drift-test/userpool' vs
            # 'aks-drift-test/system' = 2/3) clears the threshold on the parent
            # alone - pairing a DELETED child's bicep definition with a surviving
            # sibling (hiding the deletion AND fabricating name/mode property
            # drift). Require the parents to correspond and score the LEAF only.
            if "/" in bicep_name and "/" in deployed_name:
                b_parent, _, b_leaf = bicep_name.rpartition("/")
                d_parent, _, d_leaf = deployed_name.rpartition("/")
                if b_parent.lower() != d_parent.lower() and "[" not in b_parent:
                    continue
                bicep_cmp, deployed_cmp = b_leaf, d_leaf
            else:
                bicep_cmp, deployed_cmp = bicep_name, deployed_name

            bicep_clean = bicep_cmp.replace('[', '').replace(']', '').replace("'", '').replace('parameters(', '').replace(')', '')

            bicep_tokens = [t for t in bicep_clean.split('-') if len(t) > 1 and t not in ('vmName', 'vaultName', 'name')]
            deployed_tokens = [t for t in deployed_cmp.split('-') if len(t) > 1]

            if bicep_tokens and deployed_tokens:
                # Optimize fuzzy matching: use set intersection for O(n+m) instead of O(n*m)
                bicep_set = set(bicep_tokens)
                deployed_set = set(deployed_tokens)
                # Exact token matches (e.g., 'prod' in both 'vm-prod-001')
                exact_matches = len(bicep_set & deployed_set)
                # Prefix/substring matches for tokens not found exactly
                prefix_matches = sum(
                    1 for bt in bicep_tokens
                    if bt not in deployed_set and any(dt.startswith(bt) or bt in dt for dt in deployed_tokens)
                )
                matches_count = exact_matches + prefix_matches
                score = matches_count / max(len(bicep_tokens), len(deployed_tokens))
                if score > best_score:
                    best_score = score
                    best_match = candidate

        return (best_match, best_score) if best_match else None

    @staticmethod
    def match_resources(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[Tuple[Dict, Dict, float]]:
        """
        Match Bicep resources to deployed resources using intelligent contextual matching.

        Strategy:
        1. Exact name matches (highest confidence)
        2. Contextual matching: for identical-named resources, use related resources
           to disambiguate (e.g., match NICs via their VMs)
        3. Fuzzy token-based matching (parameter-based names)
        4. Positional matching as fallback for true duplicates

        Returns:
            List of (bicep_resource, deployed_resource, confidence) tuples
        """
        matches = []
        deployed_by_type = defaultdict(list)

        # Index deployed resources by normalized type (lowercase)
        for resource in deployed_resources:
            resource_type = ResourceMatcher._normalize_resource_type(resource.get("type", ""))
            deployed_by_type[resource_type].append(resource)

        # Track used deployed resources
        used_deployed = set()

        # First pass: exact matches
        for bicep_resource in bicep_resources:
            resource_type = ResourceMatcher._normalize_resource_type(bicep_resource.get("type", ""))
            bicep_name = bicep_resource.get("name", "")

            candidates = [r for r in deployed_by_type.get(resource_type, []) if id(r) not in used_deployed]
            if not candidates:
                continue

            exact_match = None
            for deployed in candidates:
                deployed_name = deployed.get("name", "")
                if bicep_name == deployed_name or bicep_name in deployed_name:
                    exact_match = deployed
                    break

            if exact_match:
                matches.append((bicep_resource, exact_match, MatchConfidenceScores.EXACT_MATCH))
                used_deployed.add(id(exact_match))
            else:
                # Try fuzzy matching for unresolvable names like sttestdrift[uniqueString(...)]
                if "[" in bicep_name and "]" in bicep_name:
                    # Extract prefix before the bracket
                    prefix = bicep_name.split("[")[0]
                    if prefix:  # Only if there's a meaningful prefix
                        prefix_matches = [d for d in candidates if d.get("name", "").startswith(prefix)]
                        if len(prefix_matches) == 1:
                            # Exactly one match found via prefix
                            matches.append((bicep_resource, prefix_matches[0], MatchConfidenceScores.PREFIX_MATCH))
                            used_deployed.add(id(prefix_matches[0]))

        # Second pass: contextual + fuzzy matching for remaining resources
        bicep_by_type = defaultdict(list)
        for bicep_resource in bicep_resources:
            if id(bicep_resource) not in {id(b) for b, _, _ in matches}:
                resource_type = ResourceMatcher._normalize_resource_type(bicep_resource.get("type", ""))
                bicep_by_type[resource_type].append(bicep_resource)

        for resource_type, bicep_res_list in bicep_by_type.items():
            candidates = [r for r in deployed_by_type.get(resource_type, []) if id(r) not in used_deployed]
            if not candidates:
                continue

            # Check if all bicep resources have identical names (e.g., 4x "parameters('vmName')-nic")
            bicep_names = [r.get("name", "") for r in bicep_res_list]
            all_identical = len(set(bicep_names)) == 1

            for bicep_idx, bicep_resource in enumerate(bicep_res_list):
                bicep_name = bicep_resource.get("name", "")
                best_match = None
                best_score = MatchConfidenceScores.NO_MATCH

                # Try contextual matching strategies
                if resource_type == "Microsoft.Compute/disks":
                    result = ResourceMatcher._match_disks_by_parent_vm(
                        bicep_resource, bicep_resources, candidates, best_score
                    )
                    if result:
                        best_match, best_score = result

                elif all_identical and resource_type == "Microsoft.Network/networkInterfaces":
                    result = ResourceMatcher._match_nics_by_associated_vm(
                        bicep_resource, bicep_resources, candidates, matches, best_score
                    )
                    if result:
                        best_match, best_score = result

                # Try fuzzy matching if contextual matching failed
                if not best_match:
                    result = ResourceMatcher._match_by_fuzzy_tokens(
                        bicep_name, candidates, best_score
                    )
                    if result:
                        best_match, best_score = result

                # Fallback: positional matching for TRUE duplicates only (multiple
                # identical-named Bicep resources, e.g. 4x "parameters('vmName')-nic").
                # Requires len > 1 - a single resource must not be positionally paired
                # with a lone unrelated candidate (that's the guarded single-candidate
                # case below, which checks name plausibility).
                if (not best_match and all_identical and len(bicep_res_list) > 1
                        and len(candidates) >= len(bicep_res_list)):
                    best_match = candidates[bicep_idx]
                    best_score = MatchConfidenceScores.POSITIONAL_MATCH

                # Single candidate fallback - only when the names plausibly correspond.
                # Guard against pairing a deleted resource's Bicep definition with an
                # unrelated, differently-named new resource of the same type (which would
                # hide BOTH a missing_in_azure and an extra_in_azure). If the Bicep name
                # has a meaningful static prefix (the literal part before a uniqueString
                # placeholder, e.g. 'acrtestdrift' in 'acrtestdrift[86c9cbf6]'), require
                # the lone candidate to share it.
                if not best_match and len(candidates) == 1:
                    cand_name = candidates[0].get("name", "").lower()
                    static_prefix = bicep_name.split("[")[0].lower().strip()
                    plausible = len(static_prefix) < 3 or cand_name.startswith(static_prefix) or static_prefix in cand_name
                    if plausible:
                        best_match = candidates[0]
                        best_score = MatchConfidenceScores.SINGLE_CANDIDATE
                    else:
                        logger.debug(
                            f"Single-candidate fallback skipped: '{bicep_name}' prefix "
                            f"'{static_prefix}' does not match lone candidate '{cand_name}' "
                            f"- treating as missing + extra"
                        )

                if best_match:
                    matches.append((bicep_resource, best_match, best_score))
                    used_deployed.add(id(best_match))

        return matches


class PropertyComparator:
    """Compare properties between desired and actual resources."""

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
        # Credential / anonymous-access exposure (ACR admin account, anonymous
        # pull, storage public blobs, key-based auth left enabled).
        "properties.adminuserenabled",
        "properties.anonymouspullenabled",
        "properties.allowblobpublicaccess",
        "properties.allowsharedkeyaccess",
        "properties.disablelocalauth",
        # Transport security (TLS floor / https enforcement).
        "properties.supportshttpstrafficonly",
        "properties.minimumtlsversion",
        "properties.minimaltlsversion",
        "properties.httpsonly",
        # Key Vault data-destruction protection.
        "properties.enablesoftdelete",
        # AI content filters - loosening one is a governance event
        "properties.contentfilters",
        # Network security: NSG rule tampering (an out-of-band allow-any
        # inbound rule) and route changes (next hop flipped off the firewall
        # appliance = inspection bypass) are the classic unauthorized changes.
        "properties.securityrules",
        "properties.routes",
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
        "properties.sslpolicy.minprotocolversion",
        "properties.webapplicationfirewallconfiguration.enabled",
        "properties.webapplicationfirewallconfiguration.firewallmode",
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
    }

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
            # Absent = API server reachable from all networks, no IP allowlist.
            "properties.apiserveraccessprofile.authorizedipranges": [],
            "properties.apiserveraccessprofile.enableprivatecluster": False,
            # Absent = local (non-AAD) accounts remain enabled.
            "properties.disablelocalaccounts": False,
            # Absent = Kubernetes RBAC enabled (the safe default; a live False
            # means someone built/mutated the cluster with RBAC off).
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
            # Platform default for new accounts is false (public blob access
            # disallowed) - a live true is anonymous-read exposure.
            "properties.allowblobpublicaccess": False,
            "properties.allowsharedkeyaccess": True,
            # Stable default (true) since API 2019-04-01.
            "properties.supportshttpstrafficonly": True,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.keyvault/vaults": {
            # Soft delete is mandatory on current vaults; a live false is a
            # data-destruction exposure. Purge protection is one-way: a live
            # true was enabled out-of-band (irreversible governance change).
            "properties.enablesoftdelete": True,
            "properties.enablepurgeprotection": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.web/sites": {
            # Azure's default is https NOT enforced - drift in either
            # direction (hardened or reverted) is an out-of-band change.
            "properties.httpsonly": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.containerregistry/registries": {
            # The classic: portal-enabled admin account (shared credential).
            "properties.adminuserenabled": False,
            "properties.anonymouspullenabled": False,
            "properties.publicnetworkaccess": "Enabled",
        },
        "microsoft.cognitiveservices/accounts": {
            "properties.publicnetworkaccess": "Enabled",
            # Absent = API-key (local) auth allowed.
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
    }

    @staticmethod
    def compare_properties(
        bicep_properties: Dict[str, Any],
        deployed_properties: Dict[str, Any],
    ) -> List[PropertyDiff]:
        """
        Compare properties between Bicep and deployed resources.

        Returns:
            List of PropertyDiff objects
        """
        diffs = []

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

        # Flatten both property dicts for comparison
        bicep_flat = PropertyComparator._flatten_dict(bicep_properties)
        deployed_flat = PropertyComparator._flatten_dict(deployed_properties)

        # Skip detailed comparison if property enrichment failed
        # (deployed_properties have no nested "properties.*" or "sku.*" keys - likely API returned empty)
        has_detailed_deployed_properties = any(
            k.startswith("properties.") or k.startswith("sku.") for k in deployed_flat.keys()
        )
        if not has_detailed_deployed_properties:
            # Property enrichment didn't work for this resource - return empty diffs
            # to avoid false positives from incomplete data (empty properties object)
            return diffs

        # Check for modified properties
        for key, bicep_value in bicep_flat.items():
            if key in deployed_flat:
                # Skip write-only properties (Azure doesn't return these in API responses)
                if PropertyComparator._is_write_only_property(key):
                    continue

                # Skip name property comparisons when the name contains unresolved expressions
                # (e.g., sttestdrift[uniqueString(...)]) - these are matched by prefix
                if key == "name" and isinstance(bicep_value, str):
                    if "[" in bicep_value and "]" in bicep_value:
                        continue

                # Skip unresolved template expressions (resolve at deploy time)
                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                deployed_value = deployed_flat[key]

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

                # Skip properties where Azure returns None (not exposed by API)
                # This prevents false positives when Bicep has explicit values but
                # the property isn't available in the Azure API response
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
                # Skip write-only properties (Azure doesn't return these in API responses)
                if PropertyComparator._is_write_only_property(key):
                    continue

                # Skip unresolved template expressions (resolve at deploy time)
                if PropertyComparator._has_unresolved_expressions(bicep_value):
                    continue

                # Skip if deployed properties are incomplete (likely property enrichment issue)
                # If deployed_flat is empty or minimal, property querying may have failed
                if len(deployed_flat) < 3:
                    continue

                # Skip if Bicep value is essentially empty (optional property not set)
                # null, empty string, empty dict, empty list — these are optional and not returning
                # from Azure API is normal behavior, not drift
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

        return diffs

    @staticmethod
    def _check_security_sentinels(
        bicep_properties: Dict, bicep_flat: Dict, deployed_flat: Dict
    ) -> List[PropertyDiff]:
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
    def _inject_default_network_acls(deployed_properties: Dict) -> Dict:
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
                return (s[:-3] if s.endswith("/32") else s), ("value", "id")
            # AI contentFilters: names repeat across sources (Hate/Prompt vs
            # Hate/Completion) - identity is the (name, source) pair.
            if "name" in el and "source" in el:
                return (
                    f"{str(el.get('name', '')).lower()}|{str(el.get('source', '')).lower()}",
                    ("name", "source"),
                )
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
        def perm_sets(policy: Dict) -> Dict[str, frozenset]:
            perms = policy.get("permissions") or {}
            if not isinstance(perms, dict):
                perms = {}
            return {
                cat: frozenset(str(p).lower() for p in (perms.get(cat) or []))
                for cat in ("keys", "secrets", "certificates", "storage")
            }

        def identity(policy: Dict) -> tuple:
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

    @staticmethod
    def _flatten_dict(d: Dict, parent_key: str = "", sep: str = ".") -> Dict:
        """Flatten nested dictionary.

        Arrays are serialized as JSON for semantic comparison (not string comparison).
        This prevents false positives from whitespace differences or element reordering.
        Example: [1,2,3] vs [1, 2, 3] will compare equal.
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(PropertyComparator._flatten_dict(v, new_key, sep=sep).items())
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

    # Placeholder the normalizer emits for an unresolvable uniqueString() inside
    # a value, e.g. 'aidrift[86c9cbf6]'. The resource NAME gets smart-match
    # remapped, but the same placeholder inside a PROPERTY value (a
    # customSubDomainName set to the resource name) reaches the comparator
    # as-is and must not be compared literally against the resolved live value.
    @staticmethod
    def _placeholder_value_matches(bicep_val: str, deployed_val: str) -> bool:
        """True when a placeholder-bearing bicep string is consistent with the
        deployed value: the fixed parts around each [hex] placeholder must
        appear in order, with the placeholders spanning arbitrary generated
        characters. 'aidrift[86c9cbf6]' matches 'aidrift3s7c7weddxr3s'."""
        import re as _re
        parts = _re.split(r"\[[0-9a-fA-F]{6,}\]", bicep_val)
        if len(parts) < 2:
            return False  # no placeholder present
        pattern = "".join(_re.escape(p) + ("[a-z0-9]*" if i < len(parts) - 1 else "")
                          for i, p in enumerate(parts))
        return _re.fullmatch(pattern, deployed_val, _re.IGNORECASE) is not None

    @staticmethod
    def _scalar_equal(bicep_val: Any, deployed_val: Any) -> bool:
        """Compare two scalars, treating Azure resource IDs case-insensitively.

        Azure returns resource IDs with inconsistent casing (e.g. '/resourceGroups/'
        vs '/resourcegroups/'), which is not real drift.
        """
        if isinstance(bicep_val, str) and isinstance(deployed_val, str):
            if "/subscriptions/" in bicep_val.lower() and "/subscriptions/" in deployed_val.lower():
                return bicep_val.lower() == deployed_val.lower()
            if "[" in bicep_val and PropertyComparator._placeholder_value_matches(bicep_val, deployed_val):
                return True
        return bicep_val == deployed_val

    @staticmethod
    def _value_matches(bicep_val: Any, deployed_val: Any) -> bool:
        """Deep SUBSET match: every field the bicep specifies must be present and
        equal in the deployed value. Deployed-only fields (Azure read-only
        augmentation like provisioningState) are ignored.
        """
        # An unresolved bicep expression (resourceId(), uniqueString(), etc.,
        # often a NESTED id like publicIpAddresses[].id) resolves at deploy time
        # and can't be compared - treat as a match rather than false drift.
        if PropertyComparator._has_unresolved_expressions(bicep_val):
            return True
        if isinstance(bicep_val, dict) and isinstance(deployed_val, dict):
            for k, v in bicep_val.items():
                # Case-insensitive key lookup (Azure may vary key casing).
                match_key = k if k in deployed_val else next(
                    (dk for dk in deployed_val if dk.lower() == k.lower()), None
                )
                if match_key is None:
                    # An empty/None bicep sub-value that Azure omits is not drift.
                    if v in (None, "", {}, []):
                        continue
                    return False
                if not PropertyComparator._value_matches(v, deployed_val[match_key]):
                    return False
            return True
        if isinstance(bicep_val, list) and isinstance(deployed_val, list):
            return PropertyComparator._list_is_subset(bicep_val, deployed_val)
        return PropertyComparator._scalar_equal(bicep_val, deployed_val)

    @staticmethod
    def _list_is_subset(bicep_list: list, deployed_list: list) -> bool:
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
                if cand is None or not PropertyComparator._value_matches(b, cand):
                    return False
            else:
                if not any(PropertyComparator._value_matches(b, d) for d in deployed_list):
                    return False

        # Named collection: flag manually-ADDED elements (deployed name not in bicep).
        if bicep_named:
            bicep_names = {str(b.get("name", "")).lower() for b in bicep_named}
            for d in deployed_list:
                if isinstance(d, dict) and "name" in d:
                    if str(d.get("name", "")).lower() not in bicep_names:
                        return False
        return True

    @staticmethod
    def _has_unresolved_expressions(value: Any) -> bool:
        """Check if value contains unresolved Bicep/ARM template expressions.

        Examples: uniqueString(), subscription(), resourceId(), format(), etc.
        These resolve at deployment time and shouldn't be reported as drift.
        """
        if not isinstance(value, str):
            return False

        value_lower = value.lower()
        # Common template functions that resolve at deploy time
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

    @staticmethod
    def _get_severity(property_path: str) -> str:
        """Determine severity of property change."""
        for critical in PropertyComparator.CRITICAL_PROPERTIES:
            if critical in property_path.lower():
                return "critical"
        return "warning"

    @staticmethod
    def _is_write_only_property(property_path: str) -> bool:
        """Check if property is write-only (not returned by Azure API).

        Write-only properties include:
        - Credentials (admin passwords, SSH keys)
        - OS profile settings (Azure returns null)
        - Immutable properties (image reference, disk creation options)
        """
        path_lower = property_path.lower()
        for write_only in PropertyComparator.WRITE_ONLY_PROPERTIES:
            if write_only == path_lower or path_lower.startswith(write_only + "."):
                return True
        return False


class ConfigurationValidator:
    """Validate resource configurations for critical issues."""

    @staticmethod
    def check_orphaned_disks(deployed_resources: List[Dict]) -> List[ResourceDrift]:
        """
        Detect orphaned disks (OS and data disks not attached to any VM).

        This is a critical issue because:
        - Orphaned disks consume storage costs
        - They indicate VMs were deleted without proper cleanup
        - They prevent resource group deletion
        """
        drifts = []

        # Get all VMs and disks
        vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")
        disks = ResourceIndexer.filter_by_type(deployed_resources, "Microsoft.Compute/disks")

        for disk in disks:
            disk_name = disk.get("name", "")
            disk_id = disk.get("id", "")

            # Check if disk is attached to any VM
            is_attached = False
            for vm_name, vm in vms.items():
                # Check OS disk
                vm_props = vm.get("properties", {})
                if vm_props.get("storageProfile", {}).get("osDisk", {}).get("managedDisk", {}).get("id") == disk_id:
                    is_attached = True
                    break

                # Check data disks
                for data_disk in vm_props.get("storageProfile", {}).get("dataDisks", []):
                    if data_disk.get("managedDisk", {}).get("id") == disk_id:
                        is_attached = True
                        break

                if is_attached:
                    break

            # If disk is not attached, it is orphaned
            if not is_attached:
                drifts.append(
                    ResourceDrift(
                        resource_type="Microsoft.Compute/disks",
                        resource_name=disk_name,
                        bicep_name="",
                        deployed_name=disk_name,
                        drift_type="critical_config_error",
                        property_diffs=[
                            PropertyDiff(
                                property_path="attachment_status",
                                desired_value="attached to VM",
                                actual_value="orphaned",
                                change_type="modified",
                                severity="critical",
                            )
                        ],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def check_vms_without_nics(deployed_resources: List[Dict]) -> List[ResourceDrift]:
        """
        Detect VMs without network interfaces (critical configuration error).

        A VM cannot function without at least one NIC. If a VM exists but has
        no NICs attached, it's a critical issue indicating:
        - Manual NIC deletion
        - Network interface failure
        - Incomplete deployment
        """
        drifts = []

        # Get all VMs and NICs
        vms = [r for r in deployed_resources
               if r.get("type") == "Microsoft.Compute/virtualMachines"]
        nic_ids = ResourceIndexer.by_id(deployed_resources, "Microsoft.Network/networkInterfaces")

        for vm in vms:
            vm_name = vm.get("name", "")
            vm_props = vm.get("properties", {})
            nic_refs = vm_props.get("networkProfile", {}).get("networkInterfaces", [])

            # Check if VM has any NICs
            has_nics = False
            for nic_ref in nic_refs:
                nic_id = nic_ref.get("id", "")
                if nic_id in nic_ids:
                    has_nics = True
                    break

            # If VM has no NICs, it's a critical issue
            if not has_nics:
                drifts.append(
                    ResourceDrift(
                        resource_type="Microsoft.Compute/virtualMachines",
                        resource_name=vm_name,
                        bicep_name="",
                        deployed_name=vm_name,
                        drift_type="critical_config_error",
                        property_diffs=[
                            PropertyDiff(
                                property_path="networkInterfaces",
                                desired_value="at least 1 NIC",
                                actual_value="0 NICs",
                                change_type="modified",
                                severity="critical",
                            )
                        ],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def check_data_disk_changes(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[ResourceDrift]:
        """
        Detect data disk additions, removals, and modifications on VMs.

        Data disk changes are important configuration drifts because they affect
        storage capacity and performance. Reports when:
        - Data disks are added to deployed VMs (not in Bicep)
        - Data disks are removed from deployed VMs (in Bicep but not deployed)
        - Data disk properties change (size, caching, etc.)
        """
        drifts = []

        # Create lookup maps
        bicep_vms = {r.get("name", ""): r for r in bicep_resources
                     if r.get("type") == "Microsoft.Compute/virtualMachines"}
        deployed_vms = ResourceIndexer.by_name(deployed_resources, "Microsoft.Compute/virtualMachines")

        # Check VMs that exist in both (matched resources)
        for vm_name in set(bicep_vms.keys()) & set(deployed_vms.keys()):
            bicep_vm = bicep_vms[vm_name]
            deployed_vm = deployed_vms[vm_name]

            bicep_disks = bicep_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])
            deployed_disks = deployed_vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])

            # Convert to dicts keyed by LUN for comparison
            bicep_by_lun = {d.get("lun"): d for d in bicep_disks if isinstance(d, dict)}
            deployed_by_lun = {d.get("lun"): d for d in deployed_disks if isinstance(d, dict)}

            # Check for added disks (deployed but not in Bicep)
            for lun, deployed_disk in deployed_by_lun.items():
                if lun not in bicep_by_lun:
                    disk_name = deployed_disk.get("name", f"DataDisk-LUN{lun}")
                    disk_size = deployed_disk.get("diskSizeGB", "unknown")
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}]",
                                    desired_value="(not defined in Bicep)",
                                    actual_value=f"{disk_name} ({disk_size}GB, LUN {lun})",
                                    change_type="added",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

            # Check for removed disks (in Bicep but not deployed)
            for lun, bicep_disk in bicep_by_lun.items():
                if lun not in deployed_by_lun:
                    disk_name = bicep_disk.get("name", f"DataDisk-LUN{lun}")
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}]",
                                    desired_value=f"{disk_name} (in Bicep)",
                                    actual_value="(not attached)",
                                    change_type="removed",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

            # Check for modified disk properties
            for lun in set(bicep_by_lun.keys()) & set(deployed_by_lun.keys()):
                bicep_disk = bicep_by_lun[lun]
                deployed_disk = deployed_by_lun[lun]

                # Check disk size
                bicep_size = bicep_disk.get("diskSizeGB")
                deployed_size = deployed_disk.get("diskSizeGB")
                if bicep_size and deployed_size and bicep_size != deployed_size:
                    drifts.append(
                        ResourceDrift(
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_name=vm_name,
                            bicep_name=vm_name,
                            deployed_name=vm_name,
                            drift_type="modified",
                            property_diffs=[
                                PropertyDiff(
                                    property_path=f"properties.storageProfile.dataDisks[{lun}].diskSizeGB",
                                    desired_value=bicep_size,
                                    actual_value=deployed_size,
                                    change_type="modified",
                                    severity="warning",
                                )
                            ],
                            match_confidence=1.0,
                        )
                    )

        return drifts


class DriftDetector:
    """Detect all types of drift."""

    @staticmethod
    def _is_internal_resource(resource: Dict) -> bool:
        """Check if resource is internal/management (not actual infrastructure)."""
        resource_type = resource.get("type", "")
        # Filter out deployment modules and other management resources
        internal_types = {
            "Microsoft.Resources/deployments",
        }
        return resource_type in internal_types

    @staticmethod
    def detect_drift(
        bicep_resources: List[Dict],
        deployed_resources: List[Dict],
    ) -> List[ResourceDrift]:
        """
        Detect all drift between Bicep and deployed resources.

        Includes:
        - Resource matching (missing, extra)
        - Property comparison (modified configs)
        - Critical configuration validation:
          * Orphaned disks (OS and data)
          * VMs without network interfaces

        Returns:
            List of ResourceDrift objects
        """
        drifts = []
        extractor = PropertyExtractor()

        # Filter out internal resources (deployments, etc.)
        bicep_resources = [r for r in bicep_resources if not DriftDetector._is_internal_resource(r)]
        deployed_resources = [r for r in deployed_resources if not DriftDetector._is_internal_resource(r)]

        # Run critical configuration validation checks
        validator = ConfigurationValidator()
        drifts.extend(validator.check_orphaned_disks(deployed_resources))
        drifts.extend(validator.check_vms_without_nics(deployed_resources))
        drifts.extend(validator.check_data_disk_changes(bicep_resources, deployed_resources))

        matches = ResourceMatcher.match_resources(bicep_resources, deployed_resources)
        comparator = PropertyComparator()

        # Track matched resources
        matched_bicep = {id(r) for r, _, _ in matches}
        matched_deployed = {id(r) for _, r, _ in matches}

        # Check matched resources for property drift
        for bicep_res, deployed_res, confidence in matches:
            bicep_props = extractor.extract_bicep_properties(bicep_res)
            deployed_props = extractor.extract_azure_properties(deployed_res)

            diffs = comparator.compare_properties(bicep_props, deployed_props)

            if diffs:
                drifts.append(
                    ResourceDrift(
                        resource_type=bicep_res.get("type", ""),
                        resource_name=bicep_res.get("name", ""),
                        bicep_name=bicep_res.get("name", ""),
                        deployed_name=deployed_res.get("name", ""),
                        drift_type="modified",
                        property_diffs=diffs,
                        match_confidence=confidence,
                    )
                )

        # Check for missing resources (in Bicep, not deployed)
        for bicep_res in bicep_resources:
            if id(bicep_res) not in matched_bicep:
                drifts.append(
                    ResourceDrift(
                        resource_type=bicep_res.get("type", ""),
                        resource_name=bicep_res.get("name", ""),
                        bicep_name=bicep_res.get("name", ""),
                        deployed_name="",
                        drift_type="missing",
                        property_diffs=[],
                        match_confidence=1.0,
                    )
                )

        # Check for extra resources (deployed, not in Bicep)
        for deployed_res in deployed_resources:
            if id(deployed_res) not in matched_deployed:
                drifts.append(
                    ResourceDrift(
                        resource_type=deployed_res.get("type", ""),
                        resource_name=deployed_res.get("name", ""),
                        bicep_name="",
                        deployed_name=deployed_res.get("name", ""),
                        drift_type="extra",
                        property_diffs=[],
                        match_confidence=1.0,
                    )
                )

        return drifts

    @staticmethod
    def generate_summary(drifts: List[ResourceDrift]) -> Dict[str, int]:
        """Generate summary of drift types."""
        summary = {
            "total": len(drifts),
            "missing": len([d for d in drifts if d.drift_type == "missing"]),
            "extra": len([d for d in drifts if d.drift_type == "extra"]),
            "modified": len([d for d in drifts if d.drift_type == "modified"]),
            "unchanged": len([d for d in drifts if d.drift_type == "unchanged"]),
        }
        return summary
