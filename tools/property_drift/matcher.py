"""
tools/property_drift/matcher.py

Match Bicep resources to deployed resources using intelligent contextual
matching. Ordered from most-reliable to least-reliable: exact name → prefix
(for uniqueString-name placeholders) → contextual (disk↔parent VM, NIC↔VM) →
fuzzy tokens → positional (only for true duplicates) → single-candidate
plausibility check.
"""

import logging
from collections import defaultdict

from .models import MatchConfidenceScores

logger = logging.getLogger(__name__)


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
    def _find_associated_resource(resource: dict, bicep_resources: list[dict], resource_type: str) -> dict:
        """Find a related resource (e.g., find VM for a NIC by name similarity)."""
        res_name = resource.get("name", "")
        name_tokens = res_name.replace('-nic', '').replace('-nic-', '-')

        for r in bicep_resources:
            if r.get("type") == resource_type:
                r_name = r.get("name", "")
                if name_tokens in r_name or r_name in name_tokens:
                    return r
        return None

    @staticmethod
    def _find_parent_vm(disk_name: str, bicep_resources: list[dict]) -> dict:
        """Find parent VM for a managed disk by extracting VM name from disk name.

        Example: vm-prod-002_OsDisk_1_<hash> → extract 'vm-prod-002'
        """
        vm_name = disk_name.split('_')[0] if '_' in disk_name else None
        if not vm_name:
            return None

        for r in bicep_resources:
            if r.get("type") == "Microsoft.Compute/virtualMachines":
                if r.get("name", "").lower() == vm_name.lower():
                    return r
        return None

    @staticmethod
    def _match_disks_by_parent_vm(
        bicep_resource: dict, bicep_resources: list[dict], candidates: list[dict], current_best_score: float
    ) -> tuple[dict, float]:
        """Match a disk to its parent VM's disk."""
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
        bicep_resource: dict, bicep_resources: list[dict], candidates: list[dict],
        matches: list[tuple[dict, dict, float]], current_best_score: float
    ) -> tuple[dict, float]:
        """Match a NIC to its associated VM's NIC."""
        associated_vm = ResourceMatcher._find_associated_resource(
            bicep_resource, bicep_resources, "Microsoft.Compute/virtualMachines"
        )
        if not associated_vm:
            return None

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
        bicep_name: str, candidates: list[dict], current_best_score: float
    ) -> tuple[dict, float]:
        """Match using fuzzy token-based matching (for parameter-based names)."""
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
                bicep_set = set(bicep_tokens)
                deployed_set = set(deployed_tokens)
                exact_matches = len(bicep_set & deployed_set)
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
        bicep_resources: list[dict],
        deployed_resources: list[dict],
    ) -> list[tuple[dict, dict, float]]:
        """Match Bicep resources to deployed resources using intelligent contextual matching.

        Strategy:
        1. Exact name matches (highest confidence)
        2. Contextual matching: for identical-named resources, use related resources
           to disambiguate (e.g., match NICs via their VMs)
        3. Fuzzy token-based matching (parameter-based names)
        4. Positional matching as fallback for true duplicates
        """
        matches = []
        deployed_by_type = defaultdict(list)

        for resource in deployed_resources:
            resource_type = ResourceMatcher._normalize_resource_type(resource.get("type", ""))
            deployed_by_type[resource_type].append(resource)

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
                    prefix = bicep_name.split("[")[0]
                    if prefix:
                        prefix_matches = [d for d in candidates if d.get("name", "").startswith(prefix)]
                        if len(prefix_matches) == 1:
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

            bicep_names = [r.get("name", "") for r in bicep_res_list]
            all_identical = len(set(bicep_names)) == 1

            for bicep_idx, bicep_resource in enumerate(bicep_res_list):
                bicep_name = bicep_resource.get("name", "")
                best_match = None
                best_score = MatchConfidenceScores.NO_MATCH

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
