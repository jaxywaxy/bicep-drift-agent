"""
RBAC role-assignment drift detection.

Role assignments are the most common out-of-band change in real estates
("temporary" Contributor grants that never leave), but they are invisible to
the normal pipeline twice over:

  * live side  - assignments are NOT rows in Resource Graph's Resources table;
                 they live in the authorizationresources table.
  * bicep side - assignment names are guid(...) expressions, which
                 diff_states._should_compare_resource deliberately skips.

So this module runs its own compare, matching on IDENTITY - (roleDefinition
GUID, principalId, scope) - instead of resource name:

  * a live assignment with no bicep counterpart  -> extra_in_azure
    (someone granted access out-of-band; details carry who/when from the
    RBAC API itself, which unlike the Activity Log has no retention limit)
  * a bicep assignment with no live counterpart  -> missing_in_azure

Bicep principalIds are often runtime expressions (a managed identity's
principalId). Those match best-effort by role GUID within the remaining
unmatched pool - same philosophy as smart_matching for uniqueString names.
"""

import fnmatch
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ROLE_ASSIGNMENT_TYPE = "Microsoft.Authorization/roleAssignments"

_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

# Roles that grant write or grant-rights access; extras with these are flagged
# high severity in the drift details so reports/notifications can call them out.
PRIVILEGED_ROLE_GUIDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # Role Based Access Control Administrator
}

# Display fallback when the roledefinitions query is unavailable (tests,
# restricted readers). The live query supersedes this for anything it returns,
# including custom roles.
BUILTIN_ROLE_NAMES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "4d97b98b-1d4f-4787-a291-c67834d212e7": "Network Contributor",
    "749f88d5-cbae-40b8-bcfc-e573ddc772fa": "Monitoring Contributor",
    "43d0d8ad-25c7-4714-9337-8ba259a9fe05": "Monitoring Reader",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
}


def _extract_guid(value: Any) -> Optional[str]:
    """Pull the role GUID out of a roleDefinitionId in ANY form it appears.

    Works on a full ARM id, a bare GUID, or an unresolved bicep expression like
    "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions',
    'b24988ac-...')]" - the GUID literal survives compilation either way.
    Takes the LAST GUID in the string: a full ARM id starts with the
    subscription GUID, and the role definition GUID is always the final segment.
    """
    matches = _GUID_RE.findall(str(value or ""))
    return matches[-1].lower() if matches else None


def _is_unresolved(value: Any) -> bool:
    """True when a bicep-side value is still a template expression, not a literal."""
    v = str(value or "")
    return not v or any(marker in v for marker in ("[", "(", "{"))


def _scope_rg(scope: str) -> Optional[str]:
    """Resource-group name from an assignment scope, or None for sub/MG scopes."""
    m = re.search(r"/resourcegroups/([^/]+)", scope or "", re.IGNORECASE)
    return m.group(1) if m else None


def _scope_target_type(scope: str) -> Optional[str]:
    """The scoped-to resource type ("Microsoft.Network/virtualNetworks") for a
    resource-scoped assignment, or None for sub/RG-level scopes."""
    m = re.search(r"/providers/([^/]+)/([^/]+)/", (scope or "") + "/", re.IGNORECASE)
    if not m or m.group(1).lower() == "microsoft.management":
        return None
    return f"{m.group(1)}/{m.group(2)}"


def fetch_role_assignments(
    subscription_id: str,
    resource_group: Optional[str] = None,
    scope: str = "resource_group",
    credential: Any = None,
) -> List[Dict]:
    """Fetch live role assignments in the scan scope via Resource Graph.

    Returns assignment dicts with resolved role names. Scope filtering keeps
    only assignments the scanned template could own:
      * resource_group scan: assignments AT the RG or on resources within it.
        Inherited sub/MG-level assignments are excluded (they belong to the
        subscription scan, and reporting them per-RG would multiply them).
      * subscription scan: sub-level assignments plus RG/resource-level ones in
        RGs matching the selector (None/'*' = all, glob or exact name filters).

    Fail-soft: any query error returns [] with a warning, so an estate without
    authorizationresources access still gets its normal resource scan.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        credential = credential or DefaultAzureCredential()
        client = ResourceGraphClient(credential)

        def _query(kql: str) -> List[Dict]:
            rows: List[Dict] = []
            skip_token = None
            while True:
                request = QueryRequest(
                    subscriptions=[subscription_id],
                    query=kql,
                    options={"skip_token": skip_token} if skip_token else None,
                )
                response = client.resources(request)
                rows.extend(response.data or [])
                skip_token = getattr(response, "skip_token", None)
                if not skip_token:
                    break
            return rows

        raw = _query(
            "authorizationresources"
            " | where type =~ 'microsoft.authorization/roleassignments'"
        )
        role_names = dict(BUILTIN_ROLE_NAMES)
        try:
            for d in _query(
                "authorizationresources"
                " | where type =~ 'microsoft.authorization/roledefinitions'"
                " | project id, roleName = properties.roleName"
            ):
                guid = _extract_guid(d.get("id"))
                if guid and d.get("roleName"):
                    role_names[guid] = d["roleName"]
        except Exception as e:
            logger.warning(f"Could not fetch role definitions (using built-in names): {e}")
    except Exception as e:
        logger.warning(f"Could not fetch role assignments (skipping RBAC drift): {e}")
        return []

    assignments = []
    for row in raw:
        props = row.get("properties", {}) or {}
        role_guid = _extract_guid(props.get("roleDefinitionId"))
        assignments.append({
            "id": row.get("id"),
            "name": row.get("name"),
            "scope": props.get("scope", ""),
            "role_guid": role_guid,
            "role_name": role_names.get(role_guid, role_guid or "unknown-role"),
            "principal_id": (props.get("principalId") or "").lower(),
            "principal_type": props.get("principalType", "Unknown"),
            "created_on": props.get("createdOn"),
            "created_by": props.get("createdBy"),
            "condition": props.get("condition"),
            "description": props.get("description"),
        })

    kept = filter_assignments_to_scope(assignments, subscription_id, resource_group, scope)
    logger.info(
        f"Found {len(kept)} role assignment(s) in scan scope "
        f"({len(assignments) - len(kept)} outside scope excluded)"
    )
    return kept


def filter_assignments_to_scope(
    assignments: List[Dict],
    subscription_id: str,
    resource_group: Optional[str],
    scope: str,
) -> List[Dict]:
    """Keep only assignments whose scope belongs to the scan (see fetch docstring)."""
    sub_prefix = f"/subscriptions/{subscription_id}".lower()
    kept = []
    for a in assignments:
        a_scope = (a.get("scope") or "").lower()
        if not a_scope.startswith(sub_prefix):
            continue  # management-group-level (or another sub) - not this scan's to own
        rg = _scope_rg(a_scope)
        if scope == "resource_group":
            if rg and resource_group and rg.lower() == resource_group.lower():
                kept.append(a)
        else:
            if rg is None:
                kept.append(a)  # subscription-level assignment
            elif not resource_group or resource_group in ("*", ""):
                kept.append(a)
            elif fnmatch.fnmatch(rg.lower(), resource_group.lower()):
                kept.append(a)
    return kept


def extract_bicep_role_assignments(arm_resources: List[Dict]) -> Tuple[List[Dict], int]:
    """Pull role assignments out of the compiled template for identity matching.

    Returns (extracted, skipped_count). An assignment whose roleDefinitionId
    carries no GUID literal (e.g. a fully parameterised custom-role id) can't
    be matched and would only produce a false missing_in_azure - those are
    skipped and counted.
    """
    extracted, skipped = [], 0
    for r in arm_resources:
        if (r.get("type") or "").lower() != ROLE_ASSIGNMENT_TYPE.lower():
            continue
        props = r.get("properties", {}) or {}
        role_guid = _extract_guid(props.get("roleDefinitionId"))
        if not role_guid:
            skipped += 1
            logger.debug(f"Skipping bicep role assignment with unresolvable role id: {r.get('name')}")
            continue
        principal = props.get("principalId")
        extracted.append({
            "role_guid": role_guid,
            "principal_id": None if _is_unresolved(principal) else str(principal).lower(),
            "scope": None if _is_unresolved(r.get("scope")) else r.get("scope"),
            "raw_name": r.get("name", ""),
        })
    return extracted, skipped


def collect_managed_identity_principals(live_resources: Optional[List[Dict]]) -> set:
    """principalIds of managed identities this estate currently deploys.

    A role assignment declared in bicep for a deployed identity carries that
    identity's principalId as a RUNTIME expression
    (reference(...).outputs.principalId), unknown at compile time, so it can only
    match live by role GUID. When an orphaned assignment to the same role also
    exists - a prior deploy cycle's identity, since deleted - role-only matching
    is first-come-first-served and may consume the orphan while flagging the
    real, current grant (a false positive seen live). Knowing which live
    principals belong to CURRENTLY-deployed identities lets Pass 2 prefer the
    real one, so the declared grant matches and only true orphans surface.
    """
    ids: set = set()
    for r in (live_resources or []):
        rtype = (r.get("type") or "").lower()
        props = r.get("properties") or {}
        if rtype == "microsoft.managedidentity/userassignedidentities":
            pid = props.get("principalId")
            if pid:
                ids.add(str(pid).lower())
        # System-assigned identities carry their principalId under identity.*
        ident = r.get("identity")
        if isinstance(ident, dict) and ident.get("principalId"):
            ids.add(str(ident["principalId"]).lower())
    return ids


def compare_role_assignments(
    arm_resources: List[Dict],
    live_assignments: List[Dict],
    deployed_principals: Optional[set] = None,
) -> List[Dict]:
    """Match bicep assignments to live ones by identity; emit drift dicts.

    Matching order (each live assignment is consumed at most once):
      1. exact (role GUID, principalId) - bicep principal resolved to a literal.
      2. role GUID only - bicep principal is a runtime expression (a deployed
         identity's principalId). Among live assignments with that role, PREFER
         one whose principal is a currently-deployed identity
         (``deployed_principals``) over an orphaned assignment to a deleted
         principal, so the declared grant matches and the orphan is flagged -
         not the other way round.

    Unmatched live -> extra_in_azure (with who/when/role in details).
    Unmatched bicep -> missing_in_azure.
    """
    deployed_principals = deployed_principals or set()
    bicep, skipped = extract_bicep_role_assignments(arm_resources)
    if skipped:
        logger.info(f"RBAC: skipped {skipped} bicep assignment(s) with unresolvable role ids")
    if not bicep and not live_assignments:
        return []

    remaining = list(live_assignments)
    unmatched_bicep = []

    # Pass 1: exact identity matches
    deferred = []
    for b in bicep:
        if b["principal_id"]:
            hit = next(
                (a for a in remaining
                 if a["role_guid"] == b["role_guid"] and a["principal_id"] == b["principal_id"]),
                None,
            )
            if hit:
                remaining.remove(hit)
            else:
                unmatched_bicep.append(b)
        else:
            deferred.append(b)

    # Pass 2: role-only matches for runtime principals. Prefer a live assignment
    # whose principal is a currently-deployed identity before falling back to
    # any assignment with the role (see collect_managed_identity_principals).
    for b in deferred:
        hit = next(
            (a for a in remaining
             if a["role_guid"] == b["role_guid"]
             and str(a.get("principal_id") or "").lower() in deployed_principals),
            None,
        )
        if hit is None:
            hit = next((a for a in remaining if a["role_guid"] == b["role_guid"]), None)
        if hit:
            remaining.remove(hit)
        else:
            unmatched_bicep.append(b)

    drifts: List[Dict] = []
    for a in remaining:
        details = {
            "role_name": a["role_name"],
            "role_definition_guid": a["role_guid"],
            "principal_id": a["principal_id"],
            "principal_type": a["principal_type"],
            "scope": a["scope"],
            "assignment_id": a["id"],
            "privileged": a["role_guid"] in PRIVILEGED_ROLE_GUIDS,
        }
        # The RBAC API records grantor and grant time directly - stronger
        # provenance than the Activity Log (no 30/90-day window).
        if a.get("created_by"):
            details["created_by"] = a["created_by"]
        if a.get("created_on"):
            details["created_on"] = a["created_on"]
        if a.get("condition"):
            details["condition"] = a["condition"]
        drifts.append({
            "type": ROLE_ASSIGNMENT_TYPE,
            "name": f"{a['role_name']} -> {a['principal_type']}:{a['principal_id']}",
            "drift_type": "extra_in_azure",
            "details": details,
        })
    for b in unmatched_bicep:
        role_name = BUILTIN_ROLE_NAMES.get(b["role_guid"], b["role_guid"])
        drifts.append({
            "type": ROLE_ASSIGNMENT_TYPE,
            "name": f"{role_name} -> {b['principal_id'] or 'unresolved-principal'}",
            "drift_type": "missing_in_azure",
            "details": {
                "role_name": role_name,
                "role_definition_guid": b["role_guid"],
                "principal_id": b["principal_id"],
                "scope": b["scope"],
                "privileged": b["role_guid"] in PRIVILEGED_ROLE_GUIDS,
            },
        })

    if drifts:
        extras = sum(1 for d in drifts if d["drift_type"] == "extra_in_azure")
        logger.info(f"RBAC drift: {extras} extra, {len(drifts) - extras} missing assignment(s)")
    return drifts


def rbac_enabled() -> bool:
    """RBAC scanning is on by default; INCLUDE_ROLE_ASSIGNMENTS=false disables it."""
    return os.environ.get("INCLUDE_ROLE_ASSIGNMENTS", "true").strip().lower() not in (
        "false", "0", "no", "off",
    )
