"""
Azure Policy assignment & exemption drift detection.

The governance twin of tools/rbac.py: policy assignments and exemptions live
in Resource Graph's ``policyresources`` table (not ``Resources``), and their
bicep names are frequently guid(...) expressions - so like role assignments
they are invisible to the normal pipeline and match on IDENTITY, not name:

  * an assignment in Azure with no bicep counterpart -> extra_in_azure
    (out-of-band governance change; provenance from properties.metadata's
    createdBy/assignedBy - no activity-log retention limit)
  * a bicep assignment with no live counterpart -> missing_in_azure
  * an EXEMPTION with no bicep counterpart -> extra_in_azure - someone
    waived a policy on a resource, prime audit-critical drift.

Assignment identity is the policy definition reference (the definition id's
trailing GUID/name) within the scan scope; exemptions key on the assignment
they exempt plus the scope they carve out.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .rbac import filter_assignments_to_scope, _is_unresolved

logger = logging.getLogger(__name__)

POLICY_ASSIGNMENT_TYPE = "Microsoft.Authorization/policyAssignments"
POLICY_EXEMPTION_TYPE = "Microsoft.Authorization/policyExemptions"


def _definition_ref(value: Any) -> Optional[str]:
    """The definition's identity: trailing segment of a policyDefinitionId.

    Works on full ARM ids ('/providers/Microsoft.Authorization/
    policyDefinitions/06a78e20-...'), bare GUIDs/names, and unresolved bicep
    expressions carrying the literal ('[subscriptionResourceId(..., '06a78e20-...')]').
    """
    s = str(value or "").rstrip("'\")]")
    if not s:
        return None
    m = re.search(r"policy(?:set)?definitions/([^/'\"\]]+)$", s, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # Unresolved expression form: subscriptionResourceId('...policyDefinitions',
    # '06a78e20-...') - the GUID literal survives; take the LAST one (ids can
    # embed the subscription GUID earlier, same as roleDefinitionIds).
    guids = re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s)
    if guids:
        return guids[-1].lower()
    if _is_unresolved(s):
        return None
    return s.split("/")[-1].lower() or None


def fetch_policy_resources(
    subscription_id: str,
    resource_group: Optional[str] = None,
    scope: str = "resource_group",
    credential: Any = None,
) -> Tuple[List[Dict], List[Dict]]:
    """Fetch live policy assignments and exemptions in the scan scope.

    Scope filtering matches RBAC's: an RG scan owns assignments AT/under the
    RG (inherited sub/MG-level assignments belong to broader scans); a
    subscription scan owns sub-level ones plus selector-matched RGs.
    Fail-soft: errors return ([], []) with a warning.
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

        raw_assignments = _query(
            "policyresources"
            " | where type =~ 'microsoft.authorization/policyassignments'"
        )
        raw_exemptions = _query(
            "policyresources"
            " | where type =~ 'microsoft.authorization/policyexemptions'"
        )
    except Exception as e:
        logger.warning(f"Could not fetch policy resources (skipping policy drift): {e}")
        return [], []

    def _shape(row: Dict) -> Dict:
        props = row.get("properties", {}) or {}
        meta = props.get("metadata", {}) or {}
        # Assignments carry their scope in properties.scope; exemptions apply
        # AT their own id's scope (the id minus the /providers/...exemptions tail).
        scope_val = props.get("scope")
        if not scope_val:
            rid = row.get("id", "")
            scope_val = re.split(r"/providers/microsoft\.authorization/policy",
                                 rid, flags=re.IGNORECASE)[0]
        return {
            "id": row.get("id"),
            "name": row.get("name"),
            "scope": scope_val or "",
            "display_name": props.get("displayName") or row.get("name"),
            "definition_ref": _definition_ref(props.get("policyDefinitionId")),
            "assignment_id": (props.get("policyAssignmentId") or "").lower(),  # exemptions only
            "enforcement_mode": props.get("enforcementMode"),
            "exemption_category": props.get("exemptionCategory"),
            "expires_on": props.get("expiresOn"),
            "created_by": meta.get("createdBy"),
            "created_on": meta.get("createdOn"),
            "assigned_by": meta.get("assignedBy"),
        }

    assignments = filter_assignments_to_scope(
        [_shape(r) for r in raw_assignments], subscription_id, resource_group, scope
    )
    exemptions = filter_assignments_to_scope(
        [_shape(r) for r in raw_exemptions], subscription_id, resource_group, scope
    )
    logger.info(
        f"Found {len(assignments)} policy assignment(s) and {len(exemptions)} "
        f"exemption(s) in scan scope"
    )
    return assignments, exemptions


def extract_bicep_policy_assignments(arm_resources: List[Dict]) -> Tuple[List[Dict], int]:
    """Pull policy assignments out of the compiled template for identity matching.

    Returns (extracted, skipped). Skipped = assignments whose definition
    reference carries no literal (fully parameterised) - unmatchable, and
    emitting missing_in_azure for them would be a false positive.
    """
    extracted, skipped = [], 0
    for r in arm_resources:
        if (r.get("type") or "").lower() != POLICY_ASSIGNMENT_TYPE.lower():
            continue
        props = r.get("properties", {}) or {}
        ref = _definition_ref(props.get("policyDefinitionId"))
        if not ref:
            skipped += 1
            logger.debug(f"Skipping bicep policy assignment with unresolvable definition: {r.get('name')}")
            continue
        extracted.append({
            "definition_ref": ref,
            "name": None if _is_unresolved(r.get("name")) else r.get("name"),
            "display_name": props.get("displayName"),
        })
    return extracted, skipped


def compare_policy_resources(
    arm_resources: List[Dict],
    live_assignments: List[Dict],
    live_exemptions: List[Dict],
) -> List[Dict]:
    """Match bicep policy assignments to live ones; emit drift dicts.

    Matching: by name when the bicep name is a literal, else by definition
    reference (each live assignment consumed once). Exemptions are compared
    presence-only against bicep policyExemptions resources (rare in IaC);
    any unmatched live exemption is an out-of-band waiver -> extra_in_azure.
    """
    bicep, skipped = extract_bicep_policy_assignments(arm_resources)
    if skipped:
        logger.info(f"Policy: skipped {skipped} bicep assignment(s) with unresolvable definitions")

    remaining = list(live_assignments)
    unmatched_bicep = []
    for b in bicep:
        hit = None
        if b["name"]:
            hit = next((a for a in remaining if (a.get("name") or "").lower() == b["name"].lower()), None)
        if hit is None:
            hit = next((a for a in remaining if a.get("definition_ref") == b["definition_ref"]), None)
        if hit is not None:
            remaining.remove(hit)
        else:
            unmatched_bicep.append(b)

    drifts: List[Dict] = []
    for a in remaining:
        details = {
            "policy_display_name": a["display_name"],
            "definition_ref": a["definition_ref"],
            "scope": a["scope"],
            "assignment_id": a["id"],
        }
        if a.get("enforcement_mode"):
            details["enforcement_mode"] = a["enforcement_mode"]
        if a.get("assigned_by"):
            details["assigned_by"] = a["assigned_by"]
        if a.get("created_by"):
            details["created_by"] = a["created_by"]
        if a.get("created_on"):
            details["created_on"] = a["created_on"]
        drifts.append({
            "type": POLICY_ASSIGNMENT_TYPE,
            "name": f"{a['display_name'] or a['name']}",
            "drift_type": "extra_in_azure",
            "details": details,
        })
    for b in unmatched_bicep:
        drifts.append({
            "type": POLICY_ASSIGNMENT_TYPE,
            "name": b["display_name"] or b["name"] or b["definition_ref"],
            "drift_type": "missing_in_azure",
            "details": {"definition_ref": b["definition_ref"]},
        })

    # Exemptions: bicep-declared ones are rare; match presence by (assignment id,
    # scope). Everything else live is an out-of-band waiver.
    bicep_exemptions = {
        ((str((r.get("properties") or {}).get("policyAssignmentId") or "")).lower(),)
        for r in arm_resources
        if (r.get("type") or "").lower() == POLICY_EXEMPTION_TYPE.lower()
    }
    for e in live_exemptions:
        if (e.get("assignment_id"),) in bicep_exemptions:
            continue
        details = {
            "exempted_assignment": e.get("assignment_id"),
            "exemption_category": e.get("exemption_category"),
            "scope": e["scope"],
        }
        if e.get("expires_on"):
            details["expires_on"] = e["expires_on"]
        if e.get("created_by"):
            details["created_by"] = e["created_by"]
        if e.get("created_on"):
            details["created_on"] = e["created_on"]
        drifts.append({
            "type": POLICY_EXEMPTION_TYPE,
            "name": e["display_name"] or e["name"],
            "drift_type": "extra_in_azure",
            "details": details,
        })

    if drifts:
        extras = sum(1 for d in drifts if d["drift_type"] == "extra_in_azure")
        logger.info(f"Policy drift: {extras} extra, {len(drifts) - extras} missing")
    return drifts


def policy_drift_enabled() -> bool:
    """Policy scanning is on by default; INCLUDE_POLICY_ASSIGNMENTS=false disables."""
    return os.environ.get("INCLUDE_POLICY_ASSIGNMENTS", "true").strip().lower() not in (
        "false", "0", "no", "off",
    )
