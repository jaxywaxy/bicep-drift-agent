"""
orchestration/attribution.py

Lifecycle attribution: fetch the RG activity log once, match the relevant event
per drift, classify change origin (pipeline / manual / policy-DINE / remediation /
system) and owner (platform vs workload), then split policy-enforced drift out of
the actionable set. Runs BEFORE the Claude call so the analysis sees who/how.
"""

import os

from orchestration.reconciliation import _find_deployed_resource
from tools.activity_log import detect_scanning_identity, fetch_policy_principal_ids, fetch_resource_group_activity, match_activity_for_resource
from tools.change_origin import build_resource_lifecycle, classify_change_origin, event_explains_drift, select_relevant_activity
from tools.config import AUTHORIZED_DEPLOYERS
from tools.logger import get_logger
from tools.ownership import classify_owner

logger = get_logger(__name__)

# The effect both inherit-tag built-ins use. Not a guess: INHERIT_TAG_DEFINITIONS
# selects on exactly those two definition GUIDs, so anything reaching the claim
# is a Modify - which is precisely why a redeploy cannot win against it.
_MODIFY_EFFECT = "Modify"


def _recover_deployed_name(resource_type: str, event_resource_id: str) -> str:
    """Extract the real deployed name for resource_type from an activity-log id.

    A deleted placeholder-named resource (log-[86c9cbf6]) has no live row to
    read the real name from, but its activity-log delete event carries the true
    Azure id (.../workspaces/log-3s7c7weddxr3s). Parse the provider section -
    [namespace, type1, name1, type2, name2, ...] - verify the type chain
    matches, and return the joined name segments ('parent/child' for children).
    Returns "" when the id doesn't parse or is for a different type.
    """
    if not event_resource_id or not resource_type:
        return ""
    provider_tail = event_resource_id.split("/providers/")[-1].split("/")
    type_segments = resource_type.split("/")  # [namespace, type1, type2, ...]
    types_in_id = [s.lower() for s in provider_tail[1::2]]
    names_in_id = provider_tail[2::2]
    if (
        len(provider_tail) < 3
        or provider_tail[0].lower() != type_segments[0].lower()
        or types_in_id != [s.lower() for s in type_segments[1:]]
        or len(names_in_id) != len(types_in_id)
    ):
        return ""
    return "/".join(names_in_id)


def _attribute_lifecycle(report_data: dict, resource_group: str) -> None:
    """Phase 3: attribute each drift via the Activity Log, attaching `lifecycle`
    and `change_origin` to every entry in report_data['drifts'] in place.

    MUST run BEFORE the Claude analysis: the agent cites change_origin (who/how)
    and reasons by lifecycle.resource_id. Running it after left both null in the
    prompt, so the agent fell back to "investigate the Activity Log" despite the
    data being available. The policy split + owner tagging run separately, after
    the analysis, via _split_policy_and_tag_owners.
    """
    drifts_to_analyze = report_data.get("drifts", [])
    logger.info(f"Found {len(drifts_to_analyze)} drift(s) to attribute")
    if len(drifts_to_analyze) == 0:
        return

    logger.info("Phase 3: Building resource lifecycle from Activity Log...")
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    live_resources = report_data.get("live_resources", [])

    # Fetch the RG's Activity Log ONCE and match each drift against it in memory
    # (a per-drift query would re-scan the whole RG N times). Also fetch the
    # policy-assignment managed-identity principals once, so policy (DINE/Modify)
    # changes are attributed to policy.
    rg_activity_events = fetch_resource_group_activity(subscription_id, resource_group, days=30)
    policy_principal_ids = fetch_policy_principal_ids(subscription_id, resource_group)

    # Identities whose changes are authorized IaC deployments: the identity this
    # scan runs as (auto-detected - typically the same OIDC app that deploys)
    # plus any client-configured DRIFT_AUTHORIZED_DEPLOYERS. Their changes are
    # attributed as pipeline deployments instead of "manual (unauthorized)";
    # the drifts themselves stay actionable.
    authorized_deployers = set(AUTHORIZED_DEPLOYERS) | detect_scanning_identity()
    logger.info(f"Authorized deployer identities: {len(authorized_deployers)}")

    for drift in drifts_to_analyze:
        try:
            resource_type = drift.get("type", "")
            bicep_name = drift.get("name", "")

            # Prefer the deployed resource's REAL id (e.g. a lock's id is nested
            # under its target). Fall back to a constructed flat id only when the
            # resource isn't in live state.
            live = _find_deployed_resource(resource_type, bicep_name, live_resources)
            if live and live.get("id"):
                resource_id = live["id"]
            else:
                deployed_name = (live or {}).get("name") or bicep_name
                resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{deployed_name}"

            # Match against pre-fetched RG events; resource_type enables matching
            # deleted resources whose exact ID can't be built.
            activity_logs = match_activity_for_resource(rg_activity_events, resource_id, resource_type)

            # Narrow the RG-wide events down to the ONE operation that explains this
            # drift (delete for missing, write/update for modified).
            relevant_logs = select_relevant_activity(activity_logs, drift.get("drift_type", ""))

            # A deleted placeholder-named resource reports its bicep expression
            # ('log-[86c9cbf6]') because there is no live row to read the real
            # name from - but the matched activity event carries the true Azure
            # id. Recover it so the report, CI summary, and recommendation use
            # the actual deployed name. Only relevant_logs are trusted: they are
            # already narrowed to the operation explaining THIS drift, whereas
            # the wider type-substring match could carry a sibling's events.
            # Local import: smart_matching's name-form check, not a new dependency.
            from tools.smart_matching import _has_unresolvable_expression
            if relevant_logs and _has_unresolvable_expression(bicep_name):
                for event in relevant_logs:
                    real_name = _recover_deployed_name(resource_type, event.get("resource_id") or "")
                    if real_name and real_name != bicep_name:
                        drift["bicep_name_expression"] = bicep_name
                        drift["name"] = real_name
                        resource_id = event.get("resource_id")
                        logger.info(f"  Resolved deployed name: {bicep_name} -> {real_name}")
                        break

            # Pass the drift type through: relevant_logs is a ONE-event list, so
            # the builder cannot tell a create from an update by ordering alone.
            lifecycle = build_resource_lifecycle(
                resource_id, relevant_logs, authorized_deployers,
                drift_type=drift.get("drift_type", ""),
            )
            drift["lifecycle"] = lifecycle.to_dict()

            # The lifecycle keeps whatever was found; the CAUSE claim does not.
            # select_relevant_activity falls back to a write when no delete
            # exists, which is useful history but cannot explain a resource
            # being gone.
            explained = event_explains_drift(
                relevant_logs[0] if relevant_logs else None,
                drift.get("drift_type", ""),
            )
            origin_info = classify_change_origin(
                relevant_logs, policy_principal_ids, authorized_deployers,
                explained=explained,
            )
            drift["change_origin"] = origin_info.to_dict()

            logger.info(
                f"  {bicep_name}: {len(activity_logs or [])} RG event(s) -> "
                f"{len(relevant_logs)} relevant; "
                f"origin={origin_info.origin.value}, by={origin_info.changed_by}"
            )

        except Exception as e:
            logger.warning(f"Failed to build lifecycle for {drift.get('name')}: {str(e)[:100]}")
            drift["lifecycle"] = {
                'resource_id': resource_id,
                'events': [],
                'created_at': None,
                'created_by': None,
                'deleted_at': None,
                'deleted_by': None,
                'last_modified_at': None,
                'last_modified_by': None,
            }
            drift["change_origin"] = {
                'origin': 'unknown',
                'category': 'unknown',
                'severity': 'medium',
                'expected': False,
                'reason': f"Could not query activity log: {str(e)[:50]}",
            }

    logger.info("Resource lifecycle detection completed")


def _policy_imposed(path: str, desired, actual, required: dict) -> dict | None:
    """The rule for 'policy mandates this exact value', shared by the drift list
    and the property_drifts summary array so the two cannot disagree.

    Returns the matching requirement, or None. Two deliberate abstentions:
    a live value that is NEITHER the template's nor policy's means someone moved
    it and policy has not reconverged (real drift), and a template that already
    agrees with policy has nothing to attribute.
    """
    if not path.lower().startswith("tags."):
        return None
    rule = required.get(path.split(".", 1)[1].lower())
    if not rule:
        return None
    if str(actual) != str(rule["value"]) or str(desired) == str(rule["value"]):
        return None
    return rule


def _prune_property_drift_summary(report_data: dict, required: dict) -> None:
    """Drop policy-claimed properties from `property_drifts` too.

    That array is a PARALLEL copy which tools/html_report.py renders the summary
    table from. Claiming a tag in `drifts` while leaving it here made the report
    contradict itself - the table listed tag rows the drift count no longer
    included, which reads as untrustworthy rather than as a filtered view
    (live report 2026-07-27).
    """
    kept = []
    for entry in report_data.get("property_drifts", []):
        diffs = entry.get("property_diffs") or []
        if not diffs:
            # extra/missing rows carry no diffs; they are not ours to touch.
            kept.append(entry)
            continue
        remaining = [
            d for d in diffs
            if not _policy_imposed(d.get("property_path", ""),
                                   d.get("desired_value"), d.get("actual_value"),
                                   required)
        ]
        if not remaining:
            continue  # every diff was policy-imposed - the row is governance now
        entry["property_diffs"] = remaining
        kept.append(entry)
    report_data["property_drifts"] = kept


def _claim_policy_required_tags(report_data: dict) -> int:
    """Move tag properties an in-scope policy MANDATES out of the actionable set.

    An inherit-tag Modify effect rewrites the value inside the deployer's own
    write, so the activity log shows one event attributed to the pipeline and the
    policy identity never appears - the caller-based path in change_origin
    cannot see it (issue #321). The evidence used here is therefore what policy
    REQUIRES: template says X, live says Y, and an in-scope assignment mandates
    exactly Y.

    Per-PROPERTY on purpose. A storage account whose tags.environment is
    policy-imposed can carry a genuinely critical allowBlobPublicAccess in the
    same record; moving the whole record to the governance section would bury it.
    Claimed properties move to `policy_enforced_properties`; only a drift with
    nothing left becomes policy-enforced outright.
    """
    required = report_data.get("policy_required_tags") or {}
    if not required:
        return 0

    claimed = 0
    for drift in report_data.get("drifts", []):
        if drift.get("drift_type") != "property_drift":
            continue
        changed = (drift.get("details") or {}).get("changed_properties") or {}
        claimed_here = 0
        for path in list(changed):
            change = changed[path] or {}
            rule = _policy_imposed(
                path, change.get("desired"), change.get("actual"), required)
            if not rule:
                continue
            drift.setdefault("policy_enforced_properties", {})[path] = {
                **change,
                "policy_assignment": rule["assignment"],
                "policy_definition": rule["definition_ref"],
                "policy_assignment_id": rule.get("assignment_id"),
                "policy_scope": rule.get("scope") or "",
                # Both inherit-tag built-ins use a Modify effect - that is what
                # INHERIT_TAG_DEFINITIONS selects on - so the effect is known,
                # not inferred, and saying so saves the reader a lookup.
                "policy_effect": _MODIFY_EFFECT,
                "reason": (
                    f"Value imposed by the {_MODIFY_EFFECT} effect of inherit-tag "
                    f"assignment '{rule['assignment']}' (inherit tag from resource "
                    f"group, mode: {rule.get('mode')}). Reconcile the template "
                    f"with the policy - redeploying loses the race on the next write."
                ),
            }
            changed.pop(path)
            claimed_here += 1
            claimed += 1

        # Per-DRIFT, not the running total: a property_drift that claimed nothing
        # and merely has no changed properties must not inherit a policy verdict
        # just because an earlier resource in the loop was claimed.
        if claimed_here and not changed:
            # Replace the now-EMPTY changed_properties with a positive statement
            # of what moved. An empty dict reads as "no property differs": a live
            # analysis concluded exactly that, called a real template-vs-policy
            # conflict "not configuration drift", and told the operator to go read
            # the assignment for values that were in the record all along. An
            # absence cannot carry that meaning; a sentence can.
            claims = drift["policy_enforced_properties"]
            details = drift.setdefault("details", {})
            details.pop("changed_properties", None)
            details["policy_enforced_summary"] = "; ".join(
                f"{path}: {v.get('desired')} -> {v.get('actual')} "
                f"(imposed by policy assignment '{v.get('policy_assignment')}')"
                for path, v in claims.items()
            )

            # Nothing actionable left on this resource - attribute the whole
            # record so it lands in the governance section, not the drift list.
            first = next(iter(claims.values()))
            drift["change_origin"] = {
                **(drift.get("change_origin") or {}),
                "origin": "policy_modify",
                "category": "policy",
                "expected": True,
                "severity": "low",
                # The governance section labels each row from policy_name; without
                # it every row reads a bare "Modified by Azure Policy".
                "policy_name": first["policy_assignment"],
                # policy_id means policyAssignmentId everywhere else in
                # change_origin - so this is the ASSIGNMENT's id, never the
                # definition GUID. Left null, a live analysis correctly refused
                # to state the effect or scope: "policy_id is null on every
                # finding, so I cannot confirm the assignment's effect (Modify
                # vs Append) or its exact scope from the data alone." Both were
                # already resolved one key away.
                "policy_id": first.get("policy_assignment_id"),
                # A Modify effect has no actor of its own - it rewrites the value
                # inside somebody else's write. Whatever changed_by/timestamp the
                # record carried describes THAT write, which may be unrelated to
                # the tag (on rsv-drift-test it was a backup-retention edit on a
                # child resource, 45 minutes later). Leaving it in place made the
                # record assert "a policy did this, and the person who did it was
                # <name>" - and agent/prompts.py tells the analysis to cite
                # changed_by directly. Keep the fact, move it out of the field
                # that reads as causation.
                "changed_by": None,
                "last_write_by": (drift.get("change_origin") or {}).get("changed_by"),
                "last_write_at": (drift.get("change_origin") or {}).get("timestamp"),
                "reason": (
                    f"Tag value imposed in-flight by the {_MODIFY_EFFECT} effect of "
                    f"inherit-tag assignment '{first['policy_assignment']}'"
                    + (f" at scope {first['policy_scope']}" if first.get("policy_scope") else "")
                    + "; no other property drifted."
                ),
            }

    _prune_property_drift_summary(report_data, required)
    if claimed:
        logger.info(
            f"Attributed {claimed} tag value(s) to in-scope policy assignments "
            f"(in-flight Modify - invisible to activity-log attribution)"
        )
    return claimed


def _split_policy_and_tag_owners(report_data: dict) -> list:
    """Phase 3/4 tail: split policy/system-enforced changes out of the actionable
    drift set and tag each actionable drift with its owner. Runs AFTER the Claude
    analysis, which sees the full attributed (pre-split) set. Returns the
    actionable list; report_data['drifts'] is replaced with it and policy-enforced
    changes move to report_data['policy_enforced_drifts'].
    """
    # change_origin.expected is True for POLICY_DINE / POLICY_MODIFY /
    # POLICY_REMEDIATION / SYSTEM_MANAGED - detected and shown in a dedicated
    # governance section, but NOT actionable drift.
    actionable, policy_enforced = [], []
    for drift in report_data.get("drifts", []):
        if (drift.get("change_origin") or {}).get("expected") is True:
            policy_enforced.append(drift)
        else:
            actionable.append(drift)
    if policy_enforced:
        logger.info(
            f"Split out {len(policy_enforced)} policy/system-enforced change(s) "
            f"(detected, not counted as actionable drift)"
        )
    report_data["drifts"] = actionable
    report_data["policy_enforced_drifts"] = policy_enforced

    # Phase 4: tag each actionable drift with its owner (platform vs workload).
    # matched_unresolvable entries are informational, not drift - keep them out of
    # the owner counts.
    for drift in actionable:
        drift["owner"] = classify_owner(drift.get("type", ""), drift)
    owner_counts = {}
    for drift in actionable:
        if drift.get("drift_type") == "matched_unresolvable":
            continue
        owner_counts[drift["owner"]] = owner_counts.get(drift["owner"], 0) + 1
    if owner_counts:
        logger.info(f"Actionable drift by owner: {owner_counts}")

    return actionable


def _build_lifecycle_and_split(report_data: dict, resource_group: str) -> list:
    """Back-compat wrapper: attribute lifecycle then split + tag owners in one
    call. main() calls the two phases separately so attribution lands before the
    Claude analysis; retained for callers/tests that want the combined step.
    """
    _attribute_lifecycle(report_data, resource_group)
    _claim_policy_required_tags(report_data)
    return _split_policy_and_tag_owners(report_data)
