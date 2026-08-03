"""
Query Azure Activity Log to determine change origin and history.

Activity Log provides audit trails for all Azure API calls, allowing us to
determine who made changes, when, how (via what method), and if it was
policy-enforced (DINE, Modify, Remediation) or manual.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.identity import DefaultAzureCredential

from .rg_selector import is_glob

try:
    from .http_util import urlopen_checked
except ImportError:
    from http_util import urlopen_checked

logger = logging.getLogger(__name__)


def fetch_policy_principal_ids(subscription_id: str, resource_group: str | None = None) -> dict:
    """
    Return a map of managed-identity principalId -> policy display name for all
    policy assignments in the subscription.

    DeployIfNotExists / Modify policies act through the assignment's managed
    identity, so the Activity Log 'caller' for a policy-driven change is that
    identity's GUID (not the string 'Azure Policy', and often without a
    policyAssignmentId on the resource write). Mapping principalId -> policy name
    lets us both attribute the change to policy AND name the responsible policy.
    Keys are lowercased GUIDs. Never raises (returns {} on failure).
    """
    import json as _json
    import urllib.request

    try:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urlopen_checked(req, timeout=30) as resp:
            data = _json.load(resp)
        mapping = {}
        for a in data.get("value", []):
            pid = (a.get("identity") or {}).get("principalId")
            if pid:
                props = a.get("properties", {}) or {}
                name = props.get("displayName") or a.get("name") or "Azure Policy"
                mapping[pid.lower()] = name
        logger.info(f"Found {len(mapping)} policy-assignment managed identity principal(s)")
        return mapping
    except Exception as e:
        logger.warning(f"Could not fetch policy assignment principals: {e}")
        return {}


def detect_scanning_identity(credential: Any | None = None) -> set:
    """
    Return the identity aliases (lowercased) of the principal this scan
    authenticates as, read from the access token's own claims.

    The drift agent typically runs in the SAME pipeline (OIDC app) that
    deploys the estate, so changes made by "self" are IaC deployments, not
    manual drift. Discovering the identity at runtime makes this work at any
    client with zero configuration - no deployer SP needs to be known in
    advance (DRIFT_AUTHORIZED_DEPLOYERS covers deploy-with-A/scan-with-B
    setups).

    Aliases cover every form Activity Log 'caller' takes: 'oid' (service
    principal / managed identity object id - the usual caller GUID), 'appid'
    (client id), and 'upn'/'unique_name' (user email for az-login-as-user).
    Decoding our own token is claim inspection, not signature validation - no
    trust decision is made from it. Never raises (returns empty set on
    failure).
    """
    import base64
    import json as _json

    try:
        cred = credential or DefaultAzureCredential()
        token = cred.get_token("https://management.azure.com/.default").token
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore stripped padding
        claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
        aliases = {
            str(claims[c]).lower()
            for c in ("oid", "appid", "upn", "unique_name")
            if claims.get(c)
        }
        logger.info(f"Scanning identity aliases: {sorted(aliases)}")
        return aliases
    except Exception as e:
        logger.warning(f"Could not detect scanning identity: {e}")
        return set()


def fetch_resource_group_activity(
    subscription_id: str,
    resource_group: str,
    days: int = 30,
    credential: Any | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch ALL Azure Monitor Activity Log events for a scan's scope, once.

    `resource_group` is the scan selector, not necessarily a resource group: a
    subscription-scoped scan passes '*' or a glob, and the whole subscription
    window is fetched for those (the API compares resourceGroupName literally,
    so filtering on a selector matches nothing).

    The Activity Log $filter only supports a limited set of fields
    (eventTimestamp, resourceGroupName, resourceId, resourceProvider, correlationId)
    combined with 'and' ONLY - no 'status', 'resourceType', or 'or'. So we pull the
    whole window here and let callers match individual resources in memory
    (see match_activity_for_resource) instead of issuing one API query per drift.

    Returns a list of normalized entry dicts (may be empty). Never raises.
    """
    if not resource_group:
        logger.warning("No resource group provided; skipping activity log fetch")
        return []
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        credential = credential or DefaultAzureCredential()
        client = MonitorManagementClient(credential, subscription_id)

        # Timezone-aware UTC (datetime.utcnow() is deprecated in Python 3.12+).
        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        # A subscription-scoped scan is driven by '*' or a glob. The API has no
        # wildcard for resourceGroupName - it compares literally - so filtering
        # on the selector asked for a resource group actually named '*' and
        # returned nothing, leaving EVERY drift unattributed behind the reason
        # "no activity log entries found". Fetch the subscription window instead
        # and let match_activity_for_resource pick per resource by resource_id,
        # which is already how the RG case works: pull once, match in memory.
        whole_subscription = is_glob(resource_group)
        clauses = [f"eventTimestamp ge '{start_time.isoformat()}'"]
        if not whole_subscription:
            clauses.append(f"resourceGroupName eq '{resource_group}'")
        filter_str = " and ".join(clauses)
        scope_label = f"subscription (selector '{resource_group}')" if whole_subscription \
            else f"resource group '{resource_group}'"
        logger.debug(f"Activity Log query: scope={scope_label}, days={days}, filter={filter_str}")

        entries = [_entry_from_log(log) for log in client.activity_logs.list(filter=filter_str)]
        logger.info(f"Activity Log: fetched {len(entries)} event(s) for {scope_label}")
        return entries
    except Exception as e:
        logger.error(f"Failed to fetch Activity Log for '{resource_group}': {e}")
        return []


def deployed_name_from_event_id(resource_type: str, event_resource_id: str) -> str:
    """Extract the deployed name for resource_type from an activity-log id.

    A deleted placeholder-named resource (log-[86c9cbf6]) has no live row to
    read the real name from, but its activity-log event carries the true Azure
    id (.../workspaces/log-3s7c7weddxr3s). Parse the provider section -
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


def _shared_affix_len(declared: str, deployed: str) -> int:
    """Longest common prefix or suffix between two names, case-insensitively.

    A partially-resolved Bicep name keeps its literal lead ('func-drift-' in
    'func-drift-[86c9cbf6]') or, for a child, its literal tail ('/kv-audit').

    Residual rule, kept only for a name still carrying raw expression text,
    which has no placeholder shape to anchor on. It is deliberately NOT the
    primary test any more: shared length cannot separate two names built to the
    same convention ('asp-test-drift' vs 'asp-func-drift-test' share 'asp-').
    smart_matching._find_best_match still selects on this signal, and that
    asymmetry is intended - it pairs a declared resource to a live one and can
    fall back to pairing in order, whereas a wrong event here asserts that a
    named person did something they did not.
    """
    a, b = declared.lower(), deployed.lower()
    prefix = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        prefix += 1
    suffix = 0
    for ca, cb in zip(reversed(a), reversed(b)):
        if ca != cb:
            break
        suffix += 1
    return max(prefix, suffix)


def _segment_pattern(declared_segment: str) -> str:
    """One name segment as a regex, each placeholder hole standing for the
    runtime string it will resolve to."""
    return "".join(
        "[^/]+" if part.startswith("[") else re.escape(part)
        for part in _PLACEHOLDER_RE.split(declared_segment)
        if part
    )


def _segments_match(declared_name: str, deployed_name: str) -> bool:
    """Does the deployed name fit the declared name's resolved shape?

    A partially resolved name is a template: literal text around placeholder
    holes ('func-drift-[86c9cbf6]', 'kvdrift[86c9cbf6]/kv-audit'). Compared
    segment by segment, so a hole cannot swallow a '/' and match across the
    parent/child boundary, and each segment must match end to end - a name is
    not "compatible" with one it merely shares a lead with.

    Aligned from the RIGHT and only over the segments both names have: an
    extension resource's event id names just the extension ('kv-audit') while
    the declared name qualifies it with its parent
    ('kvdrift[86c9cbf6]/kv-audit'), and the leaf is the part that identifies it.
    """
    declared = declared_name.split("/")
    deployed = deployed_name.split("/")
    depth = min(len(declared), len(deployed))
    compared = declared[-depth:]
    # The literal text IS the evidence. A name resolving to nothing but holes
    # ('[86c9cbf6]', from a resource named `format('{0}', uniqueString(...))`)
    # would otherwise compile to a bare '[^/]+' and match every sibling of its
    # type - the wildcard readmitting exactly the adoption #350 fixed.
    if not any(
        part and not part.startswith("[")
        for segment in compared
        for part in _PLACEHOLDER_RE.split(segment)
    ):
        return False
    return all(
        re.fullmatch(_segment_pattern(d), live, flags=re.IGNORECASE)
        for d, live in zip(compared, deployed[-depth:])
    )


def could_be_same_resource(declared_name: str, deployed_name: str) -> bool:
    """Could these two names denote the same resource?

    The type-substring fallback below collects EVERY event of a type, so two
    same-type siblings are indistinguishable by type alone. Live (issue #350):
    the function app 'func-drift-[86c9cbf6]' adopted the App Service
    'app-test-drift' - its name, its deletion event, and its actor - because
    both are Microsoft.Web/sites. The func app's own deletion vanished from the
    report and 'app-test-drift' appeared deleted twice.

    The test is the declared name's own shape, not how much text two names
    happen to share. A shared-affix threshold accepted 'asp-test-drift' as
    'asp-func-drift-test' on the four characters 'asp-' - and Azure naming
    conventions mean every resource of a type shares a lead like that by
    design, so it discriminates nothing. Both App Service Plans in the
    2026-07-28 teardown adopted one event this way.
    """
    if not declared_name or not deployed_name:
        return False
    if declared_name.lower() == deployed_name.lower():
        return True
    if _segments_match(declared_name, deployed_name):
        return True
    # A fully resolved name is a COMPLETE name, so anything it doesn't match is
    # a different resource however much of a convention they share. A name still
    # carrying raw expression text has no shape to anchor on, so it keeps the
    # shared-affix heuristic rather than losing attribution outright.
    if "(" in declared_name:
        return _shared_affix_len(declared_name, deployed_name) >= _MIN_SHARED_AFFIX
    return False


#: A resolved runtime placeholder: uniqueString/guid render as '[8 hex chars]',
#: copyIndex and friends keep their bracketed call.
_PLACEHOLDER_RE = re.compile(r"(\[[^\]]*\])")

# Three characters of shared literal name. Same threshold smart_matching accepts
# a candidate on; below it the "match" is a coincidence of one or two letters.
_MIN_SHARED_AFFIX = 3


def match_activity_for_resource(
    rg_events: list[dict[str, Any]],
    resource_id: str,
    resource_type: str | None = None,
) -> list[dict[str, Any]]:
    """
    From a pre-fetched list of RG activity events, return the ones for a resource.

    Matching:
      1. exact / prefix resource-ID match (case-insensitive) - live resources
      2. resource-type substring - deleted resources whose exact ID can't be
         built - narrowed to events whose NAME could be this resource's
    """
    resource_id_lower = (resource_id or "").lower()
    resource_type_lower = (resource_type or "").lower()

    # Primary: events for THIS resource or its sub-resources (exact id, or the
    # event id is a child path 'id/...'). We do NOT match the reverse direction
    # (our id starts with the event id) - that would wrongly match a child
    # resource (e.g. a lock) to its parent's events (the storage account writes).
    matched = [
        e for e in rg_events
        if resource_id_lower and (
            (e.get("resource_id") or "").lower() == resource_id_lower
            or (e.get("resource_id") or "").lower().startswith(resource_id_lower + "/")
        )
    ]
    if matched:
        return matched

    # Fallback ONLY for resources with no id match (e.g. deleted resources whose
    # exact id can't be resolved): match by resource type substring.
    if resource_type_lower:
        by_type = [
            e for e in rg_events
            if resource_type_lower in (e.get("resource_id") or "").lower()
        ]
        # The declared name is the tail of the id we constructed; keep only the
        # events whose own name could belong to it. Returning nothing is the
        # right failure mode - an unattributed drift reads "no event accounts
        # for this change" (#337), whereas a sibling's event names the wrong
        # actor AND renames the resource to the sibling.
        declared_name = deployed_name_from_event_id(resource_type or "", resource_id)
        if not declared_name:
            return by_type
        return [
            e for e in by_type
            if could_be_same_resource(
                declared_name,
                deployed_name_from_event_id(
                    resource_type or "", e.get("resource_id") or ""),
            )
        ]
    return []


def _entry_from_log(log: Any) -> dict[str, Any]:
    """Normalize an Azure Monitor activity-log record into our dict shape."""
    props = log.properties if log.properties else {}
    return {
        'timestamp': log.event_timestamp,
        'caller': log.caller,
        'operation': log.operation_name.value if log.operation_name else "Unknown",
        'status': log.status.value if log.status else "Unknown",
        'properties': props,
        'resource_id': log.resource_id,
        'method': props.get('method') if isinstance(props, dict) else None,
        'authorization': log.authorization if hasattr(log, 'authorization') else None,
    }
