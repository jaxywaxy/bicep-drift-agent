"""
Azure deployment stack drift detection.

The third sidecar comparator, after tools/rbac.py and tools/policy.py. Like
those, deployment stacks are invisible to the normal pipeline: Resource Graph
does NOT index Microsoft.Resources/deploymentStacks (verified - the Resources
table returns zero rows for the type), so the stack is fetched straight from
ARM REST and compared on its own terms.

Two very different things are checked here, and it matters which is which:

  1. ENFORCEMENT POSTURE - the stack's own denySettings / actionOnUnmanage /
     provisioning state. A stack carries no templateLink, tags or description
     recording what it was SUPPOSED to be, so unlike every other comparator
     there is no template to diff against. Desired state is declared in the LZ
     config (`deployment_stack.expect`) and NOTHING is asserted unless it is
     declared there. Never snapshot the live values as a baseline: a stack sat
     at `mode: none` would silently bless its own weakness forever.

  2. OWNERSHIP - the stack's `resources[]` is an AUTHORITATIVE list of what
     this IaC owns. The rest of the engine infers ownership from the resource
     group boundary, which is only a proxy and is the engine's largest source
     of false extras. Where a stack exists, its managed list replaces that
     guess: annotate_stack_ownership() tags each extra_in_azure with whether
     the stack claims it.

Deliberately NOT implemented: matching bicep-declared resources against the
managed list (template resource ids aren't resolvable at compile time), and
managed-but-missing for CHILD resources (live state expansion is partial by
type, so their absence from the live set is not evidence of deletion - see
_missing_managed_resources).

Opt-in: this runs only when a check declares `deployment_stack` in its LZ
config. Estates that don't deploy with stacks get nothing and see nothing.
"""

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .http_util import urlopen_checked

logger = logging.getLogger(__name__)

STACK_TYPE = "Microsoft.Resources/deploymentStacks"

# 2024-03-01 is the current GA version (2025-07-01 also ships, but adds only
# extension/external-input fields this comparator does not read).
STACK_API_VERSION = "2024-03-01"
RG_API_VERSION = "2021-04-01"

ARM = "https://management.azure.com"

# denySettings.mode, weakest first. A live mode that sits BELOW the declared
# expectation is a weakening; above it is stricter than asked for and is
# reported as info rather than treated as compliant drift-free.
DENY_MODE_STRENGTH = {
    "none": 0,
    "denydelete": 1,
    "denywriteanddelete": 2,
}


def stack_drift_enabled() -> bool:
    """Stack scanning is OPT-IN: it needs a configured stack to mean anything.

    INCLUDE_DEPLOYMENT_STACKS=false force-disables it even when configured.
    """
    if os.environ.get("INCLUDE_DEPLOYMENT_STACKS", "true").strip().lower() in (
        "false", "0", "no", "off",
    ):
        return False
    return load_stack_config() is not None


def load_stack_config() -> Optional[Dict]:
    """Parse the check's `deployment_stack` block from DRIFT_DEPLOYMENT_STACK.

    The workflow binds the LZ config's block to that env var as JSON (the LZ
    config is untrusted input, so it is never interpolated into shell). Returns
    None when unset, empty, malformed, or missing a stack name - all of which
    mean "this check has no stack", never an error.
    """
    raw = (os.environ.get("DRIFT_DEPLOYMENT_STACK") or "").strip()
    if not raw or raw in ("null", "{}", "[]"):
        return None
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("DRIFT_DEPLOYMENT_STACK is not valid JSON; skipping stack drift")
        return None
    if not isinstance(cfg, dict) or not cfg.get("name"):
        logger.warning("DRIFT_DEPLOYMENT_STACK has no stack 'name'; skipping stack drift")
        return None
    return cfg


def _stack_url(cfg: Dict, subscription_id: str, resource_group: Optional[str]) -> str:
    """Build the ARM URL for the configured stack's scope."""
    name = cfg["name"]
    scope = (cfg.get("scope") or "subscription").strip().lower()
    if scope in ("management_group", "managementgroup", "mg"):
        mg = cfg.get("management_group")
        if not mg:
            raise ValueError("deployment_stack scope is management_group but no management_group given")
        base = f"{ARM}/providers/Microsoft.Management/managementGroups/{mg}"
    elif scope in ("resource_group", "resourcegroup", "rg"):
        rg = cfg.get("resource_group") or resource_group
        if not rg:
            raise ValueError("deployment_stack scope is resource_group but no resource group given")
        base = f"{ARM}/subscriptions/{subscription_id}/resourceGroups/{rg}"
    else:
        base = f"{ARM}/subscriptions/{subscription_id}"
    return f"{base}/providers/{STACK_TYPE}/{name}?api-version={STACK_API_VERSION}"


def _arm_get(url: str, token: str) -> Optional[Dict]:
    """GET an ARM URL. Returns None on 404; raises on anything else."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen_checked(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def fetch_deployment_stack(
    cfg: Dict,
    subscription_id: str,
    resource_group: Optional[str] = None,
    token: Optional[str] = None,
) -> Tuple[Optional[Dict], str]:
    """Fetch the configured stack from ARM REST.

    Returns (stack, token). A 404 yields (None, token) - the stack is genuinely
    absent, which is itself drift and is reported by compare_deployment_stack.

    Any OTHER failure RAISES, for the same reason policy fetching does: an
    empty result is indistinguishable from "the stack is gone", and a transient
    error would otherwise be reported as a deleted stack. The caller catches and
    skips the whole check.
    """
    if not token:
        from azure.identity import DefaultAzureCredential
        token = DefaultAzureCredential().get_token(f"{ARM}/.default").token

    url = _stack_url(cfg, subscription_id, resource_group)
    stack = _arm_get(url, token)
    if stack is None:
        logger.warning(f"Deployment stack '{cfg['name']}' not found at its configured scope")
    else:
        managed = len((stack.get("properties") or {}).get("resources") or [])
        logger.info(f"Deployment stack '{cfg['name']}': {managed} managed resource(s)")
    return stack, token


# ---------------------------------------------------------------------------
# Enforcement posture
# ---------------------------------------------------------------------------

def _changed(path: str, desired: Any, actual: Any, severity: str) -> Tuple[str, Dict]:
    return path, {"desired": desired, "actual": actual, "severity": severity}


def _flatten_error_messages(error: Any) -> List[str]:
    """Collect the LEAF messages from an ARM error tree.

    Azure nests the real cause: the outer nodes carry generic wrappers
    ("One or more resources could not be deployed", "At least one resource
    deployment operation failed") while the leaf - the node with no further
    `details` - carries the actionable text ("A vault with the same name
    already exists in deleted state..."). Walking to the leaves is what turns a
    correlation id into a diagnosis.

    Deduped, order-preserving. Falls back to nothing if the tree is empty; the
    caller then uses the top-level message.
    """
    out: List[str] = []
    seen = set()

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        details = node.get("details")
        if isinstance(details, list) and details:
            for child in details:
                walk(child)
            return
        msg = node.get("message")
        if msg and msg not in seen:
            seen.add(msg)
            out.append(msg)

    walk(error)
    return out


def _compare_deny_settings(expect: Dict, live: Dict) -> Dict[str, Dict]:
    """Compare denySettings against declared expectations.

    Only declared keys are asserted. Mode is compared by STRENGTH, not equality,
    so a stack that is stricter than asked for is not reported as drift.
    Excluded principals/actions are exact-set compares (an added exclusion is a
    hole punched in the deny assignment), matching the Key Vault ACL treatment.
    """
    changed: Dict[str, Dict] = {}
    if not expect:
        return changed

    if "mode" in expect:
        want, got = str(expect["mode"]), str(live.get("mode", ""))
        want_s = DENY_MODE_STRENGTH.get(want.lower())
        got_s = DENY_MODE_STRENGTH.get(got.lower())
        if want_s is None:
            logger.warning(f"Unknown expected denySettings.mode '{want}'; comparing as a string")
            if want.lower() != got.lower():
                k, v = _changed("denySettings.mode", want, got, "critical")
                changed[k] = v
        elif got_s is None or got_s < want_s:
            k, v = _changed("denySettings.mode", want, got, "critical")
            changed[k] = v
        elif got_s > want_s:
            k, v = _changed("denySettings.mode", want, got, "info")
            changed[k] = v

    # A sub- or MG-scoped stack with applyToChildScopes off puts the deny
    # assignment on the resource GROUPS only, not the resources inside them -
    # the protection looks enabled while the resources stay writable. Its own
    # finding, not a footnote on the mode.
    if "apply_to_child_scopes" in expect:
        want = bool(expect["apply_to_child_scopes"])
        got = bool(live.get("applyToChildScopes"))
        if want != got:
            k, v = _changed("denySettings.applyToChildScopes", want, got, "critical")
            changed[k] = v

    for key, live_key in (("excluded_principals", "excludedPrincipals"),
                          ("excluded_actions", "excludedActions")):
        if key not in expect:
            continue
        want = sorted(str(x).lower() for x in (expect[key] or []))
        got = sorted(str(x).lower() for x in (live.get(live_key) or []))
        if want != got:
            k, v = _changed(
                f"denySettings.{live_key}", expect[key] or [], live.get(live_key) or [],
                "critical" if set(got) - set(want) else "warning",
            )
            changed[k] = v
    return changed


def _compare_action_on_unmanage(expect: Dict, live: Dict) -> Dict[str, Dict]:
    """Compare actionOnUnmanage. A `delete` regressed to `detach` means resources
    silently outlive the stack that stopped declaring them - the orphaned-cost
    path, so it is warning rather than critical (nothing is exposed, but the
    bill keeps running)."""
    changed: Dict[str, Dict] = {}
    if not expect:
        return changed
    for key, live_key in (("resources", "resources"),
                          ("resource_groups", "resourceGroups"),
                          ("management_groups", "managementGroups"),
                          ("resources_without_delete_support", "resourcesWithoutDeleteSupport")):
        if key not in expect:
            continue
        want, got = str(expect[key]), str(live.get(live_key, ""))
        if want.lower() != got.lower():
            k, v = _changed(f"actionOnUnmanage.{live_key}", want, got, "warning")
            changed[k] = v
    return changed


def _compare_stack_health(expect: Dict, props: Dict) -> Dict[str, Dict]:
    """Provisioning state and the stack's own resource-outcome lists.

    A failed stack means the last IaC run did not fully apply, so "no drift"
    from the template compare would be actively misleading - the template was
    never landed. Reported critical for exactly that reason.
    """
    changed: Dict[str, Dict] = {}
    want_state = str(expect.get("provisioning_state", "succeeded"))
    got_state = str(props.get("provisioningState", ""))
    if got_state.lower() != want_state.lower():
        k, v = _changed("provisioningState", want_state, got_state, "critical")
        changed[k] = v
        err = props.get("error") or {}
        if err:
            # The top-level message is a generic wrapper ("One or more resources
            # could not be deployed. Correlation id: ..."); the ACTIONABLE cause
            # (soft-deleted vault, quota, policy Deny) lives in the leaves of the
            # nested error.details tree. Surface the leaves - that is the whole
            # point of reporting a failed stack.
            leaves = _flatten_error_messages(err)
            k, v = _changed("error.message", None,
                            "; ".join(leaves) or err.get("message") or str(err), "critical")
            changed[k] = v

    # failedResources carries a per-resource error object; keep it, because that
    # is where Azure attaches the cause for each failed resource individually.
    failed = props.get("failedResources") or []
    if failed:
        k, v = _changed("failedResources", [], [
            {
                "id": i.get("id"),
                "code": (i.get("error") or {}).get("code"),
                "message": "; ".join(_flatten_error_messages(i.get("error") or {})) or None,
            }
            for i in failed if isinstance(i, dict)
        ], "critical")
        changed[k] = v

    for live_key, severity in (("detachedResources", "warning"),
                               ("deletedResources", "info")):
        items = props.get(live_key) or []
        if items:
            k, v = _changed(live_key, [], [i.get("id") for i in items if isinstance(i, dict)], severity)
            changed[k] = v
    return changed


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------

def _norm_id(rid: Any) -> str:
    return str(rid or "").rstrip("/").lower()


def _managed_raw_ids(stack: Optional[Dict]) -> set:
    """Owned resource ids in Azure's own casing (status: managed)."""
    if not stack:
        return set()
    return {
        str(r["id"])
        for r in ((stack.get("properties") or {}).get("resources") or [])
        if str(r.get("status", "")).lower() == "managed" and r.get("id")
    }


def managed_ids(stack: Optional[Dict]) -> set:
    """The stack's authoritative set of owned resource ids, lowercased for
    matching. Use _managed_raw_ids() when the id will be shown to a human."""
    return {_norm_id(rid) for rid in _managed_raw_ids(stack)}


def _is_bare_resource_group(rid: str) -> bool:
    return "/providers/" not in rid and "/resourcegroups/" in rid


def _is_top_level(rid: str) -> bool:
    """True for `.../providers/{ns}/{type}/{name}` with no child segments.

    Child resources are excluded from the managed-but-missing check: the live
    state expands children only for the types it knows about, so a child's
    absence from the live set is not evidence that it was deleted.
    """
    tail = re.split(r"/providers/", rid, flags=re.IGNORECASE)[-1]
    return len(tail.strip("/").split("/")) == 3


def _in_scan_scope(rid: str, scope: str, subscription_id: str, resource_group: Optional[str]) -> bool:
    """Whether the scan's live state could have seen this id at all.

    A subscription-scoped stack manages resources across many RGs while an
    RG-scoped scan sees one; comparing the full managed list against a partial
    live set would fabricate a deletion for every resource outside the scan.
    """
    if subscription_id and f"/subscriptions/{subscription_id.lower()}" not in rid:
        return False
    if scope == "resource_group" and resource_group:
        return f"/resourcegroups/{resource_group.lower()}" in rid
    return True


def _missing_managed_resources(
    stack: Dict,
    live_resources: List[Dict],
    subscription_id: str,
    resource_group: Optional[str],
    scope: str,
    token: str,
) -> List[Dict]:
    """Resources the stack still claims to manage that no longer exist.

    The stack's bookkeeping and reality have diverged: something was deleted
    out-of-band without the stack being updated. Candidates are confirmed by a
    direct ARM lookup before being reported - absence from the live set alone
    is not proof, and a fabricated deletion is the worst finding this engine
    can emit.
    """
    live_ids = {_norm_id(r.get("id")) for r in live_resources if r.get("id")}
    drifts: List[Dict] = []

    # Match on lowercased ids, but report the type and name in Azure's own
    # casing - drift type strings are matched by ignore patterns and rendered
    # in reports, where 'microsoft.storage/storageaccounts' reads as a bug.
    for raw_id in sorted(_managed_raw_ids(stack)):
        rid = _norm_id(raw_id)
        if rid in live_ids:
            continue
        if not _in_scan_scope(rid, scope, subscription_id, resource_group):
            continue

        if _is_bare_resource_group(rid):
            name = raw_id.rstrip("/").rsplit("/", 1)[-1]
            url = f"{ARM}/subscriptions/{subscription_id}/resourcegroups/{name}?api-version={RG_API_VERSION}"
            rtype = "Microsoft.Resources/resourceGroups"
        elif _is_top_level(rid):
            tail = re.split(r"/providers/", raw_id, flags=re.IGNORECASE)[-1].strip("/").split("/")
            rtype = f"{tail[0]}/{tail[1]}"
            name = tail[2]
            url = None  # confirmed via Resource Graph below
        else:
            logger.debug(f"Stack-managed child not checked for deletion (partial live expansion): {rid}")
            continue

        try:
            if url is not None:
                if _arm_get(url, token) is not None:
                    continue  # still there; the live set simply didn't list it
            elif _resource_exists(rid, subscription_id, token):
                continue
        except Exception as e:
            logger.warning(f"Could not confirm whether {rid} still exists ({e}); not reporting it")
            continue

        drifts.append({
            "type": rtype,
            "name": name,
            "drift_type": "missing_in_azure",
            "details": {
                "resource_id": raw_id,
                "stack_name": stack.get("name"),
                "reason": (
                    "The deployment stack still lists this resource as managed, but it no "
                    "longer exists. It was deleted out-of-band without updating the stack, "
                    "so the stack's ownership record is stale."
                ),
            },
        })

    if drifts:
        logger.info(f"Stack drift: {len(drifts)} managed resource(s) no longer exist")
    return drifts


def _resource_exists(rid: str, subscription_id: str, token: str) -> bool:
    """Confirm a top-level resource still exists, via Resource Graph by id.

    Resource Graph needs no per-type api-version, which a generic ARM GET would.
    """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    client = ResourceGraphClient(DefaultAzureCredential())
    safe = rid.replace("'", "")
    response = client.resources(QueryRequest(
        subscriptions=[subscription_id],
        query=f"Resources | where id =~ '{safe}' | project id",
    ))
    return bool(response.data)


def annotate_stack_ownership(
    drifts: List[Any],
    stack: Optional[Dict],
    live_resources: Optional[List[Dict]] = None,
) -> int:
    """Tag each extra_in_azure with whether the stack actually owns it.

    This is the ownership oracle replacing the resource-group-boundary guess:

      * stack-managed -> the stack still owns it but the template stopped
        declaring it. Real drift, and the fix is a stack update, not a delete.
      * unmanaged -> nothing owns it. A high-confidence orphan rather than an
        inference from which RG it happens to sit in.

    Extra drifts carry no resource id of their own (diff_states records type and
    name), so ids are resolved from the live state by (type, name). Anything
    that doesn't resolve is left UNTAGGED rather than assumed unmanaged - an
    absent tag means "not established", which is the honest reading and keeps a
    missing id from being rendered as an orphan.

    Annotates in place; returns how many drifts were tagged.
    """
    owned = managed_ids(stack)
    if not owned:
        return 0

    by_key = {}
    for r in (live_resources or []):
        if r.get("id") and r.get("type") and r.get("name"):
            by_key.setdefault((str(r["type"]).lower(), str(r["name"]).lower()), r["id"])

    tagged = 0
    for d in drifts:
        details = d.details if hasattr(d, "details") else d.get("details")
        drift_type = d.drift_type if hasattr(d, "drift_type") else d.get("drift_type")
        if drift_type != "extra_in_azure" or not isinstance(details, dict):
            continue
        rtype = d.resource_type if hasattr(d, "resource_type") else d.get("type")
        rname = d.resource_name if hasattr(d, "resource_name") else d.get("name")
        rid = _norm_id(
            details.get("resource_id")
            or details.get("id")
            or by_key.get((str(rtype or "").lower(), str(rname or "").lower()))
        )
        if not rid:
            continue
        details["stack_ownership"] = "managed" if rid in owned else "unmanaged"
        details["stack_name"] = stack.get("name")
        tagged += 1
    if tagged:
        logger.info(f"Stack ownership annotated on {tagged} extra resource(s)")
    return tagged


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def compare_deployment_stack(
    cfg: Dict,
    stack: Optional[Dict],
    live_resources: List[Dict],
    subscription_id: str,
    resource_group: Optional[str] = None,
    scope: str = "resource_group",
    token: Optional[str] = None,
) -> List[Dict]:
    """Compare a configured deployment stack against its declared expectations.

    Returns drift dicts in the same shape rbac.py and policy.py emit, so the
    caller converts them to ResourceDrift unchanged.
    """
    name = cfg.get("name")

    if stack is None:
        return [{
            "type": STACK_TYPE,
            "name": name,
            "drift_type": "missing_in_azure",
            "details": {
                "reason": (
                    "The check declares this deployment stack, but no stack of that name "
                    "exists at the configured scope. Either it was deleted - taking its deny "
                    "assignments and ownership record with it - or the estate is being "
                    "deployed without it."
                ),
                "scope": cfg.get("scope") or "subscription",
            },
        }]

    props = stack.get("properties") or {}
    expect = cfg.get("expect") or {}

    changed: Dict[str, Dict] = {}
    changed.update(_compare_deny_settings(expect.get("deny_settings") or {},
                                          props.get("denySettings") or {}))
    changed.update(_compare_action_on_unmanage(expect.get("action_on_unmanage") or {},
                                               props.get("actionOnUnmanage") or {}))
    changed.update(_compare_stack_health(expect, props))

    drifts: List[Dict] = []
    if changed:
        drifts.append({
            "type": STACK_TYPE,
            "name": name,
            "drift_type": "property_drift",
            "details": {
                "changed_properties": changed,
                "resource_id": stack.get("id"),
            },
        })

    if token:
        try:
            drifts.extend(_missing_managed_resources(
                stack, live_resources, subscription_id, resource_group, scope, token
            ))
        except Exception as e:
            logger.warning(f"Stack managed-resource check failed (continuing): {e}")

    if not expect:
        logger.info(
            f"Deployment stack '{name}' has no `expect` block: ownership is still checked, "
            "but no enforcement posture is asserted (deny settings are NOT compared)."
        )
    return drifts


def dedupe_against(stack_drifts: List[Dict], existing: List[Any]) -> List[Dict]:
    """Drop stack drifts the main compare already reported for the same resource.

    A stack-managed resource that the template also declares would otherwise be
    reported missing twice - once by the template compare, once by the stack.
    """
    seen = {
        ((d.resource_type if hasattr(d, "resource_type") else d.get("type") or "").lower(),
         (d.resource_name if hasattr(d, "resource_name") else d.get("name") or "").lower())
        for d in existing
    }
    kept = [d for d in stack_drifts
            if ((d.get("type") or "").lower(), (d.get("name") or "").lower()) not in seen]
    if len(kept) != len(stack_drifts):
        logger.debug(f"Suppressed {len(stack_drifts) - len(kept)} stack drift(s) already reported")
    return kept
