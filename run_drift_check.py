"""
run_drift_check.py

Phase 1 entry point — runs the full drift check WITHOUT an agent loop.
Get this working first. The agent comes later.

Usage:
    python run_drift_check.py <bicep-file> <resource-group>

Example:
    python run_drift_check.py ./infra/main.bicep my-resource-group
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from orchestration.targeting import _find_repo_ignore
from tools.compile_bicep import (
    compile_bicep,
    detect_deployment_scope,
    extract_resources_from_arm,
)
from tools.deployment_stacks import (
    annotate_stack_ownership,
    compare_deployment_stack,
    dedupe_against,
    fetch_deployment_stack,
    load_stack_config,
    stack_drift_enabled,
)
from tools.diff_states import ResourceDrift, diff_states, format_drift_report
from tools.get_live_state import (
    CollectionGaps,
    fetch_cross_subscription_resources,
    fetch_declared_defender_pricings,
    fetch_declared_workspace_tables,
    get_live_state,
    qualify_extension_resource_names,
    resource_group_exists,
    ScopeNotFoundError,
)
from tools.ignore_patterns import IgnorePatternList
from tools.logger import get_logger, setup_logging
from tools.normalizer.flatten import SkippedDeclarations
from tools.policy import (
    compare_policy_resources,
    fetch_policy_resources,
    fetch_resource_group_tags,
    policy_drift_enabled,
    resolve_policy_required_tags,
)
from tools.rbac import (
    collect_managed_identity_principals,
    compare_role_assignments,
    fetch_role_assignments,
    rbac_enabled,
)
from tools.redact import redact_secrets
from tools.rg_selector import rg_label

logger = get_logger(__name__)


def _load_arm_parameters_env() -> dict:
    """Parse ARM_PARAMETERS if set. Returns {} on absence or bad JSON."""
    raw = os.environ.get("ARM_PARAMETERS")
    if not raw:
        return {}
    try:
        params = json.loads(raw)
        logger.debug(f"Parameters from ARM_PARAMETERS: {params}")
        return params
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in ARM_PARAMETERS")
        return {}


def _coerce_bicepparam_value(raw: str):
    """Give a .bicepparam value its Bicep type instead of leaving it a string.

    A quoted value is a string; `true`/`false` are booleans and bare numerals
    are numbers, exactly as Bicep reads them. Returning everything as a string
    is wrong the moment a parameter feeds a resource PROPERTY: a declared
    `capacity` of '3' never equals the 3 Azure returns, so the scan invents
    property drift. Condition gates survived it by luck - the resolver happens
    to accept the string 'false' as well as False.

    Anything unrecognised (an expression, an array, an object) stays the raw
    string, which is what this line-parser could offer before.
    """
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    lowered = raw.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw.strip("'\"")


def _load_bicepparam_file(bicep_file: str, resource_group: str) -> dict:
    """Read parameters/<env>.bicepparam next to the bicep file (env = last RG segment).

    Simple line-by-line parser: `param name = 'value'` -> {name: "value"}. Strips
    // comments and surrounding quotes, and gives booleans and numbers their
    Bicep type (see _coerce_bicepparam_value) so a parameter feeding a numeric
    or boolean resource property compares against what Azure returns.
    """
    environment = resource_group.split('-')[-1]  # rg-prod → prod
    bicepparam_file = Path(bicep_file).parent / "parameters" / f"{environment}.bicepparam"
    if not bicepparam_file.exists():
        return {}
    try:
        with open(bicepparam_file, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning(f"Could not load {bicepparam_file.name}: {e}")
        return {}

    params: dict = {}
    for line in content.split('\n'):
        line = line.strip()
        if not (line.startswith('param ') and '=' in line):
            continue
        line = line.split('//')[0].strip()
        parts = line.replace('param ', '').split('=', 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        raw = parts[1].strip()
        value = _coerce_bicepparam_value(raw)
        if value != "":  # skip empty values, but keep False and 0
            params[key] = value
    if params:
        logger.debug(f"Parameters loaded from {bicepparam_file.name}: {params}")
    return params


def _load_arm_parameters_json(bicep_file: str) -> dict:
    """Read a sibling ARM parameters.json (standard `az deployment` layout).

    Flattens {parameters: {k: {value: v}}} -> {k: v}; keeps dict/list values
    intact so object params (tags) resolve as real objects.
    """
    params_json = Path(bicep_file).parent / "parameters.json"
    if not params_json.exists():
        return {}
    try:
        with open(params_json, encoding="utf-8") as f:
            raw = json.load(f).get("parameters", {})
    except Exception as e:
        logger.warning(f"Could not load {params_json}: {e}")
        return {}
    params = {
        k: v.get("value") for k, v in raw.items()
        if isinstance(v, dict) and "value" in v
    }
    if params:
        logger.info(f"Parameters loaded from {params_json}: {sorted(params)}")
    return params


def _resolve_parameter_overrides(bicep_file: str, resource_group: str) -> dict:
    """Resolve parameter overrides in precedence order: env > bicepparam > parameters.json."""
    env_params = _load_arm_parameters_env()
    if env_params:
        return env_params
    bicepparam = _load_bicepparam_file(bicep_file, resource_group)
    if bicepparam:
        return bicepparam
    return _load_arm_parameters_json(bicep_file)


def _compile_and_extract(bicep_file: str, param_overrides: dict,
                         skipped=None) -> tuple[list[dict], str]:
    """Compile Bicep → ARM and extract resources. Returns (arm_resources, deployment_scope)."""
    logger.info("Step 1: Compiling Bicep template...")
    try:
        arm_template = compile_bicep(bicep_file)
    except RuntimeError as e:
        logger.error(f"Failed to compile Bicep: {e}")
        raise

    deployment_scope = detect_deployment_scope(arm_template)
    if deployment_scope == "subscription":
        logger.info("Detected subscription-scoped template (Landing Zone)")

    try:
        arm_resources = extract_resources_from_arm(arm_template, param_overrides, skipped=skipped)
    except Exception as e:
        logger.error(f"Failed to extract resources: {e}", exc_info=True)
        raise

    logger.info(f"✓ {len(arm_resources)} resource(s) defined in Bicep (scope: {deployment_scope})")
    return arm_resources, deployment_scope


def _guard_unverifiable_scope(resource_group: str, bicep_file: str = "") -> None:
    """Refuse to report an empty live set we cannot attribute to an empty scope.

    Zero live resources has two causes that look identical here: the resource
    group exists and is empty (real, and every declared resource genuinely is
    missing), or it does not exist at all (a decommissioned/renamed RG, a stale
    lz-index entry, the wrong subscription). Resource Graph returns success with
    zero rows for BOTH, so only an explicit ARM read separates them.

    The check runs only on the empty result - the ambiguous case - so a normal
    scan pays nothing for it. An inconclusive answer aborts too: we cannot prove
    the scope exists, and 'unverified' must not render as one deletion per
    declared resource.
    """
    exists = resource_group_exists(resource_group, os.environ.get("AZURE_SUBSCRIPTION_ID"))
    if exists is True:
        logger.warning(
            f"Resource group '{resource_group}' exists but is empty - every declared "
            f"resource will be reported missing."
        )
        return
    detail = (
        "does not exist" if exists is False
        else "could not be confirmed to exist (the existence check itself failed)"
    )
    reason = (
        f"Resource group '{resource_group}' {detail}. Refusing to report the "
        f"template's resources as deleted: an unreadable scope is a targeting "
        f"problem, not drift. Check the RG name, the subscription, and whether "
        f"the environment has been decommissioned."
    )
    # Write the marker report BEFORE raising. The pipeline guarantees an
    # artifact always exists, and count_drifts deliberately fails on an empty
    # reports dir because "no report" must never be read as "no drift". Aborting
    # without a report traded a wrong answer for an unreadable one: CI failed
    # with "the drift check produced no report" instead of naming the RG.
    _write_scope_not_found_report(resource_group, bicep_file, reason)
    raise ScopeNotFoundError(reason)


def _attribute_orphans_to_missing_rgs(drifts: list, arm_resources: list[dict]) -> int:
    """Tie resources missing because their resource group is gone to that fact.

    A deleted resource group at subscription scope produces one missing_in_azure
    for the RG and one for every resource declared into it. Left unattributed
    that reads as N independent deletions, and the single finding that explains
    them competes for attention with its own consequences. The annotation lets
    the report and the analysis lead with the cause.

    They are NOT suppressed: the resources really are gone, the deletion cost
    guard needs to see them, and a reader restoring the RG needs the inventory.
    """
    missing_rgs = {
        (d.resource_name or "").lower()
        for d in drifts
        if d.resource_type == "Microsoft.Resources/resourceGroups"
        and d.drift_type == "missing_in_azure"
    }
    if not missing_rgs:
        return 0

    declared_rg = {
        (r.get("type"), r.get("name")): (r.get("_target_rg") or "")
        for r in arm_resources
    }
    attributed = 0
    for drift in drifts:
        if drift.drift_type != "missing_in_azure":
            continue
        if drift.resource_type == "Microsoft.Resources/resourceGroups":
            continue
        target = declared_rg.get((drift.resource_type, drift.resource_name), "").lower()
        if target and target in missing_rgs:
            drift.details["orphaned_by_missing_resource_group"] = target
            drift.details["note"] = (
                f"Missing because its resource group '{target}' no longer exists - "
                f"a consequence of that deletion, not an independent one. Restoring "
                f"the resource group is the prerequisite for restoring this."
            )
            attributed += 1
    if attributed:
        logger.warning(
            f"{attributed} missing resource(s) attributed to {len(missing_rgs)} deleted "
            f"resource group(s) - report the group, not {attributed} separate deletions"
        )
    return attributed


def _guard_empty_subscription(resource_group: str, bicep_file: str = "") -> None:
    """A subscription-scoped scan that saw nothing at all has no answer to give.

    One resource group missing out of many IS drift, and is reported as such -
    the template declares its RGs at this scope. But an empty subscription is
    not a landing zone that was deleted wholesale; overwhelmingly it is the
    wrong subscription, a credential without read access, or an environment
    never deployed. Reporting the entire template as missing would be the same
    maximum-severity false alarm the RG-scope guard exists to prevent.
    """
    reason = (
        f"Subscription-scoped scan (selector: {resource_group!r}) returned no "
        f"resources at all. Refusing to report the whole landing zone as deleted: "
        f"an empty subscription is a targeting or permissions problem, not drift. "
        f"Check AZURE_SUBSCRIPTION_ID, the scanning identity's read access, and "
        f"whether this environment has been deployed."
    )
    _write_scope_not_found_report(resource_group, bicep_file, reason)
    raise ScopeNotFoundError(reason)


def _write_scope_not_found_report(resource_group: str, bicep_file: str, reason: str) -> None:
    """Record an unreadable scope as its own outcome, not as zero drift.

    `scope_status` is what downstream reads: count_drifts surfaces it as a
    failure naming the RG, rather than tallying a report with no drifts as a
    clean estate.
    """
    try:
        label = rg_label(resource_group)
        output_file = Path(f"reports/{label}-drift.json")
        output_file.parent.mkdir(exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({
                "resource_group": label,
                "bicep_file": bicep_file,
                "scope_status": "not_found",
                "scope_status_reason": reason,
                "drift_count": 0,
                "drifts": [],
            }, f, indent=2, default=str)
        logger.info(f"✓ Scope-not-found marker written to: {output_file}")
    except Exception as e:
        logger.warning(f"Could not write scope-not-found report: {e}")


def _fetch_live_state(resource_group: str, deployment_scope: str, arm_resources: list[dict],
                      gaps=None, bicep_file: str = "") -> list[dict]:
    """Query Resource Graph, then augment with cross-sub resources and Defender pricings.

    Cross-sub: a vending template may deploy resources into ANOTHER subscription
    (e.g. hub-side peering from a spoke template); the scanned sub can't see
    them, so each is fetched directly and merged so it's property-compared
    instead of false-flagged missing.

    Extension names: diagnostic settings are qualified to '{scope}/{name}' to
    align with the live expansion.

    Defender: pricings are fetched only when the template declares them (every
    sub has a Free-tier row for every plan - undeclared ones would flood extras).
    """
    logger.info("Step 2: Querying live Azure state via Resource Graph...")
    try:
        scope = "subscription" if deployment_scope == "subscription" else "resource_group"
        if scope == "subscription":
            logger.debug("Querying at subscription scope...")
        live_resources = get_live_state(resource_group=resource_group, scope=scope, gaps=gaps)
    except ValueError as e:
        logger.error(f"Missing subscription ID: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to query Azure: {e}", exc_info=True)
        logger.info("Ensure you're logged in: az login")
        raise

    if not live_resources:
        # Both scopes, different reasons for the same refusal. At RG scope the
        # scope itself may not exist; at subscription scope an empty answer for a
        # whole landing zone is a user/config error (wrong subscription, no
        # permissions, nothing deployed yet) - reporting an entire LZ as drift
        # would be the same false alarm one level up.
        if deployment_scope == "subscription":
            _guard_empty_subscription(resource_group, bicep_file)
        else:
            _guard_unverifiable_scope(resource_group, bicep_file)

    logger.info(f"✓ {len(live_resources)} resource(s) deployed in Azure (scope: {deployment_scope})")

    live_resources.extend(fetch_cross_subscription_resources(arm_resources))
    qualify_extension_resource_names(arm_resources)
    live_resources.extend(fetch_declared_defender_pricings(
        arm_resources, os.environ.get("AZURE_SUBSCRIPTION_ID")
    ))
    # Bicep-driven like the pricings above, and for the same reason: a workspace
    # carries the whole built-in table catalogue (679 on the drift-test
    # workspace), so we ask for the declared tables by name rather than listing.
    live_resources.extend(fetch_declared_workspace_tables(arm_resources, live_resources))
    return live_resources


def _load_ignore_patterns(bicep_file: str) -> IgnorePatternList:
    """Load the agent's baseline .drift-ignore LAYERED with the bicep repo's.

    This used to return the FIRST file it found, so a landing zone that ships
    its own .drift-ignore silently replaced the agent's baseline instead of
    adding to it - the baseline holds the overwhelming majority of the patterns
    (Azure-created children Bicep never declares), so every one of them came
    back as drift in the Phase-1 artifact. Phase 2 layers them correctly via
    `from_files`; Phase 1 disagreeing with Phase 2 about what is ignorable is
    the bug, and `run_drift_check.py` is a supported entry point in its own
    right.

    Same two sources and the same order as
    orchestration.reconciliation._annotate_and_filter, and the same walk-up
    finder, so the two cannot drift apart again.
    """
    logger.info("Step 3: Loading ignore patterns...")
    ignore_paths = [Path(".drift-ignore")]
    repo_ignore = _find_repo_ignore(bicep_file)
    if repo_ignore:
        ignore_paths.append(repo_ignore)
        logger.info(f"Merged per-LZ ignore profile from {repo_ignore}")
    ignore_patterns = IgnorePatternList.from_files(*ignore_paths)
    if ignore_patterns.patterns:
        ignore_patterns.log_summary()
    else:
        logger.debug("No ignore patterns found")
    return ignore_patterns


def _diff_states(arm_resources: list[dict], live_resources: list[dict],
                 ignore_patterns: IgnorePatternList) -> list[ResourceDrift]:
    """Run the base template diff."""
    logger.info("Step 4: Diffing desired vs actual...")
    try:
        return diff_states(arm_resources, live_resources, ignore_patterns=ignore_patterns)
    except Exception as e:
        logger.error(f"Failed to diff states: {e}", exc_info=True)
        raise


def _to_resource_drifts(drift_dicts: list[dict]) -> list[ResourceDrift]:
    """Convert sidecar-comparator dicts into ResourceDrift records."""
    return [
        ResourceDrift(
            resource_type=d["type"],
            resource_name=d["name"],
            drift_type=d["drift_type"],
            details=d.get("details", {}),
        )
        for d in drift_dicts
    ]


def _apply_sidecar_ignore(drift_dicts: list[dict], ignore_patterns: IgnorePatternList,
                          label: str) -> list[dict]:
    """Filter a sidecar's drift list through ignore patterns and log the count."""
    if not (ignore_patterns.patterns and drift_dicts):
        return drift_dicts
    filtered, ignored = ignore_patterns.filter_drifts(drift_dicts)
    if ignored:
        logger.info(f"Ignoring {len(ignored)} {label} drift(s) per ignore patterns")
    return filtered


def _run_rbac_sidecar(arm_resources: list[dict], live_resources: list[dict],
                      resource_group: str, deployment_scope: str,
                      ignore_patterns: IgnorePatternList, drifts: list[ResourceDrift]) -> None:
    """Step 4b: RBAC role-assignment drift.

    Assignments are invisible to the normal pipeline (not in Resource Graph's
    Resources table; guid(...) names skipped by the comparator), so they get
    their own identity-based compare. Disable with INCLUDE_ROLE_ASSIGNMENTS=false.
    """
    if not rbac_enabled():
        return
    logger.info("Step 4b: Checking RBAC role assignments...")
    try:
        live_assignments = fetch_role_assignments(
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=deployment_scope if deployment_scope == "subscription" else "resource_group",
        )
        rbac_drift_dicts = compare_role_assignments(
            arm_resources, live_assignments,
            deployed_principals=collect_managed_identity_principals(live_resources),
        )
        rbac_drift_dicts = _apply_sidecar_ignore(rbac_drift_dicts, ignore_patterns, "RBAC")
        drifts.extend(_to_resource_drifts(rbac_drift_dicts))
    except Exception as e:
        logger.warning(f"RBAC drift check failed (continuing without it): {e}")


def _run_policy_sidecar(arm_resources: list[dict], resource_group: str,
                        deployment_scope: str, ignore_patterns: IgnorePatternList,
                        drifts: list[ResourceDrift]) -> dict:
    """Step 4c: Policy assignment/exemption drift - the governance twin of 4b.

    policyresources table; identity-based matching; out-of-band exemptions are
    audit-critical. Disable with INCLUDE_POLICY_ASSIGNMENTS=false.

    Returns the tag values in-scope policy requires (see
    tools.policy.resolve_policy_required_tags); {} when disabled or on failure.
    """
    if not policy_drift_enabled():
        return {}
    logger.info("Step 4c: Checking policy assignments and exemptions...")
    try:
        live_pol, live_exemptions = fetch_policy_resources(
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=deployment_scope if deployment_scope == "subscription" else "resource_group",
        )
        policy_drift_dicts = compare_policy_resources(arm_resources, live_pol, live_exemptions)
        policy_drift_dicts = _apply_sidecar_ignore(policy_drift_dicts, ignore_patterns, "policy")
        drifts.extend(_to_resource_drifts(policy_drift_dicts))
        # Reuse the fetch we just made: derive the tag values in-scope policy
        # REQUIRES, so Phase 3 can recognise an in-flight Modify it could never
        # see in the activity log. Costs one extra Resource Graph read (the RG's
        # own tags), not a per-resource call.
        return resolve_policy_required_tags(
            live_pol,
            fetch_resource_group_tags(os.environ.get("AZURE_SUBSCRIPTION_ID"),
                                      resource_group),
        )
    except Exception as e:
        logger.warning(f"Policy drift check failed (continuing without it): {e}")
    return {}


def _run_stack_sidecar(live_resources: list[dict], resource_group: str,
                       deployment_scope: str, ignore_patterns: IgnorePatternList,
                       drifts: list[ResourceDrift]) -> None:
    """Step 4d: Deployment stack drift. OPT-IN.

    Runs only when the check's LZ config declares a `deployment_stack`, because
    a stack's enforcement posture has no template to diff against and must be
    declared. Two payoffs: the stack's own denySettings/actionOnUnmanage/health,
    and its managed list as an AUTHORITATIVE ownership oracle replacing the
    RG-boundary guess.
    """
    if not stack_drift_enabled():
        return
    logger.info("Step 4d: Checking deployment stack...")
    try:
        stack_cfg = load_stack_config()
        stack_scope = deployment_scope if deployment_scope == "subscription" else "resource_group"
        live_stack, token = fetch_deployment_stack(
            stack_cfg,
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
        )
        stack_drift_dicts = compare_deployment_stack(
            stack_cfg,
            live_stack,
            live_resources,
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=stack_scope,
            token=token,
        )
        # A stack-managed resource the template also declares would be reported
        # missing twice; the template compare owns that finding.
        stack_drift_dicts = dedupe_against(stack_drift_dicts, drifts)
        stack_drift_dicts = _apply_sidecar_ignore(stack_drift_dicts, ignore_patterns, "stack")
        drifts.extend(_to_resource_drifts(stack_drift_dicts))
        annotate_stack_ownership(drifts, live_stack, live_resources)
    except Exception as e:
        logger.warning(f"Deployment stack check failed (continuing without it): {e}")


def _save_phase1_report(bicep_file: str, resource_group: str,
                        arm_resources: list[dict], live_resources: list[dict],
                        drifts: list[ResourceDrift],
                        policy_required_tags: dict | None = None,
                        collection_gaps: dict | None = None,
                        condition_skipped: list | None = None) -> None:
    """Persist the raw Phase 1 report.

    A subscription-scope scan may use '*' or a glob selector (e.g. 'prefix-*');
    use a filesystem-safe label for the file. Secret-bearing property values
    are scrubbed before write - property comparison already ignores write-only
    secrets, this covers the raw dump.
    """
    try:
        label = rg_label(resource_group)
        output_file = Path(f"reports/{label}-drift.json")
        output_file.parent.mkdir(exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({
                "resource_group": label,
                "bicep_file": bicep_file,
                "arm_resources": redact_secrets(arm_resources),
                "live_resources": redact_secrets(live_resources),
                "drift_count": len(drifts),
                # What in-scope policy MANDATES, not what it changed - Phase 3
                # matches drifted tag values against this.
                "policy_required_tags": policy_required_tags or {},
                # Types the collectors could not read this run. Any
                # missing_in_azure row of one of these types is unverified, not
                # confirmed gone - see _mark_unverified_missing.
                "collection_gaps": collection_gaps or {},
                # Declarations this scan's parameters gated off. An extra_in_azure
                # of one of these types is a parameter mismatch, not an unmanaged
                # resource - see _annotate_condition_skipped.
                "condition_skipped": condition_skipped or [],
                "drifts": [
                    {
                        "type": d.resource_type,
                        "name": d.resource_name,
                        "drift_type": d.drift_type,
                        "details": d.details,
                    }
                    for d in drifts
                ],
            }, f, indent=2, default=str)
        logger.info(f"✓ Raw output saved to: {output_file}")
    except Exception as e:
        logger.warning(f"Could not write report: {e}")


def run(bicep_file: str, resource_group: str):
    """Phase 1 orchestrator: compile → live state → diff → sidecars → persist."""
    logger.info(f"Bicep Drift Check — {bicep_file} (resource group: {resource_group})")

    param_overrides = _resolve_parameter_overrides(bicep_file, resource_group)
    skipped = SkippedDeclarations()
    arm_resources, deployment_scope = _compile_and_extract(bicep_file, param_overrides,
                                                           skipped=skipped)
    gaps = CollectionGaps()
    live_resources = _fetch_live_state(resource_group, deployment_scope, arm_resources,
                                       gaps=gaps, bicep_file=bicep_file)
    ignore_patterns = _load_ignore_patterns(bicep_file)
    drifts = _diff_states(arm_resources, live_resources, ignore_patterns)
    # Before the sidecars and the summary: a row the collectors never looked at
    # must not reach either of them claiming the resource is gone.
    _mark_unverified_missing(drifts, gaps)
    _annotate_condition_skipped(drifts, skipped)
    _attribute_orphans_to_missing_rgs(drifts, arm_resources)

    _run_rbac_sidecar(arm_resources, live_resources, resource_group, deployment_scope,
                      ignore_patterns, drifts)
    policy_required_tags = _run_policy_sidecar(arm_resources, resource_group,
                                               deployment_scope, ignore_patterns, drifts)
    _run_stack_sidecar(live_resources, resource_group, deployment_scope,
                       ignore_patterns, drifts)

    logger.info("Drift Report Summary")
    logger.info(format_drift_report(drifts, resource_group))
    _save_phase1_report(bicep_file, resource_group, arm_resources, live_resources, drifts,
                        policy_required_tags, collection_gaps=gaps.as_dict(),
                        condition_skipped=skipped.as_list())


def _mark_unverified_missing(drifts, gaps) -> int:
    """A resource of a type we could not READ is not evidence of a deletion.

    Every collector logs-and-skips, so a failed listing yields no live rows and
    the declared resources of that type fall straight through to
    `missing_in_azure` - identical in the report to a real deletion. This run
    knows which types went ungathered, so those rows say so instead.

    The row is NOT dropped. Suppressing it would hide a genuine deletion behind
    a transient ARM error, which is the same silent-swallow that left the backup
    comparators dead for a month (#330). Report it, and say it is unverified.
    """
    if not gaps:
        return 0
    marked = 0
    for drift in drifts:
        if drift.drift_type != "missing_in_azure" or not gaps.covers(drift.resource_type):
            continue
        drift.details["collection_unverified"] = True
        drift.details["collection_gap_reason"] = gaps.reason_for(drift.resource_type)
        drift.details["note"] = (
            "Live state for this type could not be collected on this run, so its "
            "absence is NOT evidence of deletion - the resource may exist. "
            f"Reason: {gaps.reason_for(drift.resource_type)}"
        )
        marked += 1
    if marked:
        logger.warning(
            f"{marked} missing_in_azure finding(s) could not be verified: "
            f"{len(gaps)} resource type(s) went ungathered this run "
            f"({', '.join(sorted(gaps.as_dict()))})"
        )
    return marked


def _annotate_condition_skipped(drifts, skipped) -> int:
    """A resource whose declaration this scan gated OFF is not unmanaged.

    `flatten_resources` drops a declaration whose `condition` resolves false, so
    the deployed resource has nothing to match and comes back `extra_in_azure` -
    which reads as "unmanaged resource, consider deleting". That is the tool
    recommending you delete something you deploy on purpose, and it cost a live
    round on 2026-07-21: a scan run with default params (deployAks=false)
    reported the real AKS cluster as unmanaged. The analysis declined to delete
    it, but only by INFERRING a contradiction from the attribution - the fact was
    known at compile time and thrown away.

    The condition evaluated false against THIS scan's parameters. That is a
    parameter mismatch between the scan and the deployment, not a verdict about
    the resource.
    """
    if not skipped:
        return 0
    annotated = 0
    for drift in drifts:
        if drift.drift_type != "extra_in_azure" or not skipped.covers(drift.resource_type):
            continue
        entry = skipped.entry_for(drift.resource_type)
        drivers = ", ".join(f"{k}={v!r}" for k, v in (entry.get("parameters") or {}).items())
        drift.details["condition_skipped"] = True
        drift.details["skipped_condition"] = entry.get("condition")
        drift.details["skipped_parameters"] = entry.get("parameters")
        drift.details["note"] = (
            "Declared in the template but condition-skipped for this scan"
            + (f" ({drivers})" if drivers else "")
            + " - a parameter mismatch between the scan and the deployment, "
            "NOT an unmanaged resource. Do not delete it on this evidence."
        )
        annotated += 1
    if annotated:
        logger.warning(
            f"{annotated} extra_in_azure finding(s) match a declaration this scan "
            f"gated off - check the scan's parameters before treating them as unmanaged"
        )
    return annotated


def main():
    # Initialize logging (DRIFT_LOG_LEVEL overrides the default)
    from tools.config import LOG_LEVEL, validate_config
    setup_logging(level=LOG_LEVEL)
    for warning in validate_config():
        logger.warning(f"Config: {warning}")

    if len(sys.argv) < 3:
        logger.error("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    if not Path(bicep_file).exists():
        logger.error(f"Bicep file not found: {bicep_file}")
        sys.exit(1)

    if not bicep_file.endswith(".bicep"):
        logger.error(f"Expected .bicep file, got: {bicep_file}")
        sys.exit(1)

    try:
        run(bicep_file, resource_group)
    except ScopeNotFoundError as e:
        # Exit 2, not 1: a scope that cannot be read is a targeting/config
        # failure, and CI should be able to tell it apart from both a real
        # error (1) and a clean scan (0) without parsing logs.
        logger.error(f"Scope not found: {e}")
        sys.exit(2)
    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Value error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
