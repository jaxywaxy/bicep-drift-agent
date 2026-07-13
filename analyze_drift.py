"""
analyze_drift.py

Phase 2 entry point: Analyze drift using Claude AI.

Usage:
    python analyze_drift.py ./path/to/main.bicep your-resource-group
    python analyze_drift.py ./path/to/main.bicep "*"  # Test all RGs in subscription

This will:
1. Run Phase 1 drift check
2. Feed results to Claude for analysis
3. Generate actionable recommendations
"""

import sys
import json
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from tools.logger import setup_logging, get_logger
from agent.drift_agent import DriftAgent
from tools.models import DriftReport, Drift
from tools.ignore_patterns import IgnorePatternList
from tools.html_report import generate_html_report
from tools.smart_matching import (
    detect_unresolvable_expressions,
    smart_match_resources,
    annotate_drifts_with_matches,
)
from tools.property_drift import DriftDetector
from tools.diff_states import _should_compare_resource, filter_unmanaged_live_resources
from run_drift_check import run as run_phase1
from tools.compile_bicep import compile_bicep, detect_deployment_scope
from tools.rg_selector import rg_label
from tools.activity_log import (
    fetch_resource_group_activity,
    match_activity_for_resource,
    fetch_policy_principal_ids,
)
from tools.ownership import classify_owner
from tools.change_origin import (
    classify_change_origin,
    build_resource_lifecycle,
    select_relevant_activity,
)

logger = get_logger(__name__)


def _find_deployed_resource(resource_type: str, bicep_name: str, live_resources: list) -> dict:
    """
    Find the deployed resource dict matching a Bicep resource.

    Bicep names may contain placeholders like [uniqueString] that resolve to
    actual names at deploy time. Returns the live resource dict (so callers can
    use its real .id / .name), or None if not found.
    """
    type_lower = resource_type.lower()

    # First try: exact name match
    for resource in live_resources:
        if (resource.get("type", "").lower() == type_lower and
                resource.get("name", "") == bicep_name):
            return resource

    # Second try: match by type + static prefix (for uniqueString placeholder names)
    name_prefix = bicep_name.split("[")[0] if "[" in bicep_name else bicep_name
    if name_prefix:
        for resource in live_resources:
            if (resource.get("type", "").lower() == type_lower and
                    resource.get("name", "").startswith(name_prefix)):
                return resource

    return None


def _print_drift_summary(drifts):
    """Emit the grep-able drift summary consumed by the CI workflow.

    Bypasses the logger so the workflow can grep these exact lines. Must be
    called with the FINAL (ignore-pattern-filtered) drift list so the summary
    matches the HTML/JSON report rather than the raw Phase 1 output.
    """
    if not drifts:
        return
    print("\n" + "=" * 60)
    for drift in drifts:
        drift_type = drift.get("drift_type", "unknown")
        resource_type = drift.get("type", "")
        resource_name = drift.get("name", "")
        if drift_type == "missing_in_azure":
            print(f"[MISSING] {resource_type}/{resource_name} is in Bicep but not deployed")
        elif drift_type == "extra_in_azure":
            print(f"[EXTRA]   {resource_type}/{resource_name} is deployed but not in Bicep")
        elif drift_type == "property_drift":
            changes = list(drift.get("details", {}).get("changed_properties", {}).keys())
            print(f"[DRIFT]   {resource_type}/{resource_name} — properties differ: {', '.join(changes)}")
    print("=" * 60 + "\n")


def _find_repo_ignore(bicep_file: str):
    """Walk up from the bicep file to find the repo's .drift-ignore.

    The bicep isn't always at <repo>/bicep/main.bicep - a landing zone may keep
    it at envs/dev/main.bicep, etc. Search ancestor directories (stopping at a
    .git dir or the filesystem root) so the per-LZ ignore profile is found
    regardless of nesting depth.
    """
    d = Path(bicep_file).resolve().parent
    for _ in range(8):
        candidate = d / ".drift-ignore"
        if candidate.exists():
            return candidate
        if (d / ".git").exists() or d.parent == d:
            break
        d = d.parent
    return None


def discover_resource_groups():
    """Query Azure for all resource groups in the current subscription.

    Uses the Resource Graph SDK (same auth/client as get_live_state) rather than
    shelling out to `az graph query`, which required the az 'graph' CLI extension.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        client = ResourceGraphClient(DefaultAzureCredential())
        request = QueryRequest(
            subscriptions=[sub_id] if sub_id else [],
            query="Resources | distinct resourceGroup",
        )
        response = client.resources(request)
        rgs = [row["resourceGroup"] for row in (response.data or []) if row.get("resourceGroup")]
        return sorted(rgs)
    except Exception as e:
        logger.error(f"Failed to discover resource groups: {e}")
        return []


def _resolve_target_resource_groups(bicep_file: str, resource_group: str) -> list:
    """Resolve which resource group(s) this invocation should scan.

    A subscription-scoped landing zone spans several RGs from ONE template and is
    scanned as a SINGLE pass (optionally filtered to an RG glob like 'jacquidev-*').
    Only an RG-scoped template treats '*' as "discover and scan each RG separately".
    """
    try:
        is_sub_scoped = detect_deployment_scope(compile_bicep(bicep_file)) == "subscription"
    except Exception as e:
        logger.warning(f"Could not detect deployment scope ({e}); assuming resource-group scope")
        is_sub_scoped = False

    if resource_group == "*" and not is_sub_scoped:
        logger.info(f"Processing: {bicep_file} (discovering all resource groups in subscription)")
        discovered_rgs = discover_resource_groups()
        if not discovered_rgs:
            logger.error("No resource groups found in subscription")
            sys.exit(1)
        logger.info(f"Found {len(discovered_rgs)} resource group(s): {', '.join(discovered_rgs)}")
        return discovered_rgs

    if is_sub_scoped:
        logger.info(
            f"Processing: {bicep_file} (subscription-scoped landing zone; "
            f"RG selector: {resource_group})"
        )
    else:
        logger.info(f"Processing: {bicep_file} (resource group: {resource_group})")
    return [resource_group]


def _run_phase1(bicep_file: str, resource_groups_to_test: list) -> None:
    """Run the Phase 1 drift check for each target resource group.

    The grep-able drift summary is intentionally emitted later (after Phase 3), so
    it reflects the ignore-filtered, policy-split drift set rather than raw output.
    """
    logger.info("Phase 1: Detecting drift...")
    try:
        for rg in resource_groups_to_test:
            logger.info(f"Running drift check for resource group: {rg}")
            run_phase1(bicep_file, rg)
    except Exception as e:
        logger.error(f"Error in Phase 1: {e}", exc_info=True)
        sys.exit(1)


def _consolidate_wildcard_results(resource_groups_to_test: list) -> None:
    """Print a consolidated Phase 1 summary across multiple resource groups.

    Wildcard (multi-RG) mode skips Claude analysis; this is the terminal output.
    """
    logger.info("✓ Wildcard mode: Skipping Phase 2 for multiple resource groups")
    logger.info(f"Consolidating Phase 1 results for {len(resource_groups_to_test)} resource groups...")
    print("\n" + "="*60)
    print("WILDCARD RESULTS SUMMARY")
    print("="*60)
    total_drifts = 0
    for rg in resource_groups_to_test:
        report_file = Path(f"reports/{rg}-drift.json")
        if report_file.exists():
            with open(report_file) as f:
                report_data = json.load(f)
            drifts = report_data.get("drifts", [])
            print(f"\n{rg}: {len(drifts)} issue(s)")
            total_drifts += len(drifts)
            for drift in drifts[:3]:  # Show first 3 issues per RG
                drift_type = drift.get("drift_type", "unknown")
                resource_type = drift.get("type", "")
                resource_name = drift.get("name", "")
                if drift_type == "missing_in_azure":
                    print(f"  [MISSING] {resource_type}/{resource_name}")
                elif drift_type == "extra_in_azure":
                    print(f"  [EXTRA]   {resource_type}/{resource_name}")
                elif drift_type == "property_drift":
                    print(f"  [DRIFT]   {resource_type}/{resource_name}")
            if len(drifts) > 3:
                print(f"  ... and {len(drifts) - 3} more")
    print(f"\nTOTAL ISSUES: {total_drifts}")
    print("="*60 + "\n")


def _apply_smart_matching(report_data: dict) -> None:
    """Detect unresolvable Bicep names and smart-match them to live resources.

    Populates report_data['smart_matched'] and ['comparison_bicep_resources'] so
    uniqueString-named resources are property-checked against their live
    counterpart instead of being false-flagged missing/extra.
    """
    logger.info("Detecting unresolvable expressions in Bicep template...")
    # Phase 1 stores the flattened resource list ("arm_resources"), not the raw
    # template, so wrap it in the {'resources': [...]} shape the detector wants.
    arm_template = report_data.get("arm_template") or {"resources": report_data.get("arm_resources", [])}
    unresolvable = detect_unresolvable_expressions(arm_template)
    if not unresolvable:
        return

    unresolvable_count = sum(len(v) for v in unresolvable.values())
    logger.info(f"Found {unresolvable_count} resource(s) with unresolvable names")
    for resource_type, names in unresolvable.items():
        for name in names:
            logger.debug(f"  {resource_type}: {name}")

    logger.info("Attempting smart resource matching...")
    bicep_resources = report_data.get("arm_resources", [])
    azure_resources = report_data.get("live_resources", [])
    matched, unmatched_bicep, _ = smart_match_resources(bicep_resources, azure_resources, unresolvable)

    if matched:
        logger.info(f"✓ Matched {len(matched)} resource(s)")
        for m in matched:
            logger.debug(f"  {m.get('type')}: {m.get('name')} → {m.get('matched_to')}")
        report_data["smart_matched"] = matched
        # Build the property-comparison bicep set from the match PAIRS (remap each
        # matched entry's name to matched_to) so a real change on a uniqueString-
        # named resource is still detected. No name-keyed dict -> no collision when
        # two resources share an identical name expression.
        report_data["comparison_bicep_resources"] = unmatched_bicep + [
            {**m, "name": m.get("matched_to")} for m in matched if m.get("matched_to")
        ]
    else:
        logger.info("No successful smart matches")


def _apply_ignore_patterns(report_data: dict, bicep_file: str) -> IgnorePatternList:
    """Load the layered ignore profile, annotate smart matches, and filter drifts.

    The profile layers the agent's baseline .drift-ignore with the bicep repo's
    per-landing-zone .drift-ignore. Smart-match annotation runs BEFORE filtering so
    a reconciled unresolvable-named resource is relabeled 'matched_unresolvable'
    rather than being swallowed by an 'extra_in_azure' ignore. Returns the loaded
    IgnorePatternList (reused for property-drift filtering).
    """
    repo_ignore = _find_repo_ignore(bicep_file)
    ignore_paths = [Path(".drift-ignore")]
    if repo_ignore:
        ignore_paths.append(repo_ignore)
        logger.info(f"Merged per-LZ ignore profile from {repo_ignore}")
    ignore_list = IgnorePatternList.from_files(*ignore_paths)

    if "smart_matched" in report_data:
        report_data["drifts"] = annotate_drifts_with_matches(
            report_data.get("drifts", []),
            report_data.get("smart_matched", []),
        )

    if ignore_list.patterns:
        logger.info("Loading ignore patterns...")
        ignore_list.log_summary()
        raw_drifts = report_data.get("drifts", [])
        filtered_drifts, ignored_drifts = ignore_list.filter_drifts(raw_drifts)

        if ignored_drifts:
            logger.info(f"Ignoring {len(ignored_drifts)} drift(s) per ignore patterns")
            for d in ignored_drifts:
                logger.debug(f"  {d['type']} '{d['name']}': {d.get('ignored_reason', 'Matched pattern')}")

        report_data["drifts"] = filtered_drifts
        report_data["ignored_drifts"] = ignored_drifts

    return ignore_list


def _detect_and_merge_property_drift(report_data: dict, ignore_list: IgnorePatternList) -> None:
    """Run property-level drift detection and merge results into report_data.

    Prefers the smart-match-aware comparison set (unresolvable-named resources
    remapped to their live name) so their properties are compared; falls back to
    the raw resources. Stores report_data['property_drifts'] and merges 'modified'
    results into the main drift list (deduped against Phase 1, tolerating
    placeholder names).
    """
    logger.info("Detecting property-level drift (comparing configurations)...")
    bicep_resources = report_data.get("comparison_bicep_resources") or report_data.get("arm_resources", [])
    deployed_resources = report_data.get("live_resources", [])
    if not (bicep_resources and deployed_resources):
        return

    # Filter resources to exclude unresolvable ones (same as Phase 1)
    filtered_bicep_resources = [r for r in bicep_resources if _should_compare_resource(r)]
    unresolvable_count = len(bicep_resources) - len(filtered_bicep_resources)
    if unresolvable_count > 0:
        logger.debug(f"Filtered {unresolvable_count} resource(s) with unresolvable expressions")

    # Drop live rows that can never be in Bicep (SQL master, undeclared App Service
    # config kinds, ...) - the SAME filter Phase 1 applies - so they don't reappear
    # as extras in this diagnostic pass.
    deployed_resources = filter_unmanaged_live_resources(deployed_resources, filtered_bicep_resources)

    property_drifts = DriftDetector.detect_drift(filtered_bicep_resources, deployed_resources)

    # Apply ignore patterns to property drifts, in the SAME shape (and with the
    # SAME canonical drift_type names) the main drift filter uses: "modified" ->
    # "property_drift", "extra" -> "extra_in_azure", "missing" -> "missing_in_azure".
    # Without the extra/missing mapping, drift_type-scoped ignore rules (e.g. the
    # privatelink A-record rule, extra_in_azure only) never match this diagnostic
    # pass, so an ignored resource leaks back into the report's property_drifts
    # section.
    _canon = {"modified": "property_drift",
              "extra": "extra_in_azure",
              "missing": "missing_in_azure"}
    raw_property_drifts = [
        {
            "type": d.resource_type,
            "name": d.resource_name,
            "drift_type": _canon.get(d.drift_type, d.drift_type),
            "details": {
                "changed_properties": {
                    diff.property_path: {
                        "desired": diff.desired_value,
                        "actual": diff.actual_value,
                        "severity": diff.severity,
                    }
                    for diff in d.property_diffs
                }
            },
        }
        for d in property_drifts
    ]
    filtered_property_dicts, ignored_property_dicts = ignore_list.filter_drifts(raw_property_drifts)
    # Property-scoped ignore rules STRIP individual properties from a surviving
    # drift (see IgnorePatternList.filter_drifts); mirror that stripping onto the
    # detector objects, otherwise a stripped noisy property (agentPoolProfiles)
    # would ride back into the report alongside the real finding it obscured.
    surviving_props = {
        (d["type"], d["name"]): set(d.get("details", {}).get("changed_properties", {}))
        for d in filtered_property_dicts
    }
    kept_drifts = []
    for d in property_drifts:
        keep = surviving_props.get((d.resource_type, d.resource_name))
        if keep is None:
            continue
        if d.drift_type == "modified" and d.property_diffs:
            d.property_diffs = [pd for pd in d.property_diffs if pd.property_path in keep]
            if not d.property_diffs:
                continue
        kept_drifts.append(d)
    property_drifts = kept_drifts

    summary = DriftDetector.generate_summary(property_drifts)

    logger.info("Drift detection complete:")
    logger.info(f"  - Total drifts: {summary['total']}")
    logger.info(f"  - Missing resources: {summary['missing']}")
    logger.info(f"  - Extra resources: {summary['extra']}")
    logger.info(f"  - Modified (config changed): {summary['modified']}")

    # Store property drifts in report
    report_data["property_drifts"] = [
        {
            "resource_type": d.resource_type,
            "resource_name": d.resource_name,
            "bicep_name": d.bicep_name,
            "deployed_name": d.deployed_name,
            "drift_type": d.drift_type,
            "match_confidence": d.match_confidence,
            "property_diffs": [
                {
                    "property_path": diff.property_path,
                    "desired_value": diff.desired_value,
                    "actual_value": diff.actual_value,
                    "change_type": diff.change_type,
                    "severity": diff.severity,
                }
                for diff in d.property_diffs
            ],
        }
        for d in property_drifts
    ]

    # Merge "modified" results into the main drift list. Phase 1 skips
    # unresolvable-named resources, so a smart-matched resource's property drift is
    # detected ONLY here - without this merge it never reaches the report summary,
    # owner tagging, or notifications.
    existing = {
        ((d.get("type") or "").lower(), d.get("name")): d
        for d in report_data.get("drifts", [])
    }

    def _phase1_reported(rtype: str, deployed_name: str):
        """Find a Phase 1 drift for this resource, tolerating placeholder names.

        Phase 1 may report the SAME resource under its bicep placeholder name
        (e.g. 'sttestdrift[86c9cbf6]' prefix-matched to 'sttestdrift3s7c...'), so an
        exact-name dedup alone would double-report the drift once per name.
        """
        exact = existing.get((rtype, deployed_name))
        if exact is not None:
            return exact
        for (etype, ename), drift in existing.items():
            if etype != rtype or not ename or "[" not in ename:
                continue
            prefix = ename.split("[", 1)[0]
            if prefix and deployed_name.lower().startswith(prefix.lower()):
                return drift
        return None

    for d in property_drifts:
        if d.drift_type != "modified" or not d.property_diffs:
            continue
        name = d.deployed_name or d.resource_name
        changed = {
            diff.property_path: {
                "desired": diff.desired_value,
                "actual": diff.actual_value,
                "severity": diff.severity,
            }
            for diff in d.property_diffs
        }
        prior = _phase1_reported((d.resource_type or "").lower(), name)
        if prior is not None:
            if prior.get("drift_type") == "matched_unresolvable":
                # The smart-match reconciled this resource's EXISTENCE, but its
                # properties drifted - upgrade to a real property drift.
                prior["drift_type"] = "property_drift"
                prior.setdefault("details", {})["changed_properties"] = changed
            else:
                continue  # already reported by Phase 1
        else:
            report_data.setdefault("drifts", []).append({
                "type": d.resource_type,
                "name": name,
                "drift_type": "property_drift",
                "details": {"changed_properties": changed},
            })
        logger.info(
            f"Merged smart-matched property drift: {d.resource_type}/{name} "
            f"({', '.join(changed)})"
        )


def _run_claude_analysis(agent, report_data: dict):
    """Build the DriftReport and, if an agent is available, run Claude analysis.

    Returns the analysis text (also stored in report_data['agent_analysis']), or
    None when no API key is configured. Re-raises on Claude API failure so the
    caller's handler still falls back to HTML generation.
    """
    drifts = [
        Drift(
            resource_type=d["type"],
            resource_name=d["name"],
            drift_type=d["drift_type"],
            details=d.get("details"),
        )
        for d in report_data.get("drifts", [])
    ]

    drift_report = DriftReport(
        bicep_file=report_data["bicep_file"],
        resource_group=report_data["resource_group"],
        drifts=drifts,
        total_missing=len([d for d in drifts if "missing" in d.drift_type]),
        total_extra=len([d for d in drifts if "extra" in d.drift_type]),
        total_modified=len([d for d in drifts if "modified" in d.drift_type]),
    )

    if not agent:
        return None

    logger.info("Calling Claude API for drift analysis...")
    try:
        agent_analysis = agent.analyze_drift(drift_report)
        logger.info("✓ Claude analysis completed")
        logger.info("DRIFT ANALYSIS")
        logger.info(agent_analysis)
        report_data["agent_analysis"] = agent_analysis
        return agent_analysis
    except Exception as e:
        logger.error(f"✗ Claude analysis failed: {type(e).__name__}: {str(e)[:200]}", exc_info=True)
        print(f"[ERROR] Claude API call failed: {type(e).__name__}")
        raise


def _build_lifecycle_and_split(report_data: dict, resource_group: str) -> list:
    """Phase 3/4: attribute each drift via the Activity Log, split out
    policy/system-enforced changes, and tag actionable drift with its owner.

    Returns the actionable drift list (report_data['drifts'] is also updated;
    policy-enforced changes move to report_data['policy_enforced_drifts']).
    """
    drifts_to_analyze = report_data.get("drifts", [])
    logger.info(f"Found {len(drifts_to_analyze)} drift(s) to generate recommendations for")
    if len(drifts_to_analyze) == 0:
        return drifts_to_analyze

    logger.info("Phase 3: Building resource lifecycle from Activity Log...")
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    live_resources = report_data.get("live_resources", [])

    # Fetch the RG's Activity Log ONCE and match each drift against it in memory
    # (a per-drift query would re-scan the whole RG N times). Also fetch the
    # policy-assignment managed-identity principals once, so policy (DINE/Modify)
    # changes are attributed to policy.
    rg_activity_events = fetch_resource_group_activity(subscription_id, resource_group, days=30)
    policy_principal_ids = fetch_policy_principal_ids(subscription_id, resource_group)

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

            lifecycle = build_resource_lifecycle(resource_id, relevant_logs)
            drift["lifecycle"] = lifecycle.to_dict()

            origin_info = classify_change_origin(relevant_logs, policy_principal_ids)
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

    # Split policy/system-enforced changes out of the actionable drift set.
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


def _generate_recommendations(agent, drifts_to_analyze: list) -> None:
    """Generate a per-drift remediation recommendation via Claude (if available).

    Skips 'matched_unresolvable' entries: they are informational (a runtime-named
    resource reconciled to its live counterpart), not actionable drift, so a
    remediation recommendation is meaningless — and, at one Claude call each,
    these dominate the run's wall time.
    """
    rec_targets = [
        d for d in drifts_to_analyze
        if d.get("drift_type") != "matched_unresolvable"
    ]
    skipped_informational = len(drifts_to_analyze) - len(rec_targets)

    if agent and rec_targets:
        logger.info(f"Generating recommendations via Claude for {len(rec_targets)} actionable drift(s)...")
        if skipped_informational:
            logger.info(f"Skipping {skipped_informational} informational (matched_unresolvable) drift(s)")
        recommendations_count = 0
        for i, drift in enumerate(rec_targets, 1):
            try:
                drift_name = drift.get("name", "unknown")
                logger.debug(f"[{i}/{len(rec_targets)}] {drift_name}...")

                recommendation = agent.get_drift_recommendation(
                    resource_type=drift.get("type", ""),
                    resource_name=drift_name,
                    drift_type=drift.get("drift_type", ""),
                    details=drift.get("details"),
                )

                drift["recommendation"] = recommendation.strip() if recommendation else "No recommendation generated"
                recommendations_count += 1

            except Exception as e:
                logger.warning(f"Failed to generate recommendation for {drift_name}: {str(e)[:50]}", exc_info=True)
                drift["recommendation"] = f"Could not generate recommendation: {str(e)[:100]}"

        logger.info(f"Generated recommendations for {recommendations_count}/{len(rec_targets)} drifts")
    elif not agent:
        logger.info("Skipping Claude recommendations (no API key)")


def _generate_html_report(report_label: str, resource_group: str, bicep_file: str) -> None:
    """Always generate the HTML report, even if Phase 2 failed, from the JSON."""
    html_file = Path(f"reports/{report_label}-drift.html")
    logger.info(f"Generating HTML report to {html_file}...")
    try:
        generate_html_report(
            drift_json_file=Path(f"reports/{report_label}-drift.json"),
            output_file=html_file,
            resource_group=resource_group,
            bicep_file=bicep_file,
        )
        logger.info(f"HTML report saved to: {html_file}")
        if html_file.exists():
            file_size = html_file.stat().st_size
            logger.info(f"HTML file verified: {file_size} bytes")
        else:
            logger.warning(f"HTML file was not created at {html_file}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        sys.exit(1)


def main():
    from tools.config import LOG_LEVEL, validate_config
    setup_logging(level=LOG_LEVEL)
    for warning in validate_config():
        logger.warning(f"Config: {warning}")

    if len(sys.argv) < 3:
        logger.error("Usage: python analyze_drift.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    # Validate inputs
    if not Path(bicep_file).exists():
        logger.error(f"Bicep file not found: {bicep_file}")
        sys.exit(1)

    logger.info("Bicep Drift Agent - Phase 1 + Phase 2")

    resource_groups_to_test = _resolve_target_resource_groups(bicep_file, resource_group)

    _run_phase1(bicep_file, resource_groups_to_test)

    # Phase 2 (Claude analysis) only runs for a single resource group.
    if len(resource_groups_to_test) > 1:
        _consolidate_wildcard_results(resource_groups_to_test)
        return

    # Single RG mode - continue with Phase 2
    resource_group = resource_groups_to_test[0]
    # A subscription-scope scan may use '*' or a glob selector; report files use a
    # filesystem-safe label (matching what Phase 1 / run_drift_check wrote).
    report_label = rg_label(resource_group)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("⚠️  ANTHROPIC_API_KEY not set in environment")
        logger.info("Skipping Claude analysis. HTML report will be generated with available drift data.")
        # Output marker to drift file so it's visible in consolidation
        print("[WARNING] Claude analysis skipped - ANTHROPIC_API_KEY not configured")
    else:
        logger.info("✓ Phase 2: Analyzing drift with Claude...")

    try:
        # Claude is optional. The deterministic drift processing (smart matching,
        # ignore-pattern filtering, property-level detection, lifecycle) ALWAYS runs
        # so the saved report/HTML match the filtered summary. Only the Claude-powered
        # steps (analysis narrative, per-drift recommendations, follow-up) are gated
        # on the API key.
        agent = DriftAgent(api_key=api_key) if api_key else None
        if not agent:
            logger.info("No ANTHROPIC_API_KEY - running drift filtering/detection without Claude analysis")

        # Load the drift report from Phase 1
        report_file = Path(f"reports/{report_label}-drift.json")
        if not report_file.exists():
            logger.error(f"Report file not found: {report_file}")
            sys.exit(1)

        with open(report_file) as f:
            report_data = json.load(f)

        # Deterministic drift processing (always runs, Claude-independent):
        _apply_smart_matching(report_data)
        ignore_list = _apply_ignore_patterns(report_data, bicep_file)
        _detect_and_merge_property_drift(report_data, ignore_list)

        # Claude analysis of the pre-split drift set (only when a key is available).
        agent_analysis = _run_claude_analysis(agent, report_data)

        # Phase 3/4: lifecycle attribution, policy split, and owner tagging.
        drifts_to_analyze = _build_lifecycle_and_split(report_data, resource_group)

        # Emit the grep-able summary from the FINAL actionable set (post Phase 3 split),
        # so the CI summary matches the report and excludes policy-enforced changes.
        _print_drift_summary(report_data.get("drifts", []))

        _generate_recommendations(agent, drifts_to_analyze)

        # Per-run cost telemetry: exact token usage (from each response's usage
        # block) and the estimated USD cost of this run's Claude calls. Stored
        # in the report so CI runs leave an auditable cost trail.
        if agent is not None:
            logger.info(f"Claude usage this run: {agent.usage.summary()}")
            report_data["agent_usage"] = agent.usage.to_dict()

        # ALWAYS persist the processed report (filtered drifts + property_drifts +
        # lifecycle, and recommendations if generated) so the HTML report - which reads
        # this JSON file - matches the filtered summary regardless of the API key.
        try:
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            logger.info(f"Saved processed drift report to JSON: {report_file}")
        except Exception as e:
            logger.warning(f"Failed to save processed report: {e}", exc_info=True)

        # Save analysis
        if agent_analysis:
            analysis_file = Path(f"reports/{report_label}-analysis.md")
            analysis_file.parent.mkdir(parents=True, exist_ok=True)
            with open(analysis_file, "w") as f:
                f.write(f"# Drift Analysis: {resource_group}\n\n")
                f.write(f"**Bicep File:** {bicep_file}\n\n")
                f.write(agent_analysis)
            logger.info(f"Analysis saved to: {analysis_file}")
        else:
            logger.warning("No agent analysis generated")

        # Interactive follow-up (only in interactive mode, with a Claude agent)
        if agent and os.isatty(0):
            logger.info("Interactive mode: Ask Claude follow-up questions (or 'quit' to exit)")
            while True:
                question = input("You: ").strip()
                if question.lower() in ("quit", "exit", "q"):
                    break
                if not question:
                    continue

                response = agent.ask_followup(question)
                logger.info(f"Claude: {response}")

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error in Phase 2: {e}", exc_info=True)
        logger.warning("Phase 2 failed, but will still generate HTML report with Phase 1 data")

    # Always generate the HTML report, even if Phase 2 failed.
    _generate_html_report(report_label, resource_group, bicep_file)


if __name__ == "__main__":
    main()
