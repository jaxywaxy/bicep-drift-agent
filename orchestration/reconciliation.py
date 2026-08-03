"""
orchestration/reconciliation.py

Turn raw Phase 1 output into the reconciled drift set: smart-match uniqueString/
guid-named resources, flag unmatched placeholder-named bicep as missing, apply the
layered .drift-ignore, and merge deep property-drift. Smart-match annotation runs
BEFORE ignore filtering so reconciled resources aren't swallowed by an
extra_in_azure rule.
"""

from orchestration.targeting import _find_repo_ignore
from pathlib import Path
from tools.diff_states import _IDENTITY_MATCHED_TYPES, _should_compare_resource, filter_unmanaged_live_resources
from tools.ignore_patterns import IgnorePatternList
from tools.logger import get_logger
from tools.property_drift import DriftDetector
from tools.smart_matching import _has_unresolvable_expression, annotate_drifts_with_matches, detect_unresolvable_expressions, smart_match_resources

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

    _flag_unmatched_placeholder_resources(report_data, unmatched_bicep)

    # Tie the rows just created back to a deleted resource group. Phase 1 ran
    # this too, but could only see literal-named rows - a placeholder-named
    # resource is proven missing only HERE, so it never reached attribution and
    # a deleted RG still read as N unrelated deletions. Idempotent, so the
    # earlier pass's work is left alone.
    #
    # Local import: run_drift_check pulls in orchestration.targeting, and a
    # module-level import here would tie the two together at import time.
    from run_drift_check import _attribute_orphans_to_missing_rgs
    _attribute_orphans_to_missing_rgs(
        report_data.get("drifts", []), report_data.get("arm_resources", [])
    )


def _flag_unmatched_placeholder_resources(report_data: dict, unmatched_bicep: list) -> None:
    """Emit missing_in_azure for placeholder-named Bicep resources with no live match.

    Phase 1 deliberately skips unresolvable-named resources (their literal name
    never matches the deployed uniqueString name), so their existence is only
    proven by smart matching. Matching is by type: an unresolvable-named resource
    still unmatched afterwards means the type's live candidates ran out — its
    deployed counterpart is GONE. Without this, deleting any uniqueString-named
    resource (storage account, key vault, SQL server, LA workspace...) produced
    no drift at all. Identity-matched governance types are excluded: their live
    rows come from separate Resource Graph tables and are compared by the
    dedicated rbac/policy paths, so their guid() names would false-flag here.
    """
    existing = {
        ((d.get("type") or "").lower(), d.get("name"))
        for d in report_data.get("drifts", [])
    }
    for resource in unmatched_bicep:
        rtype = resource.get("type") or ""
        name = resource.get("name") or ""
        rtype_lower = rtype.lower()
        if rtype_lower == "microsoft.resources/deployments" or rtype_lower in _IDENTITY_MATCHED_TYPES:
            continue
        if not _has_unresolvable_expression(name):
            continue  # literal-named resources are compared (and flagged) in Phase 1
        if (rtype_lower, name) in existing:
            continue
        logger.warning(
            f"Unresolvable-named resource has no live counterpart — missing_in_azure: {rtype}/{name}"
        )
        details = {
            "note": (
                "Runtime-generated name (uniqueString/placeholder); no deployed "
                "resource of this type left to match, so the deployed instance "
                "has been deleted or was never created."
            ),
        }
        # Carry the declaration's target resource group ON the row. Orphan
        # attribution otherwise looks it up by (type, name), and THIS name is
        # replaced in Phase 3 with the real deployed name recovered from the
        # activity log - so the lookup would miss exactly the placeholder-named
        # rows that only this stage can produce.
        if resource.get("_target_rg"):
            details["_declared_in_rg"] = resource["_target_rg"]
        report_data.setdefault("drifts", []).append({
            "type": rtype,
            "name": name,
            "drift_type": "missing_in_azure",
            "details": details,
        })


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
