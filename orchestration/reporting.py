"""
orchestration/reporting.py

Final-stage output: reconcile the actionable drift_count against COUNTED_TYPES so
the JSON matches the HTML/summary, print the grep-able CI summary, and generate
the HTML report. drift_count is actionable drift only (matched_unresolvable and
policy_enforced excluded).
"""

import sys

from pathlib import Path
from tools.count_drifts import COUNTED_TYPES
from tools.html_report import generate_html_report
from tools.logger import get_logger

logger = get_logger(__name__)


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
            # An ungathered type cannot support "not deployed" - say what is
            # actually known, or the CI log asserts a deletion nobody verified.
            if drift.get("details", {}).get("collection_unverified"):
                print(f"[UNVERIFIED] {resource_type}/{resource_name} is in Bicep and its live "
                      "state could not be read - absence is NOT evidence of deletion")
                continue
            print(f"[MISSING] {resource_type}/{resource_name} is in Bicep but not deployed")
        elif drift_type == "extra_in_azure":
            print(f"[EXTRA]   {resource_type}/{resource_name} is deployed but not in Bicep")
        elif drift_type == "property_drift":
            changes = list(drift.get("details", {}).get("changed_properties", {}).keys())
            print(f"[DRIFT]   {resource_type}/{resource_name} — properties differ: {', '.join(changes)}")
    print("=" * 60 + "\n")


def _include_placeholder_deletions(report_data: dict) -> None:
    """Add deleted uniqueString-named resources to `property_drifts`.

    That list feeds a report section of its own, and it is built from a bicep set
    that filters out unresolvable-named declarations. The filter is right for
    property COMPARISON - you cannot diff a name that never resolved - but it
    also removed the row's EXISTENCE, so a genuinely deleted placeholder-named
    resource rendered once where every literal-named finding rendered twice, and
    the section listing missing resources did not mention it at all.

    Only missing_in_azure rows are added, and only ones not already represented:
    a matched placeholder resource is present in Azure and belongs in neither
    list.
    """
    property_drifts = report_data.setdefault("property_drifts", [])
    present = {(r.get("resource_type"), r.get("resource_name")) for r in property_drifts}
    for drift in report_data.get("drifts") or []:
        if drift.get("drift_type") != "missing_in_azure":
            continue
        key = (drift.get("type"), drift.get("name"))
        if key in present:
            continue
        present.add(key)
        property_drifts.append({
            "resource_type": drift.get("type"),
            "resource_name": drift.get("name"),
            # The bicep expression is what a reader greps for in the template;
            # the row's own name is the deployed name recovered from the log.
            "bicep_name": drift.get("bicep_name_expression") or drift.get("name"),
            "deployed_name": "",
            "drift_type": "missing",
            "match_confidence": 1.0,
            "property_diffs": [],
        })


def _group_orphans_with_their_cause(report_data: dict) -> None:
    """Put each orphan immediately after the resource group that explains it.

    Rows are emitted in CREATION order, and an orphan is created a whole stage
    after its resource group - so a single deletion read as "logging RG and
    workspace deleted ... (six role assignments) ... and also a storage account".
    That is the exact failure orphan attribution exists to prevent; the link was
    in the data and nothing used it to order the output.

    Stable: rows that are not part of a deleted group keep their relative order,
    and nothing is added or dropped.
    """
    drifts = report_data.get("drifts") or []
    # Only regroup around groups that are THEMSELVES reported missing. An orphan
    # whose group is not in the report (ignored, filtered, or a different scan)
    # has nothing to sit under, and relocating it would reorder the report for
    # no reader benefit.
    reported_groups = {
        str(r.get("name") or "").lower() for r in drifts
        if r.get("type") == "Microsoft.Resources/resourceGroups"
        and r.get("drift_type") == "missing_in_azure"
    }
    orphans_by_rg: dict[str, list] = {}
    for row in drifts:
        rg = ((row.get("details") or {}).get("orphaned_by_missing_resource_group") or "").lower()
        if rg and rg in reported_groups:
            orphans_by_rg.setdefault(rg, []).append(row)
    if not orphans_by_rg:
        return

    moved = {id(r) for rows in orphans_by_rg.values() for r in rows}
    ordered = []
    for row in drifts:
        if id(row) in moved:
            continue
        ordered.append(row)
        if (row.get("type") == "Microsoft.Resources/resourceGroups"
                and row.get("drift_type") == "missing_in_azure"):
            ordered.extend(orphans_by_rg.get(str(row.get("name") or "").lower(), []))
    report_data["drifts"] = ordered


def _strip_internal_details(report_data: dict) -> None:
    """Remove pipeline-internal keys from every drift's `details` before the
    report is published.

    `_declared_in_rg` records which resource group a declaration targets so that
    orphan attribution survives the Phase 3 rename - useful to the pipeline,
    meaningless to the platform team reading the artifact, and it was appearing
    verbatim next to the human-readable note.

    The rule is the leading underscore rather than a named key, so a future
    internal field does not have to remember to add itself here.
    """
    for bucket in ("drifts", "policy_enforced_drifts", "ignored_drifts"):
        for row in report_data.get(bucket) or []:
            details = row.get("details")
            if isinstance(details, dict):
                for key in [k for k in details if str(k).startswith("_")]:
                    del details[key]


def _finalize_drift_count(report_data: dict) -> int:
    """Recompute drift_count as ACTIONABLE drift and store it.

    Phase 1 (run_drift_check) stamps drift_count = len(raw drifts). Phase 2/3
    then reconcile - relabelling unresolvable-named extras to
    matched_unresolvable and moving entries into ignored_drifts /
    policy_enforced_drifts - which shortens the drifts array, so the count must
    be recomputed or it keeps a stale Phase-1 value.

    It also has to EXCLUDE matched_unresolvable. Those records are runtime-named
    resources reconciled to their deployed counterparts - informational, not
    drift - and every other surface already treats them that way: the CI summary
    and the HTML report count via count_drifts.tally_report, and the analysis
    filters them before prompting. Counting them here left the JSON artifact
    saying `drift_count: 35` for a run the summary and report both called 2
    changed resources, so whichever number a reader saw first was the one they
    believed. Counting the same drift_types as tally_report makes this field
    equal to that function's total_issues by construction.
    """
    counted = 0
    unknown = set()
    for drift in report_data.get("drifts") or []:
        drift_type = drift.get("drift_type")
        if drift_type in COUNTED_TYPES:
            counted += 1
        elif drift_type != "matched_unresolvable":
            unknown.add(drift_type)
    if unknown:
        # A drift_type neither counted nor reconciled would vanish from every
        # surface silently. Surface it instead of quietly under-reporting.
        logger.warning(
            f"drift_count excludes unrecognised drift_type(s): {sorted(unknown)} - "
            "add them to count_drifts.COUNTED_TYPES if they are actionable"
        )
    report_data["drift_count"] = counted
    return counted


def _drift_type_counts(drifts):
    """(missing, extra, modified) counts feeding DriftReport.total_drift.

    Property drift is emitted with drift_type == "property_drift", which does
    NOT contain the substring "modified" - so a naive `"modified" in drift_type`
    check counts it as zero. That produced a summary with total_drift: 0 sitting
    next to severity_counts.critical: 3, and the analysis agent (correctly) flagged
    the contradiction and lowered its confidence. Count property_drift as a
    modification explicitly.
    """
    missing = len([d for d in drifts if "missing" in d.drift_type])
    extra = len([d for d in drifts if "extra" in d.drift_type])
    modified = len(
        [d for d in drifts if "modified" in d.drift_type or d.drift_type == "property_drift"]
    )
    return missing, extra, modified


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
