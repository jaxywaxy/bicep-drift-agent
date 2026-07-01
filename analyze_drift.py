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
from tools.property_drift import DriftDetector, PropertyExtractor
from tools.diff_states import _should_compare_resource
from run_drift_check import run as run_phase1
from tools.azure_resource_graph import ResourceGraphClient
from tools.activity_log import get_change_history
from tools.change_origin import (
    classify_change_origin,
    format_change_origin_for_display,
    build_resource_lifecycle,
    format_lifecycle_for_display,
    select_relevant_activity,
)

logger = get_logger(__name__)


def _find_deployed_resource_name(resource_type: str, bicep_name: str, live_resources: list) -> str:
    """
    Find actual deployed resource name given bicep template name.

    Bicep names may contain placeholders like [uniqueString] that are resolved
    to actual names during deployment. This function finds the deployed resource
    that matches the bicep resource.

    Args:
        resource_type: Azure resource type (e.g., 'Microsoft.Storage/storageAccounts')
        bicep_name: Name from bicep template (may contain placeholders)
        live_resources: List of live resources from deployment

    Returns:
        Actual deployed resource name, or empty string if not found
    """
    type_lower = resource_type.lower()

    # First try: exact name match
    for resource in live_resources:
        if (resource.get("type", "").lower() == type_lower and
            resource.get("name", "") == bicep_name):
            return resource.get("name", "")

    # Second try: match by type and prefix (for resources with uniqueString placeholders)
    # Extract the prefix before any [ or ] characters
    name_prefix = bicep_name.split("[")[0] if "[" in bicep_name else bicep_name
    if name_prefix:
        for resource in live_resources:
            deployed_name = resource.get("name", "")
            if (resource.get("type", "").lower() == type_lower and
                deployed_name.startswith(name_prefix)):
                return deployed_name

    return ""


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


def discover_resource_groups():
    """Query Azure for all resource groups in the current subscription."""
    try:
        client = ResourceGraphClient()
        query = "Resources | summarize by resourceGroup | project name = resourceGroup | distinct name"
        results = client.query(query)
        rgs = [result["name"] for result in results if result.get("name")]
        return sorted(rgs)
    except Exception as e:
        logger.error(f"Failed to discover resource groups: {e}")
        return []


def main():
    setup_logging(level="INFO")

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

    # Handle wildcard resource group (discover all RGs in subscription)
    if resource_group == "*":
        logger.info(f"Processing: {bicep_file} (discovering all resource groups in subscription)")
        discovered_rgs = discover_resource_groups()
        if not discovered_rgs:
            logger.error("No resource groups found in subscription")
            sys.exit(1)
        logger.info(f"Found {len(discovered_rgs)} resource group(s): {', '.join(discovered_rgs)}")
        resource_groups_to_test = discovered_rgs
    else:
        logger.info(f"Processing: {bicep_file} (resource group: {resource_group})")
        resource_groups_to_test = [resource_group]

    # Phase 1: Run drift check for each resource group
    logger.info("Phase 1: Detecting drift...")
    try:
        for rg in resource_groups_to_test:
            logger.info(f"Running drift check for resource group: {rg}")
            run_phase1(bicep_file, rg)

        # NOTE: The grep-able drift summary for workflow consolidation is emitted
        # AFTER Phase 2 (see _print_drift_summary below), so it reflects the
        # ignore-pattern-filtered drift set and matches the HTML/JSON report.
        # Emitting it here (pre-filter) would show ignored/false-positive drifts.
    except Exception as e:
        logger.error(f"Error in Phase 1: {e}", exc_info=True)
        sys.exit(1)

    # Phase 2: Analyze with Claude (only for single resource group)
    if len(resource_groups_to_test) > 1:
        logger.info("✓ Wildcard mode: Skipping Phase 2 for multiple resource groups")
        logger.info(f"Consolidating Phase 1 results for {len(resource_groups_to_test)} resource groups...")
        # Output consolidated summary
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
        return

    # Single RG mode - continue with Phase 2
    resource_group = resource_groups_to_test[0]

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
        report_file = Path(f"reports/{resource_group}-drift.json")
        if not report_file.exists():
            logger.error(f"Report file not found: {report_file}")
            sys.exit(1)

        with open(report_file) as f:
            report_data = json.load(f)

        # Detect unresolvable expressions in Bicep
        logger.info("Detecting unresolvable expressions in Bicep template...")
        arm_template = report_data.get("arm_template", {})
        unresolvable = detect_unresolvable_expressions(arm_template)
        if unresolvable:
            unresolvable_count = sum(len(v) for v in unresolvable.values())
            logger.info(f"Found {unresolvable_count} resource(s) with unresolvable names")
            for resource_type, names in unresolvable.items():
                for name in names:
                    logger.debug(f"  {resource_type}: {name}")

            # Attempt smart matching
            logger.info("Attempting smart resource matching...")
            bicep_resources = report_data.get("arm_resources", [])
            azure_resources = report_data.get("live_resources", [])
            matched, _, _ = smart_match_resources(
                bicep_resources, azure_resources, unresolvable
            )

            if matched:
                logger.info(f"✓ Matched {len(matched)} resource(s)")
                for m in matched:
                    logger.debug(f"  {m.get('type')}: {m.get('name')} → {m.get('matched_to')}")
                report_data["smart_matched"] = matched
            else:
                logger.info("No successful smart matches")

        # Load and apply ignore patterns
        ignore_list = IgnorePatternList.from_file(Path(".drift-ignore"))
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

        # Annotate drifts with smart matching information
        if "smart_matched" in report_data:
            report_data["drifts"] = annotate_drifts_with_matches(
                report_data.get("drifts", []),
                report_data.get("smart_matched", [])
            )

        # Emit the grep-able summary from the FILTERED drift set so the CI workflow
        # summary matches the HTML/JSON report (ignored drifts are excluded).
        _print_drift_summary(report_data.get("drifts", []))

        # Perform property-level drift detection
        logger.info("Detecting property-level drift (comparing configurations)...")
        bicep_resources = report_data.get("arm_resources", [])
        deployed_resources = report_data.get("live_resources", [])

        if bicep_resources and deployed_resources:
            # Filter resources to exclude unresolvable ones (same as Phase 1)
            filtered_bicep_resources = [r for r in bicep_resources if _should_compare_resource(r)]
            unresolvable_count = len(bicep_resources) - len(filtered_bicep_resources)
            if unresolvable_count > 0:
                logger.debug(f"Filtered {unresolvable_count} resource(s) with unresolvable expressions")

            # Detect property-level drift
            property_drifts = DriftDetector.detect_drift(filtered_bicep_resources, deployed_resources)

            # Apply ignore patterns to property drifts
            raw_property_drifts = [
                {
                    "type": d.resource_type,
                    "name": d.resource_name,
                    "drift_type": d.drift_type,
                }
                for d in property_drifts
            ]
            filtered_property_dicts, ignored_property_dicts = ignore_list.filter_drifts(raw_property_drifts)
            filtered_property_names = {(d["type"], d["name"]) for d in filtered_property_dicts}
            property_drifts = [d for d in property_drifts if (d.resource_type, d.resource_name) in filtered_property_names]

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

        # Build DriftReport object
        drifts = [
            Drift(
                resource_type=d["type"],
                resource_name=d["name"],
                drift_type=d["drift_type"],
                details=d.get("details")
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

        # Get analysis from Claude (only when a key is available)
        agent_analysis = None
        if agent:
            logger.info("Calling Claude API for drift analysis...")
            try:
                agent_analysis = agent.analyze_drift(drift_report)
                logger.info("✓ Claude analysis completed")
                logger.info("DRIFT ANALYSIS")
                logger.info(agent_analysis)
                # Add comprehensive analysis to report
                report_data["agent_analysis"] = agent_analysis
            except Exception as e:
                logger.error(f"✗ Claude analysis failed: {type(e).__name__}: {str(e)[:200]}", exc_info=True)
                print(f"[ERROR] Claude API call failed: {type(e).__name__}")
                raise

        # Phase 3: Detect change origin and build resource lifecycle
        drifts_to_analyze = report_data.get("drifts", [])
        logger.info(f"Found {len(drifts_to_analyze)} drift(s) to generate recommendations for")

        if len(drifts_to_analyze) > 0:
            logger.info("Phase 3: Building resource lifecycle from Activity Log...")
            subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
            live_resources = report_data.get("live_resources", [])

            for drift in drifts_to_analyze:
                try:
                    # Build resource ID for Activity Log query
                    resource_type = drift.get("type", "")
                    bicep_name = drift.get("name", "")

                    # Find actual deployed resource name (not bicep template name with placeholders)
                    deployed_name = _find_deployed_resource_name(
                        resource_type, bicep_name, live_resources
                    )

                    if not deployed_name:
                        # Fallback to bicep name if no deployed resource found
                        deployed_name = bicep_name
                        logger.debug(f"No live resource found for {resource_type}/{bicep_name}, using bicep name")

                    # Extract resource group from context (needed for resource ID)
                    # IMPORTANT: resource_type is already in "Namespace/type" form (e.g.
                    # "Microsoft.Storage/storageAccounts"). Do NOT replace '.' with '/' -
                    # that breaks the provider namespace (Microsoft.Storage -> Microsoft/Storage).
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{deployed_name}"

                    # Query Activity Log for all changes.
                    # Always pass resource_type + resource_group: the query filters by RG
                    # and matches the resource client-side. resource_type enables matching
                    # deleted resources whose exact ID is no longer resolvable.
                    activity_logs = get_change_history(
                        resource_id,
                        subscription_id,
                        days=30,
                        resource_type=resource_type,
                        resource_group=resource_group,
                    )

                    # Narrow the RG-wide events down to the ONE operation that explains
                    # this drift (delete for missing, write/update for modified).
                    relevant_logs = select_relevant_activity(
                        activity_logs, drift.get("drift_type", "")
                    )

                    # Build lifecycle + origin from the relevant event(s) only
                    lifecycle = build_resource_lifecycle(resource_id, relevant_logs)
                    drift["lifecycle"] = lifecycle.to_dict()

                    origin_info = classify_change_origin(relevant_logs)
                    drift["change_origin"] = origin_info.to_dict()

                    logger.info(
                        f"  {resource_name}: {len(activity_logs or [])} RG event(s) -> "
                        f"{len(relevant_logs)} relevant; "
                        f"origin={origin_info.origin.value}, by={origin_info.changed_by}"
                    )

                except Exception as e:
                    logger.warning(f"Failed to build lifecycle for {drift.get('name')}: {str(e)[:100]}")
                    # Fall back to minimal data
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

        # Generate per-drift recommendations (only when a key is available)
        if agent and len(drifts_to_analyze) > 0:
            logger.info("Generating recommendations via Claude...")
            recommendations_count = 0
            for i, drift in enumerate(drifts_to_analyze, 1):
                try:
                    drift_name = drift.get("name", "unknown")
                    logger.debug(f"[{i}/{len(drifts_to_analyze)}] {drift_name}...")

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

            logger.info(f"Generated recommendations for {recommendations_count}/{len(drifts_to_analyze)} drifts")
        elif not agent:
            logger.info("Skipping Claude recommendations (no API key)")

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
            analysis_file = Path(f"reports/{resource_group}-analysis.md")
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

    # Always generate HTML report, even if Phase 2 fails
    html_file = Path(f"reports/{resource_group}-drift.html")
    logger.info(f"Generating HTML report to {html_file}...")
    try:
        generate_html_report(
            drift_json_file=Path(f"reports/{resource_group}-drift.json"),
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


if __name__ == "__main__":
    main()
