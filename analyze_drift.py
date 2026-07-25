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

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from agent.drift_agent import DriftAgent
from run_drift_check import run as run_phase1
from tools.activity_log import (
    detect_scanning_identity,
    fetch_policy_principal_ids,
    fetch_resource_group_activity,
    match_activity_for_resource,
)
from tools.change_origin import (
    build_resource_lifecycle,
    classify_change_origin,
    select_relevant_activity,
)
from tools.compile_bicep import compile_bicep, detect_deployment_scope
from tools.config import AUTHORIZED_DEPLOYERS
from tools.count_drifts import COUNTED_TYPES
from tools.diff_states import (
    _IDENTITY_MATCHED_TYPES,
    _should_compare_resource,
    filter_unmanaged_live_resources,
)
from tools.html_report import generate_html_report
from tools.ignore_patterns import IgnorePatternList
from tools.logger import get_logger, setup_logging
from tools.models import Drift, DriftReport
from tools.ownership import classify_owner
from tools.property_drift import DriftDetector
from tools.rg_selector import rg_label
from tools.smart_matching import (
    _has_unresolvable_expression,
    annotate_drifts_with_matches,
    detect_unresolvable_expressions,
    smart_match_resources,
)

logger = get_logger(__name__)

from orchestration.analysis import (
    _run_claude_analysis,
    _clean_estate_summary,
)

from orchestration.attribution import (
    _attribute_lifecycle,
    _split_policy_and_tag_owners,
    _build_lifecycle_and_split,
    _recover_deployed_name,
)

from orchestration.reconciliation import (
    _apply_smart_matching,
    _flag_unmatched_placeholder_resources,
    _apply_ignore_patterns,
    _detect_and_merge_property_drift,
    _find_deployed_resource,
)

from orchestration.detection import (
    _run_phase1,
    _consolidate_wildcard_results,
)

from orchestration.reporting import (
    _finalize_drift_count,
    _drift_type_counts,
    _print_drift_summary,
    _generate_html_report,
)

from orchestration.targeting import (
    discover_resource_groups,
    _resolve_target_resource_groups,
    _find_repo_ignore,
)










































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

        with open(report_file, encoding="utf-8") as f:
            report_data = json.load(f)

        # Deterministic drift processing (always runs, Claude-independent):
        _apply_smart_matching(report_data)
        ignore_list = _apply_ignore_patterns(report_data, bicep_file)
        _detect_and_merge_property_drift(report_data, ignore_list)

        # Phase 3: attribute each drift (lifecycle + change_origin) BEFORE the
        # Claude analysis, so the agent cites who/how and reasons by resource_id
        # instead of falling back to "investigate the Activity Log". (The prior
        # ordering ran attribution after the analysis, leaving both null in the
        # prompt.)
        _attribute_lifecycle(report_data, resource_group)

        # Claude analysis of the attributed drift set (only when a key is available).
        agent_analysis = _run_claude_analysis(agent, report_data)

        # Phase 3/4 tail: split policy/system-enforced changes out and tag owners.
        drifts_to_analyze = _split_policy_and_tag_owners(report_data)

        # Emit the grep-able summary from the FINAL actionable set (post Phase 3 split),
        # so the CI summary matches the report and excludes policy-enforced changes.
        _print_drift_summary(report_data.get("drifts", []))

        # drift_count was stamped on the raw Phase-1 drifts; the array has since
        # been reconciled (ignored/policy-split entries removed). Recompute so the
        # persisted count matches the final array and the reconciled summary.
        _finalize_drift_count(report_data)


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
            # ensure_ascii=False keeps Unicode readable in the artifact; that
            # makes the explicit encoding load-bearing rather than cosmetic.
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
            logger.info(f"Saved processed drift report to JSON: {report_file}")
        except Exception as e:
            logger.warning(f"Failed to save processed report: {e}", exc_info=True)

        # Save analysis
        if agent_analysis:
            analysis_file = Path(f"reports/{report_label}-analysis.md")
            analysis_file.parent.mkdir(parents=True, exist_ok=True)
            with open(analysis_file, "w", encoding="utf-8") as f:
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
