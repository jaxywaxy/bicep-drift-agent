"""
orchestration/detection.py

Phase 1 driver: run the deterministic detection (compile bicep, fetch live state,
diff) per target resource group, and consolidate the per-RG wildcard reports for
a subscription-scope scan.
"""

import json
import sys

from pathlib import Path
from orchestration.phase1 import run as run_phase1
from tools.live_state import ScopeNotFoundError
from tools.logger import get_logger

logger = get_logger(__name__)


def _run_phase1(bicep_file: str, resource_groups_to_test: list) -> None:
    """Run the Phase 1 drift check for each target resource group.

    The grep-able drift summary is intentionally emitted later (after Phase 3), so
    it reflects the ignore-filtered, policy-split drift set rather than raw output.
    """
    logger.info("Phase 1: Detecting drift...")
    multi_rg = len(resource_groups_to_test) > 1
    skipped: list[str] = []
    try:
        for rg in resource_groups_to_test:
            logger.info(f"Running drift check for resource group: {rg}")
            try:
                run_phase1(bicep_file, rg)
            except ScopeNotFoundError as e:
                # One unreadable RG must not sink a whole subscription pass: the
                # other landing zones in the index still have real answers. A
                # single-RG scan has no remainder to salvage, so it still exits.
                if not multi_rg:
                    raise
                logger.warning(f"Skipping '{rg}': {e}")
                skipped.append(rg)
    except ScopeNotFoundError as e:
        logger.error(f"Scope not found: {e}")
        sys.exit(2)
    except Exception as e:
        logger.error(f"Error in Phase 1: {e}", exc_info=True)
        sys.exit(1)

    if skipped:
        logger.warning(
            f"{len(skipped)} resource group(s) skipped as unreadable: {', '.join(skipped)}. "
            f"They are absent from this run's results - not reported as clean."
        )


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
            with open(report_file, encoding="utf-8") as f:
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
