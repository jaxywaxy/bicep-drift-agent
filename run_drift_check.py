"""
run_drift_check.py

Phase 1 entry point — runs the full drift check WITHOUT an agent loop.
Get this working first. The agent comes later.

Usage:
    python run_drift_check.py <bicep-file> <resource-group>

Example:
    python run_drift_check.py ./infra/main.bicep my-resource-group
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from tools.logger import setup_logging, get_logger
from tools.compile_bicep import compile_bicep, extract_resources_from_arm, detect_deployment_scope
from tools.get_live_state import get_live_state
from tools.diff_states import diff_states, format_drift_report
from tools.ignore_patterns import IgnorePatternList

logger = get_logger(__name__)


def run(bicep_file: str, resource_group: str):
    logger.info(f"Bicep Drift Check — {bicep_file} (resource group: {resource_group})")

    # Load parameter overrides from environment or bicepparam file
    param_overrides = {}
    arm_params_env = os.environ.get("ARM_PARAMETERS")
    if arm_params_env:
        try:
            param_overrides = json.loads(arm_params_env)
            logger.debug(f"Parameters from ARM_PARAMETERS: {param_overrides}")
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in ARM_PARAMETERS")
    else:
        # Try to load from bicepparam file based on resource group
        environment = resource_group.split('-')[-1]  # rg-prod → prod
        bicepparam_file = Path(bicep_file).parent / "parameters" / f"{environment}.bicepparam"
        if bicepparam_file.exists():
            try:
                with open(bicepparam_file) as f:
                    bicepparam_content = f.read()
                # Parse bicepparam file (simple key=value format after 'using' line)
                for line in bicepparam_content.split('\n'):
                    line = line.strip()
                    if line.startswith('param ') and '=' in line:
                        # Remove comments first
                        line = line.split('//')[0].strip()
                        # Parse: param vaultName = 'rsv-prod-aue-001'
                        parts = line.replace('param ', '').split('=', 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip().strip("'\"")
                            if value:  # Only add non-empty values
                                param_overrides[key] = value
                if param_overrides:
                    logger.debug(f"Parameters loaded from {bicepparam_file.name}: {param_overrides}")
            except Exception as e:
                logger.warning(f"Could not load {bicepparam_file.name}: {e}")

    # Step 1: Compile Bicep → ARM JSON
    logger.info("Step 1: Compiling Bicep template...")
    try:
        arm_template = compile_bicep(bicep_file)
    except RuntimeError as e:
        logger.error(f"Failed to compile Bicep: {e}")
        raise

    # Detect deployment scope (subscription vs. resource group)
    deployment_scope = detect_deployment_scope(arm_template)
    if deployment_scope == "subscription":
        logger.info("Detected subscription-scoped template (Landing Zone)")

    try:
        arm_resources = extract_resources_from_arm(arm_template, param_overrides)
    except Exception as e:
        logger.error(f"Failed to extract resources: {e}", exc_info=True)
        raise

    logger.info(f"✓ {len(arm_resources)} resource(s) defined in Bicep (scope: {deployment_scope})")

    # Step 2: Query live Azure state via Resource Graph
    logger.info("Step 2: Querying live Azure state via Resource Graph...")
    try:
        if deployment_scope == "subscription":
            logger.debug("Querying at subscription scope...")
            live_resources = get_live_state(resource_group=resource_group, scope="subscription")
        else:
            live_resources = get_live_state(resource_group=resource_group, scope="resource_group")
    except ValueError as e:
        logger.error(f"Missing subscription ID: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to query Azure: {e}", exc_info=True)
        logger.info("Ensure you're logged in: az login")
        raise

    logger.info(f"✓ {len(live_resources)} resource(s) deployed in Azure (scope: {deployment_scope})")

    # Step 3: Load ignore patterns
    logger.info("Step 3: Loading ignore patterns...")
    ignore_patterns = IgnorePatternList.from_file(Path(".drift-ignore"))
    if ignore_patterns.patterns:
        ignore_patterns.log_summary()
    else:
        logger.debug("No ignore patterns found")

    # Step 4: Diff
    logger.info("Step 4: Diffing desired vs actual...")
    try:
        drifts = diff_states(arm_resources, live_resources, ignore_patterns=ignore_patterns)
    except Exception as e:
        logger.error(f"Failed to diff states: {e}", exc_info=True)
        raise

    # Step 5: Report
    logger.info("Drift Report Summary")
    logger.info(format_drift_report(drifts, resource_group))

    # Dump raw data for inspection
    try:
        output_file = Path(f"reports/{resource_group}-drift.json")
        output_file.parent.mkdir(exist_ok=True)
        with open(output_file, "w") as f:
            json.dump({
                "resource_group": resource_group,
                "bicep_file": bicep_file,
                "arm_resources": arm_resources,
                "live_resources": live_resources,
                "drift_count": len(drifts),
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


def main():
    # Initialize logging
    setup_logging(level="INFO")

    if len(sys.argv) < 3:
        logger.error("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    # Validate inputs
    if not Path(bicep_file).exists():
        logger.error(f"Bicep file not found: {bicep_file}")
        sys.exit(1)

    if not bicep_file.endswith(".bicep"):
        logger.error(f"Expected .bicep file, got: {bicep_file}")
        sys.exit(1)

    # Run with error handling
    try:
        run(bicep_file, resource_group)
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
