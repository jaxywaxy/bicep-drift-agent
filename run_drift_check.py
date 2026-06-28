"""
run_drift_check.py

Phase 1 entry point — runs the full drift check WITHOUT an agent loop.
Get this working first. The agent comes later.

Usage:
    python run_drift_check.py <bicep-file> <resource-group>

Example:
    python run_drift_check.py ./infra/main.bicep my-resource-group
"""

import sys
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from tools.compile_bicep import compile_bicep, extract_resources_from_arm, detect_deployment_scope
from tools.get_live_state import get_live_state
from tools.diff_states import diff_states, format_drift_report
from tools.ignore_patterns import IgnorePatternList


def run(bicep_file: str, resource_group: str):
    print(f"\n{'=' * 50}")
    print(f"Bicep Drift Check")
    print(f"{'=' * 50}")
    print(f"  Bicep file:     {bicep_file}")
    print(f"  Resource group: {resource_group}")
    print()

    # Load parameter overrides from environment
    import os
    param_overrides = {}
    arm_params_env = os.environ.get("ARM_PARAMETERS")
    if arm_params_env:
        try:
            param_overrides = json.loads(arm_params_env)
            print(f"  Parameters:     {param_overrides}")
        except json.JSONDecodeError:
            print(f"  ⚠ Invalid JSON in ARM_PARAMETERS")

    # Step 1: Compile Bicep → ARM JSON
    print("Step 1: Compiling Bicep template...")
    try:
        arm_template = compile_bicep(bicep_file)
    except RuntimeError as e:
        print(f"  ✗ Failed to compile Bicep: {e}")
        raise

    # Detect deployment scope (subscription vs. resource group)
    deployment_scope = detect_deployment_scope(arm_template)
    if deployment_scope == "subscription":
        print(f"  ℹ Detected subscription-scoped template (Landing Zone)")

    try:
        arm_resources = extract_resources_from_arm(arm_template, param_overrides)
    except Exception as e:
        print(f"  ✗ Failed to extract resources: {e}")
        raise

    print(f"  ✓ {len(arm_resources)} resource(s) defined in Bicep (scope: {deployment_scope})")
    for r in arm_resources[:10]:  # Show first 10
        print(f"    {r.get('type')} — {r.get('name')}")
    if len(arm_resources) > 10:
        print(f"    ... and {len(arm_resources) - 10} more")

    # Step 2: Query live Azure state
    print("\nStep 2: Querying live Azure state...")
    try:
        if deployment_scope == "subscription":
            print(f"  ℹ Querying at subscription scope...")
            live_resources = get_live_state(scope="subscription")
        else:
            live_resources = get_live_state(resource_group=resource_group, scope="resource_group")
    except ValueError as e:
        print(f"  ✗ Missing subscription ID: {e}")
        raise
    except Exception as e:
        print(f"  ✗ Failed to query Azure: {e}")
        print("  💡 Ensure you're logged in: az login")
        raise

    print(f"  ✓ {len(live_resources)} resource(s) deployed in Azure (scope: {deployment_scope})")
    for r in live_resources[:10]:  # Show first 10
        print(f"    {r.get('type')} — {r.get('name')}")
    if len(live_resources) > 10:
        print(f"    ... and {len(live_resources) - 10} more")

    # Step 3: Load ignore patterns
    print("\nStep 3: Loading ignore patterns...")
    ignore_patterns = IgnorePatternList.from_file(Path(".drift-ignore"))
    if ignore_patterns.patterns:
        ignore_patterns.print_summary()
    else:
        print("  ℹ No ignore patterns found")

    # Step 4: Diff
    print("\nStep 4: Diffing desired vs actual...")
    try:
        drifts = diff_states(arm_resources, live_resources, ignore_patterns=ignore_patterns)
    except Exception as e:
        print(f"  ✗ Failed to diff states: {e}")
        raise

    # Step 5: Report
    print()
    print(format_drift_report(drifts, resource_group))

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

        print(f"\n  ✓ Raw output saved to: {output_file}")
        print("    Open this to see the full shape mismatch details.\n")
    except Exception as e:
        print(f"\n  ⚠ Warning: Could not write report: {e}\n")


def main():
    if len(sys.argv) < 3:
        print("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    # Validate inputs
    if not Path(bicep_file).exists():
        print(f"Error: Bicep file not found: {bicep_file}")
        sys.exit(1)

    if not bicep_file.endswith(".bicep"):
        print(f"Error: Expected .bicep file, got: {bicep_file}")
        sys.exit(1)

    # Run with error handling
    try:
        run(bicep_file, resource_group)
    except FileNotFoundError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
