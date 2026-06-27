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

from tools.compile_bicep import compile_bicep, extract_resources_from_arm
from tools.get_live_state import get_live_state
from tools.diff_states import diff_states, format_drift_report


def run(bicep_file: str, resource_group: str):
    print(f"\n{'=' * 50}")
    print(f"Bicep Drift Check")
    print(f"{'=' * 50}")
    print(f"  Bicep file:     {bicep_file}")
    print(f"  Resource group: {resource_group}")
    print()

    # Step 1: Compile Bicep → ARM JSON
    print("Step 1: Compiling Bicep...")
    arm_template = compile_bicep(bicep_file)
    arm_resources = extract_resources_from_arm(arm_template)
    print(f"  → {len(arm_resources)} resource(s) defined in Bicep")
    for r in arm_resources:
        print(f"    {r.get('type')} — {r.get('name')}")

    # Step 2: Query live Azure state
    print("\nStep 2: Querying live Azure state...")
    live_resources = get_live_state(resource_group)
    print(f"  → {len(live_resources)} resource(s) deployed in Azure")
    for r in live_resources:
        print(f"    {r.get('type')} — {r.get('name')}")

    # Step 3: Diff
    print("\nStep 3: Diffing desired vs actual...")
    drifts = diff_states(arm_resources, live_resources)

    # Step 4: Report
    print()
    print(format_drift_report(drifts, resource_group))

    # Dump raw data for inspection — useful while building out normalisation
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

    print(f"\n  Raw output saved to: {output_file}")
    print("  (Open this to see the shape mismatch — that's the next problem to solve.)\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
