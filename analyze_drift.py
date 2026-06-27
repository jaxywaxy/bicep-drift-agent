"""
analyze_drift.py

Phase 2 entry point: Analyze drift using Claude AI.

Usage:
    python analyze_drift.py ./path/to/main.bicep your-resource-group

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

from agent.drift_agent import DriftAgent
from tools.models import DriftReport, Drift
from run_drift_check import run as run_phase1


def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_drift.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    # Validate inputs
    if not Path(bicep_file).exists():
        print(f"Error: Bicep file not found: {bicep_file}")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"Bicep Drift Agent - Phase 1 + Phase 2")
    print(f"{'=' * 60}\n")

    # Phase 1: Run drift check
    print("📊 Phase 1: Detecting drift...")
    try:
        run_phase1(bicep_file, resource_group)
    except Exception as e:
        print(f"Error in Phase 1: {e}")
        sys.exit(1)

    # Phase 2: Analyze with Claude
    print("\n🤖 Phase 2: Analyzing drift with Claude...\n")

    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("Error: ANTHROPIC_API_KEY not set in environment")
            print("Set it with: export ANTHROPIC_API_KEY='your-key'")
            sys.exit(1)

        agent = DriftAgent(api_key=api_key)

        # Load the drift report from Phase 1
        report_file = Path(f"reports/{resource_group}-drift.json")
        if not report_file.exists():
            print(f"Error: Report file not found: {report_file}")
            sys.exit(1)

        with open(report_file) as f:
            report_data = json.load(f)

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

        # Get analysis from Claude
        analysis = agent.analyze_drift(drift_report)

        print("\n" + "=" * 60)
        print("📋 DRIFT ANALYSIS")
        print("=" * 60 + "\n")
        print(analysis)
        print("\n" + "=" * 60 + "\n")

        # Save analysis
        analysis_file = Path(f"reports/{resource_group}-analysis.md")
        with open(analysis_file, "w") as f:
            f.write(f"# Drift Analysis: {resource_group}\n\n")
            f.write(f"**Bicep File:** {bicep_file}\n\n")
            f.write(analysis)

        print(f"✓ Analysis saved to: {analysis_file}")

        # Interactive follow-up
        print("\n💬 Ask Claude follow-up questions (or 'quit' to exit):\n")
        while True:
            question = input("You: ").strip()
            if question.lower() in ("quit", "exit", "q"):
                break
            if not question:
                continue

            response = agent.ask_followup(question)
            print(f"\nClaude: {response}\n")

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error in Phase 2: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
