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

        # Detect unresolvable expressions in Bicep
        print("\n🔍 Detecting unresolvable expressions in Bicep template...")
        arm_template = report_data.get("arm_template", {})
        unresolvable = detect_unresolvable_expressions(arm_template)
        if unresolvable:
            print(f"Found {sum(len(v) for v in unresolvable.values())} resource(s) with unresolvable names:")
            for resource_type, names in unresolvable.items():
                for name in names:
                    print(f"  - {resource_type}: {name}")

            # Attempt smart matching
            print("\n🔗 Attempting smart resource matching...")
            bicep_resources = report_data.get("arm_resources", [])
            azure_resources = report_data.get("live_resources", [])
            matched, _, _ = smart_match_resources(
                bicep_resources, azure_resources, unresolvable
            )

            if matched:
                print(f"✓ Matched {len(matched)} resource(s):")
                for m in matched:
                    print(f"  - {m.get('type')}: {m.get('name')} → {m.get('matched_to')}")
                report_data["smart_matched"] = matched
            else:
                print("⊘ No successful smart matches")

        # Load and apply ignore patterns
        ignore_list = IgnorePatternList.from_file(Path(".drift-ignore"))
        if ignore_list.patterns:
            print(f"\n📋 Loading ignore patterns...")
            ignore_list.print_summary()
            raw_drifts = report_data.get("drifts", [])
            filtered_drifts, ignored_drifts = ignore_list.filter_drifts(raw_drifts)

            if ignored_drifts:
                print(f"\n⊘ Ignoring {len(ignored_drifts)} drift(s) per ignore patterns")
                for d in ignored_drifts:
                    print(f"  - {d['type']} '{d['name']}': {d.get('ignored_reason', 'Matched pattern')}")

            report_data["drifts"] = filtered_drifts
            report_data["ignored_drifts"] = ignored_drifts

        # Annotate drifts with smart matching information
        if "smart_matched" in report_data:
            report_data["drifts"] = annotate_drifts_with_matches(
                report_data.get("drifts", []),
                report_data.get("smart_matched", [])
            )

        # Perform property-level drift detection
        print("\n🔎 Detecting property-level drift (comparing configurations)...")
        bicep_resources = report_data.get("arm_resources", [])
        deployed_resources = report_data.get("live_resources", [])

        if bicep_resources and deployed_resources:
            # Filter resources to exclude unresolvable ones (same as Phase 1)
            filtered_bicep_resources = [r for r in bicep_resources if _should_compare_resource(r)]
            unresolvable_count = len(bicep_resources) - len(filtered_bicep_resources)
            if unresolvable_count > 0:
                print(f"  ℹ Filtered {unresolvable_count} resource(s) with unresolvable expressions")

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

            print(f"✓ Drift detection complete:")
            print(f"  - Total drifts: {summary['total']}")
            print(f"  - Missing resources: {summary['missing']}")
            print(f"  - Extra resources: {summary['extra']}")
            print(f"  - Modified (config changed): {summary['modified']}")

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

        # Get analysis from Claude
        analysis = agent.analyze_drift(drift_report)

        print("\n" + "=" * 60)
        print("📋 DRIFT ANALYSIS")
        print("=" * 60 + "\n")
        print(analysis)
        print("\n" + "=" * 60 + "\n")

        # Generate per-drift recommendations
        drifts_to_analyze = report_data.get("drifts", [])
        print(f"\n💡 Found {len(drifts_to_analyze)} drift(s) to generate recommendations for")

        if len(drifts_to_analyze) > 0:
            print("🤖 Generating recommendations via Claude...")
            recommendations_count = 0

            for i, drift in enumerate(drifts_to_analyze, 1):
                try:
                    drift_name = drift.get("name", "unknown")
                    print(f"  [{i}/{len(drifts_to_analyze)}] {drift_name}...", end=" ", flush=True)

                    recommendation = agent.get_drift_recommendation(
                        resource_type=drift.get("type", ""),
                        resource_name=drift_name,
                        drift_type=drift.get("drift_type", ""),
                        details=drift.get("details"),
                    )

                    drift["recommendation"] = recommendation.strip() if recommendation else "No recommendation generated"
                    recommendations_count += 1
                    print("✓")

                except Exception as e:
                    print(f"✗ ({str(e)[:50]})")
                    drift["recommendation"] = f"Could not generate recommendation: {str(e)[:100]}"

            print(f"\n✓ Generated recommendations for {recommendations_count}/{len(drifts_to_analyze)} drifts")

            # Update JSON report with recommendations
            try:
                with open(report_file, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
                print(f"✓ Saved recommendations to JSON: {report_file}")

                # Verify recommendations are in the file
                with open(report_file) as f:
                    verify_data = json.load(f)
                recs_verified = sum(1 for d in verify_data.get("drifts", []) if d.get("recommendation"))
                print(f"✓ Verified {recs_verified} recommendations in saved JSON file")
            except Exception as e:
                print(f"✗ Failed to save recommendations: {e}")
        else:
            print("⊘ No drifts to analyze for recommendations")

        # Save analysis
        analysis_file = Path(f"reports/{resource_group}-analysis.md")
        with open(analysis_file, "w") as f:
            f.write(f"# Drift Analysis: {resource_group}\n\n")
            f.write(f"**Bicep File:** {bicep_file}\n\n")
            f.write(analysis)

        print(f"✓ Analysis saved to: {analysis_file}")

        # Generate HTML report
        html_file = Path(f"reports/{resource_group}-drift.html")
        generate_html_report(
            drift_json_file=Path(f"reports/{resource_group}-drift.json"),
            output_file=html_file,
            resource_group=resource_group,
            bicep_file=bicep_file,
        )
        print(f"✓ HTML report saved to: {html_file}")

        # Interactive follow-up (only in interactive mode)
        if os.isatty(0):
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
