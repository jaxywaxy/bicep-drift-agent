"""
Azure Functions app for on-demand drift analysis.

Provides HTTP endpoints to run drift checks and retrieve analysis.
"""

import azure.functions as func
import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv()

from agent.drift_agent import DriftAgent
from tools.models import Drift, DriftReport
from run_drift_check import run as run_phase1

app = func.FunctionApp()


@app.function_name("DriftCheckFunction")
@app.route("drift-check", methods=["POST"])
def drift_check(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP endpoint to run drift check.

    Request body:
    {
        "bicepFile": "./infra/main.bicep",
        "resourceGroup": "rg-prod",
        "parameters": {"environment": "prod"}
    }

    Returns drift analysis as JSON.
    """
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )

    bicep_file = req_body.get("bicepFile")
    resource_group = req_body.get("resourceGroup")
    parameters = req_body.get("parameters", {})

    if not bicep_file or not resource_group:
        return func.HttpResponse(
            json.dumps({"error": "Missing bicepFile or resourceGroup"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Phase 1: Run drift check
        os.environ["ARM_PARAMETERS"] = json.dumps(parameters)

        # Run drift check and capture output
        run_phase1(bicep_file, resource_group)

        # Phase 2: Load report and analyze with Claude
        report_file = Path(f"reports/{resource_group}-drift.json")

        if not report_file.exists():
            return func.HttpResponse(
                json.dumps({"error": "Drift report not generated"}),
                status_code=500,
                mimetype="application/json"
            )

        with open(report_file) as f:
            report_data = json.load(f)

        # Build DriftReport
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
            parameters=parameters,
            drifts=drifts,
            total_missing=len([d for d in drifts if "missing" in d.drift_type]),
            total_extra=len([d for d in drifts if "extra" in d.drift_type]),
            total_modified=len([d for d in drifts if "modified" in d.drift_type]),
        )

        # Get Claude analysis
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return func.HttpResponse(
                json.dumps({"error": "ANTHROPIC_API_KEY not configured"}),
                status_code=500,
                mimetype="application/json"
            )

        agent = DriftAgent(api_key=api_key)
        analysis = agent.analyze_drift(drift_report)

        return func.HttpResponse(
            json.dumps({
                "bicepFile": bicep_file,
                "resourceGroup": resource_group,
                "driftCount": drift_report.total_drift,
                "missing": drift_report.total_missing,
                "extra": drift_report.total_extra,
                "modified": drift_report.total_modified,
                "analysis": analysis,
                "reportPath": str(report_file)
            }, indent=2),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        return func.HttpResponse(
            json.dumps({
                "error": str(e),
                "type": type(e).__name__
            }),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name("HealthFunction")
@app.route("health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "service": "bicep-drift-agent",
            "version": "2.0"
        }),
        status_code=200,
        mimetype="application/json"
    )


@app.function_name("AnalysisFunction")
@app.route("analyze/{resource_group}", methods=["GET"])
def get_analysis(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get saved analysis for a resource group.

    Query params:
    - format: "json" or "markdown" (default: json)
    """
    resource_group = req.route_params.get("resource_group")
    fmt = req.params.get("format", "json")

    try:
        if fmt == "markdown":
            report_file = Path(f"reports/{resource_group}-analysis.md")
            if report_file.exists():
                with open(report_file) as f:
                    return func.HttpResponse(
                        f.read(),
                        status_code=200,
                        mimetype="text/markdown"
                    )
        else:
            report_file = Path(f"reports/{resource_group}-drift.json")
            if report_file.exists():
                with open(report_file) as f:
                    return func.HttpResponse(
                        f.read(),
                        status_code=200,
                        mimetype="application/json"
                    )

        return func.HttpResponse(
            json.dumps({"error": "Report not found"}),
            status_code=404,
            mimetype="application/json"
        )

    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
