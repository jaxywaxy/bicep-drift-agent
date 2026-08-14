"""
Generate HTML reports from drift analysis results.
"""

import html
import json
import logging
import re
from datetime import datetime
from pathlib import Path

import markdown

from .count_drifts import tally_report

logger = logging.getLogger(__name__)


def _esc(value) -> str:
    """HTML-escape any value for safe interpolation into report markup.

    Resource names/types and property values come from Azure/Bicep data and may
    contain angle brackets (e.g. a tag or description value), so they must be
    escaped before being placed into the HTML body.
    """
    return html.escape(str(value))


# Report stylesheet. Extracted from the html_content f-string: the CSS is
# fully static, and living inside an f-string forced every one of its 168
# braces to be doubled ({{ / }}), so it could not be read, linted, or pasted
# into a browser as real CSS. Kept as a plain (non-f) string - interpolated
# once into the template - so the braces are literal again.
_REPORT_CSS = """            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: #f5f5f5;
                color: #333;
                line-height: 1.6;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            header {
                background: white;
                padding: 30px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }

            header h1 {
                font-size: 28px;
                margin-bottom: 10px;
            }

            .status {
                display: inline-block;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 600;
                margin-bottom: 15px;
            }

            .status.success {
                background: #d4edda;
                color: #155724;
            }

            .status.warning {
                background: #fff3cd;
                color: #856404;
            }

            .meta {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
                font-size: 14px;
            }

            .meta-item {
                background: #f8f9fa;
                padding: 10px;
                border-radius: 4px;
                border-left: 3px solid #0066cc;
            }

            .meta-label {
                font-weight: 600;
                color: #555;
            }

            .meta-value {
                color: #333;
                margin-top: 5px;
                word-break: break-all;
            }

            .metrics {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }

            .metric-card {
                background: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }

            .metric-card.total {
                border-top: 4px solid #ff9800;
            }

            .metric-card.missing {
                border-top: 4px solid #f44336;
            }

            .metric-card.extra {
                border-top: 4px solid #2196f3;
            }

            .metric-card.modified {
                border-top: 4px solid #ff9800;
            }

            .metric-card.critical {
                border-top: 4px solid #d32f2f;
            }

            /* Green, matching the origin-policy badge: this card is the only
               one on the header that is not a call to action. */
            .metric-card.governance {
                border-top: 4px solid #2e7d32;
            }

            .metric-sub {
                font-size: 11px;
                color: #888;
            }

            .metric-number {
                font-size: 32px;
                font-weight: 700;
                margin: 10px 0;
                color: #333;
            }

            .metric-label {
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .section {
                background: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }

            .section h2 {
                font-size: 20px;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid #f0f0f0;
            }

            .no-drift {
                text-align: center;
                padding: 40px 20px;
                color: #666;
            }

            .no-drift svg {
                width: 64px;
                height: 64px;
                margin-bottom: 15px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }

            th {
                background: #f8f9fa;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #e9ecef;
                word-break: break-word;
            }

            td {
                padding: 12px;
                border-bottom: 1px solid #e9ecef;
                word-break: break-word;
                white-space: normal;
                overflow-wrap: break-word;
            }

            td code {
                word-break: break-all;
                display: block;
            }

            tr:hover {
                background: #f8f9fa;
            }

            .badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
            }

            .badge.missing {
                background: #ffebee;
                color: #c62828;
            }

            .badge.extra {
                background: #e3f2fd;
                color: #1565c0;
            }

            .badge.modified {
                background: #fff3e0;
                color: #e65100;
            }

            /* Severity chips in the Drift Details cell. Same palette as the
               property-change cards above, so one property reads the same in
               both places. */
            .badge.critical { background: #ffebee; color: #c62828; }
            .badge.high     { background: #fff3e0; color: #e65100; }
            .badge.medium   { background: #fff8e1; color: #f57f17; }
            .badge.low,
            .badge.info     { background: #e3f2fd; color: #1565c0; }

            .badge.owner-platform {
                background: #eceff1;
                color: #455a64;
                border: 1px solid #b0bec5;
            }

            .badge.owner-workload {
                background: #ede7f6;
                color: #5e35b1;
                border: 1px solid #b39ddb;
            }

            .affected-type {
                color: #888;
                font-size: 11px;
            }

            .affected-list {
                margin-top: 8px;
                padding-left: 12px;
                border-left: 2px solid #e0e0e0;
                font-size: 13px;
            }

            .detail-change {
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
                font-size: 13px;
            }

            .detail-change:last-child {
                border-bottom: none;
            }

            .detail-values {
                font-family: monospace;
                font-size: 12px;
                color: #555;
                margin-top: 4px;
                word-break: break-all;
            }

            .badge.origin-policy {
                background: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #81c784;
            }

            .badge.origin-system {
                background: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #81c784;
            }

            .badge.origin-manual {
                background: #ffebee;
                color: #c62828;
                border: 1px solid #ef5350;
            }

            .badge.origin-unknown {
                background: #f5f5f5;
                color: #666;
                border: 1px solid #ccc;
            }

            /* Risk severity, deliberately a HOTTER palette than the origin
               chips beside it: origin is provenance, this is consequence, and
               the two were previously conflated into one grey "Unknown". */
            .badge.severity-critical {
                background: #b71c1c;
                color: #fff;
                border: 1px solid #7f0000;
            }

            .badge.severity-high {
                background: #ffebee;
                color: #b71c1c;
                border: 1px solid #e53935;
            }

            .badge.severity-medium {
                background: #fff3e0;
                color: #e65100;
                border: 1px solid #fb8c00;
            }

            .badge.severity-low {
                background: #fffde7;
                color: #f57f17;
                border: 1px solid #fdd835;
            }

            .badge.severity-informational {
                background: #e3f2fd;
                color: #1565c0;
                border: 1px solid #64b5f6;
            }

            .badge.severity-unknown {
                background: #f5f5f5;
                color: #999;
                border: 1px solid #ddd;
            }

            .lifecycle-timeline {
                margin-top: 15px;
                padding: 12px;
                background: #fafafa;
                border-left: 4px solid #1976d2;
                border-radius: 4px;
                font-size: 13px;
            }

            .lifecycle-header {
                margin-bottom: 10px;
                padding-bottom: 8px;
                border-bottom: 1px solid #ddd;
                font-weight: bold;
            }

            .lifecycle-event {
                margin-bottom: 10px;
                padding: 8px;
                background: white;
                border-left: 3px solid #999;
                display: flex;
                gap: 12px;
                align-items: flex-start;
                flex-wrap: wrap;
            }

            .lifecycle-event.timeline-create {
                border-left-color: #4caf50;
                background: #f1f8e9;
            }

            .lifecycle-event.timeline-delete {
                border-left-color: #f44336;
                background: #ffebee;
            }

            .lifecycle-event.timeline-modify {
                border-left-color: #ff9800;
                background: #fff3e0;
            }

            .timeline-event-time {
                font-weight: bold;
                color: #1976d2;
                min-width: 80px;
            }

            .timeline-event-op {
                background: #e0e0e0;
                padding: 2px 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
                min-width: 60px;
                text-align: center;
            }

            .timeline-event-actor {
                color: #555;
                font-family: monospace;
                font-size: 12px;
                flex: 1;
                min-width: 150px;
            }

            .timeline-event-method {
                color: #888;
                font-size: 12px;
            }

            .timeline-event-reason {
                width: 100%;
                color: #666;
                padding-top: 4px;
                border-top: 1px solid #eee;
                font-style: italic;
            }

            .lifecycle-deleted {
                margin-top: 10px;
                padding: 10px;
                background: #ffebee;
                border: 1px solid #f44336;
                border-radius: 4px;
                color: #c62828;
            }

            .lifecycle-empty {
                padding: 10px;
                color: #999;
                font-style: italic;
            }

            pre {
                background: #f5f5f5;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
                font-size: 12px;
                line-height: 1.4;
            }







            .matched-item {
                background: #f0f9ff;
                border: 1px solid #bfe7f5;
                border-left: 4px solid #0284c7;
                border-radius: 6px;
                padding: 16px;
                margin-bottom: 16px;
            }

            .matched-header {
                display: flex;
                gap: 10px;
                align-items: center;
                margin-bottom: 12px;
                font-weight: 600;
                color: #333;
            }

            .matched-badge {
                display: inline-block;
                padding: 4px 8px;
                background: #0284c7;
                color: white;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
            }

            .matched-details {
                background: white;
                padding: 12px;
                border-radius: 4px;
                font-size: 13px;
                line-height: 1.8;
            }

            .matched-details div {
                margin-bottom: 8px;
            }

            .matched-details .label {
                font-weight: 600;
                color: #555;
                display: inline-block;
                min-width: 120px;
            }

            .matched-details code {
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
                color: #d73a49;
            }

            .property-change {
                background: white;
                border: 1px solid #e0e0e0;
                border-left: 3px solid #ff9800;
                border-radius: 4px;
                padding: 12px;
                margin-bottom: 12px;
                font-size: 13px;
            }

            .property-change.critical {
                border-left-color: #f44336;
                background: #ffebee;
            }

            .property-change.warning {
                border-left-color: #ff9800;
                background: #fff3e0;
            }

            .property-change.info {
                border-left-color: #2196f3;
                background: #e3f2fd;
            }

            .property-path {
                font-family: monospace;
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
            }

            .property-values {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
                margin-top: 8px;
            }

            .property-value {
                padding: 8px;
                background: #f5f5f5;
                border-radius: 3px;
                font-family: monospace;
                font-size: 12px;
                word-break: break-all;
            }

            .property-value-label {
                font-size: 11px;
                font-weight: 600;
                color: #666;
                text-transform: uppercase;
                margin-bottom: 4px;
            }

            .section.agent-analysis {
                background: linear-gradient(135deg, #f0f7ff 0%, #ffffff 100%);
                border-left: 4px solid #0066cc;
            }

            .analysis-content {
                background: white;
                padding: 16px;
                border-radius: 6px;
                line-height: 1.8;
                margin-top: 12px;
            }

            .analysis-content p { margin-bottom: 12px; color: #333; }
            .analysis-content h1 { font-size: 20px; margin: 4px 0 10px; }
            .analysis-content h2 {
                font-size: 18px; font-weight: 600; color: #333;
                margin-top: 16px; margin-bottom: 8px; border: none; padding-bottom: 0;
            }
            .analysis-content h3 { font-size: 16px; font-weight: 600; color: #555; margin: 14px 0 8px; }
            .analysis-content h4 { font-size: 14px; font-weight: 600; color: #666; margin: 12px 0 6px; }
            .analysis-content strong { color: #0066cc; font-weight: 700; }
            .analysis-content ul, .analysis-content ol { margin: 0 0 12px 22px; }
            .analysis-content li { margin-bottom: 6px; }
            .analysis-content code {
                background: #f5f5f5; padding: 2px 6px; border-radius: 3px;
                font-family: monospace; color: #d73a49; word-break: break-word;
            }
            .analysis-content pre { margin-bottom: 12px; }
            .analysis-content pre code { background: none; color: inherit; padding: 0; }
            .analysis-content table { margin: 8px 0 14px; font-size: 13px; }
            .analysis-content th, .analysis-content td { padding: 8px 10px; }
            .analysis-content hr { border: none; border-top: 1px solid #e9ecef; margin: 16px 0; }

            footer {
                text-align: center;
                padding: 20px;
                color: #999;
                font-size: 12px;
            }

            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }

                header {
                    padding: 15px;
                }

                header h1 {
                    font-size: 20px;
                }

                table {
                    font-size: 12px;
                }

                td, th {
                    padding: 8px;
                }

                pre {
                    font-size: 10px;
                }




            }"""


def generate_html_report(
    drift_json_file: Path,
    output_file: Path,
    resource_group: str,
    bicep_file: str,
) -> None:
    """Generate an HTML report from a drift JSON file.

    Raises:
        FileNotFoundError: If the drift JSON file doesn't exist
        json.JSONDecodeError: If the JSON file is invalid
        IOError: If there are permission issues reading/writing files
    """
    try:
        with open(drift_json_file, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Drift JSON file not found: {drift_json_file}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in drift report {drift_json_file}: {e}")
        raise
    except OSError as e:
        logger.error(f"Failed to read drift report {drift_json_file}: {e}")
        raise

    # matched_unresolvable entries are NOT drift: they record that a runtime-named
    # resource (uniqueString/format) was reconciled to its deployed counterpart.
    # They already render in the dedicated "🔗 Smart-Matched Resources" section;
    # including them here painted empty 'Modified {}' rows in the drift table and
    # inflated the totals/status.
    drifts = [d for d in data.get("drifts", []) if d.get("drift_type") != "matched_unresolvable"]
    # The consolidated remediation narrative (one Claude call for the whole
    # estate) - it replaced the per-drift recommendation cards.
    agent_analysis = data.get("agent_analysis")
    # Counted by the same code as the CI summary (tools/count_drifts) so the two
    # surfaces cannot disagree. The emphasis matches it too: CHANGED RESOURCES is
    # the headline (it is how drift is remediated - redeploy the module), critical
    # is the one thing a resource count cannot express, and property paths are
    # supporting detail because one human action can emit several of them.
    counts = tally_report(data)
    total = counts["total_issues"]
    missing = counts["missing_count"]
    extra = counts["extra_count"]
    modified = counts["drift_count"]
    critical = counts["critical_count"]
    changed_properties = counts["changed_property_count"]

    # Determine status
    if total == 0:
        status = "✅ No Drift"
        status_class = "success"
    else:
        status = "⚠️ Drift Detected"
        status_class = "warning"

    # Generate drift rows and recommendations
    drift_rows = ""

    for i, drift in enumerate(drifts, 1):
        drift_type = drift["drift_type"]
        type_badge = _get_type_badge(drift_type)

        details_html = _render_details_cell(drift.get("details", ""))

        # Get change origin info
        change_origin = drift.get("change_origin", {})
        origin_badge = _get_origin_badge(change_origin)
        owner_badge = _get_owner_badge(drift.get("owner"))
        severity_badge = _get_severity_badge(drift.get("severity"))

        # Get lifecycle info
        lifecycle = drift.get("lifecycle", {})
        lifecycle_html = _get_lifecycle_html(lifecycle)

        drift_rows += f"""
        <tr>
            <td><strong>{html.escape(drift['type'])}</strong></td>
            <td><code>{html.escape(drift['name'])}</code></td>
            <td>{type_badge}</td>
            <td>{severity_badge}</td>
            <td>{owner_badge}</td>
            <td>{origin_badge}</td>
            <td>
                {details_html}
                {lifecycle_html}
            </td>
        </tr>
        """


    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bicep Drift Report - {html.escape(resource_group)}</title>
        <style>
{_REPORT_CSS}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div class="status {status_class}">{status}</div>
                <h1>Bicep Drift Analysis Report</h1>

                <div class="meta">
                    <div class="meta-item">
                        <div class="meta-label">Resource Group</div>
                        <div class="meta-value">{html.escape(resource_group)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Bicep File</div>
                        <div class="meta-value">{html.escape(bicep_file)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Generated</div>
                        <div class="meta-value">{timestamp}</div>
                    </div>
                </div>
            </header>

            <div class="metrics">
                <div class="metric-card modified">
                    <div class="metric-label">Changed Resources</div>
                    <div class="metric-number">{modified}</div>
                    <div class="metric-sub">{changed_properties} property path(s)</div>
                </div>
                <div class="metric-card critical">
                    <div class="metric-label">Critical</div>
                    <div class="metric-number">{critical}</div>
                    <div class="metric-sub">of the {changed_properties} property path(s)</div>
                </div>
                <div class="metric-card missing">
                    <div class="metric-label">Missing</div>
                    <div class="metric-number">{missing}</div>
                </div>
                <div class="metric-card extra">
                    <div class="metric-label">Extra</div>
                    <div class="metric-number">{extra}</div>
                </div>
                <div class="metric-card total">
                    <div class="metric-label">Total Issues</div>
                    <div class="metric-number">{total}</div>
                    <div class="metric-sub">changed + missing + extra</div>
                </div>
                {_render_governance_metric(data)}
            </div>

            {_render_property_drift_section(data)}

            <div class="section">
                <h2>📋 Drift Details ({total})</h2>
                {_render_drift_section(total, drift_rows)}
            </div>

            {_render_policy_enforced_section(data)}

            {_render_agent_analysis_section(agent_analysis)}

            {_render_smart_matched_section(data)}

            <footer>
                Generated by Bicep Drift Agent | {timestamp}{_render_agent_usage_footer(data)}
            </footer>
        </div>
    </body>
    </html>
    """

    output_file.parent.mkdir(parents=True, exist_ok=True)
    # encoding is explicit, never the locale default: the report is full of
    # emoji (status badges, section headings) and Azure values can carry any
    # Unicode. On a runner with LANG unset (C/POSIX) the default encoding is
    # ASCII and this raises UnicodeEncodeError on the first badge - losing the
    # report entirely, which for this tool is the worst possible failure.
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info(f"HTML report generated: {output_file}")


def _get_type_badge(drift_type: str) -> str:
    """Get HTML badge for drift type."""
    if "missing" in drift_type.lower():
        return '<span class="badge missing">Missing</span>'
    elif "extra" in drift_type.lower():
        return '<span class="badge extra">Extra</span>'
    else:
        return '<span class="badge modified">Modified</span>'


def _get_owner_badge(owner) -> str:
    """Get HTML badge for the responsible owner (platform vs workload)."""
    # Muted, and never the drift-type or origin palette. These reused .modified
    # (orange) and .origin-policy (green), so an owner sat next to a severity
    # badge in the same row wearing the same colours and read as a second
    # severity signal. Ownership is routing information, not a judgement.
    if owner == "platform":
        return '<span class="badge owner-platform" title="Owned by the platform team">🏛️ Platform</span>'
    if owner == "workload":
        return '<span class="badge owner-workload" title="Owned by the application/workload team">📦 Workload</span>'
    return '<span class="badge origin-unknown">—</span>'


_SEVERITY_ICONS = {
    "critical": "🚨", "high": "🔴", "medium": "🟠",
    "low": "🟡", "informational": "ℹ️",
}


def _get_severity_badge(severity: str | None) -> str:
    """RISK severity for the row - what this resource is, not who touched it.

    Its own column because the Origin badge cannot carry it: a finding with no
    Activity Log entry has origin AND category 'unknown', so it renders a grey
    "Unknown" however serious the resource is. Live 2026-08-09: a standing
    subscription-scope Owner grant absent from Bicep, classified HIGH, showed
    as grey Unknown - the only severity in the report was change_origin's
    MEDIUM, which is a statement about attribution confidence.
    """
    key = str(severity or "").lower()
    if key not in _SEVERITY_ICONS:
        return '<span class="badge severity-unknown">—</span>'
    return (f'<span class="badge severity-{html.escape(key)}" '
            f'title="Risk severity: {html.escape(key)}">'
            f'{_SEVERITY_ICONS[key]} {html.escape(key.title())}</span>')


def _get_origin_badge(change_origin: dict) -> str:
    """Get HTML badge for change origin."""
    if not change_origin:
        return '<span class="badge origin-unknown">Unknown</span>'

    origin = change_origin.get('origin', 'unknown')

    # Policy-enforced changes (green)
    if 'policy' in origin:
        return '<span class="badge origin-policy" title="Policy-enforced change">✅ Policy</span>'

    # System-managed changes (green)
    if origin == 'system_managed':
        return '<span class="badge origin-system" title="System-managed change">✅ System</span>'

    # Authorized IaC deployment (green) - the scanning identity or a configured
    # DRIFT_AUTHORIZED_DEPLOYERS pipeline identity made the change. The drift
    # itself is still actionable; only the attribution is benign.
    if origin == 'authorized_deployment':
        return '<span class="badge origin-system" title="Deployed by an authorized pipeline identity">🚀 Pipeline</span>'

    # Manual/unauthorized changes (red)
    if origin in ('manual_change', 'terraform_change'):
        icon = '⚠️' if origin == 'manual_change' else '🔄'
        title = 'Manual change - requires review' if origin == 'manual_change' else 'External IaC tool (Terraform)'
        return f'<span class="badge origin-manual" title="{title}">{icon} Manual</span>'

    # An out-of-band change we could not attribute is still out-of-band. The row
    # already carries category and severity; deriving the badge from `origin`
    # alone greys out a HIGH finding purely because no actor was recorded.
    if change_origin.get('category') == 'out_of_band':
        return ('<span class="badge origin-manual" title="Out-of-band change - no actor '
                'recorded in the Activity Log">⚠️ Out-of-band</span>')

    # Unknown
    return '<span class="badge origin-unknown">Unknown</span>'


def _get_lifecycle_html(lifecycle: dict) -> str:
    """Get HTML timeline for resource lifecycle events."""
    if not lifecycle or not lifecycle.get('events'):
        return '<div class="lifecycle-empty">No activity log history found</div>'

    events = lifecycle.get('events', [])
    if not events:
        return '<div class="lifecycle-empty">No activity log history found</div>'

    # Create timeline HTML
    timeline_html = '<div class="lifecycle-timeline">'
    timeline_html += '<div class="lifecycle-header">'
    timeline_html += f'<strong>Resource Lifecycle ({len(events)} event{"s" if len(events) != 1 else ""})</strong>'

    # Show creation info
    created_at = lifecycle.get('created_at')
    created_by = lifecycle.get('created_by')
    if created_at:
        created_dt = created_at.split('T')[0] if isinstance(created_at, str) else 'Unknown'
        timeline_html += f'<br><small>Created: {created_dt} by {created_by or "Unknown"}</small>'

    timeline_html += '</div>'

    # Timeline events (in reverse chronological order for display)
    for event in reversed(events):
        timestamp = event.get('timestamp', 'Unknown')
        operation = event.get('operation', 'unknown').upper()
        actor = event.get('actor', 'Unknown')
        method = event.get('method', 'Unknown')
        reason = event.get('reason', '')

        # Format timestamp
        if isinstance(timestamp, str):
            ts_display = timestamp.split('T')[0] if 'T' in timestamp else timestamp
        else:
            ts_display = 'Unknown'

        # Color code by operation type
        op_color = 'timeline-create' if operation == 'CREATE' else \
                   'timeline-delete' if operation == 'DELETE' else \
                   'timeline-modify' if 'MODIFY' in operation else \
                   'timeline-event'

        timeline_html += f'''
        <div class="timeline-event {op_color}">
            <div class="timeline-event-time">{ts_display}</div>
            <div class="timeline-event-op">{operation}</div>
            <div class="timeline-event-actor">{actor}</div>
            <div class="timeline-event-method">{method}</div>
            {f'<div class="timeline-event-reason">{reason}</div>' if reason else ''}
        </div>
        '''

    # Show deletion info if deleted
    deleted_at = lifecycle.get('deleted_at')
    deleted_by = lifecycle.get('deleted_by')
    if deleted_at:
        deleted_dt = deleted_at.split('T')[0] if isinstance(deleted_at, str) else 'Unknown'
        timeline_html += f'<div class="lifecycle-deleted"><strong>⚠️ Deleted: {deleted_dt} by {deleted_by or "Unknown"}</strong></div>'

    timeline_html += '</div>'
    return timeline_html


def _render_details_cell(details) -> str:
    """Render a drift's details as prose, not as a JSON dump.

    This cell used to be json.dumps(indent=2) inside a <pre>, squeezed into a
    fixed-layout six-column table. It restated - in developer syntax - what the
    Modified Configuration section above had already shown properly, so the two
    disagreed on which was authoritative while neither was pleasant to read.

    Keys other than changed_properties still fall through to the <pre>: this is
    a diagnostic cell and dropping a key we did not anticipate would lose
    evidence silently, which is worse than an ugly cell.
    """
    if not isinstance(details, dict):
        return f"<pre>{html.escape(str(details))}</pre>" if details else "<em>No additional details</em>"

    changed = details.get("changed_properties") or {}
    blocks = ""
    for path, change in changed.items():
        if not isinstance(change, dict):
            # A shape we don't model - show it rather than swallow it.
            blocks += (f'<div class="detail-change"><code>{html.escape(str(path))}</code>: '
                       f"{html.escape(str(change))}</div>")
            continue
        severity = str(change.get("severity", "")).lower()
        chip = (f'<span class="badge {html.escape(severity)}">{html.escape(severity)}</span>'
                if severity else "")
        blocks += f"""<div class="detail-change">
                    <code>{html.escape(str(path))}</code> {chip}
                    <div class="detail-values">{_esc(json.dumps(change.get("desired"), default=str))}
                        &rarr; <strong>{_esc(json.dumps(change.get("actual"), default=str))}</strong></div>
                </div>"""

    rest = {k: v for k, v in details.items() if k != "changed_properties"}
    if rest:
        blocks += f"<pre>{html.escape(json.dumps(rest, indent=2, default=str))}</pre>"
    return blocks or "<em>No additional details</em>"


def _render_governance_metric(data: dict) -> str:
    """A card for the policy-enforced rows, so the header accounts for the page.

    Without it the header reads "Total Issues: 1" above a table of nineteen
    governance rows, and a reader who trusts the number does not know they are
    there while a reader who scrolls concludes the number is wrong. Both
    readings cost the report its credibility, and an operator reported exactly
    the second one.

    It sits AFTER Total Issues and says so in the sub-line: these are
    deliberately outside that sum (see count_drifts.COUNTED_TYPES), and a card
    placed among the summed ones would imply it is part of the arithmetic.
    Rendered only when non-zero, matching the section itself - a clean estate
    should not carry a governance card reading zero.
    """
    count = len(data.get("policy_enforced_drifts") or [])
    if not count:
        return ""
    return f"""<div class="metric-card governance">
                    <div class="metric-label">Policy-Enforced</div>
                    <div class="metric-number">{count}</div>
                    <div class="metric-sub">governance &mdash; not in Total Issues</div>
                </div>"""


def _render_policy_enforced_section(data: dict) -> str:
    """Render the Policy / System-Enforced changes section (detected, not actionable drift)."""
    items = data.get("policy_enforced_drifts", [])
    if not items:
        return ""

    # Map drift type -> a clear human action phrase.
    action_by_drift = {
        "extra_in_azure": "Added by",
        "missing_in_azure": "Removed by",
        "property_drift": "Modified by",
    }
    # Distinguish policy vs Azure-service (system-managed) origin for the "by" label.
    def _agent(origin: str) -> str:
        return "an Azure service" if origin == "system_managed" else "Azure Policy"

    # Group by the governance FACT (what changed + who imposed it), not by
    # resource. An inherit-tag policy applies to every resource in the RG, so
    # one assignment produced nineteen rows that differed only in the resource
    # name - a screen and a half of scrolling carrying a single fact. Grouping
    # is the normal case for Modify/DINE effects, not a fixture artifact.
    # dict preserves insertion order, so the grouped output stays deterministic.
    groups: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for d in items:
        co = d.get("change_origin", {}) or {}
        origin = co.get("origin") or "unknown"
        drift_type = d.get("drift_type", "")
        action = action_by_drift.get(drift_type, "Changed by")
        policy = co.get("policy_name")
        agent = _agent(origin)
        # e.g. "Added by Azure Policy: DINE CanNotDelete lock on storage"
        summary = f"{action} {agent}" + (f": {policy}" if policy and policy != "Unknown Policy" else "")
        when = (co.get("timestamp") or "").split("T")[0] or "-"
        # Show the property and BOTH values. Without them the row says only
        # "Modified by Azure Policy", which reads as if the change itself were
        # missing from the report - a live reader concluded exactly that.
        changes = "<br>".join(
            f"<code>{html.escape(path)}</code>: "
            f"{html.escape(str(v.get('desired')))} &rarr; "
            f"<strong>{html.escape(str(v.get('actual')))}</strong>"
            for path, v in (d.get("policy_enforced_properties") or {}).items()
        ) or "<em>whole resource</em>"

        groups.setdefault((changes, summary), []).append(
            (str(d.get("type", "")), str(d.get("name", "")), when))

    rows = ""
    for (changes, summary), members in groups.items():
        # A group can span days (a policy sweeping an RG is not instantaneous)
        # and can carry no timestamp at all - a Modify effect leaves no activity
        # log event, which is the whole reason this section exists.
        dates = sorted({w for _, _, w in members if w and w != "-"})
        if not dates:
            when = "-"
        elif len(dates) == 1:
            when = dates[0]
        else:
            when = f"{dates[0]} &ndash; {dates[-1]}"

        listing = "".join(
            f"<div><code>{html.escape(name)}</code> "
            f"<span class=\"affected-type\">{html.escape(rtype)}</span></div>"
            for rtype, name, _ in members
        )
        if len(members) == 1:
            affected = listing
        else:
            # Collapsed by default: the count is the fact, the names are the
            # evidence, and an operator only needs the evidence when the count
            # surprises them.
            affected = (f"<details><summary><strong>{len(members)} resources</strong></summary>"
                        f'<div class="affected-list">{listing}</div></details>')

        rows += f"""
                <tr>
                    <td>{changes}</td>
                    <td><span class="badge origin-policy">🛡️ {html.escape(summary)}</span></td>
                    <td>{affected}</td>
                    <td>{when or '-'}</td>
                </tr>
        """

    return f"""
            <div class="section">
                <h2>🛡️ Policy / System-Enforced Changes ({len(items)})</h2>
                <p>These resources were <strong>added, modified, or removed by Azure Policy or an
                   Azure service</strong> — not manual/out-of-band changes. The values below
                   <strong>are</strong> different from the template; they are separated out because
                   policy re-applies them on every write, so <strong>redeploying will not fix
                   them</strong> — reconcile the template with the policy instead. Not counted as
                   actionable drift.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Change</th><th>What happened</th>
                            <th>Affected</th><th>When</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
    """


def _render_drift_section(total: int, drift_rows: str) -> str:
    """Render drift section HTML."""
    if total == 0:
        return """
        <div class="no-drift">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <h3>No Drift Detected</h3>
            <p>Your infrastructure matches the Bicep template</p>
        </div>
        """
    else:
        return f"""
        <table>
            <thead>
                <tr>
                    <th>Resource Type</th>
                    <th>Resource Name</th>
                    <th>Drift Type</th>
                    <th>Severity</th>
                    <th>Owner</th>
                    <th>Change Origin</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {drift_rows}
            </tbody>
        </table>
        """


def _render_property_drift_section(data: dict) -> str:
    """Render property-level drift section."""
    property_drifts = data.get("property_drifts", [])
    if not property_drifts:
        return ""

    # Separate by drift type
    modified = [d for d in property_drifts if d["drift_type"] == "modified"]
    missing = [d for d in property_drifts if d["drift_type"] == "missing"]
    extra = [d for d in property_drifts if d["drift_type"] == "extra"]
    # Critical configuration issues surfaced by ConfigurationValidator
    # (orphaned disks, VMs with no NIC). These have no Bicep counterpart, so
    # they don't fit the missing/extra/modified buckets — render them on their own.
    critical_config = [d for d in property_drifts if d["drift_type"] == "critical_config_error"]

    html = ""

    if critical_config:
        html += """
            <div class="section">
                <h2>🚨 Critical Configuration Issues</h2>
                <p>Detected in the live environment (independent of Bicep) — these need attention:</p>
                <div style="margin-top: 16px;">
        """
        for resource in critical_config:
            resource_type = resource.get("resource_type", "")
            resource_name = resource.get("deployed_name") or resource.get("resource_name", "")
            issues = "; ".join(
                f"{diff.get('property_path', '')}: {diff.get('actual_value', '')}"
                for diff in resource.get("property_diffs", [])
            )
            html += (
                "<div style='padding: 8px; background: #fff3e0; border-left: 4px solid #e65100; "
                "border-radius: 4px; margin-bottom: 8px;'>"
                f"<strong>{_esc(resource_type)}</strong> — {_esc(resource_name)}"
                f"<div style='font-size: 12px; color: #666;'>{_esc(issues)}</div></div>"
            )
        html += """
                </div>
            </div>
        """

    # Modified resources section
    if modified:
        # Path count is stated per section rather than as a headline: one human
        # action can emit several paths, so it measures comparator granularity.
        paths = sum(len(r.get("property_diffs") or []) for r in modified)
        html += f"""
            <div class="section">
                <h2>⚙️ Modified Configuration ({len(modified)})</h2>
                <p>These resources exist in both Bicep and Azure, but their configuration has changed
                   — <strong>{len(modified)} resource(s)</strong>, {paths} property path(s):</p>
                <div style="margin-top: 16px;">
        """

        for resource in modified:
            resource_name = resource.get("deployed_name", resource.get("resource_name", "unknown"))
            resource_type = resource.get("resource_type", "")
            html += f"""
                    <div class="property-drift-resource">
                        <h3>{_esc(resource_type)}</h3>
                        <p><strong>{_esc(resource_name)}</strong></p>
            """

            for diff in resource.get("property_diffs", []):
                severity = diff.get("severity", "info")
                prop_path = diff.get("property_path", "")
                change_type = diff.get("change_type", "")
                desired = diff.get("desired_value", "N/A")
                actual = diff.get("actual_value", "N/A")

                html += f"""
                        <div class="property-change {_esc(severity)}">
                            <div class="property-path">{_esc(prop_path)}</div>
                            <div style="font-size: 11px; color: #666; margin-bottom: 8px;">{_esc(change_type.title())}</div>
                            <div class="property-values">
                                <div>
                                    <div class="property-value-label">Expected (Bicep)</div>
                                    <div class="property-value">{_esc(json.dumps(desired, default=str))}</div>
                                </div>
                                <div>
                                    <div class="property-value-label">Actual (Azure)</div>
                                    <div class="property-value">{_esc(json.dumps(actual, default=str))}</div>
                                </div>
                            </div>
                        </div>
                """

            html += """
                    </div>
            """

        html += """
                </div>
            </div>
        """

    # Missing resources section
    if missing:
        html += """
            <div class="section">
                <h2>❌ Missing Resources</h2>
                <p>Defined in Bicep but not deployed to Azure:</p>
                <div style="margin-top: 16px;">
        """
        for resource in missing:
            resource_type = resource.get("resource_type", "")
            resource_name = resource.get("resource_name", "")
            html += f"<div style='padding: 8px; background: #ffebee; border-radius: 4px; margin-bottom: 8px;'><strong>{_esc(resource_type)}</strong> — {_esc(resource_name)}</div>"
        html += """
                </div>
            </div>
        """

    # Extra resources section
    if extra:
        html += """
            <div class="section">
                <h2>⚠️ Extra Resources</h2>
                <p>Deployed to Azure but not defined in Bicep (orphaned or out-of-band changes):</p>
                <div style="margin-top: 16px;">
        """
        for resource in extra:
            resource_type = resource.get("resource_type", "")
            resource_name = resource.get("deployed_name", resource.get("resource_name", ""))
            html += f"<div style='padding: 8px; background: #e3f2fd; border-radius: 4px; margin-bottom: 8px;'><strong>{_esc(resource_type)}</strong> — {_esc(resource_name)}</div>"
        html += """
                </div>
            </div>
        """

    return html


def _render_agent_usage_footer(data: dict) -> str:
    """One-line agent usage/cost note for the footer (PR #218 telemetry).

    Renders nothing when the run had no API key (no agent_usage block), but a
    provider that was configured and FAILED says so. Those two cases used to
    render identically - silence - so a torn-down endpoint produced green runs
    with no analysis and no signal, noticed only because the cost line
    disappeared. The failure stays non-fatal; it just stops being invisible.

    Says "Agent analysis", not "Claude analysis": the provider is selectable
    (DRIFT_LLM_PROVIDER) and the footer prints the model beside the label, so
    the hardcoded vendor produced the self-contradicting "Claude analysis
    (gpt-5-mini)" in a live report.
    """
    usage = data.get("agent_usage")
    failure = data.get("agent_analysis_error")
    if not usage or not usage.get("calls"):
        if failure:
            return (
                f"<br>Agent analysis unavailable this run "
                f"({_esc(str(failure.get('error_type', 'error')))}): "
                f"{_esc(str(failure.get('hint', '')))}"
            )
        return ""
    models = ", ".join(usage.get("models") or []) or "unknown model"
    cost = usage.get("estimated_cost_usd")
    cost_str = f"est. ${cost:.4f}" if cost is not None else "cost unknown (no price for model)"
    return (
        f"<br>Agent analysis ({_esc(models)}): {usage.get('calls', 0)} call(s) · "
        f"{usage.get('input_tokens', 0):,} in / {usage.get('output_tokens', 0):,} out tokens · {_esc(cost_str)}"
    )


def _render_matched_item(resource: dict) -> str:
    """Render one smart-matched resource card."""
    bicep_name = _esc(resource.get("name", "unknown"))
    azure_name = _esc(resource.get("matched_to", "unknown"))
    confidence = _esc(resource.get("match_confidence", "unknown").title())
    resource_type = _esc(resource.get("type", "unknown"))
    reason = _esc(resource.get("match_reason", "Smart matched by type"))
    return f"""
        <div class="matched-item">
            <div class="matched-header">
                <span class="matched-badge">{confidence}</span>
                <strong>{resource_type}</strong>
            </div>
            <div class="matched-details">
                <div><span class="label">Bicep Name:</span> <code>{bicep_name}</code></div>
                <div><span class="label">Deployed As:</span> <code>{azure_name}</code></div>
                <div><span class="label">Reason:</span> {reason}</div>
            </div>
        </div>
        """


def _render_smart_matched_section(data: dict) -> str:
    """Render smart-matched resources section.

    Matches are the audit trail for the (heuristic) smart matcher, not drift -
    a mis-pair here is how a wrong match gets spotted. High-confidence matches
    collapse behind a one-line summary so 30 "nothing is wrong" cards don't
    bury the actionable sections; anything below high confidence stays visible
    because those are exactly the rows worth a glance.
    """
    matched = data.get("smart_matched", [])
    if not matched:
        return ""

    flagged = [r for r in matched
               if str(r.get("match_confidence", "")).lower() != "high"]
    confident = [r for r in matched
                 if str(r.get("match_confidence", "")).lower() == "high"]

    flagged_html = ""
    if flagged:
        cards = "".join(_render_matched_item(r) for r in flagged)
        flagged_html = f"""
                <p><strong>⚠️ {len(flagged)} match(es) below high confidence</strong> — worth a glance; a wrong pairing here can hide real drift:</p>
                <div style="margin-top: 16px;">
                    {cards}
                </div>
        """

    confident_html = ""
    if confident:
        cards = "".join(_render_matched_item(r) for r in confident)
        confident_html = f"""
                <details style="margin-top: 16px;">
                    <summary style="cursor: pointer; font-weight: 600;">✅ {len(confident)} resource(s) reconciled to deployed names with high confidence — no drift (click to expand)</summary>
                    <div style="margin-top: 16px;">
                        {cards}
                    </div>
                </details>
        """

    return f"""
            <div class="section">
                <h2>🔗 Smart-Matched Resources ({len(matched)})</h2>
                <p>These resources are defined in Bicep but use runtime-generated names (like uniqueString()). They have been matched to deployed resources:</p>
                {flagged_html}
                {confident_html}
            </div>
            """


# Fenced code blocks and inline code spans, in one alternation so split()
# yields [text, code, text, code, ...] with code at odd indices.
_MD_CODE_RE = re.compile(r"(```.*?```|`[^`\n]+`)", re.DOTALL)


def _neutralize_raw_html(text: str) -> str:
    """Escape '<' outside markdown code regions so model output cannot inject
    markup. Code regions are left raw: python-markdown escapes &, < and >
    inside code itself, so pre-escaping them there double-escapes (the
    &quot;-in-az-commands bug). An unclosed fence falls through to the escaped
    branch - cosmetic at worst, never unsafe.
    """
    parts = _MD_CODE_RE.split(text)
    return "".join(
        part if i % 2 else part.replace("<", "&lt;")
        for i, part in enumerate(parts)
    )


# Schemes a link in the narrative may carry. Everything else is neutralised:
# `javascript:` and `data:` are the two that execute, and no legitimate
# remediation plan needs either.
_SAFE_URI_SCHEMES = frozenset({"http", "https", "mailto"})
_URI_ATTR_RE = re.compile(r'\s(href|src)\s*=\s*"([^"]*)"', re.IGNORECASE)
_URI_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*):", re.IGNORECASE)


def _uri_is_safe(value: str) -> bool:
    """Does this attribute value carry an allowed scheme (or none at all)?

    Normalises what a scheme can hide behind before deciding: HTML entities
    ('&#106;avascript:'), embedded control characters ('java\\nscript:'),
    surrounding whitespace, and casing - python-markdown passes all four
    straight into the href. A value with no scheme is relative, so safe.
    """
    cleaned = re.sub(r"[\s\x00-\x1f]", "", html.unescape(value))
    match = _URI_SCHEME_RE.match(cleaned)
    return match.group(1).lower() in _SAFE_URI_SCHEMES if match else True


def _neutralize_unsafe_uris(rendered_html: str) -> str:
    """Defang link targets the markdown renderer built from model output.

    _neutralize_raw_html stops raw tags, but markdown's OWN link syntax needs
    no '<': `[go](javascript:...)` becomes a live anchor. The narrative quotes
    live resource names and tag values, which are written by anyone with write
    access to the scanned subscription - including whoever made the drift being
    reported - so a name is not a trustworthy link target.
    """
    return _URI_ATTR_RE.sub(
        lambda m: m.group(0) if _uri_is_safe(m.group(2)) else f' {m.group(1)}="#"',
        rendered_html,
    )


def _render_agent_analysis_section(agent_analysis: str) -> str:
    """Render the consolidated remediation analysis (Claude's single narrative).

    This replaced the per-drift recommendation cards. The narrative is ONE call
    that sees every drift at once, so it can order the work, flag "investigate
    before you overwrite this", and recommend a what-if first - none of which N
    isolated per-resource calls could do (all five in a real 5-drift run
    independently said "redeploy the Bicep template" and none mentioned
    what-if). It also costs O(1) instead of O(N).

    Rendered via markdown (the narrative uses tables, lists and inline code).
    Raw HTML is NEUTRALIZED FIRST: it is model output that quotes live
    resource names, so a name like '<script>' must never become markup.
    But a blanket html.escape() double-escaped code regions - markdown escapes
    &/</> inside code spans/fences itself, so a pre-escaped quote in an az CLI
    command rendered literally as &quot; in the report. Only '<' (the sole
    character that can open a tag) is escaped, and only OUTSIDE code regions;
    this also lets '>' blockquotes render instead of showing as &gt;.

    Link TARGETS are then defanged after rendering (_neutralize_unsafe_uris):
    markdown's own '[text](target)' syntax needs no '<', so escaping alone
    leaves `javascript:`/`data:` anchors live.
    """
    if not agent_analysis:
        return ""

    analysis_html = _neutralize_unsafe_uris(markdown.markdown(
        _neutralize_raw_html(agent_analysis),
        extensions=["tables", "fenced_code", "sane_lists"],
    ))
    return f"""
            <div class="section agent-analysis">
                <h2>🛠️ Remediation Analysis</h2>
                <p>Analysis of the drift, its likely cause, and the order to fix it in:</p>
                <div class="analysis-content">
                    {analysis_html}
                </div>
            </div>
            """
