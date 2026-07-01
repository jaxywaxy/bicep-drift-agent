"""
Generate HTML reports from drift analysis results.
"""

import re
import json
import html
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


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
        with open(drift_json_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Drift JSON file not found: {drift_json_file}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in drift report {drift_json_file}: {e}")
        raise
    except IOError as e:
        logger.error(f"Failed to read drift report {drift_json_file}: {e}")
        raise

    drifts = data.get("drifts", [])
    agent_analysis = data.get("agent_analysis", None)
    total = len(drifts)
    missing = len([d for d in drifts if "missing" in d["drift_type"]])
    extra = len([d for d in drifts if "extra" in d["drift_type"]])
    # Property-level changes are recorded with drift_type "property_drift" (not the
    # literal "modified"), so count those as modified too - otherwise a changed
    # property (e.g. storage accessTier) shows up in Total but not in Modified.
    modified = len([d for d in drifts if "modified" in d["drift_type"] or "property" in d["drift_type"]])

    # Determine status
    if total == 0:
        status = "✅ No Drift"
        status_class = "success"
    else:
        status = "⚠️ Drift Detected"
        status_class = "warning"

    # Generate drift rows and recommendations
    drift_rows = ""
    recommendations_html = ""

    for i, drift in enumerate(drifts, 1):
        drift_type = drift["drift_type"]
        type_badge = _get_type_badge(drift_type)

        # Format details
        details = drift.get("details", "")
        if isinstance(details, dict):
            details = json.dumps(details, indent=2)
        elif not details:
            details = "No additional details"

        # Get change origin info
        change_origin = drift.get("change_origin", {})
        origin_badge = _get_origin_badge(change_origin)

        # Get lifecycle info
        lifecycle = drift.get("lifecycle", {})
        lifecycle_html = _get_lifecycle_html(lifecycle)

        drift_rows += f"""
        <tr>
            <td><strong>{html.escape(drift['type'])}</strong></td>
            <td><code>{html.escape(drift['name'])}</code></td>
            <td>{type_badge}</td>
            <td>{origin_badge}</td>
            <td>
                <pre>{html.escape(details)}</pre>
                {lifecycle_html}
            </td>
        </tr>
        """

        # Build recommendations section
        recommendation = drift.get("recommendation", "")
        if recommendation:
            # Process recommendation text to handle long strings better
            # Replace newlines with <br> for proper display, escape HTML first
            rec_text = html.escape(recommendation)
            rec_text = rec_text.replace('\n', '<br>')

            recommendations_html += f"""
        <div class="recommendation-item">
            <div class="recommendation-header">
                <span class="recommendation-number">#{i}</span>
                <strong>{html.escape(drift['name'])}</strong>
                {type_badge}
            </div>
            <div class="recommendation-resource">{html.escape(drift['type'])}</div>
            <div class="recommendation-text">{rec_text}</div>
        </div>
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
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: #f5f5f5;
                color: #333;
                line-height: 1.6;
            }}

            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}

            header {{
                background: white;
                padding: 30px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            header h1 {{
                font-size: 28px;
                margin-bottom: 10px;
            }}

            .status {{
                display: inline-block;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 600;
                margin-bottom: 15px;
            }}

            .status.success {{
                background: #d4edda;
                color: #155724;
            }}

            .status.warning {{
                background: #fff3cd;
                color: #856404;
            }}

            .meta {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
                font-size: 14px;
            }}

            .meta-item {{
                background: #f8f9fa;
                padding: 10px;
                border-radius: 4px;
                border-left: 3px solid #0066cc;
            }}

            .meta-label {{
                font-weight: 600;
                color: #555;
            }}

            .meta-value {{
                color: #333;
                margin-top: 5px;
                word-break: break-all;
            }}

            .metrics {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }}

            .metric-card {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            .metric-card.total {{
                border-top: 4px solid #ff9800;
            }}

            .metric-card.missing {{
                border-top: 4px solid #f44336;
            }}

            .metric-card.extra {{
                border-top: 4px solid #2196f3;
            }}

            .metric-card.modified {{
                border-top: 4px solid #ff9800;
            }}

            .metric-number {{
                font-size: 32px;
                font-weight: 700;
                margin: 10px 0;
                color: #333;
            }}

            .metric-label {{
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            .section {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            .section h2 {{
                font-size: 20px;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid #f0f0f0;
            }}

            .section.agent-analysis {{
                background: linear-gradient(135deg, #f0f7ff 0%, #ffffff 100%);
                border-left: 4px solid #0066cc;
            }}

            .analysis-content {{
                background: white;
                padding: 16px;
                border-radius: 6px;
                line-height: 1.8;
                margin-top: 12px;
            }}

            .analysis-content p {{
                margin-bottom: 12px;
                color: #333;
            }}

            .analysis-content h2 {{
                font-size: 18px;
                font-weight: 600;
                color: #333;
                margin-top: 16px;
                margin-bottom: 8px;
                border: none;
                padding-bottom: 0;
            }}

            .analysis-content h3 {{
                font-size: 16px;
                font-weight: 600;
                color: #555;
                margin-top: 14px;
                margin-bottom: 8px;
            }}

            .analysis-content h4 {{
                font-size: 14px;
                font-weight: 600;
                color: #666;
                margin-top: 12px;
                margin-bottom: 6px;
            }}

            .analysis-content strong {{
                color: #0066cc;
                font-weight: 700;
            }}

            .no-drift {{
                text-align: center;
                padding: 40px 20px;
                color: #666;
            }}

            .no-drift svg {{
                width: 64px;
                height: 64px;
                margin-bottom: 15px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }}

            th {{
                background: #f8f9fa;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #e9ecef;
                word-break: break-word;
            }}

            td {{
                padding: 12px;
                border-bottom: 1px solid #e9ecef;
                word-break: break-word;
                white-space: normal;
                overflow-wrap: break-word;
            }}

            td code {{
                word-break: break-all;
                display: block;
            }}

            tr:hover {{
                background: #f8f9fa;
            }}

            .badge {{
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
            }}

            .badge.missing {{
                background: #ffebee;
                color: #c62828;
            }}

            .badge.extra {{
                background: #e3f2fd;
                color: #1565c0;
            }}

            .badge.modified {{
                background: #fff3e0;
                color: #e65100;
            }}

            .badge.origin-policy {{
                background: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #81c784;
            }}

            .badge.origin-system {{
                background: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #81c784;
            }}

            .badge.origin-manual {{
                background: #ffebee;
                color: #c62828;
                border: 1px solid #ef5350;
            }}

            .badge.origin-unknown {{
                background: #f5f5f5;
                color: #666;
                border: 1px solid #ccc;
            }}

            .lifecycle-timeline {{
                margin-top: 15px;
                padding: 12px;
                background: #fafafa;
                border-left: 4px solid #1976d2;
                border-radius: 4px;
                font-size: 13px;
            }}

            .lifecycle-header {{
                margin-bottom: 10px;
                padding-bottom: 8px;
                border-bottom: 1px solid #ddd;
                font-weight: bold;
            }}

            .lifecycle-event {{
                margin-bottom: 10px;
                padding: 8px;
                background: white;
                border-left: 3px solid #999;
                display: flex;
                gap: 12px;
                align-items: flex-start;
                flex-wrap: wrap;
            }}

            .lifecycle-event.timeline-create {{
                border-left-color: #4caf50;
                background: #f1f8e9;
            }}

            .lifecycle-event.timeline-delete {{
                border-left-color: #f44336;
                background: #ffebee;
            }}

            .lifecycle-event.timeline-modify {{
                border-left-color: #ff9800;
                background: #fff3e0;
            }}

            .timeline-event-time {{
                font-weight: bold;
                color: #1976d2;
                min-width: 80px;
            }}

            .timeline-event-op {{
                background: #e0e0e0;
                padding: 2px 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
                min-width: 60px;
                text-align: center;
            }}

            .timeline-event-actor {{
                color: #555;
                font-family: monospace;
                font-size: 12px;
                flex: 1;
                min-width: 150px;
            }}

            .timeline-event-method {{
                color: #888;
                font-size: 12px;
            }}

            .timeline-event-reason {{
                width: 100%;
                color: #666;
                padding-top: 4px;
                border-top: 1px solid #eee;
                font-style: italic;
            }}

            .lifecycle-deleted {{
                margin-top: 10px;
                padding: 10px;
                background: #ffebee;
                border: 1px solid #f44336;
                border-radius: 4px;
                color: #c62828;
            }}

            .lifecycle-empty {{
                padding: 10px;
                color: #999;
                font-style: italic;
            }}

            pre {{
                background: #f5f5f5;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
                font-size: 12px;
                line-height: 1.4;
            }}

            .recommendation-item {{
                background: #f0f7ff;
                border: 1px solid #e0e7ff;
                border-left: 4px solid #0066cc;
                border-radius: 6px;
                padding: 18px;
                margin-bottom: 18px;
                display: flex;
                flex-direction: column;
            }}

            .recommendation-header {{
                display: flex;
                gap: 12px;
                align-items: flex-start;
                margin-bottom: 12px;
                font-weight: 600;
                color: #333;
                flex-wrap: wrap;
                word-break: break-word;
            }}

            .recommendation-header strong {{
                flex: 1;
                min-width: 200px;
                word-break: break-word;
            }}

            .recommendation-number {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 28px;
                height: 28px;
                background: #0066cc;
                color: white;
                border-radius: 50%;
                font-size: 12px;
                font-weight: 700;
                flex-shrink: 0;
            }}

            .recommendation-resource {{
                font-size: 12px;
                color: #666;
                margin-bottom: 8px;
                font-family: monospace;
            }}

            .recommendation-text {{
                background: white;
                padding: 14px;
                border-radius: 4px;
                line-height: 1.8;
                color: #333;
                font-size: 14px;
                word-break: break-word;
                overflow-wrap: break-word;
                white-space: normal;
                max-width: 100%;
                overflow: visible;
            }}

            .matched-item {{
                background: #f0f9ff;
                border: 1px solid #bfe7f5;
                border-left: 4px solid #0284c7;
                border-radius: 6px;
                padding: 16px;
                margin-bottom: 16px;
            }}

            .matched-header {{
                display: flex;
                gap: 10px;
                align-items: center;
                margin-bottom: 12px;
                font-weight: 600;
                color: #333;
            }}

            .matched-badge {{
                display: inline-block;
                padding: 4px 8px;
                background: #0284c7;
                color: white;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
            }}

            .matched-details {{
                background: white;
                padding: 12px;
                border-radius: 4px;
                font-size: 13px;
                line-height: 1.8;
            }}

            .matched-details div {{
                margin-bottom: 8px;
            }}

            .matched-details .label {{
                font-weight: 600;
                color: #555;
                display: inline-block;
                min-width: 120px;
            }}

            .matched-details code {{
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
                color: #d73a49;
            }}

            .property-change {{
                background: white;
                border: 1px solid #e0e0e0;
                border-left: 3px solid #ff9800;
                border-radius: 4px;
                padding: 12px;
                margin-bottom: 12px;
                font-size: 13px;
            }}

            .property-change.critical {{
                border-left-color: #f44336;
                background: #ffebee;
            }}

            .property-change.warning {{
                border-left-color: #ff9800;
                background: #fff3e0;
            }}

            .property-change.info {{
                border-left-color: #2196f3;
                background: #e3f2fd;
            }}

            .property-path {{
                font-family: monospace;
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
            }}

            .property-values {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
                margin-top: 8px;
            }}

            .property-value {{
                padding: 8px;
                background: #f5f5f5;
                border-radius: 3px;
                font-family: monospace;
                font-size: 12px;
                word-break: break-all;
            }}

            .property-value-label {{
                font-size: 11px;
                font-weight: 600;
                color: #666;
                text-transform: uppercase;
                margin-bottom: 4px;
            }}

            footer {{
                text-align: center;
                padding: 20px;
                color: #999;
                font-size: 12px;
            }}

            @media (max-width: 768px) {{
                .container {{
                    padding: 10px;
                }}

                header {{
                    padding: 15px;
                }}

                header h1 {{
                    font-size: 20px;
                }}

                table {{
                    font-size: 12px;
                }}

                td, th {{
                    padding: 8px;
                }}

                pre {{
                    font-size: 10px;
                }}

                .recommendation-item {{
                    padding: 12px;
                    margin-bottom: 12px;
                }}

                .recommendation-header {{
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 8px;
                }}

                .recommendation-text {{
                    padding: 10px;
                    font-size: 13px;
                }}

                .recommendation-number {{
                    width: 24px;
                    height: 24px;
                    font-size: 10px;
                }}
            }}
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
                <div class="metric-card total">
                    <div class="metric-label">Total Issues</div>
                    <div class="metric-number">{total}</div>
                </div>
                <div class="metric-card missing">
                    <div class="metric-label">Missing</div>
                    <div class="metric-number">{missing}</div>
                </div>
                <div class="metric-card extra">
                    <div class="metric-label">Extra</div>
                    <div class="metric-number">{extra}</div>
                </div>
                <div class="metric-card modified">
                    <div class="metric-label">Modified</div>
                    <div class="metric-number">{modified}</div>
                </div>
            </div>

            {_render_agent_analysis_section(agent_analysis)}

            {_render_property_drift_section(data)}

            <div class="section">
                <h2>Drift Details</h2>
                {_render_drift_section(total, drift_rows)}
            </div>

            {_render_smart_matched_section(data)}

            {_render_recommendations_section(total, recommendations_html)}

            <footer>
                Generated by Bicep Drift Agent | {timestamp}
            </footer>
        </div>
    </body>
    </html>
    """

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        f.write(html_content)

    logger.info(f"HTML report generated: {output_file}")


def _render_agent_analysis_section(agent_analysis: str) -> str:
    """Render comprehensive agent analysis section."""
    if not agent_analysis:
        return ""

    # Convert markdown-style formatting to HTML
    analysis_html = html.escape(agent_analysis)
    # Convert bold: **text** → <strong>text</strong>
    analysis_html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', analysis_html)
    # Convert headers: # Header → <h3>Header</h3>
    analysis_html = re.sub(r'^### (.+)$', r'<h4>\1</h4>', analysis_html, flags=re.MULTILINE)
    analysis_html = re.sub(r'^## (.+)$', r'<h3>\1</h3>', analysis_html, flags=re.MULTILINE)
    analysis_html = re.sub(r'^# (.+)$', r'<h2>\1</h2>', analysis_html, flags=re.MULTILINE)
    # Convert line breaks to proper paragraphs
    analysis_html = re.sub(r'\n\n+', '</p><p>', analysis_html)
    analysis_html = f"<p>{analysis_html}</p>"

    return f"""
            <div class="section agent-analysis">
                <h2>🔍 Comprehensive Drift Analysis</h2>
                <p>Claude AI's analysis of drift patterns, root causes, and remediation strategy:</p>
                <div class="analysis-content">
                    {analysis_html}
                </div>
            </div>
            """


def _get_type_badge(drift_type: str) -> str:
    """Get HTML badge for drift type."""
    if "missing" in drift_type.lower():
        return '<span class="badge missing">Missing</span>'
    elif "extra" in drift_type.lower():
        return '<span class="badge extra">Extra</span>'
    else:
        return '<span class="badge modified">Modified</span>'


def _get_origin_badge(change_origin: dict) -> str:
    """Get HTML badge for change origin."""
    if not change_origin:
        return '<span class="badge origin-unknown">Unknown</span>'

    origin = change_origin.get('origin', 'unknown')
    expected = change_origin.get('expected', False)

    # Policy-enforced changes (green)
    if 'policy' in origin:
        return '<span class="badge origin-policy" title="Policy-enforced change">✅ Policy</span>'

    # System-managed changes (green)
    if origin == 'system_managed':
        return '<span class="badge origin-system" title="System-managed change">✅ System</span>'

    # Manual/unauthorized changes (red)
    if origin in ('manual_change', 'terraform_change'):
        icon = '⚠️' if origin == 'manual_change' else '🔄'
        title = 'Manual change - requires review' if origin == 'manual_change' else 'External IaC tool (Terraform)'
        return f'<span class="badge origin-manual" title="{title}">{icon} Manual</span>'

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

    html = ""

    # Modified resources section
    if modified:
        html += f"""
            <div class="section">
                <h2>⚙️ Modified Configuration</h2>
                <p>These resources exist in both Bicep and Azure, but their configuration has changed:</p>
                <div style="margin-top: 16px;">
        """

        for resource in modified:
            resource_name = resource.get("deployed_name", resource.get("resource_name", "unknown"))
            resource_type = resource.get("resource_type", "")
            html += f"""
                    <div class="property-drift-resource">
                        <h3>{resource_type}</h3>
                        <p><strong>{resource_name}</strong></p>
            """

            for diff in resource.get("property_diffs", []):
                severity = diff.get("severity", "info")
                prop_path = diff.get("property_path", "")
                change_type = diff.get("change_type", "")
                desired = diff.get("desired_value", "N/A")
                actual = diff.get("actual_value", "N/A")

                html += f"""
                        <div class="property-change {severity}">
                            <div class="property-path">{prop_path}</div>
                            <div style="font-size: 11px; color: #666; margin-bottom: 8px;">{change_type.title()}</div>
                            <div class="property-values">
                                <div>
                                    <div class="property-value-label">Expected (Bicep)</div>
                                    <div class="property-value">{json.dumps(desired, default=str)}</div>
                                </div>
                                <div>
                                    <div class="property-value-label">Actual (Azure)</div>
                                    <div class="property-value">{json.dumps(actual, default=str)}</div>
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
        html += f"""
            <div class="section">
                <h2>❌ Missing Resources</h2>
                <p>Defined in Bicep but not deployed to Azure:</p>
                <div style="margin-top: 16px;">
        """
        for resource in missing:
            resource_type = resource.get("resource_type", "")
            resource_name = resource.get("resource_name", "")
            html += f"<div style='padding: 8px; background: #ffebee; border-radius: 4px; margin-bottom: 8px;'><strong>{resource_type}</strong> — {resource_name}</div>"
        html += """
                </div>
            </div>
        """

    # Extra resources section
    if extra:
        html += f"""
            <div class="section">
                <h2>⚠️ Extra Resources</h2>
                <p>Deployed to Azure but not defined in Bicep (orphaned or out-of-band changes):</p>
                <div style="margin-top: 16px;">
        """
        for resource in extra:
            resource_type = resource.get("resource_type", "")
            resource_name = resource.get("deployed_name", resource.get("resource_name", ""))
            html += f"<div style='padding: 8px; background: #e3f2fd; border-radius: 4px; margin-bottom: 8px;'><strong>{resource_type}</strong> — {resource_name}</div>"
        html += """
                </div>
            </div>
        """

    return html


def _render_smart_matched_section(data: dict) -> str:
    """Render smart-matched resources section."""
    matched = data.get("smart_matched", [])
    if not matched:
        return ""

    matched_html = ""
    for resource in matched:
        bicep_name = resource.get("name", "unknown")
        azure_name = resource.get("matched_to", "unknown")
        confidence = resource.get("match_confidence", "unknown").title()
        resource_type = resource.get("type", "unknown")

        matched_html += f"""
        <div class="matched-item">
            <div class="matched-header">
                <span class="matched-badge">{confidence}</span>
                <strong>{resource_type}</strong>
            </div>
            <div class="matched-details">
                <div><span class="label">Bicep Name:</span> <code>{bicep_name}</code></div>
                <div><span class="label">Deployed As:</span> <code>{azure_name}</code></div>
                <div><span class="label">Reason:</span> {resource.get("match_reason", "Smart matched by type")}</div>
            </div>
        </div>
        """

    return f"""
            <div class="section">
                <h2>🔗 Smart-Matched Resources</h2>
                <p>These resources are defined in Bicep but use runtime-generated names (like uniqueString()). They have been matched to deployed resources:</p>
                <div style="margin-top: 16px;">
                    {matched_html}
                </div>
            </div>
            """


def _render_recommendations_section(total: int, recommendations_html: str) -> str:
    """Render recommendations section HTML."""
    if total == 0 or not recommendations_html.strip():
        return ""

    return f"""
            <div class="section">
                <h2>💡 Remediation Recommendations</h2>
                <p>Claude AI has generated the following recommendations to resolve each drift:</p>
                <div style="margin-top: 16px;">
                    {recommendations_html}
                </div>
            </div>
            """


if __name__ == "__main__":
    import sys
    from pathlib import Path
    try:
        from .logger import setup_logging
    except ImportError:
        # When run as standalone script, add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent))
        from logger import setup_logging

    setup_logging(level="INFO")

    if len(sys.argv) < 3:
        logger.error("Usage: python -m tools.html_report <drift-json> <output-html>")
        sys.exit(1)

    json_file = Path(sys.argv[1])
    html_file = Path(sys.argv[2])

    if not json_file.exists():
        logger.error(f"{json_file} not found")
        sys.exit(1)

    generate_html_report(json_file, html_file, "resource-group", "main.bicep")
