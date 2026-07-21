#!/usr/bin/env python3
"""
Publish a landing zone's drift result as a rolling GitHub issue in the LZ repo.

The Slack digest's report link points at the Actions run in the drift-agent
repo, which workload teams typically cannot read (and granting read would
expose every LZ's reports to every team). Workload teams DO have access to
their own landing-zone repo, so the drift result is published there:

- drift found  -> create (or update) ONE rolling issue titled
  "Drift Report - <lz>" carrying the digest lines and the per-resource
  recommendations (which deliberately no longer go to chat).
- scan clean   -> close the open issue with a resolution comment.

The issue URL is exported (GITHUB_OUTPUT issue_url=...) so the notification
step can point workload-routed teams at it instead of the Actions run.

Failure posture: publishing is an enhancement, never a gate - a missing token
or a 403 (token lacks issues:write on the LZ repo) logs a warning and exits 0.
"""

import json
import logging
import os
import pathlib
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from .send_notifications import events_from_report
    from .http_util import urlopen_checked
except ImportError:
    from send_notifications import events_from_report
    from http_util import urlopen_checked

logger = logging.getLogger(__name__)

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
# Hidden marker locating "our" issue regardless of title edits.
# Use a generic marker (avoid embedding the repository name).
ISSUE_MARKER = "<!-- drift-agent:drift-report -->"
ISSUE_LABEL = "drift-report"
REQUEST_TIMEOUT = 15


def _api_request(
    method: str, url: str, token: str, payload: Optional[Dict[str, Any]] = None
) -> Tuple[int, Any]:
    """One GitHub REST call. Returns (status, parsed_json_or_None)."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen_checked(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        logger.warning(f"GitHub API request failed: {type(e).__name__}: {e}")
        return 0, None


def find_open_report_issue(repo: str, token: str, lz_name: str) -> Optional[Dict[str, Any]]:
    """Locate the rolling drift issue: an open issue carrying ISSUE_MARKER.

    Matched on the hidden body marker (not the title) so a renamed issue is
    still found; lz_name disambiguates if one repo hosts several LZ configs.
    """
    status, issues = _api_request(
        "GET", f"{GITHUB_API}/repos/{repo}/issues?state=open&per_page=100", token
    )
    if status != 200 or not isinstance(issues, list):
        return None
    for issue in issues:
        body = issue.get("body") or ""
        if ISSUE_MARKER in body and f"drift-report:{lz_name}" in body:
            return issue
    return None


def _load_reports(reports_dir: str) -> List[Tuple[str, Dict[str, Any], str]]:
    """(resource_group, report, path) for every *-drift.json in the directory."""
    reports = []
    for json_file in sorted(pathlib.Path(reports_dir).glob("*-drift.json")):
        try:
            with open(json_file, encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read {json_file}: {e}")
            continue
        reports.append((report.get("resource_group") or json_file.stem, report, str(json_file)))
    return reports


def build_issue_body(reports_dir: str, lz_name: str, run_url: str) -> Tuple[str, int]:
    """Render the issue body. Returns (markdown, actionable_drift_count)."""
    sections = []
    total = 0
    critical = 0
    analyses: List[Tuple[str, str]] = []

    for rg, report, report_path in _load_reports(reports_dir):
        # Same event shape as the channel digest, so the issue lines and the
        # Slack lines can never disagree.
        events = events_from_report(report_path)
        if not events:
            continue

        total += len(events)
        lines = []
        for event in events:
            sev = (event.severity or "").lower()
            if sev == "critical":
                critical += 1
            line = f"- **[{event.event_type}]** `{event.resource_type}/{event.resource_name}`"
            if event.details:
                line += f" — {event.details.splitlines()[0]}"
            if event.owner and event.owner != "unknown":
                line += f" _(owner: {event.owner})_"
            lines.append(line)
        sections.append(f"### `{rg}`\n\n" + "\n".join(lines))

        # The consolidated remediation narrative: ONE Claude call that saw every
        # drift, so it orders the work and can say "investigate before you
        # overwrite this" - which the per-resource recommendations it replaced
        # could not, being blind to each other.
        analysis = report.get("agent_analysis")
        if analysis:
            analyses.append((rg, analysis))

    scanned = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        ISSUE_MARKER,
        f"<!-- drift-report:{lz_name} -->",
        f"## 🔍 Drift Report — {lz_name}",
        "",
        f"**{total} issue(s)**" + (f" ({critical} critical)" if critical else "")
        + f" · scanned {scanned} · [workflow run]({run_url})",
        "",
    ]
    body_parts = ["\n".join(header)] + sections

    if analyses:
        # Collapsed: the drift list above is the summary; open this for the plan.
        # GitHub renders the markdown (tables, lists, code) natively - no
        # conversion needed, unlike the HTML report.
        blocks = ["## 🛠️ Remediation Analysis"]
        multi = len(analyses) > 1
        for rg, analysis in analyses:
            summary = f"Remediation plan{f' — {rg}' if multi else ''} (click to expand)"
            blocks.append(f"<details>\n<summary>{summary}</summary>\n\n{analysis}\n\n</details>")
        body_parts.append("\n\n".join(blocks))

    body_parts.append(
        "_Updated automatically by the drift-detection pipeline; this issue closes "
        "when a scan comes back clean._"
    )
    return "\n\n".join(body_parts), total


def publish(reports_dir: str, repo: str, lz_name: str, run_url: str, token: str) -> str:
    """Create/update the rolling issue (drift) or close it (clean).

    Returns the issue URL when one is open after this call, else "".
    """
    body, total = build_issue_body(reports_dir, lz_name, run_url)
    existing = find_open_report_issue(repo, token, lz_name)

    if total == 0:
        if existing:
            number = existing["number"]
            _api_request(
                "POST", f"{GITHUB_API}/repos/{repo}/issues/{number}/comments", token,
                {"body": f"✅ Drift resolved — latest scan is clean ([workflow run]({run_url}))."},
            )
            status, _ = _api_request(
                "PATCH", f"{GITHUB_API}/repos/{repo}/issues/{number}", token,
                {"state": "closed", "state_reason": "completed"},
            )
            if status == 200:
                logger.info(f"Closed drift issue #{number} in {repo} (scan clean)")
            else:
                logger.warning(f"Could not close drift issue #{number} in {repo} (HTTP {status})")
        else:
            logger.info("Scan clean and no open drift issue — nothing to publish")
        return ""

    title = f"Drift Report — {lz_name}"
    if existing:
        number = existing["number"]
        status, issue = _api_request(
            "PATCH", f"{GITHUB_API}/repos/{repo}/issues/{number}", token,
            {"title": title, "body": body},
        )
        if status == 200 and issue:
            logger.info(f"Updated drift issue #{number} in {repo} ({total} issue(s))")
            return issue.get("html_url", "")
        logger.warning(f"Could not update drift issue #{number} in {repo} (HTTP {status})")
        return existing.get("html_url", "")

    status, issue = _api_request(
        "POST", f"{GITHUB_API}/repos/{repo}/issues", token,
        {"title": title, "body": body, "labels": [ISSUE_LABEL]},
    )
    if status == 201 and issue:
        logger.info(f"Created drift issue #{issue.get('number')} in {repo} ({total} issue(s))")
        return issue.get("html_url", "")
    if status in (403, 404):
        # 404 is GitHub's response when the token cannot even see the repo.
        logger.warning(
            f"Cannot create issues in {repo} (HTTP {status}) - the token needs "
            "issues:write on the landing-zone repo. Skipping issue publication."
        )
    else:
        logger.warning(f"Could not create drift issue in {repo} (HTTP {status})")
    return ""


if __name__ == "__main__":
    try:
        from logger import setup_logging
    except ImportError:
        from tools.logger import setup_logging
    setup_logging(level="INFO")

    if len(sys.argv) < 5:
        logger.error(
            "Usage: python publish_lz_issue.py <reports_dir> <lz_repo> <lz_name> <run_url>"
        )
        sys.exit(1)

    reports_dir, lz_repo, lz_name, run_url = sys.argv[1:5]
    token = (
        os.environ.get("DRIFT_ISSUE_TOKEN")
        or os.environ.get("BICEP_REPO_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or ""
    ).strip()

    issue_url = ""
    if not token:
        logger.warning("No token available (DRIFT_ISSUE_TOKEN/BICEP_REPO_TOKEN/GITHUB_TOKEN); skipping issue publication")
    else:
        issue_url = publish(reports_dir, lz_repo, lz_name, run_url, token)

    if issue_url:
        print(f"Drift issue: {issue_url}")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"issue_url={issue_url}\n")
    sys.exit(0)
