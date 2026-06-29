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
from typing import Dict, List, Any
from dataclasses import dataclass
import urllib.request
import urllib.error


@dataclass
class DriftEvent:
    """A drift event to filter and notify about."""
    event_type: str  # DRIFT, EXTRA, MISSING
    resource_type: str
    resource_name: str
    details: str = ""


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
            print("⚠ Warning: Invalid DRIFT_NOTIFICATIONS JSON format")
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

        # Send to team-based webhooks
        for team_name, team_config in self.teams.items():
            success = self._send_to_team(team_name, team_config, events, context)
            all_success = all_success and success

        # Fallback to legacy webhooks if no team config
        if not self.teams:
            if self.legacy_slack_url:
                success = self._send_to_slack(
                    self.legacy_slack_url, events[0] if events else None, context
                )
                all_success = all_success and success

            if self.legacy_teams_url:
                success = self._send_to_teams(
                    self.legacy_teams_url, events[0] if events else None, context
                )
                all_success = all_success and success

        return all_success

    def _send_to_team(
        self, team_name: str, config: Dict[str, Any], events: List[DriftEvent], context: Dict[str, str]
    ) -> bool:
        """Send notifications to a specific team."""
        success = True

        # Get filter for this team (default: all)
        filter_str = config.get("filter", "all")
        notification_filter = NotificationFilter(filter_str)
        filtered_events = [e for e in events if notification_filter.should_notify(e)]

        if not filtered_events:
            print(f"  ℹ {team_name}: No events match filter '{filter_str}'")
            return True

        # Get template (use platform-specific default if not provided)
        template_str = config.get("template")

        # Send to Slack if configured
        slack_url = config.get("slack")
        if slack_url:
            template = MessageTemplate(template_str, platform="slack")
            for event in filtered_events:
                event_context = {**context, "event_type": event.event_type, "resource_type": event.resource_type, "resource_name": event.resource_name, "details": event.details}
                message = template.render(event_context)
                success = self._send_to_slack(slack_url, message) and success
            if success:
                print(f"  ✓ {team_name}: Slack notification sent ({len(filtered_events)} event(s))")
            else:
                print(f"  ✗ {team_name}: Slack notification failed")

        # Send to Teams if configured
        teams_url = config.get("teams")
        if teams_url:
            template = MessageTemplate(template_str, platform="teams")
            for event in filtered_events:
                event_context = {**context, "event_type": event.event_type, "resource_type": event.resource_type, "resource_name": event.resource_name, "details": event.details}
                message = template.render(event_context)
                success = self._send_to_teams(teams_url, message) and success
            if success:
                print(f"  ✓ {team_name}: Teams notification sent ({len(filtered_events)} event(s))")
            else:
                print(f"  ✗ {team_name}: Teams notification failed")

        return success

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
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200
        except Exception as e:
            print(f"  ✗ Slack error: {type(e).__name__}: {e}")
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
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status in (200, 201)
        except Exception as e:
            print(f"  ✗ Teams error: {type(e).__name__}: {e}")
            return False


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
        print(f"⚠ Drift output file not found: {output_file}")

    return events


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python send_notifications.py <drift_output_file> [report_url]")
        sys.exit(1)

    output_file = sys.argv[1]
    report_url = sys.argv[2] if len(sys.argv) > 2 else "See GitHub Actions run"

    events = parse_drift_output(output_file)
    router = NotificationRouter()

    context = {
        "report_url": report_url,
        "total_events": str(len(events)),
        "drift_count": str(len([e for e in events if e.event_type == "DRIFT"])),
        "extra_count": str(len([e for e in events if e.event_type == "EXTRA"])),
        "missing_count": str(len([e for e in events if e.event_type == "MISSING"])),
    }

    if events:
        print(f"\n📢 Sending notifications for {len(events)} event(s)...")
        success = router.send_notifications(events, context)
        sys.exit(0 if success else 1)
    else:
        print("✓ No drift events to notify")
        sys.exit(0)
