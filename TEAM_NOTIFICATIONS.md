# Team-Based Notifications

Send drift detection reports to different Slack channels or Teams webhooks per team, with custom message templates and filtering.

## Quick Start

Set repository variable `DRIFT_NOTIFICATIONS` with your team configuration:

```json
{
  "frontend": {
    "slack": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "filter": "extra,missing"
  },
  "backend": {
    "teams": "https://outlook.webhook.office.com/webhookb2/...",
    "filter": "drift"
  },
  "devops": {
    "slack": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "teams": "https://outlook.webhook.office.com/webhookb2/...",
    "filter": "all"
  }
}
```

## Configuration

### Basic Team Setup

Each team can have:
- **slack**: Slack webhook URL (optional)
- **teams**: Teams/Office 365 webhook URL (optional)
- **filter**: Drift event types to notify about (optional, default: all)
- **template**: Custom message template (optional, uses platform default)

### Filtering Options

Control what drift events trigger notifications:

| Filter | Description | Events Sent |
|--------|-------------|-------------|
| `all` | All drift events (default) | DRIFT + EXTRA + MISSING |
| `drift` | Configuration changes only | DRIFT |
| `extra` | Deployed but not in IaC | EXTRA |
| `missing` | In IaC but not deployed | MISSING |
| `extra,missing` | Only orphaned resources | EXTRA + MISSING |
| `drift,extra` | Configuration or orphaned | DRIFT + EXTRA |

### Default Behavior

- **No filter specified**: All events (`drift`, `extra`, `missing`)
- **No webhook specified**: Silent (no notification)
- **Multiple webhooks**: Sends to both Slack and Teams

## Setup by Scenario

### Scenario 1: Single Team (Minimal)

All drift events to one Slack channel:

```bash
gh variable set DRIFT_NOTIFICATIONS --body '{
  "ops": {
    "slack": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
  }
}'
```

### Scenario 2: Multi-Team with Different Concerns

```bash
gh variable set DRIFT_NOTIFICATIONS --body '{
  "frontend": {
    "slack": "https://hooks.slack.com/services/XXX/frontend",
    "filter": "drift"
  },
  "backend": {
    "slack": "https://hooks.slack.com/services/XXX/backend",
    "filter": "all"
  },
  "database": {
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "missing"
  }
}'
```

**Frontend team** → Only notified of configuration changes (drift)
**Backend team** → Notified of all drift events
**Database team** → Only notified of missing resources (deployments)

### Scenario 3: Environment-Specific Notifications

Dev team gets all alerts, prod team only critical issues:

```bash
gh variable set DRIFT_NOTIFICATIONS --body '{
  "dev": {
    "slack": "https://hooks.slack.com/services/XXX/dev-alerts",
    "filter": "all"
  },
  "prod": {
    "slack": "https://hooks.slack.com/services/XXX/prod-alerts",
    "filter": "extra"
  }
}'
```

### Scenario 4: Both Slack and Teams

Notify both platforms per team:

```bash
gh variable set DRIFT_NOTIFICATIONS --body '{
  "ops": {
    "slack": "https://hooks.slack.com/services/XXX",
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "all"
  }
}'
```

## Custom Message Templates

Override default message format per team using `{{ variables }}`:

### Slack Template

```json
{
  "frontend": {
    "slack": "https://hooks.slack.com/services/XXX",
    "template": ":warning: *{{ event_type }}* in {{ resource_type }}\n`{{ resource_name }}`\n{{ details }}\n<{{ report_url }}|View Report>"
  }
}
```

**Available variables:**
- `{{ event_type }}` → DRIFT, EXTRA, or MISSING
- `{{ resource_type }}` → e.g., Microsoft.Storage/storageAccounts
- `{{ resource_name }}` → Resource name
- `{{ details }}` → Additional details
- `{{ report_url }}` → Link to GitHub Actions run
- `{{ total_events }}` → Total number of events
- `{{ drift_count }}` → Number of DRIFT events
- `{{ extra_count }}` → Number of EXTRA events
- `{{ missing_count }}` → Number of MISSING events

### Teams Template

```json
{
  "database": {
    "teams": "https://outlook.webhook.office.com/...",
    "template": "{\"@type\":\"MessageCard\",\"@context\":\"https://schema.org/extensions\",\"summary\":\"{{ event_type }}\",\"themeColor\":\"ff0000\",\"sections\":[{\"activityTitle\":\"{{ resource_type }}\",\"facts\":[{\"name\":\"Resource\",\"value\":\"{{ resource_name }}\"},{\"name\":\"Type\",\"value\":\"{{ event_type }}\"}]}]}"
  }
}
```

## Backward Compatibility

The old single-webhook approach still works:

```bash
gh secret set SLACK_WEBHOOK_URL --body "https://hooks.slack.com/services/..."
gh secret set TEAMS_WEBHOOK_URL --body "https://outlook.webhook.office.com/..."
```

**Used when:** No `DRIFT_NOTIFICATIONS` variable is set

**Priority:**
1. Team-based `DRIFT_NOTIFICATIONS` (if set)
2. Legacy `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` secrets
3. No notification

## Event Parsing

The system automatically parses drift output for:

```
[DRIFT] Microsoft.Storage/storageAccounts/myaccount — properties differ: accessTier
[EXTRA] Microsoft.Web/serverFarms/asp-prod — deployed but not in Bicep
[MISSING] Microsoft.KeyVault/vaults/kv-prod — in Bicep but not deployed
```

## Examples

### Frontend Team: Only Config Changes

```json
{
  "frontend": {
    "slack": "https://hooks.slack.com/services/T00/B00/XX",
    "filter": "drift"
  }
}
```

Gets notified when configuration drifts, not for orphaned resources.

### DevOps Team: All Critical Issues

```json
{
  "devops": {
    "slack": "https://hooks.slack.com/services/T00/B00/XX",
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "all"
  }
}
```

Gets notified via both Slack and Teams for all drift events.

### Database Team: Only Missing Resources

```json
{
  "database": {
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "missing"
  }
}
```

Only gets notified when resources defined in Bicep are not deployed.

### Custom Template Example

```json
{
  "security": {
    "slack": "https://hooks.slack.com/services/T00/B00/XX",
    "template": ":rotating_light: *SECURITY ALERT*\n*Type:* {{ event_type }}\n*Resource:* {{ resource_type }}/{{ resource_name }}\n:link: <{{ report_url }}|Review Report>"
  }
}
```

## Troubleshooting

### Notifications Not Sending

1. **Check variable is set:**
   ```bash
   gh variable list | grep DRIFT_NOTIFICATIONS
   ```

2. **Check webhook URLs are valid:**
   - Slack: Should start with `https://hooks.slack.com/services/`
   - Teams: Should start with `https://outlook.webhook.office.com/`

3. **Check JSON syntax:**
   ```bash
   echo 'YOUR_JSON' | python3 -m json.tool
   ```

4. **Check filter configuration:**
   - Valid values: `all`, `drift`, `extra`, `missing`
   - Comma-separated: `drift,extra,missing`

### Messages Malformed

- Verify template syntax (proper `{{ variable }}` format)
- Check for unescaped quotes in template
- Test with default template first

### Webhook Failing

- Verify webhook URLs are current (webhooks can expire)
- Check webhook has permission in Slack/Teams
- Ensure team/channel still exists

## See Also

- [Enterprise Configuration](ENTERPRISE_CONFIGURATION.md)
- [Drift Detection Guide](docs/DRIFT_DETECTION_GUIDE.md)
- [GitHub Actions Secrets & Variables](https://docs.github.com/en/actions/learn-github-actions/variables)
- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [Teams Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using)
