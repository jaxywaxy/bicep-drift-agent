# Team-Based Notifications

Send drift detection reports to Slack/Teams webhooks with filtering and custom templates.

## Quick Start

Add to your `.github/drift-lz-config.yml` (in your Bicep repo):

```yaml
name: myteam
notifications:
  slack: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
  filter: all

checks:
  - name: MyServices
    repo: myorg/my-bicep
    path: bicep/main.bicep
    resource_groups: [rg-prod, rg-dr]
```

That's it! Notifications will be sent to your Slack channel on drift.

---

## Configuration

### Basic Setup

```yaml
notifications:
  slack: https://hooks.slack.com/services/...     # Slack webhook (optional)
  teams: https://outlook.webhook.office.com/...  # Teams webhook (optional)
  filter: all|drift|extra|missing                # Event filter (optional)
```

**At least one webhook (Slack or Teams) is required for notifications.**

### Filtering Options

Control which events trigger notifications:

| Filter | Events Sent | Use Case |
| --- | --- | --- |
| `all` | DRIFT + EXTRA + MISSING | Get all issues (default) |
| `drift` | DRIFT only | Config changes only |
| `extra` | EXTRA only | Orphaned resources only |
| `missing` | MISSING only | Missing deployments only |
| `drift,extra` | DRIFT + EXTRA | Config changes or orphaned |
| `extra,missing` | EXTRA + MISSING | Resource issues only |

### Owner-Based Routing (CAF/ALZ)

In a Cloud Adoption Framework landing zone, the **platform team** owns the network
fabric (VNets, subnets, NSG resources, route tables) while **app teams** own their
workloads. The agent tags every drift with an `owner` (`platform` or `workload`), so
you can route each owner's drift to the team that can actually fix it.

Add `owners` to a team's notification config:

```yaml
notifications:
  platform-team:
    teams: https://outlook.webhook.office.com/.../platform
    owners: [platform]          # only platform-owned drift (network fabric)
  app-team:
    slack: https://hooks.slack.com/services/XXX/app
    owners: [workload]          # only workload-owned drift
```

| `owners` value | Team receives |
| --- | --- |
| *(omitted)* | **All** owners (backward compatible — pre-Phase-4 behavior) |
| `[platform]` | Only platform-owned drift (network fabric) |
| `[workload]` | Only workload-owned drift |
| `[platform, workload]` | Both (same as omitting) |

`owners` combines with `filter` (AND): a team with `owners: [platform]` and
`filter: drift` receives only property-drift on platform-owned resources.

> Owner tags are only present when notifying from the **JSON** report
> (`reports/<rg>-drift.json`). Text-parsed events have no owner and route to every
> team (owners defaults to "all").

---

## Examples

### Example 1: Basic Slack Notification

```yaml
name: frontend
notifications:
  slack: https://hooks.slack.com/services/T00000000/B00000000/XXXX

checks:
  - name: Frontend Services
    repo: myorg/frontend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-frontend-prod, rg-frontend-dr]
```

Sends all drift events to Slack.

---

### Example 2: Teams Webhook

```yaml
name: backend
notifications:
  teams: https://outlook.webhook.office.com/webhookb2/...

checks:
  - name: Backend APIs
    repo: myorg/backend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-backend-prod, rg-backend-dr]
```

Sends all drift events to Teams channel.

---

### Example 3: Both Slack and Teams

```yaml
name: critical
notifications:
  slack: https://hooks.slack.com/services/XXX
  teams: https://outlook.webhook.office.com/...

checks:
  - name: Critical Infrastructure
    repo: myorg/critical-infra
    path: bicep/main.bicep
    resource_groups: [rg-critical-prod, rg-critical-dr]
```

Sends to both Slack and Teams simultaneously.

---

### Example 4: Filtered Notifications

```yaml
name: backend
notifications:
  slack: https://hooks.slack.com/services/XXX/backend
  filter: drift                                    # Only config changes

checks:
  - name: Backend Services
    repo: myorg/backend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-backend-prod, rg-backend-dr]
```

Only notifies when resource configurations change, not for orphaned/missing resources.

---

### Example 5: Multiple Checks with Single Notification

```yaml
name: enterprise
notifications:
  slack: https://hooks.slack.com/services/XXX/enterprise
  filter: all

checks:
  - name: Compute Layer
    repo: myorg/enterprise-compute
    path: bicep/compute/main.bicep
    resource_groups: [rg-compute, rg-compute-dr]
  
  - name: Data Layer
    repo: myorg/enterprise-data
    path: bicep/data/main.bicep
    resource_groups: [rg-data, rg-data-dr]
  
  - name: Networking Layer
    repo: myorg/enterprise-network
    path: bicep/network/main.bicep
    resource_groups: [rg-network, rg-firewall]
```

All three layers run in parallel, results consolidated into **one notification** sent to Slack.

---

## Event Types

The system sends three types of drift events:

```text
[DRIFT] Microsoft.Storage/storageAccounts/myaccount — properties differ: accessTier
```

→ Resource exists but configuration changed (sku, size, settings, etc.)

```text
[EXTRA] Microsoft.Web/serverFarms/asp-prod — deployed but not in Bicep
```

→ Resource deployed in Azure but not defined in Bicep (orphaned)

```text
[MISSING] Microsoft.KeyVault/vaults/kv-prod — in Bicep but not deployed
```

→ Resource defined in Bicep but not deployed to Azure (undeployed)

---

## Getting Webhook URLs

### Slack

1. Go to <https://api.slack.com/apps>
2. Create new app → "From scratch"
3. Name it, select workspace
4. Go to **Incoming Webhooks** → Enable it
5. Click **Add New Webhook to Workspace**
6. Select channel, authorize
7. Copy the webhook URL

### Teams/Microsoft 365

1. Go to your Teams channel
2. Click **⋯** (More options) → **Connectors**
3. Search for "Incoming Webhook"
4. Configure → Give it a name
5. Copy the webhook URL

---

## Troubleshooting

### Notifications Not Sending

**Check 1: Webhook URL is valid**

```bash
# Test Slack webhook
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test"}' \
  YOUR_SLACK_WEBHOOK_URL

# Should get response: 1
```

**Check 2: Filter configuration is correct**

Valid values: `all`, `drift`, `extra`, `missing`, or comma-separated combinations

```yaml
notifications:
  slack: https://...
  filter: drift,extra              # ✓ Correct
  # filter: drift, extra           # ✗ No spaces!
```

**Check 3: Webhook is in config file**

```bash
# Verify config file exists
cat .github/drift-lz-config.yml | grep -A3 notifications
```

**Check 4: Landing zone is in index**

```bash
# Verify LZ is in drift-agent repo's lz-index.yml
gh api repos/ORG/bicep-drift-agent/contents/.github/lz-index.yml
```

### Messages Malformed

- Verify Slack/Teams webhook URLs are current (can expire)
- Check that the webhook still has permissions
- Ensure the channel/team still exists

### No Output in Channel

- Webhook may be failing silently
- Test webhook independently (see above)
- Check GitHub Actions logs: workflow step "Send consolidated notifications"

---

## Advanced: Custom Templates

To use custom message templates, add `template` to notifications:

```yaml
notifications:
  slack: https://hooks.slack.com/services/XXX
  template: "⚠️ *{{ event_type }}* in {{ resource_type }}\n`{{ resource_name }}`\n{{ details }}\n<{{ report_url }}|View Report>"
```

**Available variables:**

- `{{ event_type }}` → DRIFT, EXTRA, or MISSING
- `{{ resource_type }}` → e.g., Microsoft.Storage/storageAccounts
- `{{ resource_name }}` → Resource name
- `{{ details }}` → Additional details
- `{{ owner }}` → platform, workload, or unknown (Phase 4 owner-routing)
- `{{ report_url }}` → Link to GitHub Actions run
- `{{ drift_count }}` → Number of DRIFT events
- `{{ extra_count }}` → Number of EXTRA events
- `{{ missing_count }}` → Number of MISSING events

---

## See Also

- [Landing Zones Guide](LANDING_ZONES.md) — Full hybrid architecture
- [Enterprise Configuration](ENTERPRISE_CONFIGURATION.md) — Setup for organizations
- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [Teams Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using)
