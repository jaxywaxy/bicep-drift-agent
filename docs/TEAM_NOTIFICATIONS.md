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

### Webhook URLs as Secrets (recommended)

A webhook URL is a bearer secret: anyone holding it can post to your channel, and
Slack revokes webhook URLs it finds committed in public repos. Instead of putting
the URL in the config, reference a GitHub secret with a `${DRIFT_WEBHOOK_*}`
placeholder:

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
    owners: [platform]
  app-team:
    slack: "${DRIFT_WEBHOOK_APPTEAM}"
    owners: [workload]
```

Then create the secret in the repository where the workflows run (for example,
the central drift agent repository) — not the landing-zone repo:

```bash
gh secret set DRIFT_WEBHOOK_PLATFORM --body "https://outlook.webhook.office.com/webhookb2/..."
gh secret set DRIFT_WEBHOOK_APPTEAM --body "https://hooks.slack.com/services/..."
```

Rules:

- **Only names prefixed `DRIFT_WEBHOOK_` are expandable.** The notifications
  block lives in the scanned LZ repo, which the agent treats as untrusted data —
  the prefix stops a config from smuggling other CI secrets (e.g.
  `${ANTHROPIC_API_KEY}`) into a webhook URL.
- Placeholders resolve from environment variables first (handy for local runs),
  then from the CI secrets context the workflow injects.
- An unresolved placeholder **fails the notification step** (exit 1) rather than
  silently delivering nothing — a missing secret should be visible.
- Plain URLs still work unchanged (backward compatible), and placeholders can be
  embedded in a longer value if needed.

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

**Owner routing requires the multi-team shape.** A *flat* single-channel config:

```yaml
notifications:
  slack: "${DRIFT_WEBHOOK_WORKLOAD}"
```

is wrapped as **one** team with no `owners`, so it receives **every** owner's
drift — platform findings land in that one channel and no platform channel
exists. To route by owner you must use the multi-team shape above (a `platform`
team and a `workload` team, each with its own `owners` and webhook). Splitting
the channels is opt-in; a flat config is intentionally "send everything here".

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

### What never triggers a notification

Two report entry types are informational and deliberately excluded from events:

- **Policy-enforced changes** (`policy_enforced_drifts`) — changes made by Azure
  Policy (DINE/Modify). They appear in the report's governance section but are
  not actionable drift, so they never page anyone.
- **Smart-matched resources** (`matched_unresolvable`) — bookkeeping that a
  runtime-named resource (`uniqueString()` etc.) was reconciled to its deployed
  counterpart. Shown in the report's "🔗 Smart-Matched Resources" section only.

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
# Verify LZ is in the central drift agent repo's lz-index.yml (replace placeholders)
gh api repos/ORG/DRIFT_AGENT_REPO/contents/.github/lz-index.yml
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

## Message Format

By default each team receives **one digest message per run** — the same
one-liners as the GitHub Actions summary, plus a link to the run's report:

```text
⚠️ Bicep Drift Detected — 3 issue(s) (1 critical)
• [DRIFT] Microsoft.ContainerRegistry/registries/acrtestdrift — 🚨 CRITICAL properties differ: properties.adminUserEnabled
• [MISSING] Microsoft.Authorization/locks/keyvault-cannotdelete — in Bicep but not deployed
• [EXTRA] Microsoft.Storage/storageAccounts/stunmanaged — deployed but not in Bicep
Report: https://github.com/<org>/<repo>/actions/runs/<id>
```

At most 20 drift lines are listed; further drifts collapse into an
"… and N more — see the report" pointer. Claude remediation recommendations
are **never** sent to chat — they live in the HTML/JSON report the message
links to.

---

## Workload-Team Report Access: the LZ Drift Issue

The digest's default report link is the **Actions run in the drift-agent
repo**, which requires read access to that repo — and granting it would expose
*every* landing zone's reports to every team. Instead, each run publishes the
drift result as a **rolling GitHub issue in the landing zone's own repo**
(`Drift Report — <lz>`, label `drift-report`), which the workload team can
already read:

- **Drift found** → the issue is created (or its body updated) with the same
  one-liners as the digest, per resource group, plus the full per-resource
  recommendations in collapsible sections.
- **Scan clean** → the open issue is closed with a "✅ Drift resolved" comment.
- When an issue was published, **every team's** `{{ report_url }}` is the
  issue link — workload teams can't read the drift-agent repo, and the issue
  body carries the workflow-run link so platform teams are one click from the
  full artifacts. Without an issue (e.g. missing token), the link falls back
  to the Actions run. Custom templates get both: `{{ issue_url }}` and
  `{{ run_url }}`.

**Token requirement:** issue publication uses `BICEP_REPO_TOKEN` (the same
secret used to fetch LZ repos), which must have **`issues: write`** on the
landing-zone repos. If the token is missing or read-only, publication is
skipped with a warning — notifications still send, linking to the Actions run.

---

## Advanced: Custom Templates

Adding a `template` opts the team out of the digest: the template renders
**once per drift event** (the historic behavior), so expect one message per
drift:

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
- `{{ severity }}` → critical, warning, or info (empty when the source has none; property drift takes the highest per-property severity, and critical findings also get a `🚨 CRITICAL` prefix in `{{ details }}`)
- `{{ report_url }}` → Link to GitHub Actions run
- `{{ drift_count }}` → Number of DRIFT events
- `{{ extra_count }}` → Number of EXTRA events
- `{{ missing_count }}` → Number of MISSING events

---

## Related Documentation

- [README.md](../README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CAPABILITIES.md](CAPABILITIES.md) 
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Teams and Slack Notification configuration
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY.md](SECURITY.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team