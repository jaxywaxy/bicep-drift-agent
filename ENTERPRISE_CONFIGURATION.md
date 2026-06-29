# Enterprise Configuration Guide

For enterprise deployments with **multiple teams**, **multiple infrastructure layers**, and **multiple resource groups per team**.

## Quick Answer

**Where is the configuration?**

- **Index file** (what repo to test, owned by drift-agent) → `.github/lz-index.yml`
- **Team config** (which Bicep files + RGs to test, owned by each team) → `.github/drift-lz-config.yml` in their Bicep repo

---

## Architecture

```
bicep-drift-agent/ (central tool)
├── .github/
│   ├── lz-index.yml                    ← Maps landing zones to external repos
│   └── workflows/
│       ├── drift-check-lz-hybrid.yml   ← Orchestrator (reusable)
│       ├── drift-lz-template.yml       ← Template to copy for each team
│       ├── drift-lz-frontend.yml       ← Copy of template (one per team)
│       ├── drift-lz-backend.yml        ← Copy of template (one per team)
│       └── drift-lz-database.yml       ← Copy of template (one per team)

myorg/frontend-bicep/ (team A's Bicep repo)
├── bicep/
│   └── main.bicep
└── .github/
    └── drift-lz-config.yml             ← Team A owns this

myorg/backend-bicep/ (team B's Bicep repo)
├── bicep/
│   └── main.bicep
└── .github/
    └── drift-lz-config.yml             ← Team B owns this
```

---

## Setup for Teams/Organizations

### Step 1: Central Tool Setup (drift-agent repo, one-time)

Add landing zones to the index file:

```bash
# Edit .github/lz-index.yml
landing_zones:
  frontend:
    repo: myorg/frontend-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * 1,3,5'           # Mon, Wed, Fri 9am UTC
    workflow: drift-lz-frontend.yml

  backend:
    repo: myorg/backend-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 14 * * 2,4'            # Tue, Thu 2pm UTC
    workflow: drift-lz-backend.yml
```

### Step 2: Each Team Creates Config (their Bicep repo, one-time)

Team A creates their drift config in their Bicep repo:

```bash
# myorg/frontend-bicep/.github/drift-lz-config.yml
name: frontend
notifications:
  slack: https://hooks.slack.com/services/XXX/frontend
  filter: all

checks:
  - name: Frontend Services
    repo: myorg/frontend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-frontend-prod, rg-frontend-dr]
```

Team B does the same:

```bash
# myorg/backend-bicep/.github/drift-lz-config.yml
name: backend
notifications:
  slack: https://hooks.slack.com/services/XXX/backend
  filter: drift

checks:
  - name: Backend APIs
    repo: myorg/backend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-backend-api, rg-backend-api-dr]
  
  - name: Backend Data
    repo: myorg/backend-data
    path: bicep/databases/main.bicep
    resource_groups: [rg-backend-sql, rg-backend-sql-dr]
```

### Step 3: Azure Secrets (one-time)

Set secrets in drift-agent repo:

```bash
gh secret set AZURE_CLIENT_ID --body "YOUR_CLIENT_ID"
gh secret set AZURE_TENANT_ID --body "YOUR_TENANT_ID"
gh secret set AZURE_SUBSCRIPTION_ID --body "YOUR_SUB_ID"
gh secret set ANTHROPIC_API_KEY --body "YOUR_API_KEY"
```

### Step 4: Workflows Run on Schedule

Each team workflow runs on its configured schedule (from lz-index.yml):

```bash
# Automatic: Runs on schedule
# Manual: gh workflow run drift-lz-frontend.yml
```

---

## Configuration Files Reference

### lz-index.yml (drift-agent repo)

Maps each landing zone to its external Bicep repo and config:

```yaml
landing_zones:
  LANDING_ZONE_NAME:
    repo: org/repo-name                 # GitHub repo with Bicep
    config_path: .github/drift-lz-config.yml  # Path to config in that repo
    schedule: '0 9 * * 1,3,5'          # Cron schedule (UTC)
    workflow: drift-lz-LANDING_ZONE_NAME.yml  # Workflow file to trigger
```

**Example:**
```yaml
landing_zones:
  frontend:
    repo: myorg/frontend-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * 1,3,5'
    workflow: drift-lz-frontend.yml
  
  backend:
    repo: myorg/backend-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 14 * * 2,4'
    workflow: drift-lz-backend.yml
```

### drift-lz-config.yml (team's Bicep repo)

Teams configure what to test in their own repo:

```yaml
name: team-name                                    # Display name
notifications:
  slack: https://hooks.slack.com/services/...    # Slack webhook (optional)
  teams: https://outlook.webhook.office.com/...  # Teams webhook (optional)
  filter: all|drift|extra|missing                # Filter (optional, default: all)

checks:
  - name: Check Name                              # Display name for this check
    repo: org/bicep-repo                          # Repo with Bicep
    branch: main                                  # Branch (default: main)
    path: bicep/main.bicep                        # Path to Bicep file
    resource_groups: [rg-prod, rg-dr]             # RGs to test
```

**Example:**
```yaml
name: backend
notifications:
  slack: https://hooks.slack.com/services/XXX/backend
  filter: drift

checks:
  - name: Backend APIs
    repo: myorg/backend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-backend-api, rg-backend-api-dr]
  
  - name: Backend Databases
    repo: myorg/backend-data
    path: bicep/databases/main.bicep
    resource_groups: [rg-backend-sql, rg-backend-sql-dr, rg-backend-cache]
```

---

## Common Scenarios

### Scenario 1: Add a New Team

**Step 1** — Edit drift-agent `.github/lz-index.yml`:
```yaml
newteam:
  repo: myorg/newteam-bicep
  config_path: .github/drift-lz-config.yml
  schedule: '0 10 * * *'
  workflow: drift-lz-newteam.yml
```

**Step 2** — Team creates `.github/drift-lz-config.yml` in their Bicep repo

**Step 3** — Copy `.github/workflows/drift-lz-template.yml` to `drift-lz-newteam.yml`, update:

- Workflow name
- Schedule (cron)
- `landing_zone` parameter

---

### Scenario 2: Team with Multiple Layers

```yaml
name: enterprise
notifications:
  slack: https://hooks.slack.com/services/XXX/enterprise

checks:
  - name: Compute Layer
    repo: myorg/enterprise-compute
    path: bicep/compute/main.bicep
    resource_groups: [rg-compute, rg-compute-dr]
  
  - name: Networking Layer
    repo: myorg/enterprise-network
    path: bicep/network/main.bicep
    resource_groups: [rg-network, rg-firewall]
  
  - name: Data Layer
    repo: myorg/enterprise-data
    path: bicep/databases/main.bicep
    resource_groups: [rg-sql, rg-sql-dr, rg-cache]
```

All three layers run in parallel, results consolidated into one notification.

---

### Scenario 3: Multiple Teams, Different Notification Preferences

**Frontend Team** (only config changes):
```yaml
# myorg/frontend-bicep/.github/drift-lz-config.yml
name: frontend
notifications:
  slack: https://hooks.slack.com/services/XXX/frontend
  filter: drift                    # Only notify on DRIFT, not EXTRA/MISSING
```

**Backend Team** (all issues):
```yaml
# myorg/backend-bicep/.github/drift-lz-config.yml
name: backend
notifications:
  slack: https://hooks.slack.com/services/XXX/backend
  filter: all                      # Notify on DRIFT, EXTRA, MISSING
```

**Database Team** (both Slack and Teams):
```yaml
# myorg/database-bicep/.github/drift-lz-config.yml
name: database
notifications:
  slack: https://hooks.slack.com/services/XXX/database
  teams: https://outlook.webhook.office.com/...
  filter: extra,missing            # Only orphaned/missing, not config changes
```

---

## Private Repository Access

For private Bicep repos, set `BICEP_REPO_TOKEN`:

```bash
gh secret set BICEP_REPO_TOKEN --body "ghp_xxxxxxxxxxxx"
```

The token needs:

- `repo` scope (full repo access)
- Access to all team's Bicep repos

---

## Troubleshooting

### "Landing Zone not found in lz-index.yml"

**Check:**

```bash
# Verify landing zone exists
cat .github/lz-index.yml | grep -A3 "LANDING_ZONE_NAME:"

# Check exact spelling matches workflow parameter
```

### "Config file not found"

**Check:**

```bash
# Verify config exists in team's Bicep repo
gh api repos/myorg/bicep-repo/contents/.github/drift-lz-config.yml

# Update config_path in lz-index.yml if wrong
```

### "Repository not found" for Bicep repo

**Check:**

```bash
# Verify Bicep repo is accessible
gh repo view myorg/bicep-repo

# For private repos, ensure BICEP_REPO_TOKEN is set
gh secret list | grep BICEP_REPO_TOKEN
```

### "Notifications not sending"

See [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md)

---

## Scheduling Tips

**Avoid thundering herd** — stagger schedules:

```yaml
landing_zones:
  frontend:
    schedule: '0 9 * * 1,3,5'      # Mon, Wed, Fri 9am
  backend:
    schedule: '0 14 * * 2,4'      # Tue, Thu 2pm
  database:
    schedule: '0 18 * * *'        # Daily 6pm
  platform:
    schedule: '0 3 * * *'         # Daily 3am
```

**Off-peak Azure testing:**

- 3am UTC: lowest API throttling
- 6pm UTC: end of business for US teams
- Avoid 9-5 UTC when Azure load is highest

---

## See Also

- [Landing Zones Guide](LANDING_ZONES.md) — Full hybrid architecture
- [Team Notifications](TEAM_NOTIFICATIONS.md) — Notification configuration
- [GitHub Actions Secrets & Variables](https://docs.github.com/en/actions/learn-github-actions/variables)
