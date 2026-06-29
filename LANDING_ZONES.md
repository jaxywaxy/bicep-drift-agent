# Landing Zone Drift Testing

Enterprise-scale drift detection for Azure Landing Zones with multiple repos, multiple resource groups, and team-based notifications.

## Architecture

One **Landing Zone** = One **Team** with multiple **infrastructure layers**

```
Frontend Landing Zone (Team A)
├── Layer 1: Compute (Repo A, Bicep File X)
│   ├── RG: rg-frontend-compute
│   ├── RG: rg-frontend-compute-dr
│   └── RG: rg-frontend-compute-staging
│
├── Layer 2: Networking (Repo B, Bicep File Y)
│   ├── RG: rg-frontend-network
│   ├── RG: rg-frontend-vwan
│   └── RG: rg-frontend-security
│
├── Layer 3: Data (Repo A, Bicep File Z)
│   ├── RG: rg-frontend-data
│   ├── RG: rg-frontend-cache
│   └── RG: rg-frontend-backup
│
└── Consolidated Notification
    └── #frontend-lz-drift (Slack) + Teams (optional)
```

---

## Quick Setup

### Step 1: Define Your Landing Zones

```bash
gh variable set DRIFT_LANDING_ZONES --body '{
  "frontend": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/T00/B00/XX",
      "filter": "all"
    },
    "checks": [
      {
        "name": "Compute Layer",
        "repo": "myorg/frontend-compute",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": [
          "rg-frontend-compute",
          "rg-frontend-compute-dr"
        ]
      },
      {
        "name": "Network Layer",
        "repo": "myorg/shared-networking",
        "branch": "main",
        "path": "bicep/frontend/main.bicep",
        "resource_groups": [
          "rg-frontend-network",
          "rg-frontend-vwan"
        ]
      }
    ]
  }
}'
```

### Step 2: Trigger Workflow

```bash
gh workflow run drift-lz-frontend.yml
```

**Result:** 
- Tests 2 repos × 2-3 RGs each = 4-6 drift checks
- Consolidates all results
- Sends 1 notification to #frontend-lz-drift

---

## Configuration

### Full Landing Zone Schema

```json
{
  "landing_zone_name": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/...",
      "teams": "https://outlook.webhook.office.com/...",
      "filter": "all|drift|extra|missing|drift,extra"
    },
    "checks": [
      {
        "name": "Layer Name",
        "repo": "org/repo-name",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": [
          "rg-prod",
          "rg-dr",
          "rg-staging"
        ]
      }
    ]
  }
}
```

### Field Descriptions

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `name` | ✅ | Display name for this infrastructure layer | "Compute Layer", "Database" |
| `repo` | ✅ | GitHub repo containing Bicep | "myorg/frontend-compute" |
| `branch` | ❌ | Git branch (default: main) | "main", "develop", "v1.0" |
| `path` | ✅ | Path to Bicep file in repo | "bicep/main.bicep" |
| `resource_groups` | ✅ | List of RGs to test against | ["rg-prod", "rg-dr"] |

### Notification Filters

| Filter | Events |
|--------|--------|
| `all` | DRIFT + EXTRA + MISSING |
| `drift` | Configuration changes only |
| `extra` | Orphaned resources only |
| `missing` | Undeployed resources only |
| `drift,extra` | Config changes + orphaned |
| `extra,missing` | Orphaned + undeployed |

---

## Examples

### Example 1: Simple Landing Zone (Single Layer)

```json
{
  "platform": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/XXX/platform"
    },
    "checks": [
      {
        "name": "Core Infrastructure",
        "repo": "myorg/platform-bicep",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": ["rg-platform-prod", "rg-platform-dr"]
      }
    ]
  }
}
```

### Example 2: Complex Landing Zone (Multi-Layer)

```json
{
  "enterprise": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/XXX/enterprise",
      "teams": "https://outlook.webhook.office.com/...",
      "filter": "all"
    },
    "checks": [
      {
        "name": "Compute",
        "repo": "myorg/enterprise-compute",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": [
          "rg-enterprise-aks",
          "rg-enterprise-aks-dr",
          "rg-enterprise-vms"
        ]
      },
      {
        "name": "Networking",
        "repo": "myorg/shared-networking",
        "branch": "main",
        "path": "bicep/enterprise/main.bicep",
        "resource_groups": [
          "rg-enterprise-hub",
          "rg-enterprise-firewall",
          "rg-enterprise-security"
        ]
      },
      {
        "name": "Data",
        "repo": "myorg/enterprise-data",
        "branch": "main",
        "path": "bicep/databases/main.bicep",
        "resource_groups": [
          "rg-enterprise-sql",
          "rg-enterprise-sql-dr",
          "rg-enterprise-cache",
          "rg-enterprise-storage"
        ]
      },
      {
        "name": "Security",
        "repo": "myorg/enterprise-security",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": [
          "rg-enterprise-security",
          "rg-enterprise-identity"
        ]
      }
    ]
  }
}
```

### Example 3: Multi-Team Enterprise Setup

```json
{
  "frontend": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/XXX/frontend",
      "filter": "all"
    },
    "checks": [
      {
        "name": "Web Tier",
        "repo": "myorg/frontend-web",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": ["rg-frontend-web", "rg-frontend-web-dr"]
      },
      {
        "name": "API Tier",
        "repo": "myorg/frontend-api",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": ["rg-frontend-api"]
      }
    ]
  },
  "backend": {
    "notifications": {
      "teams": "https://outlook.webhook.office.com/...",
      "filter": "extra"
    },
    "checks": [
      {
        "name": "Services",
        "repo": "myorg/backend-services",
        "branch": "main",
        "path": "bicep/main.bicep",
        "resource_groups": ["rg-backend-svc", "rg-backend-svc-dr"]
      }
    ]
  },
  "data": {
    "notifications": {
      "slack": "https://hooks.slack.com/services/XXX/data",
      "filter": "missing"
    },
    "checks": [
      {
        "name": "Databases",
        "repo": "myorg/data-bicep",
        "branch": "main",
        "path": "bicep/databases/main.bicep",
        "resource_groups": ["rg-data-sql", "rg-data-sql-dr", "rg-data-cache"]
      }
    ]
  }
}
```

---

## Setting Up Landing Zones

### Step 1: Plan Your Landing Zones

Map your infrastructure to landing zones:

```
Organization Structure         Landing Zones
────────────────────────────  ─────────────────
Frontend Team
  ├── Web Layer                → frontend
  ├── API Layer
  └── Cache Layer

Backend Team
  ├── Services                 → backend
  └── Integration

Platform Team
  ├── Networking               → platform
  ├── Security
  └── Shared Services

Data Team
  ├── Databases                → data
  └── Warehousing
```

### Step 2: Create Landing Zone Configuration

For each team/LZ, list the infrastructure layers:

```bash
# Frontend LZ = 3 layers across 2 repos
{
  "frontend": {
    "checks": [
      { "name": "Web", "repo": "frontend-web", ... },
      { "name": "API", "repo": "frontend-api", ... },
      { "name": "Cache", "repo": "frontend-web", ... }
    ]
  }
}
```

### Step 3: Set Repository Variable

```bash
gh variable set DRIFT_LANDING_ZONES --body '{...your LZ config...}'
```

**Tip:** Use jq to validate JSON before setting:
```bash
echo '{...your config...}' | jq . && gh variable set DRIFT_LANDING_ZONES --body '{...}'
```

### Step 4: Create Team Workflow

Copy one of the example workflows:

```bash
# For Frontend team
cp .github/workflows/drift-lz-frontend.yml.example .github/workflows/drift-lz-frontend.yml

# For Backend team
cp .github/workflows/drift-lz-backend.yml.example .github/workflows/drift-lz-backend.yml
```

Edit the schedule to match team needs:

```yaml
on:
  schedule:
    - cron: '0 9 * * 1,3,5'  # Mon, Wed, Fri at 9am
```

### Step 5: Test

```bash
# Manual trigger
gh workflow run drift-lz-frontend.yml

# Monitor
gh run list --workflow drift-lz-frontend.yml
```

---

## Workflow Execution

### What Happens

1. **Parse Configuration**
   - Reads DRIFT_LANDING_ZONES variable
   - Extracts checks for requested LZ
   - Validates configuration

2. **Parallel Drift Checks**
   - Each layer tested in parallel
   - Each RG tested against its Bicep
   - Separate report per layer

3. **Consolidate Results**
   - Combine all layer reports
   - Calculate totals
   - Generate summary

4. **Send Notification**
   - Apply team's filter (all/drift/extra/missing)
   - Apply custom template
   - Send to Slack/Teams

5. **Publish Summary**
   - Post to GitHub Actions summary
   - Upload full reports as artifact
   - Retain for 30 days

---

## Scheduling

### Recommended Schedules

```yaml
# Critical infrastructure (daily)
- cron: '0 6 * * *'

# Important infrastructure (3x per week)
- cron: '0 9 * * 1,3,5'

# Standard infrastructure (2x per week)
- cron: '0 14 * * 2,4'

# Non-critical infrastructure (weekly)
- cron: '0 18 * * 0'

# Off-peak times
- cron: '0 3 * * *'   # 3am UTC
- cron: '0 23 * * *'  # 11pm UTC
```

**Tip:** Stagger team schedules to avoid Azure throttling:

```
Frontend: Mon/Wed/Fri 9am
Backend:  Tue/Thu 2pm
Data:     Daily 6pm
Platform: Daily 3am
```

---

## Multi-Repo Access

### Same Organization, Private Repos
✅ **Automatic** - GITHUB_TOKEN has access

### Different Organization, Private Repos
⚠️ **Requires** Personal Access Token (PAT)

```bash
# 1. Create PAT in GitHub settings (scope: repo)
# 2. Add as secret
gh secret set BICEP_REPO_TOKEN --body 'ghp_xxxx'

# 3. Workflow automatically uses it for cross-org private access
```

See [CROSS_REPO_SETUP.md](CROSS_REPO_SETUP.md) for details.

---

## Notifications Per Landing Zone

Each LZ gets **one consolidated notification** with:

- Summary table (DRIFT, EXTRA, MISSING counts)
- Details from all layers
- Filtered by team's notification config
- Routed to team's Slack/Teams channel

Example notification:

```
🏗️ Frontend Landing Zone Drift Check

⚠️ 5 Issues Detected

| Type | Count |
|------|-------|
| Configuration Changes (DRIFT) | 2 |
| Orphaned Resources (EXTRA) | 2 |
| Undeployed Resources (MISSING) | 1 |
| TOTAL | 5 |

Layers Checked:
  ✓ Compute Layer (2 RGs)
  ✓ Network Layer (2 RGs)
  ⚠ Data Layer (3 RGs) - 3 issues

View Report: [GitHub Actions Run]
```

---

## Troubleshooting

### "Landing Zone not found"

**Cause:** Typo in workflow input or DRIFT_LANDING_ZONES variable

**Fix:**
```bash
# Check variable is set
gh variable get DRIFT_LANDING_ZONES

# Verify LZ name exactly
# (YAML is case-sensitive)
```

### "Repository not found" on private cross-org repo

**Cause:** Missing BICEP_REPO_TOKEN

**Fix:**
```bash
# Create PAT and set secret
gh secret set BICEP_REPO_TOKEN --body 'ghp_xxxx'
```

### "No drift detected" but you know there's drift

**Cause:** Resource group mismatch or Bicep path wrong

**Fix:**
```bash
# Verify resource group exists
az group show --name rg-prod

# Verify Bicep file path in repo
gh api repos/myorg/repo/contents/bicep/main.bicep
```

### Workflow runs but doesn't send notifications

**Cause:** Notification config missing or malformed

**Fix:**
```bash
# Validate JSON in DRIFT_LANDING_ZONES
gh variable get DRIFT_LANDING_ZONES | jq .

# Verify Slack/Teams URL format
# Slack: https://hooks.slack.com/services/...
# Teams: https://outlook.webhook.office.com/...
```

---

## Performance

### Expected Runtime

| Layers | RGs | Est. Time |
|--------|-----|-----------|
| 1 | 2 | 2-3 min |
| 2 | 4 | 3-4 min |
| 3 | 6 | 4-5 min |
| 4 | 8+ | 5-7 min |

Parallel execution means layers run simultaneously, not serially.

### Cost Optimization

- ✅ Shallow clone (fetch-depth: 1) = ~80% faster checkout
- ✅ Parallel layer testing = better resource utilization
- ✅ Off-peak scheduling = lower Azure throttle risk

---

## Best Practices

✅ **One LZ per team** - Clear ownership and notifications

✅ **Related layers in same LZ** - Easier to understand drift impact

✅ **Separate repos for independent layers** - Enables team autonomy

✅ **Staggered schedules** - Avoid Azure API throttling

✅ **Regular manual runs** - Test configuration before scheduling

✅ **Monitor trends** - Weekly reports help identify patterns

---

## See Also

- [CROSS_REPO_SETUP.md](CROSS_REPO_SETUP.md) - Multi-repo testing guide
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Notification configuration
- [ENTERPRISE_CONFIGURATION.md](ENTERPRISE_CONFIGURATION.md) - General setup
