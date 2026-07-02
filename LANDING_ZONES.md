# Landing Zone Drift Testing (Hybrid Model)

Enterprise drift detection where **teams own their LZ configuration** in their Bicep repository, while the **central tool orchestrates** drift checks.

## Architecture

```
bicep-drift-agent/  (Central drift detection tool)
├── .github/
│   ├── lz-index.yml                    ← Maps LZs to external repos
│   └── workflows/
│       ├── drift-check-lz-hybrid.yml   ← Orchestrator workflow
│       ├── drift-lz-template.yml       ← Template to copy
│       ├── drift-lz-frontend.yml       ← Copy for team 1
│       ├── drift-lz-backend.yml        ← Copy for team 2
│       └── drift-lz-database.yml       ← Copy for team 3
└── tools/

myorg/frontend-compute/  (Team's Bicep repo)
├── bicep/
│   ├── compute/
│   │   └── main.bicep
│   └── data/
│       └── main.bicep
└── .github/
    └── drift-lz-config.yml             ← Frontend LZ config (owned by team)

myorg/backend-api/  (Another team's Bicep repo)
├── bicep/
│   └── main.bicep
└── .github/
    └── drift-lz-config.yml             ← Backend LZ config (owned by team)
```

## How It Works

### 1. Index File (drift-agent repo)

```yaml
# bicep-drift-agent/.github/lz-index.yml
landing_zones:
  frontend:
    repo: myorg/frontend-compute
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * 1,3,5'
    workflow: drift-lz-frontend.yml
  
  backend:
    repo: myorg/backend-api
    config_path: .github/drift-lz-config.yml
    schedule: '0 14 * * 2,4'
    workflow: drift-lz-backend.yml
```

### 2. LZ Config File (in each Bicep repo)

```yaml
# myorg/frontend-compute/.github/drift-lz-config.yml
name: frontend
notifications:
  slack: https://hooks.slack.com/services/XXX/frontend
  filter: all

checks:
  - name: Compute Layer
    repo: myorg/frontend-compute
    branch: main
    path: bicep/compute/main.bicep
    resource_groups: [rg-frontend-compute, rg-frontend-compute-dr]
  
  - name: Data Layer
    repo: myorg/frontend-compute
    branch: main
    path: bicep/data/main.bicep
    resource_groups: [rg-frontend-data, rg-frontend-backup]
```

### 3. Execution Flow

```
1. Workflow triggers (e.g., drift-lz-frontend.yml)
   ↓
2. Hybrid orchestrator reads lz-index.yml in drift-agent
   "frontend" → fetch from "myorg/frontend-compute"
   ↓
3. Clones external repo, reads .github/drift-lz-config.yml
   ↓
4. Parses config: 2 layers, 4 resource groups
   ↓
5. Runs drift checks in parallel
   (clones each Bicep repo mentioned in checks)
   ↓
6. Consolidates results from all layers
   ↓
7. Sends single notification based on team's config
```

---

## Quick Setup

### Step 1: Add LZ to Index

Edit `.github/lz-index.yml` in drift-agent repo:

```yaml
landing_zones:
  myteam:
    repo: myorg/my-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * 1,3,5'
    workflow: drift-lz-myteam.yml
```

### Step 2: Team Creates Config in Their Repo

```yaml
# myorg/my-bicep/.github/drift-lz-config.yml
name: myteam
notifications:
  slack: https://hooks.slack.com/services/XXX/myteam
  filter: all

checks:
  - name: Layer Name
    repo: myorg/my-bicep
    branch: main
    path: bicep/main.bicep
    resource_groups: [rg-prod, rg-dr]
```

### Step 3: Create Team Workflow

Copy `.github/workflows/drift-lz-template.yml` to `drift-lz-myteam.yml`, update the name, schedule, and landing_zone:

```yaml
name: My Team Landing Zone Drift

on:
  schedule:
    - cron: '0 9 * * 1,3,5'
  workflow_dispatch:

jobs:
  drift:
    uses: ./.github/workflows/drift-check-lz-hybrid.yml
    with:
      landing_zone: myteam
    secrets: inherit
```

### Step 4: Test

```bash
gh workflow run drift-lz-myteam.yml
```

---

## LZ Config Reference

```yaml
name: team-name                              # Required: display name
subscription_id: "12345678-abcd-..."        # Required: Azure subscription ID for resources
notifications:
  slack: https://hooks.slack.com/...       # Optional: Slack webhook
  teams: https://outlook.webhook.office.com/... # Optional: Teams webhook
  filter: all|drift|extra|missing          # Optional: filter events (default: all)

checks:
  - name: Check Display Name               # Required: human-readable name (what this Bicep deploys)
    repo: org/repo-name                    # Required: GitHub repo with Bicep
    branch: main                           # Optional: branch (default: main)
    path: bicep/main.bicep                 # Required: path to Bicep file
    resource_groups:                       # Required: RGs this Bicep deploys to
      - rg-prod
      - rg-dr
```

---

## Examples

### Complete Example with All Parameters

```yaml
# This example shows every available parameter and option
name: backend                                          # Display name for this LZ
subscription_id: "12345678-abcd-1234-abcd-123456789012" # Azure subscription ID (required)

notifications:
  slack: https://hooks.slack.com/services/AAA/BBB/CCC # Slack webhook (optional)
  teams: https://outlook.webhook.office.com/...       # Teams webhook (optional)
  filter: all                                          # Filter: all, drift, extra, missing (default: all)

checks:
  # Check 1: Backend API services
  - name: Backend APIs                                 # Human-readable check name
    repo: myorg/backend-api                            # GitHub repo with Bicep
    branch: main                                       # Branch to test (default: main)
    path: bicep/main.bicep                             # Path to Bicep file in that repo
    resource_groups:                                   # List of RGs this Bicep deploys to
      - rg-backend-api-prod
      - rg-backend-api-dr

  # Check 2: Backend databases
  - name: Backend Data
    repo: myorg/backend-databases
    branch: main
    path: bicep/databases/main.bicep
    resource_groups:
      - rg-backend-sql
      - rg-backend-sql-dr
      - rg-backend-cache

  # Check 3: Shared infrastructure from different repo
  - name: Monitoring
    repo: myorg/shared-infrastructure
    branch: main
    path: bicep/monitoring/main.bicep
    resource_groups:
      - rg-logging
      - rg-monitoring
```

**What each parameter means:**

| Parameter | Required | Description | Example |
| --- | --- | --- | --- |
| `name` | Yes | Display name for the landing zone | `backend` |
| `subscription_id` | Yes | Azure subscription ID where resources are deployed | `12345678-abcd-1234-abcd-123456789012` |
| `notifications.slack` | No | Slack webhook for notifications | `https://hooks.slack.com/...` |
| `notifications.teams` | No | Teams webhook for notifications | `https://outlook.webhook.office.com/...` |
| `notifications.filter` | No | Which events to send: `all`, `drift`, `extra`, `missing` | `all` |
| `checks[].name` | Yes | Human-readable check name (what this Bicep deploys) | `Backend APIs` |
| `checks[].repo` | Yes | GitHub repository with Bicep code | `myorg/backend-api` |
| `checks[].branch` | No | Git branch to use (default: `main`) | `main` |
| `checks[].path` | Yes | Path to Bicep file within repo | `bicep/main.bicep` |
| `checks[].resource_groups` | Yes | List of Azure RGs this Bicep deploys to | `[rg-backend-api-prod, rg-backend-api-dr]` |

---

### Simple Single-Check Example

```yaml
name: platform
subscription_id: "12345678-abcd-1234-abcd-123456789012"
notifications:
  slack: https://hooks.slack.com/services/XXX/platform

checks:
  - name: Platform Infrastructure
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    resource_groups: [rg-platform-prod, rg-platform-dr]
```

---

### Multi-Check Example

```yaml
name: enterprise
subscription_id: "87654321-dcba-4321-dcba-987654321098"
notifications:
  slack: https://hooks.slack.com/services/XXX/enterprise
  teams: https://outlook.webhook.office.com/...
  filter: drift                                        # Only notify on config changes, not EXTRA/MISSING

checks:
  - name: Compute Layer
    repo: myorg/enterprise-compute
    path: bicep/compute/main.bicep
    resource_groups: [rg-compute, rg-compute-dr, rg-compute-staging]
  
  - name: Networking Layer
    repo: myorg/shared-networking
    path: bicep/enterprise/main.bicep
    resource_groups: [rg-network, rg-firewall, rg-security]
  
  - name: Data Layer
    repo: myorg/enterprise-data
    path: bicep/databases/main.bicep
    resource_groups: [rg-sql, rg-sql-dr, rg-cache, rg-storage]
  
  - name: Security Layer
    repo: myorg/enterprise-security
    path: bicep/main.bicep
    resource_groups: [rg-security, rg-identity]
```

---

## Key Advantages

✅ **Teams Own Configuration**

- Config lives in same repo as Bicep
- Updated in same PR as infrastructure changes
- Versioned with infrastructure code

✅ **Central Tool Orchestrates**

- Single drift-agent repo for all teams
- Consistent workflow logic across org
- Easy to improve tool for everyone

✅ **Flexible and Scalable**

- Add new team: just add to lz-index.yml
- Team modifies config: only touches their repo
- Multi-layer support with parallel execution

✅ **Clean Separation**

- Tool logic: drift-agent repo
- Infrastructure config: team's Bicep repo
- Easy to maintain and evolve

---

## Platform vs Workload Landing Zones

In a CAF/ALZ topology there are two kinds of landing zone, and the same agent
scans both — the difference is entirely in the LZ config + its `.drift-ignore`:

| | **Workload LZ** | **Platform LZ** |
| --- | --- | --- |
| Owns | Its app resources | Shared network fabric (VNets, subnets, NSG *resources*, route tables, peering) |
| Network fabric | Referenced-as-existing → **ignored** via `.drift-ignore` | **In scope** (no network ignores) so its drift surfaces |
| Notifications | Single team channel | **Owner-routed**: `owners: [platform]` → platform team, leaked `owners: [workload]` → app channel |

The agent tags every drift with `owner` = `platform` or `workload` (network
fabric ⇒ platform; NSG `securityRules` ⇒ workload even though the NSG resource
is platform-owned). Notification configs route on that tag — see
[Owner-Based Routing](TEAM_NOTIFICATIONS.md#owner-based-routing-cafalz).

A ready-to-copy platform LZ config is in
[`examples/drift-lz-platform-config.yml`](examples/drift-lz-platform-config.yml).

---

## Troubleshooting

### "Landing Zone not found in lz-index.yml"

**Cause:** Missing or misspelled LZ name in index

**Fix:**

```bash
# Verify LZ exists in index
gh api repos/org/repo/contents/.github/lz-index.yml | jq '.landing_zones'

# Check exact spelling
```

### "Config file not found"

**Cause:** Team's config path wrong or not created

**Fix:**

```bash
# Verify config exists in team's repo
gh api repos/org/bicep-repo/contents/.github/drift-lz-config.yml
```

### "Repository not found" on cross-org repo

**Cause:** Missing BICEP_REPO_TOKEN for private repos

**Fix:**

```bash
gh secret set BICEP_REPO_TOKEN --body 'ghp_xxxx'
```

### Config parsing fails

**Cause:** Invalid YAML syntax

**Fix:**

```bash
# Validate YAML locally
cat .github/drift-lz-config.yml | python3 -c "import sys, yaml; yaml.safe_load(sys.stdin)"
```

---

## Scheduling Tips

**Avoid thundering herd:**

```yaml
# Stagger team schedules
frontend:  '0 9 * * 1,3,5'    # Mon, Wed, Fri 9am
backend:   '0 14 * * 2,4'    # Tue, Thu 2pm
database:  '0 18 * * *'      # Daily 6pm
platform:  '0 3 * * *'       # Daily 3am
```

**Off-peak Azure testing:**

- 3am UTC: lowest API throttling
- 6pm UTC: end of business for US teams
- Avoid 9-5 UTC when Azure load is highest

---

## See Also

- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) — Azure OIDC setup (enterprise way)
- [ENTERPRISE_CONFIGURATION.md](ENTERPRISE_CONFIGURATION.md) — General setup
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) — Notification configuration
- [CROSS_REPO_SETUP.md](CROSS_REPO_SETUP.md) — Multi-repo testing guide
