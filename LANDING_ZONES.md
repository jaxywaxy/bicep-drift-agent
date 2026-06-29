# Landing Zone Drift Testing (Hybrid Model)

Enterprise drift detection where **teams own their LZ configuration** in their Bicep repository, while the **central tool orchestrates** drift checks.

## Architecture

```
bicep-drift-agent/  (Central drift detection tool)
├── .github/
│   ├── lz-index.yml                    ← Maps LZs to external repos
│   └── workflows/
│       ├── drift-check-lz-hybrid.yml   ← Orchestrator workflow
│       ├── drift-lz-frontend.yml       ← Team 1 trigger
│       ├── drift-lz-backend.yml        ← Team 2 trigger
│       └── drift-lz-database.yml       ← Team 3 trigger
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

Copy `drift-lz-frontend.yml`, update the schedule:

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
notifications:
  slack: https://hooks.slack.com/...       # Optional: Slack webhook
  teams: https://outlook.webhook.office.com/... # Optional: Teams webhook
  filter: all|drift|extra|missing          # Optional: filter events (default: all)

checks:
  - name: Layer Display Name               # Required: human-readable name
    repo: org/repo-name                    # Required: GitHub repo with Bicep
    branch: main                           # Optional: branch (default: main)
    path: bicep/main.bicep                 # Required: path to Bicep file
    resource_groups:                       # Required: list of RGs to test
      - rg-prod
      - rg-dr
      - rg-staging
```

---

## Examples

### Simple Single-Layer LZ

```yaml
name: platform
notifications:
  slack: https://hooks.slack.com/services/XXX/platform
checks:
  - name: Core Infrastructure
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    resource_groups: [rg-platform-prod, rg-platform-dr]
```

### Complex Multi-Layer LZ

```yaml
name: enterprise
notifications:
  slack: https://hooks.slack.com/services/XXX/enterprise
  teams: https://outlook.webhook.office.com/...
  filter: all

checks:
  - name: Compute
    repo: myorg/enterprise-compute
    path: bicep/compute/main.bicep
    resource_groups: [rg-compute, rg-compute-dr, rg-compute-staging]
  
  - name: Networking
    repo: myorg/shared-networking
    path: bicep/enterprise/main.bicep
    resource_groups: [rg-network, rg-firewall, rg-security]
  
  - name: Data
    repo: myorg/enterprise-data
    path: bicep/databases/main.bicep
    resource_groups: [rg-sql, rg-sql-dr, rg-cache, rg-storage]
  
  - name: Security
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

- [ENTERPRISE_CONFIGURATION.md](ENTERPRISE_CONFIGURATION.md) — General setup
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) — Notification configuration
- [CROSS_REPO_SETUP.md](CROSS_REPO_SETUP.md) — Multi-repo testing guide
