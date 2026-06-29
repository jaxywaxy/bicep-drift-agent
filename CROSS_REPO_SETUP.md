# Cross-Repository Drift Testing

Test Bicep code from one repo against live Azure resources, with team-based notifications.

## Architecture

```
┌─────────────────────────┐         ┌──────────────────────┐
│ bicep-drift-agent       │         │ drift-test-resources │
│ (drift detection tool)  │─────→   │ (Bicep templates)    │
│                         │         │                      │
│ • Workflow runner       │         │ • main.bicep         │
│ • Python tools          │         │ • storage.bicep      │
│ • Notifications         │         │ • appservice.bicep   │
└─────────────────────────┘         └──────────────────────┘
          │
          └──→ Azure Resources (rg-drift-test)
               Compare desired vs actual state
               Send reports to teams
```

## Quick Setup

### Step 1: Set Bicep Repository Configuration

```bash
gh variable set DRIFT_BICEP_REPO --body 'jaxywaxy/drift-test-resources'
gh variable set DRIFT_BICEP_BRANCH --body 'main'
gh variable set DRIFT_BICEP_PATH --body 'bicep/main.bicep'
```

### Step 2: Set Test Resource Group

```bash
gh variable set DRIFT_RESOURCE_GROUP --body 'rg-drift-test'
```

### Step 3: Configure Team Notifications

```bash
gh variable set DRIFT_NOTIFICATIONS --body '{
  "devops": {
    "slack": "https://hooks.slack.com/services/T123/B456/xxx",
    "filter": "all"
  }
}'
```

### Step 4: Run Workflow

```bash
gh workflow run drift-check.yml
```

**Result:** Workflow clones drift-test-resources (shallow), tests it, sends notifications

---

## Multi-Team Configuration

Different teams test different repos:

```bash
# Team A: Frontend Infrastructure
gh variable set DRIFT_BICEP_REPO --body 'myorg/frontend-bicep'
gh variable set DRIFT_RESOURCE_GROUP --body 'rg-frontend-prod'
gh variable set DRIFT_NOTIFICATIONS --body '{
  "frontend": {
    "slack": "https://hooks.slack.com/services/XXX",
    "filter": "drift"
  }
}'

# Team B: Backend Infrastructure
gh variable set DRIFT_BICEP_REPO --body 'myorg/backend-bicep'
gh variable set DRIFT_RESOURCE_GROUP --body 'rg-backend-prod'
gh variable set DRIFT_NOTIFICATIONS --body '{
  "backend": {
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "extra"
  }
}'
```

Each team uses same drift detection tool, different Bicep repos.

---

## Configuration Variables

### Bicep Repository

| Variable | Purpose | Default | Example |
|----------|---------|---------|---------|
| `DRIFT_BICEP_REPO` | GitHub repo with Bicep | `jaxywaxy/drift-test-resources` | `myorg/infrastructure-bicep` |
| `DRIFT_BICEP_BRANCH` | Branch to test | `main` | `develop`, `v1.0`, `staging` |
| `DRIFT_BICEP_PATH` | Path to Bicep file in repo | `bicep/main.bicep` | `infra/prod/main.bicep` |

### Azure Resources

| Variable | Purpose | Default | Example |
|----------|---------|---------|---------|
| `DRIFT_RESOURCE_GROUP` | Resource group to scan | `rg-prod` | `rg-drift-test`, `rg-frontend` |
| `DRIFT_ARM_PARAMETERS` | ARM parameters (JSON) | `{"environment":"prod","location":"australiaeast"}` | `{"environment":"test","location":"eastus"}` |

### Notifications

| Variable | Purpose | Example |
|----------|---------|---------|
| `DRIFT_NOTIFICATIONS` | Team mappings & filters | See [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) |

---

## Scenarios

### Scenario 1: Simple Validation

Single team validates Bicep against live resources:

```bash
gh variable set DRIFT_BICEP_REPO --body 'myorg/my-bicep'
gh variable set DRIFT_RESOURCE_GROUP --body 'rg-prod'
gh variable set DRIFT_NOTIFICATIONS --body '{"ops": {"slack": "https://..."}}'
```

### Scenario 2: Multiple Environments

Same Bicep repo, different branches per environment:

```bash
# Develop workflow uses dev branch
DRIFT_BICEP_BRANCH=develop DRIFT_RESOURCE_GROUP=rg-dev gh workflow run drift-check.yml

# Staging workflow uses staging branch
DRIFT_BICEP_BRANCH=staging DRIFT_RESOURCE_GROUP=rg-staging gh workflow run drift-check.yml

# Production workflow uses main branch
DRIFT_BICEP_BRANCH=main DRIFT_RESOURCE_GROUP=rg-prod gh workflow run drift-check.yml
```

### Scenario 3: Cross-Team Validation

Each team owns their Bicep repo, shares drift detection tool:

```bash
# Team A (Frontend)
gh variable set DRIFT_BICEP_REPO --body 'myorg/frontend-infra'
gh variable set DRIFT_NOTIFICATIONS --body '{
  "frontend": {
    "slack": "https://hooks.slack.com/services/XXX/frontend",
    "filter": "all"
  }
}'

# Team B (Backend) 
gh variable set DRIFT_BICEP_REPO --body 'myorg/backend-infra'
gh variable set DRIFT_NOTIFICATIONS --body '{
  "backend": {
    "slack": "https://hooks.slack.com/services/XXX/backend",
    "filter": "extra"
  }
}'

# Team C (Database)
gh variable set DRIFT_BICEP_REPO --body 'myorg/database-infra'
gh variable set DRIFT_NOTIFICATIONS --body '{
  "database": {
    "teams": "https://outlook.webhook.office.com/...",
    "filter": "missing"
  }
}'
```

### Scenario 4: GitHub-Hosted Vs Private Repos

Support both public and private repos:

```bash
# Public repo (no token needed)
gh variable set DRIFT_BICEP_REPO --body 'jaxywaxy/drift-test-resources'

# Private repo (uses GITHUB_TOKEN from secrets)
gh variable set DRIFT_BICEP_REPO --body 'myorg/private-bicep'
```

---

## How It Works

1. **Workflow Triggered**
   ```
   Push to main or workflow_dispatch
   ```

2. **Clone Tools**
   ```
   actions/checkout@v7
   ↓
   bicep-drift-agent repo
   ```

3. **Shallow Clone External Bicep** (fast!)
   ```
   actions/checkout@v7 (fetch-depth: 1)
   ↓
   Clone DRIFT_BICEP_REPO @ DRIFT_BICEP_BRANCH
   ↓
   bicep-repo/ directory (only latest commit)
   ```

4. **Run Drift Check**
   ```
   python3 analyze_drift.py bicep-repo/<DRIFT_BICEP_PATH> <DRIFT_RESOURCE_GROUP>
   ```

5. **Parse Results**
   ```
   Extract [DRIFT], [EXTRA], [MISSING] events
   ```

6. **Send Notifications**
   ```
   For each team in DRIFT_NOTIFICATIONS:
   ├─ Filter events by team config
   ├─ Apply custom template
   └─ Send to Slack/Teams
   ```

7. **Cleanup** (automatic)
   ```
   GitHub Actions runner destroyed
   All temporary files cleaned up
   ```

---

## Performance

**Shallow Clone Benefits:**
- 80% faster than full clone (~2s vs 10s)
- Minimal bandwidth usage (~10-50MB vs 100-500MB)
- Fetches only latest commit
- Automatic cleanup (no storage cost)

**Network Time:**
```
Workflow start     0s
Clone tools        2s
Shallow clone      2-5s  ← Fast!
Run drift check    5-15s
Send notifications 2-5s
───────────────────────
Total              11-32s per run
```

---

## Troubleshooting

### "Repository not found"

**Cause:** Wrong repo name or private repo without access

**Fix:**
```bash
# Check repo exists
gh repo view jaxywaxy/drift-test-resources

# For private repos, ensure GITHUB_TOKEN has access
# (automatically available in GitHub Actions)
```

### "Bicep file not found"

**Cause:** Path doesn't exist in the cloned repo

**Fix:**
```bash
# List files in repo
gh api repos/jaxywaxy/drift-test-resources/contents/bicep

# Update DRIFT_BICEP_PATH to correct path
gh variable set DRIFT_BICEP_PATH --body 'correct/path/main.bicep'
```

### "Drift check command not found"

**Cause:** Tools weren't properly checked out

**Fix:**
- Verify first checkout uses `actions/checkout@v7` (no `path` specified)
- Second checkout must use `path: bicep-repo`
- Run drift check from root directory

### "Notifications not sent"

See [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) troubleshooting

---

## See Also

- [Enterprise Configuration](ENTERPRISE_CONFIGURATION.md)
- [Team Notifications](TEAM_NOTIFICATIONS.md)
- [Drift Detection Guide](docs/DRIFT_DETECTION_GUIDE.md)
