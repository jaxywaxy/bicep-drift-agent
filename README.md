# Bicep Drift Agent

Production-ready infrastructure drift detection for enterprise Bicep deployments. Detects missing resources, extra resources, property-level changes, and critical SKU modifications.

## What it does

1. Compiles Bicep files to ARM JSON
2. Queries live Azure state via Azure Resource Graph (KQL)
3. Compares desired state (Bicep) vs actual state (Azure)
4. Reports drift with property-level details
5. Sends notifications to teams via Slack/Teams

## For enterprises: Hybrid Landing Zone model

Multiple teams, multiple infrastructure layers, multiple resource groups—all self-service.

**Teams own their config** (versioned with their Bicep):

```yaml
# myorg/my-bicep/.github/drift-lz-config.yml
name: myteam
notifications:
  slack: https://hooks.slack.com/services/XXX

checks:
  - name: My Infrastructure
    repo: myorg/my-bicep
    path: bicep/main.bicep
    resource_groups: [rg-prod, rg-dr]
```

**Central tool orchestrates** (in this drift-agent repo):

```yaml
# .github/lz-index.yml
landing_zones:
  myteam:
    repo: myorg/my-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * *'
    workflow: drift-lz-myteam.yml
```

**Result:** Single notification per team, consolidated report, no manual setup.

## Quick start

### Setup (one-time)

1. Add landing zone to `.github/lz-index.yml`
2. Team creates `.github/drift-lz-config.yml` in their Bicep repo
3. Create workflow (copy `drift-lz-frontend.yml`, update schedule)
4. Set Azure secrets

### Run

```bash
# Automatic: runs on schedule
# Manual:
gh workflow run drift-lz-myteam.yml
```

See [LANDING_ZONES.md](LANDING_ZONES.md) for complete setup.

---

## Features

✅ **Enterprise-ready**

- Multiple teams, multiple repos, multiple RGs
- Parallel drift checks
- Consolidated notifications

✅ **Accurate drift detection**

- Property-level comparison
- Bicep module support
- Expression resolution (parameters, variables, format, concat)
- Resource type normalization (handles Azure SDK casing)
- Write-only property filtering

✅ **Smart resource matching**

- Fuzzy prefix matching for `[uniqueString()]` names
- 0.95 confidence for exact matches
- 0.85 confidence for prefix matches
- Contextual matching via parent resource references

✅ **Critical resource protection**

- Lock detection and removal alerts (CanNotDelete/CanNotModify)
- IaC-managed locks for key resources
- Automatic drift alerts on lock removal

✅ **Flexible notifications**

- Slack and/or Teams
- Per-team filtering (drift only, extra only, missing only)
- Custom message templates

---

## Architecture

```
bicep-drift-agent/ (central tool)
├── .github/
│   ├── lz-index.yml                    # Maps LZs to external repos
│   └── workflows/
│       ├── drift-check-lz-hybrid.yml   # Orchestrator (reusable)
│       ├── drift-lz-frontend.yml       # Team triggers
│       ├── drift-lz-backend.yml
│       └── drift-lz-database.yml
├── tools/
│   ├── compile_bicep.py                # Bicep → ARM JSON
│   ├── get_live_state.py               # Query Azure resources
│   ├── property_drift.py                # Compare & diff
│   ├── normalizer.py                   # Resolve expressions
│   └── send_notifications.py           # Slack/Teams
└── requirements.txt

myorg/frontend-bicep/ (team's Bicep repo)
├── bicep/
│   └── main.bicep
└── .github/
    └── drift-lz-config.yml             # Team owns this
```

---

## Setup for your organization

### Step 1: Azure secrets (one-time)

Set in drift-agent repo settings:

```bash
gh secret set AZURE_CLIENT_ID --body "..."
gh secret set AZURE_TENANT_ID --body "..."
gh secret set AZURE_SUBSCRIPTION_ID --body "..."
gh secret set ANTHROPIC_API_KEY --body "..."
```

For private Bicep repos:

```bash
gh secret set BICEP_REPO_TOKEN --body "ghp_xxxx"
```

### Step 2: Add landing zones

Edit `.github/lz-index.yml`:

```yaml
landing_zones:
  frontend:
    repo: myorg/frontend-bicep
    config_path: .github/drift-lz-config.yml
    schedule: '0 9 * * 1,3,5'
    workflow: drift-lz-frontend.yml
```

### Step 3: Teams create config

Each team in their Bicep repo:

```bash
# myorg/frontend-bicep/.github/drift-lz-config.yml
name: frontend
notifications:
  slack: https://hooks.slack.com/services/XXX
  filter: all

checks:
  - name: Frontend Services
    repo: myorg/frontend-bicep
    path: bicep/main.bicep
    resource_groups: [rg-frontend-prod, rg-frontend-dr]
```

### Step 4: Create team workflows

Copy `drift-lz-frontend.yml`, update:

- Schedule (cron expression)
- Landing zone name
- Workflow name

See [ENTERPRISE_CONFIGURATION.md](ENTERPRISE_CONFIGURATION.md) for multi-team setups.

---

## Local development

### Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Set ANTHROPIC_API_KEY and AZURE_SUBSCRIPTION_ID
```

### Run drift check locally

```bash
python run_drift_check.py ./path/to/main.bicep your-resource-group
```

With parameters:

```bash
export ARM_PARAMETERS='{"environment":"prod"}'
python run_drift_check.py ./main.bicep my-rg
```

### Test individual tools

```bash
# Compile Bicep to ARM
python -m tools.compile_bicep ./main.bicep

# Query live Azure state
python -m tools.get_live_state your-resource-group

# Run full drift check
python run_drift_check.py ./main.bicep your-resource-group
```

---

## How drift detection works

### 1. Compile Bicep → ARM Template

```bash
az bicep build --file main.bicep --outfile template.json
```

### 2. Extract Desired State

- Parse ARM template
- Resolve parameters and variables
- Handle expressions: `[parameters('foo')]`, `[format('x-{0}', param)]`
- Flatten nested deployments
- Extract resource definitions

### 3. Query Live State

- Connect to Azure via `DefaultAzureCredential`
- Use Azure Resource Graph (KQL) for efficient querying
- Query resources by resource group
- Get actual resource properties and state

### 4. Normalize & Compare

- Normalize resource types to lowercase (Azure SDK inconsistency)
- Match deployed resources to Bicep definitions
- Fuzzy prefix matching for runtime-generated names
- Filter out write-only/immutable properties
- Compare property by property

### 5. Generate Report

- [DRIFT] = resource exists but config changed
- [EXTRA] = resource deployed but not in Bicep
- [MISSING] = resource in Bicep but not deployed
- Send to Slack/Teams

---

## Ignore Patterns

Create `.drift-ignore` to filter expected drift (60+ patterns pre-configured):

```yaml
ignore:
  # Auto-created resources (not IaC-managed)
  - resource_type: "Microsoft.Network/networkWatchers"
    reason: "Auto-created by Azure in each region"
  
  # Child resources with unresolvable names
  - resource_type: "Microsoft.OperationalInsights/workspaces/tables"
    reason: "Child resource with parameter-based parent name"
  
  # Optional properties
  - resource_type: "Microsoft.KeyVault/vaults"
    property: "properties.networkAcls"
    reason: "Null when not specified; not functional drift"
```

See `.drift-ignore` for complete list of patterns and reasoning.

## Documentation

- [LANDING_ZONES.md](LANDING_ZONES.md) — Full hybrid architecture guide
- [ENTERPRISE_CONFIGURATION.md](ENTERPRISE_CONFIGURATION.md) — Multi-team setup
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) — Notification configuration

---

## Limitations

- Runtime functions (`uniqueString()`, `copyIndex()`) are fuzzy-matched, not fully resolved
- Complex nested ARM expressions may be partially unresolved
- Drift checks don't run on PRs (Azure federated identity only configured for push/manual)

## Roadmap

- Agent-based analysis for unresolvable expressions
- Drift remediation suggestions
- PR comments with detailed findings
- Terraform support

---

## Project structure

```text
bicep-drift-agent/
├── tools/
│   ├── compile_bicep.py        # bicep build
│   ├── get_live_state.py       # Query Azure ARM API
│   ├── property_drift.py        # Diff & comparison
│   ├── normalizer.py            # Expression resolution
│   ├── send_notifications.py    # Slack/Teams posting
│   └── models.py                # Data models
├── run_drift_check.py           # Local CLI entry point
├── requirements.txt
├── .env.example
└── .github/
    ├── lz-index.yml
    └── workflows/
        ├── drift-check-lz-hybrid.yml
        ├── drift-lz-frontend.yml
        ├── drift-lz-backend.yml
        └── drift-lz-database.yml
```

---

## Built with

- **Python** — Drift detection tools
- **Bicep** — Infrastructure as code
- **Azure SDK** — Query live resources
- **GitHub Actions** — CI/CD orchestration
- **Anthropic Claude** — AI analysis and recommendations
