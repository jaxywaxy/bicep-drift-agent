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
3. Create workflow (copy `drift-lz-template.yml`, update schedule)
4. Set Azure secrets

### Run

```bash
# Automatic: runs on schedule
# Manual:
gh workflow run drift-lz-myteam.yml
```

See [LANDING_ZONES.md](docs/LANDING_ZONES.md) for complete setup.

---

## Features

✅ **Enterprise-ready (CAF-aligned)**

- Multiple teams, multiple repos, multiple RGs
- **Subscription-scoped landing zones**: scan a whole subscription (one sub = one LZ) or an RG glob in a single pass — see [LANDING_ZONES.md](docs/LANDING_ZONES.md)
- Parallel drift checks, consolidated notifications

✅ **Accurate drift detection**

- Property-level comparison
- Bicep module support
- Expression resolution (parameters, variables, format, concat)
- Parameter files auto-discovered (`.bicepparam` or `parameters.json` next to the bicep)
- Azure read-only augmentation ignored (subset comparison of fields), but manually **added** routes/NSG-rules/subnets ARE flagged
- Resource type normalization (handles Azure SDK casing), write-only property filtering

✅ **Smart resource matching**

- Runtime-generated names (`uniqueString()`, `format()`, …) matched to their deployed resources — and still **property-compared** (a SKU change on a uniqueString-named storage account is detected)
- Matched resources render in their own report section, never as drift noise

✅ **Owner routing (platform vs workload)**

- Every drift is classified `platform` (network fabric: VNets, subnets, NSGs, route tables, NAT gateways, …) or `workload` (apps, data, keyvaults, private endpoints)
- NSG nuance handled: the NSG *resource* is platform-owned, its *securityRules* route to the app team
- Notifications route per owner so the right team gets paged

✅ **Change origin (who/what/when)**

- Activity Log lifecycle: manual change vs Azure Policy (DINE/Modify, attributed by the assignment's managed identity) vs system-managed
- Policy-enforced changes are split into a governance section — detected, never counted as actionable drift
- Attribution window: 30 days (by design; drift *detection* itself has no time limit)

✅ **Critical resource protection**

- Lock detection and removal alerts (CanNotDelete/CanNotModify)
- Locks & Cosmos child resources fetched via ARM REST (not indexed by Resource Graph)

✅ **Flexible notifications**

- Slack and/or Teams, custom message templates
- Per-team filtering by drift type (drift/extra/missing) **and** by owner (`owners: [platform]`)
- Policy-enforced and smart-matched entries never page anyone

---

## Architecture

```text
bicep-drift-agent/ (central tool)
├── .github/
│   ├── lz-index.yml                    # Maps LZs to external repos
│   └── workflows/
│       ├── drift-check-lz-hybrid.yml   # Orchestrator (reusable)
│       ├── drift-lz-landingzone.yml    # Per-LZ triggers (one per landing zone)
│       ├── drift-lz-test.yml
│       ├── drift-lz-database.yml
│       └── drift-lz-template.yml       # Copy me for a new LZ
├── tools/
│   ├── compile_bicep.py                # Bicep → ARM JSON (cached)
│   ├── get_live_state.py               # Resource Graph + ARM REST (locks, cosmos)
│   ├── property_drift.py               # Compare & diff (subset semantics)
│   ├── normalizer.py                   # Expression/parameter resolution
│   ├── smart_matching.py               # uniqueString-name ↔ live resource matching
│   ├── ownership.py                    # platform vs workload classification
│   ├── rg_selector.py                  # '*' / glob RG selector resolution
│   ├── activity_log.py                 # Activity Log fetch + per-resource matching
│   ├── change_origin.py                # manual / policy / system attribution
│   ├── ignore_patterns.py              # layered .drift-ignore profiles
│   ├── html_report.py                  # HTML report generation
│   └── send_notifications.py           # Slack/Teams owner-routed delivery
├── examples/
│   └── drift-lz-platform-config.yml    # Platform-LZ reference config
└── requirements.txt

myorg/frontend-bicep/ (team's Bicep repo)
├── bicep/  (or envs/dev/, any depth)
│   ├── main.bicep
│   └── parameters.json                 # Auto-discovered next to the bicep
├── .drift-ignore                       # Per-LZ ignore profile (repo root)
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

Copy `drift-lz-template.yml`, update:

- Schedule (cron expression)
- Landing zone name
- Workflow name

See [ENTERPRISE_CONFIGURATION.md](docs/ENTERPRISE_CONFIGURATION.md) for multi-team setups.

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
# Full pipeline (detection + smart matching + owner tagging + change origin + reports)
python analyze_drift.py ./path/to/main.bicep your-resource-group

# Subscription-scoped landing zone: scan the whole subscription in one pass
python analyze_drift.py ./envs/dev/main.bicep "*"

# Phase 1 only (raw detection, no report enrichment)
python run_drift_check.py ./path/to/main.bicep your-resource-group
```

Parameters are auto-discovered from a `parameters.json` next to the bicep (or a
`.bicepparam`); to override explicitly:

```bash
export ARM_PARAMETERS='{"environment":"prod"}'
python analyze_drift.py ./main.bicep my-rg
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
- Load parameters: `ARM_PARAMETERS` env var → `parameters/<env>.bicepparam` → `parameters.json` next to the bicep (auto-discovered)
- Resolve expressions: `[parameters('foo')]`, `[format('x-{0}', param)]` — object/array params resolve to real values
- Flatten nested deployments (modules)

### 3. Query Live State

- Connect to Azure via `DefaultAzureCredential`
- Use Azure Resource Graph (KQL) for efficient querying
- Resource-group scope, or **subscription scope** for landing zones (`*` / RG glob selectors)
- Augment with locks + Cosmos child resources via ARM REST (not in Resource Graph)

### 4. Normalize & Compare

- Normalize resource types to lowercase (Azure SDK inconsistency)
- Smart-match runtime-generated names (`uniqueString()` etc.) to deployed resources, then property-compare them too
- Subset comparison of fields (Azure's read-only augmentation like `provisioningState` isn't drift) — but manually **added** elements in named collections (routes, securityRules, subnets) are
- Filter out write-only/immutable properties and unresolvable expressions

### 5. Classify & Attribute

- Tag each drift with an **owner**: `platform` (network fabric) or `workload` (apps/data) — see [LANDING_ZONES.md](docs/LANDING_ZONES.md#platform-vs-workload-landing-zones)
- Query the Activity Log (30-day window) for **change origin**: manual, Azure Policy (DINE/Modify via the assignment's managed identity), or system
- Split policy-enforced changes into a governance section (not actionable drift)

### 6. Generate Report & Notify

- [DRIFT] = resource exists but config changed
- [EXTRA] = resource deployed but not in Bicep
- [MISSING] = resource in Bicep but not deployed
- HTML report: drift table with owner + origin badges, policy-enforced section, smart-matched section
- Notifications routed per team by drift type and owner

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

- [LANDING_ZONES.md](docs/LANDING_ZONES.md) — Full hybrid architecture guide
- [ENTERPRISE_CONFIGURATION.md](docs/ENTERPRISE_CONFIGURATION.md) — Multi-team setup
- [TEAM_NOTIFICATIONS.md](docs/TEAM_NOTIFICATIONS.md) — Notification configuration

---

## Limitations

- Runtime functions (`uniqueString()`, `copyIndex()`) are smart-matched (and property-compared), not fully resolved — an ambiguous match falls back to longest-common-name-prefix
- Complex nested ARM expressions may be partially unresolved (skipped rather than false-flagged)
- Change-origin attribution covers the last 30 days of Activity Log (Azure platform max is 90; detection itself has no time limit)
- For a multi-RG landing-zone scan, change-origin attribution is best-effort (Activity Log is fetched per RG)
- Drift checks don't run on PRs (Azure federated identity only configured for push/manual)

## Roadmap

- Drift remediation suggestions
- PR comments with detailed findings
- Terraform support

---

## Testing

```bash
python -m unittest discover -s tests   # 100 stdlib unittest tests, no pytest needed
```

---

## Built with

- **Python** — Drift detection tools
- **Bicep** — Infrastructure as code
- **Azure SDK** — Query live resources
- **GitHub Actions** — CI/CD orchestration
- **Anthropic Claude** — AI analysis and recommendations
