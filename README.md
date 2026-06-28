# bicep-drift-agent

Detects drift between a Bicep file and deployed Azure state. Built as a learning project for agentic AI workflows.

## What it does

1. Compiles a Bicep file to ARM JSON
2. Queries live Azure state via the ARM API
3. Diffs the two
4. Reports what's drifted and how

## Project phases

### Phase 1 (✅ Done): Standalone tools

- ✅ Compiles Bicep → ARM JSON
- ✅ Queries live Azure state
- ✅ Normalizes both shapes for comparison
- ✅ Generates drift reports
- ✅ Resolves parameters and variables
- ✅ Flattens nested deployments
- ✅ Filters out module references
- 📝 Limitation: Can't fully resolve complex ARM functions (format with runtime values, uniqueString, etc.)

### Phase 2 (Next): Agent loop

Wrap the tools for the Anthropic API. Let Claude reason over the diff, classify severity, and write a proper report. Handle unresolvable expressions and complex resource relationships.

### Phase 3 (Later): Expand scope

- Type-specific property comparison (VM, storage, networking)
- PR creation with drift report
- CI/CD integration
- Drift remediation suggestions

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Fill in ANTHROPIC_API_KEY and AZURE_SUBSCRIPTION_ID
```

Azure auth uses `DefaultAzureCredential` — if you're already logged in via `az login`, it just works.

## Run it

```bash
python run_drift_check.py ./path/to/main.bicep your-resource-group-name
```

### With parameter values

If your Bicep template uses parameters (like `environment=prod`), pass them via the `.env` file:

```bash
# .env
ARM_PARAMETERS={"environment":"prod","location":"australiaeast"}
```

Or set it inline:

```bash
export ARM_PARAMETERS='{"environment":"prod"}' && python run_drift_check.py ./main.bicep my-rg
```

## Project structure

```
bicep-drift-agent/
├── tools/
│   ├── compile_bicep.py     # az bicep build → ARM JSON
│   ├── get_live_state.py    # ARM API → live resource state
│   └── diff_states.py       # desired vs actual comparison
├── agent/                   # Phase 2 — agent loop goes here
├── reports/                 # Output JSON files (gitignored)
├── tests/
├── run_drift_check.py       # Phase 1 entry point
├── requirements.txt
└── .env.example
```

## The normalizer: Solving the shape mismatch

ARM templates use expressions like `[parameters('vmName')]` and `[format('prefix-{0}', parameters('env'))]`.
Live Azure state has fully resolved values like `prefix-prod`.

The **normalizer** (`tools/normalizer.py`) bridges this gap by:

1. **Extracting parameters** from the template with their default values
2. **Merging parameter overrides** from the environment
3. **Resolving expressions** in resource names:
   - `[parameters('foo')]` → looks up parameter value
   - `[variables('bar')]` → looks up variable value
   - `[format('template-{0}', param)]` → substitutes arguments
   - `[uniqueString(...)]` → placeholder (can't resolve at compile time)
4. **Flattening nested deployments** recursively
5. **Filtering out module references** that don't map to real resources

Remaining limitations:

- Runtime functions like `uniqueString()`, `copyIndex()` can't be resolved without execution context
- Complex nested functions still partially unresolved
- This is why Phase 2 needs an agent — to reason about unresolvable expressions

## CI/CD: GitHub Actions Workflows

### For this repo: Built-in drift checks

This repository has two built-in workflows:

**Single Environment** — `drift-check.yml`

- Checks one resource group per run
- Automatically triggered on push
- Manual trigger for on-demand checks

**Multi-Environment** — `drift-check-multi-env.yml`

- Checks multiple resource groups in parallel
- Default: checks rg-dev and rg-prod
- Customizable via workflow input
- See [MULTI_ENVIRONMENT.md](MULTI_ENVIRONMENT.md) for details

### For other repos: Reusable workflow

Infrastructure repositories can use the **reusable drift-check workflow** to check their own Bicep files. See [REUSABLE_WORKFLOW.md](REUSABLE_WORKFLOW.md) for setup instructions.

**Quick example:**

```yaml
jobs:
  drift-check:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
    with:
      bicep_file: infra/main.bicep
      resource_group: my-rg
      fail_on_drift: true
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.DRIFT_CHECK_ANTHROPIC_API_KEY }}
      AZURE_CLIENT_ID: ${{ secrets.DRIFT_CHECK_AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: ${{ secrets.DRIFT_CHECK_AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.DRIFT_CHECK_AZURE_SUBSCRIPTION_ID }}
```

---

### Automatic triggers (this repo)

- **Push to main/develop** with changes to `.bicep` files or workflow config
- Generates a drift report and uploads artifacts
- Results visible in the workflow run summary

### Manual trigger

Go to **Actions** → **Bicep Drift Check** → **Run workflow** and enter:
- **Bicep file path** (default: `./infra/main.bicep`)
- **Azure resource group** (default: `rg-prod`)

### Required GitHub secrets

Configure these in your repository settings:

| Secret | Description |
| --- | --- |
| `ANTHROPIC_API_KEY` | API key from [console.anthropic.com](https://console.anthropic.com) |
| `AZURE_CLIENT_ID` | Azure service principal client ID (for OIDC auth) |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |

### Optional: Slack and Teams notifications

To receive drift reports in Slack or Teams, add these secrets:

| Secret | Setup |
| --- | --- |
| `SLACK_WEBHOOK_URL` | [Create incoming webhook](https://api.slack.com/messaging/webhooks) in Slack workspace |
| `TEAMS_WEBHOOK_URL` | [Create connector webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using) in Teams channel |

Both are optional—the workflow will automatically post to whichever services are configured.

## Report Formats

The drift check generates multiple report formats:

### HTML Report

Beautiful, interactive HTML report with:

- Status summary with color-coded metrics
- Detailed drift table showing all drift information
- **Dedicated remediation section** with Claude AI recommendations
- Resource type and drift type filters
- Mobile-responsive design
- Easy to share with stakeholders

**Drift Details Table:**
Shows each drift with resource type, name, drift type, and detailed change information.

**Remediation Recommendations Section:**
Numbered recommendations for resolving each drift, powered by Claude. Each recommendation includes:

- Numbered badge (#1, #2, etc.)
- Resource type and name
- Claude's AI-generated remediation suggestion

Available in the `drift-reports` artifact after workflow completes.

### JSON Report

Machine-readable report containing:

- Raw drift data
- ARM and live resource states
- All metadata for processing
- Used by Phase 2 analysis

### Ignoring Expected Drift

Some drift is expected or acceptable. Use `.drift-ignore` to suppress known differences:

```yaml
# .drift-ignore
ignore:
  # Ignore auto-created managed identities
  - resource_type: "Microsoft.ManagedIdentity/*"
    reason: "Auto-created by Azure services"
  
  # Ignore scaling changes
  - resource_type: "Microsoft.Compute/virtualMachineScaleSets"
    drift_type: "*capacity*"
    reason: "Auto-scaling expected"
  
  # Ignore specific resources
  - resource_name: "temporary-*"
    reason: "Temporary resources"
```

**Features:**

- Wildcard pattern matching (`*` and `?`)
- Filter by resource type, name, or drift type
- Document why each pattern is ignored
- Filtered drifts are excluded from metrics

Copy [`.drift-ignore.example`](.drift-ignore.example) to `.drift-ignore` in your repo root to customize.

### Viewing results

1. **Workflow summary** — Shows status, metrics, and issues directly in the GitHub Actions run
2. **Artifacts** — Download detailed JSON reports from the "drift-reports" artifact
3. **Logs** — See full execution logs and error messages in the workflow logs

### Current limitations

- ⚠️ Drift checks **do not run on pull requests** (Azure federated identity credentials only configured for push/manual triggers)
- To enable PR support, update your Azure Entra app's federated identity credential to accept `repo:*:pull_request` subject claims

## Testing the tools individually

```bash
# Test Bicep compilation
python -m tools.compile_bicep ./path/to/main.bicep

# Test live state query
python -m tools.get_live_state your-resource-group

# Then run the full check
python run_drift_check.py ./path/to/main.bicep your-resource-group
```
