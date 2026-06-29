# Enterprise Configuration Guide

## GitHub Actions Drift Detection Workflow

The drift detection workflow is fully configurable for enterprise deployments without modifying code.

### Configuration Priority

Configurations are applied in this order (first match wins):

1. **Workflow Dispatch Inputs** (manual override via GitHub UI)
2. **Repository Variables** (org-wide settings)
3. **Default Values** (built-in fallbacks)

---

## Repository Variables

Set these in GitHub → Settings → Secrets and variables → Variables:

### `DRIFT_BICEP_FILE`
Path to the Bicep template to test against.

**Example:**
```
../drift-test-resources/bicep/main.bicep
./infra/main.bicep
../enterprise-bicep/prod/main.bicep
```

**Default if not set:** `./infra/main.bicep`

---

### `DRIFT_RESOURCE_GROUP`
Azure resource group to test drift against.

**Example:**
```
rg-drift-test
rg-prod
rg-enterprise-validate
```

**Default if not set:** `rg-prod`

---

### `DRIFT_ARM_PARAMETERS`
ARM template parameters as JSON (location, environment, etc).

**Example:**
```json
{"environment":"prod","location":"australiaeast"}
```

```json
{"environment":"test","location":"eastus"}
```

**Default if not set:**
```json
{"environment":"prod","location":"australiaeast"}
```

---

## Setup for Teams/Organizations

### Step 1: Set Repository Variables

```bash
# Via GitHub CLI (requires gh auth)
gh variable set DRIFT_BICEP_FILE --body '../drift-test-resources/bicep/main.bicep'
gh variable set DRIFT_RESOURCE_GROUP --body 'rg-drift-test'
gh variable set DRIFT_ARM_PARAMETERS --body '{"environment":"test","location":"australiaeast"}'
```

Or via GitHub UI:
1. Go to **Settings** → **Secrets and variables** → **Variables**
2. Click **New repository variable**
3. Add each configuration above

### Step 2: Set Azure Secrets

Required secrets (already configured):
- `AZURE_CLIENT_ID` - Service principal client ID
- `AZURE_TENANT_ID` - Azure tenant ID
- `AZURE_SUBSCRIPTION_ID` - Azure subscription ID
- `ANTHROPIC_API_KEY` - Claude AI API key

Optional webhooks:
- `SLACK_WEBHOOK_URL` - For Slack notifications
- `TEAMS_WEBHOOK_URL` - For Teams notifications

### Step 3: Run Workflow

**Automatic:** Workflow runs on push to `main` or `develop` branches

**Manual:** Use workflow_dispatch
```bash
gh workflow run drift-check.yml \
  -f bicep_file='./custom/path/main.bicep' \
  -f resource_group='rg-custom'
```

---

## Multi-Team Setup

For organizations with multiple teams, create separate repository variables per team environment:

**Team A (Frontend):**
```
DRIFT_BICEP_FILE = ./teams/frontend/main.bicep
DRIFT_RESOURCE_GROUP = rg-frontend-prod
```

**Team B (Backend):**
```
DRIFT_BICEP_FILE = ./teams/backend/main.bicep
DRIFT_RESOURCE_GROUP = rg-backend-prod
```

Then use workflow_dispatch to select team-specific runs.

---

## Environment-Specific Configurations

For dev/test/prod environments:

**GitHub Environments** (Settings → Environments):
- Create `dev`, `test`, `prod` environments
- Assign different variables per environment
- Restrict deployments by approvers

Then trigger workflow for specific environment:
```bash
gh workflow run drift-check.yml --ref main \
  -f bicep_file='./infra/main.bicep' \
  -f resource_group='rg-test'
```

---

## Troubleshooting

### Variables Not Being Used
1. Verify variables are set: `gh variable list`
2. Check workflow file uses correct variable names (e.g., `${{ vars.DRIFT_BICEP_FILE }}`)
3. Variables must be set in the same repository as the workflow

### Path Issues
- Use relative paths from repository root
- `.../` goes up one directory
- `./` refers to repository root

### Parameter Issues
- ARM_PARAMETERS must be valid JSON
- Common locations: `australiaeast`, `eastus`, `westeurope`, `uksouth`
- Environment values: `dev`, `test`, `prod`

---

## Example: Production Setup

```bash
# Set production variables
gh variable set DRIFT_BICEP_FILE \
  --body '../../enterprise-templates/prod/main.bicep'

gh variable set DRIFT_RESOURCE_GROUP \
  --body 'rg-prod-drift-check'

gh variable set DRIFT_ARM_PARAMETERS \
  --body '{"environment":"prod","location":"australiaeast"}'

# Set secrets (one-time setup)
gh secret set AZURE_CLIENT_ID --body "YOUR_CLIENT_ID"
gh secret set AZURE_TENANT_ID --body "YOUR_TENANT_ID"
gh secret set AZURE_SUBSCRIPTION_ID --body "YOUR_SUB_ID"
gh secret set ANTHROPIC_API_KEY --body "YOUR_API_KEY"

# Run workflow
gh workflow run drift-check.yml
```

---

## See Also

- [Drift Detection Guide](docs/DRIFT_DETECTION_GUIDE.md)
- [Multi-Environment Testing](MULTI_ENVIRONMENT.md)
- [GitHub Secrets & Variables](https://docs.github.com/en/actions/learn-github-actions/variables)
