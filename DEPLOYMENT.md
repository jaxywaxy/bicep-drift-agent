# Deployment Guide: GitHub Actions + Azure Functions

This guide covers deploying the Bicep Drift Agent as a service using GitHub Actions for CI/CD and Azure Functions for on-demand analysis.

## Architecture

```
┌─────────────────┐
│ GitHub Actions  │  ← Triggered on Bicep changes
│  (CI/CD)        │  ← Comments on PRs
└────────┬────────┘
         │
         ├─→ Phase 1: Detect drift
         ├─→ Phase 2: Claude analysis
         └─→ Block merge if critical
         
┌─────────────────┐
│  Azure Functions│  ← HTTP endpoint
│ (On-demand)     │  ← Manual checks
└────────┬────────┘
         │
         ├─→ Run drift check
         ├─→ AI analysis
         └─→ Return JSON
```

---

## Part 1: GitHub Actions Setup

### 1.1 Add GitHub Secrets

Store these in **Settings → Secrets and variables → Actions**:

```
AZURE_CLIENT_ID       = (Service Principal Client ID)
AZURE_TENANT_ID       = (Azure Tenant ID)
AZURE_SUBSCRIPTION_ID = (Azure Subscription ID)
ANTHROPIC_API_KEY     = (Your Anthropic API Key)
```

### 1.2 Get Service Principal Credentials

```bash
# Create a service principal
az ad sp create-for-rbac \
  --name drift-agent \
  --role Reader \
  --scopes /subscriptions/{SUBSCRIPTION_ID}

# This outputs:
# {
#   "clientId": "...",
#   "clientSecret": "...",
#   "subscriptionId": "...",
#   "tenantId": "..."
# }

# Use clientId, tenantId, subscriptionId for GitHub secrets
```

### 1.3 Workflow Features

The workflow (`.github/workflows/drift-check.yml`):

- **Triggers on:**
  - Push to `main` or `develop` branches (Bicep files changed)
  - Pull requests to `main`
  - Manual dispatch (workflow_dispatch)

- **Actions:**
  - Compiles Bicep files
  - Runs Phase 1 drift detection
  - Runs Phase 2 AI analysis
  - Comments on PRs with findings
  - **Blocks merge if >5 drift issues** (configurable)
  - Uploads reports as artifacts

- **Configuration:**
  Edit the workflow file to:
  - Change `paths:` to match your Bicep directory structure
  - Adjust `ARM_PARAMETERS` for your environment
  - Modify drift threshold for PR blocking

### 1.4 Test the Workflow

```bash
# Trigger manually
gh workflow run drift-check.yml \
  -f bicep_file='./infra/main.bicep' \
  -f resource_group='rg-prod'
```

---

## Part 2: Azure Functions Setup

### 2.1 Prerequisites

```bash
# Install Azure Functions Core Tools
brew tap azure/azure-cli
brew install azure-functions-core-tools@4

# Install func CLI
func --version  # Should be 4.x+
```

### 2.2 Create Function App in Azure

```bash
# Variables
RESOURCE_GROUP="drift-agent-rg"
LOCATION="australiaeast"
STORAGE_ACCOUNT="driftfuncstore"
FUNCTION_APP="drift-agent-func"

# Create resource group
az group create -n $RESOURCE_GROUP -l $LOCATION

# Create storage account (required for Functions)
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Create Function App
az functionapp create \
  --resource-group $RESOURCE_GROUP \
  --consumption-plan-location $LOCATION \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name $FUNCTION_APP \
  --storage-account $STORAGE_ACCOUNT
```

### 2.3 Configure Application Settings

```bash
# Set environment variables in the Function App
az functionapp config appsettings set \
  --name $FUNCTION_APP \
  --resource-group $RESOURCE_GROUP \
  --settings \
    ANTHROPIC_API_KEY="sk-ant-..." \
    ARM_PARAMETERS='{"environment":"prod"}'

# Allow managed identity for Azure auth
az functionapp identity assign \
  --name $FUNCTION_APP \
  --resource-group $RESOURCE_GROUP
```

### 2.4 Grant Permissions

```bash
# Get the managed identity object ID
OBJECT_ID=$(az functionapp identity show \
  --name $FUNCTION_APP \
  --resource-group $RESOURCE_GROUP \
  --query principalId -o tsv)

# Grant Reader role on subscription
az role assignment create \
  --assignee $OBJECT_ID \
  --role Reader \
  --scope /subscriptions/{SUBSCRIPTION_ID}
```

### 2.5 Deploy Function App

```bash
# From the project root
func azure functionapp publish $FUNCTION_APP --python

# Or using GitHub Actions (see example below)
```

### 2.6 Test the Function

```bash
# Get function URL
FUNCTION_URL=$(az functionapp function show \
  --name $FUNCTION_APP \
  --resource-group $RESOURCE_GROUP \
  --function-name DriftCheckFunction \
  --query "invokeUrlTemplate" -o tsv)

# Test drift check
curl -X POST "$FUNCTION_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "bicepFile": "./infra/main.bicep",
    "resourceGroup": "rg-prod",
    "parameters": {"environment": "prod"}
  }'

# Test health
curl "$FUNCTION_URL/../health"
```

### 2.7 Function Endpoints

**POST /api/drift-check**
- Run drift analysis
- Request body: `{bicepFile, resourceGroup, parameters}`
- Returns: Full analysis JSON

**GET /api/health**
- Health check
- Returns: `{status: "healthy"}`

**GET /api/analyze/{resourceGroup}**
- Retrieve saved analysis
- Query param: `?format=json|markdown`
- Returns: Report file

---

## Part 3: GitHub Actions + Function Integration

Optionally call the Function from GitHub Actions:

```yaml
# In your workflow
- name: Call drift function
  run: |
    curl -X POST "${{ secrets.FUNCTION_URL }}" \
      -H "Content-Type: application/json" \
      -d '{
        "bicepFile": "./infra/main.bicep",
        "resourceGroup": "rg-prod",
        "parameters": {"environment": "prod"}
      }'
```

---

## Part 4: Monitoring & Logs

### View Function Logs

```bash
# Stream logs from Function App
func azure functionapp logstream $FUNCTION_APP \
  --resource-group $RESOURCE_GROUP
```

### Set Up Alerts

```bash
# Create alert for function failures
az monitor metrics alert create \
  --name "DriftFunction-Failures" \
  --resource-group $RESOURCE_GROUP \
  --scopes "/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP" \
  --condition "total FunctionExecutionCount where Outcome != Success" \
  --threshold 5
```

---

## Part 5: Security Best Practices

1. **Use Managed Identity** (not connection strings)
2. **Restrict Function Access:**
   ```bash
   # Only allow from specific IPs/networks
   az functionapp config access-restriction set \
     --name $FUNCTION_APP \
     --resource-group $RESOURCE_GROUP \
     --rule-name GitHub \
     --action Allow \
     --priority 100 \
     --ip-address <github-runner-ip-range>/24
   ```

3. **Use Azure Key Vault** for secrets:
   ```bash
   # Store ANTHROPIC_API_KEY in Key Vault
   az keyvault secret set \
     --vault-name my-vault \
     --name anthropic-api-key \
     --value "sk-ant-..."
   
   # Reference in Function App
   az functionapp config appsettings set \
     --name $FUNCTION_APP \
     --resource-group $RESOURCE_GROUP \
     --settings ANTHROPIC_API_KEY="@Microsoft.KeyVault(SecretUri=...)"
   ```

4. **Enable HTTPS Only:**
   ```bash
   az functionapp config set \
     --name $FUNCTION_APP \
     --resource-group $RESOURCE_GROUP \
     --https-only true
   ```

---

## Part 6: CI/CD for Function Deployment

Add to `.github/workflows/deploy-functions.yml`:

```yaml
name: Deploy Function App

on:
  push:
    branches: [main]
    paths:
      - 'function_app.py'
      - 'function_requirements.txt'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      
      - uses: azure/functions-action@v1
        with:
          app-name: drift-agent-func
          package: .
          runtime: 'python'
          runtime-version: '3.11'
```

---

## Troubleshooting

### Function Not Triggering
- Check Application Insights logs
- Verify function_app.py is at project root
- Run `func start` locally to test

### Auth Failures
- Verify managed identity has Reader role
- Check ANTHROPIC_API_KEY is set
- Run `az login` to verify CLI access

### GitHub Actions Secrets Not Found
- Confirm secrets are in correct organization
- Use `${{ secrets.SECRET_NAME }}` syntax
- Restart workflow after adding secrets

---

## Next Steps

1. ✅ Set up GitHub Actions workflow
2. ✅ Deploy Azure Function App
3. ✅ Add PR checks
4. ✅ Set up monitoring
5. Monitor drift over time
6. Integrate with Slack/Teams for notifications

For questions or issues, check:
- Azure Functions docs: https://learn.microsoft.com/azure/azure-functions
- GitHub Actions: https://docs.github.com/actions
