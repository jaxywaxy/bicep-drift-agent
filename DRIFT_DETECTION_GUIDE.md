# Production-Ready Bicep Infrastructure Drift Detection System

## Executive Summary

Managing cloud infrastructure as code (IaC) is critical for consistency, security, and cost control. However, infrastructure changes often occur outside the IaC pipeline—through manual Azure Portal updates, scripts, or system-managed configurations. These **out-of-band changes** create drift between your intended infrastructure state (Bicep templates) and actual deployed state.

This guide documents a **production-ready drift detection system** that:
- ✅ Detects missing, extra, and modified resources
- ✅ Compares resource properties at the field level
- ✅ Generates AI-powered remediation recommendations
- ✅ Intelligently matches resources despite parameter expressions
- ✅ Filters expected differences via customizable ignore patterns
- ✅ Integrates with GitHub Actions and Azure Federated Identity
- ✅ Produces detailed HTML and JSON reports

## Architecture Overview

### The Problem

Traditional drift detection answers: **"Is resource X deployed?"** But modern infrastructure needs to answer: **"Is resource X configured exactly as defined in Bicep?"**

Consider this scenario:
```bicep
param environment string = 'dev'
param vmName string = 'vm-prod-001'

resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: '${vmName}'
  location: resourceGroup().location
  properties: {
    osProfile: {
      computerName: vmName
    }
    tags: {
      environment: environment          // Parameter expression
      managed: 'true'
    }
  }
}
```

When deployed with `environment=prod`, Azure stores the **resolved value** `"prod"` not the **expression** `"[parameters('environment')]"`. A naive drift checker sees this as drift. Our system knows it's expected and ignores it.

### System Components

```
┌─────────────────┐
│  Bicep Template │
│  (IaC source)   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│         Phase 1: Drift Detection                         │
├─────────────────────────────────────────────────────────┤
│  1. Compile Bicep → ARM JSON                            │
│  2. Query Live Azure State                              │
│  3. Intelligent Resource Matching (fuzzy + contextual)  │
│  4. Property-Level Drift Analysis                       │
│  5. Apply Ignore Patterns (filter false positives)      │
│  6. Generate JSON Report                                │
└─────────────────┬───────────────────────────────────────┘
                  │
         ┌────────┴────────┐
         ▼                 ▼
┌──────────────┐    ┌──────────────────┐
│ JSON Report  │    │ Phase 2: Analysis │
│  (machine)   │    │  (Claude AI)      │
└──────────────┘    └────────┬─────────┘
                             │
                    ┌────────▼────────┐
                    │ HTML Report     │
                    │ + Recommend.    │
                    │ (human-readable)│
                    └─────────────────┘
```

### Key Design Decisions

**1. Property-Level Drift Detection**
Instead of just checking resource existence, we compare individual properties. A VM with a different SKU, different tags, or different networking is caught.

**2. Smart Resource Matching**
Azure resource names often contain parameter expressions that resolve at deployment time. We use:
- **Exact name matching** (confidence: 0.95)
- **Contextual parent-resource matching** (confidence: 0.90) — e.g., matching disk to VM via naming pattern
- **Fuzzy token matching** (confidence: 0.25+) — e.g., matching "vm-prod-001-nic" when template says "parameters('vmName')-nic"
- **Positional fallback** (confidence: 0.60) — for identical-named resources

**3. Ignore Patterns with Reasons**
Rather than hardcoding exclusions, we provide a `.drift-ignore` file where each pattern explains why it's ignored:
```yaml
ignore:
  - resource_type: "Microsoft.Compute/disks"
    reason: "OS/data disks are auto-created and managed by VMs"
  
  - resource_type: "Microsoft.Network/virtualNetworks"
    reason: "VNets are part of LZ pattern, referenced as 'existing'"
```

This makes intent explicit and drift reports trustworthy.

**4. AI-Powered Recommendations**
For each drift found, Claude AI generates context-aware remediation steps, not generic advice.

## Supported Azure Resources

The system intelligently handles these resource categories:

### ✅ Compute
- Virtual Machines & properties (tags, SKU, config)
- VM extensions (filtered as auto-managed)
- Virtual Machine Scale Sets
- Disks (filtered as auto-managed)

### ✅ Networking
- Virtual Networks & subnets (LZ pattern)
- Network Interfaces
- Load Balancers (auto-created)
- Public IP Addresses (auto-created/existing)
- Network Security Groups (existing)

### ✅ Storage
- Storage Accounts
- Blob/File/Table/Queue Services (auto-managed)
- Containers

### ✅ Databases
- SQL Servers & Databases
- Master DB (auto-created, ignored)
- Auditing & Security Policies

### ✅ Application Services
- App Service Plans
- Web Apps & Function Apps
- Deployment Slots (auto-managed)

### ✅ Container Services
- Azure Kubernetes Service (AKS)
- Agent Pools (auto-managed)

### ✅ Infrastructure Services
- Recovery Services Vaults
- Key Vaults
- API Management
- Log Analytics Workspaces (auto-created)
- Application Insights

### ✅ System Resources
- Resource Locks (filtered as policy-managed)
- Role Assignments (filtered as policy-managed)
- Diagnostic Settings (filtered as auto-managed)

## Installation & Setup

### Prerequisites

```bash
# Azure CLI (v2.50+)
az --version

# Python 3.11+
python3 --version

# Git
git --version

# Bicep build capability
az bicep install
```

### Clone and Configure

```bash
# Clone the repo
git clone <your-repo-url>
cd backup-compliance-deployment/drift-detection

# Create Python environment
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# or: .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements File

```
# requirements.txt
anthropic>=0.18.0
pyyaml>=6.0
python-dotenv>=1.0.0
```

### Environment Configuration

```bash
# Create .env file
cat > .env << 'EOF'
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_TENANT_ID=<your-tenant-id>
ANTHROPIC_API_KEY=<your-anthropic-api-key>
EOF

# Or set environment variables
export AZURE_SUBSCRIPTION_ID="..."
export AZURE_TENANT_ID="..."
export ANTHROPIC_API_KEY="..."
```

## Quick Start

### 1. Run Drift Check (Local)

```bash
# Phase 1: Detect drift (produces JSON report)
python run_drift_check.py ./main.bicep rg-prod

# Phase 1 + Phase 2: Detect drift + Get AI analysis
python analyze_drift.py ./main.bicep rg-prod
```

**Output:**
```
================================================
Bicep Drift Check
================================================
  Bicep file:     ./main.bicep
  Resource group: rg-prod

Step 1: Compiling Bicep template...
  ✓ 12 resource(s) defined in Bicep

Step 2: Querying live Azure state...
  ✓ 18 resource(s) deployed in Azure

Step 3: Loading ignore patterns...
Loaded 31 ignore pattern(s):
  1. type=Microsoft.Network/networkWatchers
     Reason: Auto-created by Azure in each region...
  ...

Step 4: Diffing desired vs actual...
Step 5: Report

Drift Report — rg-prod
==================================================
Found 5 drift(s):

  [MISSING] Microsoft.RecoveryServices/vaults/backupPolicies is in Bicep but not deployed
  [EXTRA]   Microsoft.Storage/storageAccounts/drifttest1234 is deployed but not in Bicep
  [DRIFT]   Microsoft.Compute/virtualMachines/vm-prod-001 — properties differ: tags.environment
  ...
```

### 2. With Parameter Overrides

```bash
# Deploy to different environment
ARM_PARAMETERS='{"environment":"staging","location":"eastus"}' \
python analyze_drift.py ./main.bicep rg-staging
```

### 3. Check Specific Resources Only

```bash
# Filter in .drift-ignore to ignore known-good resources
# Then re-run the check
python analyze_drift.py ./main.bicep rg-prod
```

## Deployment: GitHub Actions Workflow

### Setup GitHub Secrets

```bash
# Federated Identity setup (OIDC, no secrets stored)
# See: https://docs.microsoft.com/en-us/azure/active-directory/workload-identities/workload-identity-federation

# Store in GitHub Secrets:
AZURE_CLIENT_ID        # Service principal client ID
AZURE_TENANT_ID        # Tenant ID
AZURE_SUBSCRIPTION_ID  # Subscription ID
ANTHROPIC_API_KEY      # Claude API key
```

### Workflow File

```yaml
# .github/workflows/bicep-drift-check.yml
name: Bicep Drift Check

on:
  push:
    branches: [main, develop]
    paths:
      - 'bicep/**/*.bicep'
  pull_request:
    branches: [main]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment (dev/prod)'
        required: true
        default: 'prod'

jobs:
  drift-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r drift-detection/requirements.txt
          curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

      - name: Azure Login (OIDC)
        uses: azure/login@v3
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Run Drift Check
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          ARM_PARAMETERS: '{"environment":"${{ github.event.inputs.environment || ''prod'' }}","location":"australiaeast"}'
        run: |
          cd drift-detection
          python analyze_drift.py ../bicep/main.bicep rg-prod

      - name: Generate Report
        if: always()
        run: |
          echo "## 🔍 Drift Detection Report" >> $GITHUB_STEP_SUMMARY
          cat reports/rg-prod-analysis.md >> $GITHUB_STEP_SUMMARY

      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: drift-reports
          path: drift-detection/reports/
          retention-days: 30

      - name: Post to Slack (Optional)
        if: failure()
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d '{"text":"⚠️ Drift detected in production. Check: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"}'
```

### Run Workflow

```bash
# Automatic: Push to main triggers drift check
git push origin main

# Manual: Via GitHub UI or CLI
gh workflow run bicep-drift-check.yml -f environment=prod
```

## Deployment: Azure Function App

For continuous monitoring, deploy the drift check as an Azure Function:

### 1. Create Function App

```bash
# Variables
RESOURCE_GROUP="rg-prod"
FUNCTION_APP_NAME="drift-check-$(date +%s)"
STORAGE_ACCOUNT="driftcheck$(date +%s%N | cut -c 1-8)"
LOCATION="australiaeast"

# Create resource group (if needed)
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

# Create storage account
az storage account create \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS

# Create Function App (Python runtime)
az functionapp create \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --storage-account "$STORAGE_ACCOUNT" \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux

echo "✓ Function App created: $FUNCTION_APP_NAME"
```

### 2. Deploy Drift Check Code

```bash
# Initialize function project
func init drift-function --python
cd drift-function

# Create Timer Trigger function (runs daily)
func new --name DriftCheck --template "Timer trigger"

# Copy drift detection code
cp -r ../drift-detection/tools ./
cp -r ../drift-detection/tools ./DriftCheck/

# Create function code
cat > DriftCheck/function_app.py << 'EOF'
import azure.functions as func
import os
import json
from pathlib import Path
from datetime import datetime
from tools.ignore_patterns import IgnorePatternList
from tools.compile_bicep import compile_bicep, extract_resources_from_arm
from tools.get_live_state import get_live_state
from tools.diff_states import diff_states, format_drift_report

app = func.FunctionApp()

@app.function_name("DriftCheck")
@app.schedule(schedule="0 9 * * *")  # 9 AM daily
def drift_check_timer(mytimer: func.TimerRequest) -> None:
    """Run drift check on daily schedule"""
    
    bicep_file = "./bicep/main.bicep"
    resource_group = os.environ.get("TARGET_RG", "rg-prod")
    
    try:
        # Compile Bicep
        arm_template = compile_bicep(bicep_file)
        arm_resources = extract_resources_from_arm(arm_template)
        
        # Query Azure
        live_resources = get_live_state(resource_group=resource_group)
        
        # Load ignore patterns
        ignore_patterns = IgnorePatternList.from_file(Path(".drift-ignore"))
        
        # Detect drift
        drifts = diff_states(arm_resources, live_resources, ignore_patterns)
        
        # Log results
        report = format_drift_report(drifts, resource_group)
        
        if drifts:
            # Send alert (e.g., to Application Insights, webhook, etc.)
            send_alert(f"⚠️ Drift detected: {len(drifts)} issue(s)", report)
        
        return "OK"
        
    except Exception as e:
        send_alert(f"❌ Drift check failed: {str(e)}", "")
        raise

def send_alert(title: str, details: str) -> None:
    """Send alert to monitoring system"""
    # Implementation: call webhook, Application Insights, etc.
    pass

if __name__ == "__main__":
    app.run(host='localhost', port=8000)
EOF

# Deploy to Azure
func azure functionapp publish "$FUNCTION_APP_NAME"
```

### 3. Configure Environment Variables

```bash
az functionapp config appsettings set \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --settings \
    AZURE_SUBSCRIPTION_ID="$AZURE_SUBSCRIPTION_ID" \
    AZURE_TENANT_ID="$AZURE_TENANT_ID" \
    ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    TARGET_RG="rg-prod"
```

### 4. Set Up Managed Identity

```bash
# Enable managed identity for the function
az functionapp identity assign \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --identities [system]

# Get principal ID
PRINCIPAL_ID=$(az functionapp identity show \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv)

# Grant Reader role on target resource group
az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role Reader \
  --scope "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"
```

## Customizing Ignore Patterns

### Understanding Ignore Patterns

The `.drift-ignore` file controls what's reported as drift. Each pattern includes a reason:

```yaml
ignore:
  # Auto-created by Azure (system)
  - resource_type: "Microsoft.Network/networkWatchers"
    reason: "Auto-created by Azure in each region, not IaC-managed"

  # Auto-managed by parent resource
  - resource_type: "Microsoft.Compute/disks"
    reason: "OS/data disks auto-created by VMs, not separately defined"

  # Landing Zone infrastructure (external dependency)
  - resource_type: "Microsoft.Network/virtualNetworks"
    reason: "VNets are part of LZ pattern, referenced as 'existing' in Bicep"

  # Expected parameter drift
  - resource_type: "Microsoft.Compute/virtualMachines"
    reason: "Parameter expressions resolve at deployment time"

  # Application-specific (your additions)
  - resource_type: "Microsoft.Insights/components"
    resource_name: "custom-app-insights-.*"
    reason: "Application Insights managed by application deployment"
```

### Adding Custom Patterns

For your organization's specific needs:

```yaml
ignore:
  # Example: Ignoring monitoring resources managed by ops team
  - resource_type: "Microsoft.Insights/metricAlerts"
    reason: "Alert rules managed separately by on-call team"

  # Example: Ignoring firewall rules for compliance reasons
  - resource_type: "Microsoft.Sql/servers/firewallRules"
    resource_name: "AllowAzureServices"
    reason: "Firewall rule auto-created for Azure services"

  # Example: Name pattern matching
  - resource_type: "Microsoft.Storage/storageAccounts"
    resource_name: "backup.*"
    reason: "Backup storage accounts managed by backup solution"
```

### Validating Patterns

```bash
# Check which resources would be ignored
python3 << 'EOF'
from pathlib import Path
from tools.ignore_patterns import IgnorePatternList

patterns = IgnorePatternList.from_file(Path(".drift-ignore"))
patterns.print_summary()
EOF
```

## Understanding Reports

### JSON Report (`rg-prod-drift.json`)

Machine-readable format with full details:

```json
{
  "resource_group": "rg-prod",
  "bicep_file": "./main.bicep",
  "drift_count": 5,
  "drifts": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "name": "vm-prod-001",
      "drift_type": "property_drift",
      "details": {
        "changed_properties": {
          "tags.environment": {
            "desired": "[parameters('environment')]",
            "actual": "prod",
            "severity": "warning"
          }
        }
      }
    }
  ]
}
```

### HTML Report (`rg-prod-drift.html`)

Human-readable dashboard with:
- Status summary (# missing, # extra, # modified)
- Drift details table
- Property-level changes with side-by-side diffs
- AI-generated remediation recommendations
- Severity levels (critical, warning, info)

### Analysis File (`rg-prod-analysis.md`)

Claude's high-level assessment:
```markdown
# Drift Analysis: rg-prod

## Summary
Found 5 drift issues across 3 resources. Most are parameter expressions
resolving at deployment time (expected) or auto-managed resources.

## Critical Issues
None detected.

## Recommendations
1. Review vm-prod-001 tags — ensure environment parameter is set correctly
2. Investigate extra storage accounts — determine if intentional
3. Add custom ignore patterns for compliance monitoring resources
```

## Troubleshooting

### Issue: "Bicep file not found"

```bash
# Verify path
ls -la ./bicep/main.bicep

# Use absolute path
python analyze_drift.py /full/path/to/main.bicep rg-prod
```

### Issue: "Resource group not found" or "No resources in Azure"

```bash
# Verify Azure login
az account show

# Check resource group exists
az group show --name rg-prod

# List resources in RG
az resource list --resource-group rg-prod
```

### Issue: "ANTHROPIC_API_KEY not set"

```bash
# Check environment variable
echo $ANTHROPIC_API_KEY

# Set it
export ANTHROPIC_API_KEY="sk-..."

# Or in .env file
echo 'ANTHROPIC_API_KEY=sk-...' > .env
```

### Issue: "Parameter expression not recognized"

```bicep
# ❌ Unresolvable (filtered out)
name: guid(resourceGroup().id)

# ✅ Resolvable (matched intelligently)
name: '${vmName}-nic'  # Fuzzy matched to actual name
```

### Issue: "False positives in report" (resources showing as drift when they shouldn't)

```bash
# 1. Check current ignore patterns
python3 << 'EOF'
from pathlib import Path
from tools.ignore_patterns import IgnorePatternList
patterns = IgnorePatternList.from_file(Path(".drift-ignore"))
patterns.print_summary()
EOF

# 2. Add pattern for the resource
cat >> .drift-ignore << 'EOF'

  - resource_type: "Microsoft.SomeType/resource"
    reason: "Explanation of why this is expected"
EOF

# 3. Re-run drift check
python analyze_drift.py ./main.bicep rg-prod
```

## Best Practices

### 1. Run Drift Checks Regularly

```bash
# Daily via GitHub Actions
# OR via scheduled Azure Function
# OR manually before deployments
```

### 2. Version Control Your Ignore Patterns

```bash
# Commit .drift-ignore to source control
git add .drift-ignore
git commit -m "docs: update ignore patterns for LZ infrastructure"
```

### 3. Act on Drift Reports

| Drift Type | Action |
|-----------|--------|
| Missing resource | Redeploy Bicep template |
| Extra resource | Investigate origin; import to IaC or delete |
| Property drift | Update Bicep to match deployed state OR redeploy |

### 4. Document External Dependencies

```bicep
// This VM uses a VNet deployed by a separate Landing Zone template
resource nic 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        subnet: {
          id: resourceId(
            subscription().subscriptionId,
            lzResourceGroup,
            'Microsoft.Network/virtualNetworks/subnets',
            'vnet-prod',
            'subnet-vms'
          )
        }
      }
    ]
  }
}
```

### 5. Alert on Critical Drift

```yaml
# In GitHub Actions: fail if critical changes detected
- name: Check for critical drift
  if: failure()
  run: |
    if grep -q "CRITICAL" drift_output.txt; then
      echo "❌ Critical configuration drift detected"
      exit 1
    fi
```

## Advanced: Custom Resource Matching

For specialized resources not handled by default fuzzy matching:

```python
# tools/smart_matching.py - extend ResourceMatcher
class ResourceMatcher:
    def _find_associated_resource(self, bicep_res, live_resources):
        """Add custom matching logic"""
        
        # Example: Match AppInsights by application type
        if bicep_res['type'] == 'Microsoft.Insights/components':
            ai_type = bicep_res.get('properties', {}).get('applicationType')
            return next(
                r for r in live_resources
                if r['type'] == bicep_res['type']
                and r.get('properties', {}).get('applicationType') == ai_type
            )
```

## Performance Considerations

| Size | Scope | Time | Notes |
|------|-------|------|-------|
| 10-20 resources | Single RG | ~10s | Local, instant feedback |
| 50-100 resources | Multiple RGs | ~30s | GitHub Actions, acceptable |
| 200+ resources | Subscription | ~60s+ | Consider filtering by scope |

### Optimize Large Deployments

```bash
# Option 1: Run on specific RG only
python analyze_drift.py ./main.bicep rg-prod

# Option 2: Filter Bicep scope to specific resources
# (edit main.bicep to reduce scope)

# Option 3: Cache ARM compilation
az bicep build ./bicep/main.bicep --outdir /tmp
```

## Security Considerations

### 1. Credentials

- **Never commit secrets** to git
- Use GitHub Secrets for sensitive values
- Use Azure Managed Identity in Function Apps
- Use `.env` locally (add to `.gitignore`)

### 2. RBAC

```bash
# Function App only needs Reader on target RG
az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role Reader \
  --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"
```

### 3. API Keys

```bash
# Anthropic API key
# - Store in GitHub Secrets
# - Rotate regularly
# - Monitor usage via Anthropic dashboard
```

## Conclusion

This drift detection system provides **visibility into infrastructure changes** at scale. By combining:

- **Intelligent resource matching** (handles parameter expressions)
- **Property-level comparison** (catches config changes)
- **AI-powered analysis** (context-aware recommendations)
- **Customizable ignore patterns** (reduces noise)

...you achieve a trustworthy source of truth about your Azure infrastructure.

Start today:

```bash
# 1. Download the code
git clone <repo>

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run your first drift check
python analyze_drift.py ./main.bicep rg-prod

# 4. Review the HTML report
open reports/rg-prod-drift.html
```

---

**Questions?** Check the troubleshooting section or review the source code in `drift-detection/tools/`.

**Want to extend it?** The modular design makes it easy to add custom resource matchers, ignore patterns, or notification integrations.
