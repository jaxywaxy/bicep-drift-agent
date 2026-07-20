# Azure Authentication Setup (OIDC)

Enterprise-grade authentication for drift detection using GitHub OIDC (OpenID Connect) with Workload Identity Federation. No secrets stored in GitHub.

## Architecture

```
GitHub Actions Workflow
    ↓
GitHub OIDC Token
    ↓
Azure Entra ID (Federated Credential)
    ↓
Service Principal (Reader on Management Group)
    ↓
Azure Resources (Query-only access)
```

## Prerequisites

- Azure subscription with Owner/Access Management permissions
-- GitHub repository (your-org/your-repo)
- Azure CLI installed and authenticated (`az login`)

## Setup Steps

### Step 1: Identify Your Management Group

```bash
# List all management groups
az account management-group list --output table

# If you have a specific org management group, use it
# Example: "myorg" or "contoso"
MGMT_GROUP="your-management-group-name"

# Verify the management group exists
az account management-group show --name $MGMT_GROUP
```

**Why Management Group?**
- ✅ Covers all subscriptions in the group (auto-scales as subscriptions are added)
- ✅ Teams manage subscriptions independently
- ✅ No per-subscription configuration needed
- ✅ Central tool, distributed team ownership

---

### Step 2: Create Azure App Registration & Federated Credential

```bash
# Set variables
MGMT_GROUP="your-management-group-name"  # Update this
TENANT_ID=$(az account show --query tenantId -o tsv)
GITHUB_REPO="your-org/your-repo"  # Update to your repo

echo "Creating OIDC federation for GitHub..."
echo "Tenant ID: $TENANT_ID"
echo "Management Group: $MGMT_GROUP"
echo "GitHub Repo: $GITHUB_REPO"
echo ""

# Create app registration
echo "Step 1/4: Creating app registration..."
APP_ID=$(az ad app create \
  --display-name "drift-agent-oidc" \
  --query appId -o tsv)

echo "✓ Created app: $APP_ID"

# Create service principal
echo "Step 2/4: Creating service principal..."
PRINCIPAL_ID=$(az ad sp create \
  --id $APP_ID \
  --query id -o tsv)

echo "✓ Created service principal: $PRINCIPAL_ID"

# Grant Reader role at Management Group level
echo "Step 3/4: Granting Reader role on management group..."
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/$MGMT_GROUP

echo "✓ Granted Reader role on management group: $MGMT_GROUP"
echo "  (Covers all subscriptions under this group)"

# Add federated credential for GitHub
echo "Step 4/4: Creating federated credential..."
az identity federated-credential create \
  --name "github-oidc" \
  --identity-name $APP_ID \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:$GITHUB_REPO:ref:refs/heads/feature/cleanup-and-recommendations" \
  --audiences "api://AzureADTokenExchange"

echo "✓ Federated credential created"
echo ""
echo "=========================================="
echo "✅ OIDC Setup Complete"
echo "=========================================="
echo ""
echo "Save these for GitHub secrets:"
echo ""
echo "AZURE_CLIENT_ID=$APP_ID"
echo "AZURE_TENANT_ID=$TENANT_ID"
echo ""
```

---

### Step 3: Add GitHub Secrets

In the repository where the workflows run (e.g. the central drift-agent repository or your CI repo):

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add these **2 secrets** (no client secret needed - that's the power of OIDC!):

| Secret Name | Value |
|-------------|-------|
| `AZURE_CLIENT_ID` | (from Step 2 output) |
| `AZURE_TENANT_ID` | (from Step 2 output) |

**Important:** These are not secrets in the traditional sense - they're just IDs. The actual credential is the GitHub OIDC token, which is automatically provided by GitHub and exchanged for an Azure token.

---

### Step 4: Update GitHub Ref (if needed)

The federated credential above is scoped to:
```
repo:your-org/your-repo:ref:refs/heads/feature/cleanup-and-recommendations
```

**When you merge to main**, update the federated credential:

```bash
APP_ID="your-app-id"  # From Step 2

az identity federated-credential delete \
  --name "github-oidc" \
  --identity-name $APP_ID \
  --yes

az identity federated-credential create \
  --name "github-oidc-main" \
  --identity-name $APP_ID \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:your-org/your-repo:ref:refs/heads/main" \
  --audiences "api://AzureADTokenExchange"
```

Or, for all branches:
```bash
--subject "repo:your-org/your-repo:*"
```

---

## How It Works

1. **GitHub Actions workflow starts** → drift-check-lz-hybrid.yml runs
2. **Azure Login step** → Requests OIDC token from GitHub
3. **GitHub OIDC Provider** → Issues token signed with GitHub's key
4. **Azure Entra ID** → Validates GitHub token against federated credential
5. **Token Exchange** → Exchanges GitHub OIDC token for Azure access token
6. **Service Principal** → Authenticated to Azure with Reader role on management group
7. **Drift Detection** → Queries Azure resources using that access token
8. **No secrets** → Token is short-lived (< 1 hour), never stored

---

## Troubleshooting

### "Federated credential not found"
```bash
# Verify the federated credential was created
az identity federated-credential show \
  --name "github-oidc" \
  --identity-name $APP_ID
```

### "AADSTS700016: Application not found in directory"
The GitHub token couldn't be exchanged. Check:
- `AZURE_CLIENT_ID` secret is correct
- `AZURE_TENANT_ID` secret is correct
- Federated credential subject matches your GitHub ref exactly

### "User does not have access to perform action"
The service principal doesn't have Reader role on the management group:
```bash
# Verify role assignment
az role assignment list \
  --assignee $PRINCIPAL_ID \
  --scope /providers/Microsoft.Management/managementGroups/$MGMT_GROUP
```

### "The subscription does not contain management group"
Update your federated credential to use the correct management group path:
```bash
az identity federated-credential list --identity-name $APP_ID
```

---

## Security Benefits

✅ **No secrets in GitHub**
- Only app ID and tenant ID (public identifiers)
- No credentials to rotate or compromise

✅ **Automatic token rotation**
- GitHub OIDC tokens are short-lived (< 1 hour)
- Azure access tokens are automatically renewed

✅ **Audit trail**
- All authentication logged in Azure Entra audit logs
- Full traceability to GitHub workflow and branch

✅ **Least privilege**
- Reader-only access (query-only, no modifications)
- Scoped to specific management group
- Can be further restricted to resource groups if needed

✅ **Scalability**
- New subscriptions added to management group are automatically covered
- No configuration changes needed

---

## Next Steps

1. ✅ Complete Step 1-3 above
2. ✅ Push feature branch to GitHub
3. ✅ Run workflow: `gh workflow run drift-lz-test.yml --ref feature/cleanup-and-recommendations`
4. ✅ Verify authentication succeeds in workflow logs
5. ✅ Merge to main and update federated credential for production branch
6. ✅ Teams add `subscription_id` to their `drift-lz-config.yml`

---

## Scanning Identity vs Deployer Identity

The drift agent recognises changes made by the identity it **runs as** as
authorized IaC deployments automatically (it reads its own token claims at
scan time). If your estates are **deployed by a different app registration**
than the one the drift agent authenticates with — e.g. one OIDC app per repo,
or separate deploy/scan identities for least privilege — add the deployer
identities to the `DRIFT_AUTHORIZED_DEPLOYERS` **repository variable** so
their deploys are not reported as out-of-band manual changes:

```bash
gh variable set DRIFT_AUTHORIZED_DEPLOYERS --body "<deployer-sp-object-id>"
```

The bundled workflows pass this variable into the scan job automatically.
Use the service principal **object ID** (what the Activity Log `caller` field
records), not the appId. See
[CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md#authorized-deployers).

---

## See Also

- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration

