# Using the Reusable Drift Check Workflow

Infrastructure repositories can use this drift-checking service via a reusable workflow.

## Setup (One-time)

### 1. Add GitHub secrets to your infrastructure repo

In your repo's GitHub settings, add these secrets:
- `DRIFT_CHECK_ANTHROPIC_API_KEY` — Anthropic API key
- `DRIFT_CHECK_AZURE_CLIENT_ID` — Azure service principal client ID
- `DRIFT_CHECK_AZURE_TENANT_ID` — Azure tenant ID
- `DRIFT_CHECK_AZURE_SUBSCRIPTION_ID` — Azure subscription ID

Optional:
- `DRIFT_CHECK_SLACK_WEBHOOK_URL` — Slack webhook for notifications
- `DRIFT_CHECK_TEAMS_WEBHOOK_URL` — Teams webhook for notifications

### 2. Create a workflow file

Create `.github/workflows/drift-check.yml` in your infrastructure repo:

```yaml
name: Check Bicep Drift

on:
  push:
    branches: [main]
    paths:
      - 'bicep/**/*.bicep'
  pull_request:
    branches: [main]
    paths:
      - 'bicep/**/*.bicep'
  workflow_dispatch:
    inputs:
      bicep_file:
        description: 'Path to Bicep file'
        default: 'bicep/main.bicep'
      resource_group:
        description: 'Resource group name'
        default: 'my-rg'

jobs:
  drift-check:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
    with:
      bicep_file: ${{ github.event.inputs.bicep_file || 'bicep/main.bicep' }}
      resource_group: ${{ github.event.inputs.resource_group || 'my-rg' }}
      fail_on_drift: true
      fail_threshold: 3
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.DRIFT_CHECK_ANTHROPIC_API_KEY }}
      AZURE_CLIENT_ID: ${{ secrets.DRIFT_CHECK_AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: ${{ secrets.DRIFT_CHECK_AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.DRIFT_CHECK_AZURE_SUBSCRIPTION_ID }}
      SLACK_WEBHOOK_URL: ${{ secrets.DRIFT_CHECK_SLACK_WEBHOOK_URL }}
      TEAMS_WEBHOOK_URL: ${{ secrets.DRIFT_CHECK_TEAMS_WEBHOOK_URL }}
```

## Configuration

### Inputs

| Input | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `bicep_file` | string | Yes | — | Path to Bicep file (relative to your repo root) |
| `resource_group` | string | Yes | — | Azure resource group name |
| `fail_on_drift` | boolean | No | `false` | Fail the workflow if drift is detected |
| `fail_threshold` | number | No | `0` | Number of drift issues to tolerate (0 = any drift fails) |

### Outputs

After the drift check runs, you can use these outputs:

```yaml
jobs:
  drift-check:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
    # ...

  follow-up:
    runs-on: ubuntu-latest
    needs: drift-check
    steps:
      - name: Check drift results
        run: |
          echo "Total drifts: ${{ needs.drift-check.outputs.total_drifts }}"
          echo "Status: ${{ needs.drift-check.outputs.status }}"
          
          if [ "${{ needs.drift-check.outputs.status }}" = "drift_found" ]; then
            # Do something with drift detected
            echo "Drift detected!"
          fi
```

Available outputs:
- `total_drifts` — Total number of drift issues
- `missing` — Number of missing resources
- `extra` — Number of extra resources
- `status` — Either `success` or `drift_found`

## Examples

### Basic: Check drift on push

```yaml
uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
with:
  bicep_file: infra/main.bicep
  resource_group: my-resource-group
```

### Strict: Fail if any drift detected

```yaml
uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
with:
  bicep_file: infra/main.bicep
  resource_group: my-resource-group
  fail_on_drift: true
```

### Lenient: Allow up to 5 issues

```yaml
uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
with:
  bicep_file: infra/main.bicep
  resource_group: my-resource-group
  fail_on_drift: true
  fail_threshold: 5
```

### Multi-environment: Check multiple RGs

```yaml
jobs:
  drift-dev:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
    with:
      bicep_file: infra/main.bicep
      resource_group: my-rg-dev

  drift-prod:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-reusable.yml@main
    with:
      bicep_file: infra/main.bicep
      resource_group: my-rg-prod
      fail_on_drift: true
```

## How it works

1. Your infrastructure repo triggers the workflow
2. The reusable workflow:
   - Clones this drift-agent repo (source of truth)
   - Checks out your repo
   - Runs Python drift detection
   - Posts results to Slack/Teams if configured
   - Reports status back to your workflow
3. Your workflow can decide what to do based on the results

## Limitations

- Requires Azure Federated Identity credentials set up for your service principal
- Azure auth runs in the drift-agent repo's environment, not yours
- If your Bicep file references modules from your repo, paths must be relative

## Support

For issues with the drift-checking service itself, open issues in `jaxywaxy/bicep-drift-agent`.

For workflow integration questions specific to your repo, see the examples above or customize as needed.
