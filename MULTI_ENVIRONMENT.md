# Multi-Environment Drift Checking

Check drift across multiple Azure resource groups in a single workflow run.

## Quick Start

The `drift-check-multi-env` workflow checks multiple environments in parallel. By default, it checks:
- `rg-dev`
- `rg-prod`

Each environment is checked independently and generates its own report.

## Manual Trigger with Custom Environments

Go to **Actions** → **Bicep Drift Check - Multi-Environment** → **Run workflow** and provide:

```json
[
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-dev"},
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-staging"},
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-prod"}
]
```

Each object requires:
- `bicep_file` — Path to the Bicep template
- `resource_group` — Azure resource group name

## How It Works

1. **Parse environments** — Reads the environment list (default or from input)
2. **Parallel execution** — Runs drift checks in parallel (up to 3 at a time)
3. **Per-environment reports** — Each RG gets its own:
   - HTML report
   - JSON data
   - Recommendations
4. **Summary** — Workflow summary shows all checked environments

## Examples

### Example 1: Check dev, staging, and prod

**Manual trigger input:**
```json
[
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-dev"},
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-staging"},
  {"bicep_file": "./infra/main.bicep", "resource_group": "rg-prod"}
]
```

### Example 2: Different Bicep files per environment

```json
[
  {"bicep_file": "./infra/dev.bicep", "resource_group": "rg-dev"},
  {"bicep_file": "./infra/prod.bicep", "resource_group": "rg-prod"}
]
```

### Example 3: Multiple resource groups from same template

```json
[
  {"bicep_file": "./infra/shared.bicep", "resource_group": "rg-shared-dev"},
  {"bicep_file": "./infra/shared.bicep", "resource_group": "rg-shared-prod"},
  {"bicep_file": "./infra/compute.bicep", "resource_group": "rg-compute-dev"},
  {"bicep_file": "./infra/compute.bicep", "resource_group": "rg-compute-prod"}
]
```

## Viewing Results

After the workflow completes:

1. **Workflow Summary** — High-level overview of all checked environments
2. **Artifacts** — Download individual reports:
   - `drift-reports-rg-dev`
   - `drift-reports-rg-staging`
   - `drift-reports-rg-prod`
   - etc.

Each artifact contains:
- `{resource_group}-drift.html` — Beautiful HTML report
- `{resource_group}-drift.json` — Raw drift data
- `{resource_group}-analysis.md` — Claude's analysis

## Using in Infrastructure Repos

Infrastructure repos can use the matrix workflow via the reusable workflow. Example:

```yaml
# .github/workflows/drift-check.yml in your infrastructure repo
name: Drift Check

on:
  push:
    paths:
      - 'bicep/**/*.bicep'
  workflow_dispatch:

jobs:
  multi-env-drift:
    uses: jaxywaxy/bicep-drift-agent/.github/workflows/drift-check-multi-env.yml@main
    with:
      environments: |
        [
          {"bicep_file": "./bicep/main.bicep", "resource_group": "rg-dev"},
          {"bicep_file": "./bicep/main.bicep", "resource_group": "rg-prod"}
        ]
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.DRIFT_CHECK_ANTHROPIC_API_KEY }}
      AZURE_CLIENT_ID: ${{ secrets.DRIFT_CHECK_AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: ${{ secrets.DRIFT_CHECK_AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.DRIFT_CHECK_AZURE_SUBSCRIPTION_ID }}
```

## Parallelization

The workflow runs up to **3 environments in parallel** by default. This:
- ⚡ Reduces total execution time
- 🔒 Stays within Azure API rate limits
- 📊 Keeps logs readable

To change the max parallel jobs, edit `max-parallel` in the workflow YAML.

## Limitations

- Each environment uses the same secrets (ANTHROPIC_API_KEY, Azure credentials)
- Different subscriptions require separate credential sets (use different secrets)
- Large numbers of environments (>10) may need API throttling adjustments

## Troubleshooting

**Workflow doesn't appear in Actions menu:**
- Ensure the workflow file is on `main` or `develop` branch
- GitHub caches workflows; wait a few minutes

**JSON parse error:**
- Validate JSON at [jsonlint.com](https://jsonlint.com)
- Ensure bicep_file and resource_group keys are present

**Some environments pass, some fail:**
- Check the individual artifact reports for each failing RG
- Drift isn't fatal by default (fail_on_drift: false) — review reports to decide on remediation
