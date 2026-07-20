# Configuration Reference

## Overview

This document defines all supported configuration options for Bicep Drift Agent.

Configuration is split into three areas:

| Configuration | Purpose |
|--------------|---------|
| `lz-index.yml` | Registers landing zones with the central drift-agent platform |
| `drift-lz-config.yml` | Defines what resources are scanned and how findings are reported |
| `.drift-ignore` | Excludes known or accepted drift from reporting |

---

# Configuration Hierarchy

```text
Drift Agent Repository
│
└── .github/
    └── lz-index.yml


Landing Zone Repository
│
├── .github/
│   └── drift-lz-config.yml
│
└── .drift-ignore
```

---

# Landing Zone Index

## File

```text
.github/lz-index.yml
```

## Purpose

The landing zone index is maintained in the drift-agent repository and maps landing zones to their source repositories and configuration files.

Each landing zone registered in the index becomes available for workflow execution.

---

## Schema

```yaml
landing_zones:
  <landing-zone-name>:
    repo: <organisation/repository>
    config_path: <path>
    workflow: <workflow-file>
```

---

## Properties

| Property | Required | Description |
|----------|-----------|-------------|
| `landing_zones` | Yes | Collection of registered landing zones |
| `<landing-zone-name>` | Yes | Logical identifier used by workflows |
| `repo` | Yes | Repository containing landing zone configuration |
| `config_path` | Yes | Path to `drift-lz-config.yml` |
| `workflow` | Yes | Workflow associated with the landing zone |

---

## Example

```yaml
landing_zones:
  platform:
    repo: myorg/platform-bicep
    config_path: .github/drift-lz-config.yml
    workflow: drift-lz-platform.yml

  workload-a:
    repo: myorg/workload-a
    config_path: .github/drift-lz-config.yml
    workflow: drift-lz-workload-a.yml
```

---

# Landing Zone Configuration

## File

```text
.github/drift-lz-config.yml
```

## Purpose

Defines:

- Scan targets
- Subscription scope
- Resource group scope
- Notification routing
- Repository locations
- Ownership configuration

---

# Root Schema

```yaml
name: platform

subscription_id: "00000000-0000-0000-0000-000000000000"

notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"

checks:
  - name: Platform Connectivity
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    subscription_scoped: true
    resource_groups:
      - "*"
```

---

## Root Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Friendly landing zone name |
| `subscription_id` | Recommended | Azure subscription ID being scanned |
| `notifications` | No | Notification destinations and routing rules |
| `checks` | Yes | List of Bicep scans to perform |

---

# Checks

Checks define the infrastructure that should be evaluated.

---

## Schema

```yaml
checks:
  - name: Platform Connectivity
    repo: myorg/platform-bicep
    branch: main
    path: bicep/main.bicep
    subscription_scoped: true
    resource_groups:
      - "*"
```

---

## Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Friendly display name |
| `repo` | Yes | Repository containing Bicep |
| `branch` | No | Branch to scan. Default: `main` |
| `path` | Yes | Path to the Bicep file |
| `subscription_scoped` | No | Indicates the Bicep deploys at subscription scope |
| `resource_groups` | Yes | List of resource groups or selectors |

---

# Resource Group Selectors

Resource groups may be specified using:

---

## Explicit Resource Groups

```yaml
resource_groups:
  - rg-platform
  - rg-management
```

---

## Wildcard

```yaml
resource_groups:
  - "*"
```

All resource groups within the subscription.

---

## Pattern Matching

```yaml
resource_groups:
  - rg-platform-*
```

Matches all resource groups that satisfy the pattern.

---

## Mixed Configuration

```yaml
resource_groups:
  - rg-connectivity
  - rg-platform-*
  - "*"
```

---

# Subscription Scanned Landing Zones

Use when a single Bicep deployment represents the complete landing zone.

```yaml
checks:
  - name: Platform Landing Zone
    subscription_scoped: true
    resource_groups:
      - "*"
```

Recommended for:

- Azure Landing Zones
- Platform subscriptions
- Connectivity subscriptions
- Management subscriptions

---

# Resource Group Scanned Landing Zones

Use when a deployment targets specific resource groups.

```yaml
checks:
  - name: Application Layer
    resource_groups:
      - rg-app-prod
      - rg-app-dr
```

Recommended for:

- Applications
- Shared services
- Isolated workloads

---

# Notifications

Notifications control where findings are delivered.

---

## Basic Example

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
```

---

## Multiple Teams

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"

  app-team:
    slack: "${DRIFT_WEBHOOK_APP}"
```

---

## Owner Routing

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
    owners:
      - platform

  workload-team:
    slack: "${DRIFT_WEBHOOK_WORKLOAD}"
    owners:
      - workload
```

---

## Filtering Drift Types

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
    filter: drift
```

---

## Notification Properties

| Property | Required | Description |
|----------|----------|-------------|
| `teams` | No | Teams webhook URL or secret reference |
| `slack` | No | Slack webhook URL or secret reference |
| `owners` | No | Filter by ownership category |
| `filter` | No | Filter by drift type |
| `template` | No | Custom notification template |

At least one notification target should be supplied.

---

# Ownership Filters

Supported ownership types:

```yaml
owners:
  - platform
```

```yaml
owners:
  - workload
```

```yaml
owners:
  - platform
  - workload
```

---

# Drift Type Filters

Supported values:

```yaml
filter: all
```

```yaml
filter: drift
```

```yaml
filter: extra
```

```yaml
filter: missing
```

```yaml
filter: drift,extra
```

```yaml
filter: extra,missing
```

---

# Secret-Backed Webhooks

Recommended:

```yaml
teams: "${DRIFT_WEBHOOK_PLATFORM}"
```

Avoid:

```yaml
teams: https://outlook.webhook.office.com/...
```

Webhook URLs should be stored as GitHub Secrets.

---

# Ignore Rules

## File

```text
.drift-ignore
```

## Purpose

Suppresses known or accepted drift.

---

## Schema

```yaml
ignore:
  - resource_type: "Microsoft.Network/networkWatchers"
    reason: "Azure managed"

  - resource_type: "Microsoft.KeyVault/vaults"
    property: "properties.networkAcls"
    reason: "Managed externally"
```

---

## Properties

| Property | Required | Description |
|----------|----------|-------------|
| `resource_type` | Yes | Azure resource type |
| `property` | No | Specific property to ignore |
| `name_pattern` | No | Resource name pattern |
| `reason` | Recommended | Why the ignore exists |

---

# Environment Variables

The following environment variables are recognised.

| Variable | Purpose |
|-----------|---------|
| `ARM_PARAMETERS` | Override parameter values |
| `INCLUDE_ROLE_ASSIGNMENTS` | Enable RBAC drift detection |
| `INCLUDE_POLICY_ASSIGNMENTS` | Enable policy drift detection |
| `ANTHROPIC_API_KEY` | Optional AI analysis |
| `DRIFT_AUTHORIZED_DEPLOYERS` | Additional deployer identities (see below) |

## Authorized Deployers

Changes made by a known IaC deployer identity are attributed as
**authorized deployments** in reports (🚀 Pipeline badge, low severity)
rather than "manual change (out-of-band)". The drift itself stays in the
actionable set — only the attribution changes.

The identity the drift agent **runs as is always recognised automatically**
(read from its own access-token claims at scan time). No configuration is
needed when the agent scans with the same identity that deploys the estate.

Set `DRIFT_AUTHORIZED_DEPLOYERS` only when an estate is deployed by a
*different* identity than the one that scans it.

**Recommended: repository variable.** The bundled workflows already pass the
repository variable `DRIFT_AUTHORIZED_DEPLOYERS` into the scan job — no
workflow edits needed:

```bash
# Comma-separated. Accepts object IDs, appIds or UPNs - whatever form
# the Activity Log 'caller' field takes for that identity (object ID
# for service principals, email for users).
gh variable set DRIFT_AUTHORIZED_DEPLOYERS \
  --body "aaaaaaaa-1111-2222-3333-444444444444,deployer@example.com"
```

(Or in the GitHub UI: **Settings → Secrets and variables → Actions →
Variables**.) It is a variable, not a secret: identity object IDs are not
sensitive, and keeping them visible aids review.

**Custom pipelines:** if you run the tool outside the bundled workflows, set
the same value as an environment variable on the analyze step:

```yaml
env:
  DRIFT_AUTHORIZED_DEPLOYERS: "aaaaaaaa-1111-2222-3333-444444444444,deployer@example.com"
```

Notes:

- Azure Policy managed identities always classify as policy-enforced,
  even if listed here.
- Listing an identity does not suppress its drift; it only stops the
  change-origin column labelling the pipeline's own deploys as
  out-of-band manual changes.

---

# GitHub Secrets

## Required

| Secret | Purpose |
|----------|----------|
| `AZURE_CLIENT_ID` | OIDC application identifier |
| `AZURE_TENANT_ID` | Azure tenant identifier |

---

## Optional

| Secret | Purpose |
|----------|----------|
| `BICEP_REPO_TOKEN` | PAT for cross-repo access: checkout of private LZ/bicep repos + publishing drift issues to LZ repos (needs `issues: write` there). Falls back to `github.token` (same-repo only) |
| `DRIFT_WEBHOOK_*` | Slack/Teams notifications |
| `ANTHROPIC_API_KEY` | AI-generated recommendations |

---

# Recommended Platform Configuration

```yaml
name: platform

subscription_id: "00000000-0000-0000-0000-000000000000"

notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
    owners:
      - platform

checks:
  - name: Platform Landing Zone
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    subscription_scoped: true
    resource_groups:
      - "*"
```

---

# Recommended Workload Configuration

```yaml
name: workload-a

notifications:
  app-team:
    teams: "${DRIFT_WEBHOOK_APP}"

checks:
  - name: Application Resources
    repo: myorg/workload-a
    path: bicep/main.bicep
    resource_groups:
      - rg-app-prod
      - rg-app-dr
```

---

# Related Documentation

- [README.md](../README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CAPABILITIES.md](CAPABILITIES.md) 
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Teams and Slack Notification configuration
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY_MODEL.md](SECURITY_MODEL.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
