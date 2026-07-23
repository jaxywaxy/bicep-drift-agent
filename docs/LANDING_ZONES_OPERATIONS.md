# Landing Zone Operations Guide

## Overview

Bicep Drift Agent is designed to operate across multiple Azure Landing Zones, subscriptions, repositories, and teams using a centralised orchestration model.

Rather than embedding drift detection logic into each application or platform repository, a central drift-agent repository manages orchestration, scheduling, execution, reporting, and notifications. Individual teams maintain ownership of their Bicep code, drift configuration, and notification preferences.

This operating model aligns with Azure Landing Zones and the Cloud Adoption Framework (CAF), enabling scalable drift detection across enterprise Azure environments.

---

# Operating Model

## Shared Responsibility Model

| Responsibility | Owner |
|----------------|-------|
| Drift detection platform | Platform engineering team |
| Workflow orchestration | Platform engineering team |
| Landing zone registration | Platform engineering team |
| Bicep templates | Landing zone owner |
| Drift configuration | Landing zone owner |
| Ignore rules | Landing zone owner |
| Notification routing | Landing zone owner |
| Drift remediation | Resource owner |

This approach allows a single drift detection platform to service many teams while keeping infrastructure ownership close to the teams responsible for deployment and support.

---

# Architecture

```text
Drift Agent Repository
│
├── .github/
│   ├── lz-index.yml
│   └── workflows/
│
└── Detection Engine


Landing Zone Repository
│
├── bicep/
├── .drift-ignore
└── .github/
    └── drift-lz-config.yml
```

The drift-agent repository maintains a catalogue of landing zones and orchestrates all drift detection activities.

Landing zone repositories contain the infrastructure definitions and configuration that determine what should be scanned.

---

# Landing Zone Registration

Each landing zone is registered in the central index.

## Example

```yaml
landing_zones:
  platform:
    repo: myorg/platform-bicep
    config_path: .github/drift-lz-config.yml
    workflow: drift-lz-platform.yml

  data:
    repo: myorg/data-platform
    config_path: .github/drift-lz-config.yml
    workflow: drift-lz-data.yml
```

The index provides:

- Repository location
- Configuration location
- Workflow association

Adding a landing zone does not require code changes to the detection engine.

---

# Landing Zone Configuration

Each landing zone owns a configuration file stored within its repository.

Location:

```text
.github/drift-lz-config.yml
```

## Example

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

The configuration defines:

- What should be scanned
- Which repository contains the Bicep
- Which Azure scope is evaluated
- How findings are reported
- Who receives notifications

---

# Onboarding a Landing Zone

## Step 1 – Configure Azure Authentication

Configure GitHub OIDC and Azure Workload Identity Federation.

See:

```text
AZURE_AUTHENTICATION.md
```

## Step 2 – Register the Landing Zone

Add an entry to:

```text
.github/lz-index.yml
```

## Step 3 – Create Landing Zone Configuration

Add:

```text
.github/drift-lz-config.yml
```

to the landing zone repository.

## Step 4 – Configure Notifications

Configure:

- Slack
- Teams
- Owner routing
- Event filtering

See:

```text
TEAM_NOTIFICATIONS.md
```

## Step 5 – Execute Validation

Run the workflow manually:

```bash
gh workflow run drift-lz-platform.yml
```

Confirm:

- Azure authentication succeeds
- Bicep is discovered
- Drift analysis completes
- Notifications are delivered

## Step 6 – Enable Scheduling

Add an appropriate schedule for the landing zone.

---

# Scan Models

The platform supports two scanning patterns.

## Resource Group Scoped

Use when a template represents infrastructure deployed into one or more specific resource groups.

```yaml
checks:
  - name: Application Services
    path: bicep/main.bicep
    resource_groups:
      - rg-app-prod
      - rg-app-dr
```

Each resource group is evaluated independently.

### Suitable For

- Application workloads
- Shared services deployed per-resource-group
- Smaller environments

---

## Subscription Scoped

Use when a template represents an entire landing zone.

```yaml
checks:
  - name: Platform Landing Zone
    subscription_scoped: true
    resource_groups:
      - "*"
```

The template is compared against the entire landing zone in a single pass.

### Suitable For

- Azure Landing Zones
- CAF-aligned environments
- Platform subscriptions
- Enterprise networking deployments

---

# Resource Group Selectors

The platform supports flexible resource-group targeting.

## Explicit Resource Groups

```yaml
resource_groups:
  - rg-platform
  - rg-management
```

## Wildcard

```yaml
resource_groups:
  - "*"
```

Scans all resource groups in the subscription.

## Pattern Matching

```yaml
resource_groups:
  - rg-platform-*
```

Expands dynamically to matching resource groups.

---

# Platform vs Workload ownership

The platform classifies findings to support operational rou*ing.

## Platform-Owned Resources
Examples:

- Virtual Networks
- Subnets
- Route Tables
- Network Security Groups
- NAT Gateways
- Firewall Policies (and their rule collection groups)
- Load Balancers / Application Gateways (+ WAF policies), Front Door
- Public IP Addresses
- Management infrastructure
- Governance resources

## Workload-Owned Resource*

Examples:

- Applications
- Databases
- Storage Accounts
- Key Vaults
- AI Services
- Private Endpoints

## Special Cases

| Resource | Owner |
|-----------|--------|
| NSG Resource | Platform |
| NSG Security Rules | Workload |
| Firewall Policy | Platform |
| Firewall Rule Collection Groups | Platform |
| Subscription RBAC | Platform |
| Resource RBAC | Resource Owner |

> Note the asymmetry: NSG *security rules* are workload-owned (app teams manage
> their own micro-segmentation), but a firewall policy's *rule collection groups*
> stay platform-owned — a central firewall's egress rules are platform-managed
> fabric, so the child follows its parent policy rather than flipping to workload.

Ownership classification allows notifications to be routed directly to the team responsible for remediation.

---

# Ignore Profiles

Expected drift can be excluded using:

```text
.drift-ignore
```

located within the landing zone repository.

Common examples include:

- Azure-managed resources
- Auto-created service components
- Known platform-generated objects
- Organisation-specific exceptions

Ignore profiles are merged with the platform baseline to minimise false positives.

---

# Notification Routing

Notifications can be delivered through:

- Slack
- Microsoft Teams
- GitHub Issues

Notifications support:

- Drift-type filterin*
- Owner-based routing
- Team-specific channels
- Custom message templates

Example:

```yaml
notifications:
  platform-team:
    teams: "$DRIFT_WEBHOOK_PLATFORM}"
    owners:
      - platform

  app-team:
    slack: "${DRIFT_WEBHOOK_APPLICATION}"
    owners:
      - workload
`*`

---

# Operational Procedures

## Add a New Landing Zone

1. Register the repository in `lz-index.yml.
2. Create `drift-lz-config.yml`.
3. Configure notification targets.
4. Execute a manual validation scan.
5. Enable scheduling.

---

## Update Landing Zone Scope

Modify:

``yaml
checks:
```

within the landing zone configuration.

Changes should be committed alongside infrastructure updates whenever possible.
---

## Update Notification Routing

Modify:

```yaml
notifications:```

within the landing zone configuration.

Changes take effect during the next scan.

---

## Retire a Landing Zone

1. Remove the landing zone from `lz-index.yml`.
2. Disable associated workflows.
3. Archive historical reports if required.
4. Remove notification routing.

----
# Scheduling Recommendations

To avoid high concurrency and Azure API contention, stagger landing zone schedules.

## Recommended Pattern
| Landing Zone | Schedule |
|--------------|----------|
| Platform | )3:00 UTC |
| Shared Services | 06:00 UTC |
| Applications | 09:00 UTC|
| Data Platforms | 12:00 UTC |

Large environments should avoid scheduling all landing zones simultaneously.

---

# Troubleshooting

## Landing Zone Not Found

Verify:

``yaml
landing_zones:
```

contains the expected entry in:

```text
.github/lz-index.yml
```

---

## Configuration File Not Found

Verify:

``text
.github/drift-lz-config.yml```

exists in the target reposito*y.

---

## Authentication Failure*
Review:

```text
AZURE_AUTHENTICA*ION.md
```

Verify:

- Federated credential configuration
- GitHub OIDC permissions
- Service principal access
- Azure Management Group sco*e

---

## Notifications Not Deliv*red

Verify:

- Webhook secrets exist
- Secret names match configurat*on
- Team channels remain valid
- notification filtering rules are co*rect

See:

```text
TEAM_NOTIFICATIONS.md
```

---

# Best Practices
✅ Keep drift configuration in the same repository as the Bicep being validated.

✅ Use subscription-scoped scans for Azure Landing Zones.

✅ Route findings to owning teams us*ng ownership classification.

✅ Store notification endpoints as GitHub Secrets.

✅ Review ignore patterns regularly.

✅ Use GitHub OIDC rather than Azure client secrets.

✅ Validate manually before enabling schedules.

✅ Align landing zones with existing Azure governance boundar*es.

---

# Related Documentation

- [README.md](../README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CAPABILITIES.md](CAPABILITIES.md) 
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Teams and Slack Notification configuration
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY.md](SECURITY.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
