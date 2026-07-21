# Architecture

## Overview

Bicep Drift Agent is an enterprise drift detection service for Azure environments managed with Bicep. It compares the desired state defined in Infrastructure as Code with the actual state deployed in Azure, identifies drift, enriches findings with governance and ownership context, and routes actionable reports to the teams responsible for remediation.

The solution is designed to support Azure Landing Zone and Cloud Adoption Framework (CAF) operating models, where multiple teams manage infrastructure across subscriptions, landing zones, and repositories.

The service follows a hybrid ownership model:

- A central drift-agent repository owns workflows, drift detection logic, reporting, and orchestration.
- Individual platform or application teams own their Bicep code, drift configuration, notification preferences, and ignore rules.
- The agent operates in read-only mode and performs analysis without modifying Azure resources.

---

## Goals

The solution aims to:

- Detect configuration drift between Bicep and Azure.
- Identify missing and unmanaged resources.
- Detect governance and security drift.
- Classify ownership of findings.
- Route notifications to the correct operational team.
- Support enterprise-scale Azure Landing Zone deployments.
- Operate without storing Azure credentials in GitHub.

---

## High-Level Architecture

```text
┌─────────────────────────────┐
│ Team Bicep Repositories     │
│                             │
│  .github/drift-lz-config.yml│
│  .drift-ignore              │
│  bicep/*.bicep              │
└─────────────┬───────────────┘
              │
              ▼

┌─────────────────────────────┐
│ Bicep Drift Agent           │
│                             │
│  lz-index.yml               │
│  GitHub Actions             │
│  Drift Detection Engine     │
│  Reporting Engine           │
│  Notification Engine        │
└─────────────┬───────────────┘
              │
              ▼

┌─────────────────────────────┐
│ Azure                       │
│                             │
│  Resource Graph             │
│  ARM REST APIs              │
│  Activity Logs              │
│  RBAC APIs                  │
│  Policy Resources           │
└─────────────┬───────────────┘
              │
              ▼

┌─────────────────────────────┐
│ Outputs                     │
│                             │
│  HTML Reports               │
│  JSON Reports               │
│  Slack Notifications        │
│  Teams Notifications        │
│  GitHub Issues              │
└─────────────────────────────┘
```

---

## Core Operating Model

The architecture separates drift detection tooling from infrastructure ownership.

| Responsibility | Owner |
|----------------|-------|
| Detection engine | Platform engineering team |
| GitHub workflows | Platform engineering team |
| Landing zone registration | Platform engineering team |
| Bicep templates | Workload or platform team |
| Drift configuration | Workload or platform team |
| Ignore rules | Workload or platform team |
| Notification routing | Owning team |

This model allows a single drift platform to service multiple teams without centralising ownership of infrastructure definitions.

---

## Azure Authentication Architecture

The service uses GitHub OIDC and Azure Workload Identity Federation for authentication. No Azure client secrets are stored in GitHub.

### Authentication Flow

```text
GitHub Actions Workflow
          │
          ▼
 GitHub OIDC Token
          │
          ▼
Azure Entra ID
(Federated Credential)
          │
          ▼
Service Principal
(Reader Role)
          │
          ▼
Management Group
          │
          ▼
Azure Subscriptions
          │
          ▼
Azure Resource Graph
ARM REST APIs
Activity Logs
```

GitHub issues an OIDC token to the workflow. Azure Entra ID validates the token against a federated credential and exchanges it for an Azure access token. The resulting service principal operates with Reader permissions against the target management group and the subscriptions beneath it.

### Security Characteristics

- No client secret stored in GitHub.
- Short-lived authentication tokens.
- GitHub-to-Azure trust established through federated credentials.
- Reader-only access by default.
- Authentication is auditable through Azure Entra ID.
- New subscriptions under the management group can be covered without per-subscription credential configuration.
- External landing zone config is treated as untrusted input; workflow steps bind it to environment variables rather than interpolating it into shell.
- Reusable workflows receive an explicit least-privilege secret set rather than inheriting all repository secrets.
- GitHub Actions are pinned to commit SHAs and kept current by Dependabot.

---

## Landing Zone Model

A landing zone is represented by a configuration file stored alongside the infrastructure it describes.

```text
Team Repository
│
├── bicep/
├── .drift-ignore
└── .github/
    └── drift-lz-config.yml
```

A central index maintained by the drift service identifies which landing zones should be scanned.

```text
Drift Agent Repository
│
└── .github/
    └── lz-index.yml
```

This enables teams to manage drift scope in the same repository and pull requests used to manage their infrastructure.

---

## Detection Pipeline

The drift detection engine consists of six logical stages.

### 1. Desired State Processing

The agent:

- Compiles Bicep to ARM templates.
- Resolves parameters.
- Expands modules.
- Processes subscription-scoped and resource-group-scoped deployments.

### 2. Live State Collection

The agent gathers live Azure state from:

- Azure Resource Graph
- ARM REST APIs
- Activity Log
- RBAC APIs
- Azure Policy resources

Additional ARM queries are used for resources not fully represented in Resource Graph.

### 3. Normalisation

Resource data is normalised to reduce false positives.

Examples include:

- Resource type casing
- Generated Azure defaults
- Azure-added read-only properties
- Runtime-generated resource names
- Parent-child resource relationships

### 4. Drift Analysis

The comparison engine identifies three drift classes:

| Type | Description |
|------|-------------|
| Property Drift | Resource exists but configuration differs |
| Missing Resource | Defined in Bicep but not present in Azure |
| Extra Resource | Exists in Azure but not defined in Bicep |

Three domains sit outside this template comparison and run as sidecar
comparators, because their objects are not indexed the way ordinary resources
are and cannot be matched by resource name: RBAC role assignments
(`tools/rbac.py`), policy assignments and exemptions (`tools/policy.py`), and
deployment stacks (`tools/deployment_stacks.py`). Each fetches its own live
state, matches on identity, and returns drift in the same shape the main
comparison emits. A failure in any one of them is logged and skipped rather
than failing the scan.

#### Deployment stacks

Deployment stacks are a special case worth understanding before relying on the
result, and the constraints are architectural rather than incidental.

Resource Graph does not index `Microsoft.Resources/deploymentStacks`, so the
stack is read directly from ARM REST.

The stack serves two distinct purposes here. Its `resources[]` list is an
**authoritative ownership record** — everywhere else the engine infers ownership
from the resource-group boundary, which is a proxy and the largest single source
of false extras. Where a stack exists, extras are tagged as stack-managed or
genuinely unmanaged instead of being inferred. Separately, the stack's
`denySettings`, `actionOnUnmanage` and provisioning state describe an
**enforcement posture**.

That second purpose breaks the engine's usual assumption. Every other comparator
diffs Azure against a compiled template; a stack carries no record of what it was
supposed to be, so its desired state is declared in the landing-zone config and
only declared keys are compared. Live values are deliberately never used as a
baseline — a permanently wide-open stack would otherwise validate itself.

Detection is also asymmetric by design. Stale ownership is reported only for
top-level resources and resource groups, and only after a direct lookup confirms
the resource is gone: live-state expansion is partial by type, so absence from
the live set is not proof of deletion, and a fabricated deletion is the worst
finding the engine can emit.

The full limitation set, including what deny assignments do and do not prevent,
is in [CAPABILITIES.md](CAPABILITIES.md#deployment-stack-drift).

### 5. Enrichment

Detected drift is enriched with:

- Ownership classification
- Severity
- Change attribution
- Governance context
- Policy awareness

### 6. Reporting and Notification

Results are transformed into:

- JSON reports
- HTML reports
- GitHub summaries
- Slack notifications
- Teams notifications
- Landing-zone GitHub issues

---

## Ownership Classification

To support Azure Landing Zones, findings are tagged as either platform-owned or workload-owned.

| Owner | Examples |
|-------|----------|
| Platform | VNets, subnets, route tables, network fabric, governance resources |
| Workload | Applications, databases, storage accounts, Key Vaults |
| Mixed | NSG resources are platform-owned while security rules are workload-owned |

This ownership model allows findings to be routed directly to the team capable of remediation.

---

## Governance and Security Analysis

In addition to infrastructure drift, the service evaluates governance and security controls.

### Governance

- RBAC role assignments
- Azure Policy assignments
- Policy exemptions
- Privileged access grants
- Deployment stack enforcement posture and ownership (opt-in)

### Security

- Key Vault access policies
- Network ACLs
- Storage firewalls
- AI safety policies
- Model deployment changes
- Resource lock removal

These controls are evaluated separately from standard configuration drift to improve operational visibility and prioritisation.

---

## Reporting Architecture

The service generates multiple report formats for different audiences.

| Output | Audience |
|--------|----------|
| JSON | Automation and integration |
| HTML | Platform engineers and consultants |
| GitHub Summary | CI/CD users |
| Slack | Operational teams |
| Teams | Operational teams |
| GitHub Issue | Landing-zone owners |

Notification filtering can be based on:

- Drift type
- Ownership
- Notification target
- Landing zone

---

## Scalability Characteristics

The architecture is designed to scale across:

- Multiple subscriptions
- Multiple landing zones
- Multiple repositories
- Multiple operational teams
- Platform and workload environments

Landing zones can be added through configuration rather than platform code changes, allowing new workloads to onboard with minimal effort.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Central orchestration | Consistent operation across teams |
| Team-owned configuration | Keeps drift scope versioned with infrastructure |
| GitHub Actions execution | Native integration with Infrastructure as Code workflows |
| Resource Graph first | Efficient enterprise-scale querying |
| ARM REST augmentation | Covers resources not indexed in Resource Graph |
| Owner-based routing | Sends findings to the correct team |
| OIDC authentication | Eliminates Azure secret management |
| Read-only operation | Safe use in enterprise environments |

---

## Related Documentation

- [README.md](../README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CAPABILITIES.md](CAPABILITIES.md) 
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Teams and Slack Notification configuration
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY_MODEL.md](SECURITY_MODEL.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
