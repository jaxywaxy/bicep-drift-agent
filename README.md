# Bicep Drift Agent

Enterprise drift detection for Azure environments managed with Bicep.

Bicep Drift Agent continuously compares the desired state defined in Bicep with the actual state deployed in Azure, helping platform and application teams detect configuration drift, governance issues, unmanaged resources, and security-sensitive changes before they become operational problems.

---

## Why it exists

Infrastructure drift is inevitable.

Manual changes, emergency fixes, policy remediation, access changes, and unmanaged deployments can all cause Azure resources to diverge from Infrastructure as Code.

The Bicep Drift Agent provides a repeatable, enterprise-friendly way to:

- Detect configuration drift
- Identify unmanaged resources
- Detect missing deployments
- Highlight security and governance changes
- Route findings to the correct team
- Generate actionable reports

---

## What it detects

### Resource Drift

Configuration differences between Azure and Bicep.

Examples:

- SKU changes
- Network configuration changes
- Firewall rule changes
- Diagnostic setting drift
- Resource lock removal

### Missing Resources

Resources defined in Bicep but not deployed in Azure.

### Unmanaged Resources

Resources deployed in Azure that do not exist in Bicep.

### Governance Drift

Changes to:

- RBAC assignments
- Azure Policy assignments
- Policy exemptions

### Security-Sensitive Drift

Changes affecting:

- Key Vault access
- Storage firewalls
- AI model deployments
- Network boundaries
- Privileged access assignments

See docs/CAPABILITIES.md for full coverage details.

---

## How it works

The agent compares desired state from Bicep with live state from Azure.

```text
Bicep Templates
        │
        ▼
Compile & Resolve
        │
        ▼
Desired State Model
        │
        ├──────────────┐
        │              │
        ▼              ▼
 Azure Resource Graph + ARM REST
        │
        ▼
 Actual State Model
        │
        ▼
 Drift Analysis
        │
        ▼
 Classification & Attribution
        │
        ▼
 Reports & Notifications
```

The workflow is:

1. Compile Bicep to ARM JSON
2. Resolve parameters and modules
3. Query live Azure state
4. Compare desired and actual state
5. Classify drift findings
6. Generate reports
7. Notify owning teams

---

## Enterprise Operating Model

The solution uses a hybrid ownership model.

The central drift-agent repository owns:

- Detection logic
- Workflows
- Reporting
- Notification framework

Each landing-zone team owns:

- Bicep code
- Drift configuration
- Ignore rules
- Notification preferences

```text
drift-agent repository
│
├── .github/lz-index.yml
└── GitHub Actions

team Bicep repository
│
├── .github/drift-lz-config.yml
├── .drift-ignore
└── bicep/
```

This allows teams to manage their own drift scope while using a centrally managed detection platform.

See docs/LANDING_ZONE_OPERATIONS.md.

---

## Key Features

✅ Multi-team, multi-repository operation

✅ Azure Landing Zone aligned

✅ Subscription-scoped or resource-group-scoped scanning

✅ Property-level drift detection

✅ Runtime-generated resource name matching

✅ Platform vs workload ownership routing

✅ Azure Policy awareness

✅ RBAC and policy assignment drift detection

✅ Slack and Teams notifications

✅ HTML and JSON reporting

✅ GitHub OIDC authentication

✅ No Azure credentials stored in GitHub

---

## Quick Start

### Prerequisites

- Azure environment managed with Bicep
- GitHub repository
- GitHub Actions enabled
- Azure Workload Identity Federation configured

See:

- docs/AZURE_AUTHENTICATION.md

### 1. Register a landing zone

Add an entry to:

```yaml
.github/lz-index.yml
```

Example:

```yaml
landing_zones:
  platform:
    repo: myorg/platform-bicep
    config_path: .github/drift-lz-config.yml
    workflow: drift-lz-platform.yml
```

### 2. Create landing-zone configuration

In the target Bicep repository:

```yaml
name: platform

checks:
  - name: Platform Connectivity
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    subscription_scoped: true
    resource_groups:
      - "*"
```

### 3. Configure notifications

Example:

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
    owners:
      - platform
```

See [docs/TEAM_NOTIFICATIONS.md](docs/TEAM_NOTIFICATIONS.md).

### 4. Run a scan

```bash
gh workflow run drift-lz-platform.yml
```

---

## Documentation

| Document | Purpose |
|-----------|----------|
| `docs/ARCHITECTURE.md` | Solution architecture and design decisions |
| `docs/CAPABILITIES.md` | Supported drift detection capabilities |
| `docs/LANDING_ZONE_OPERATIONS.md` | Landing-zone onboarding and operations |
| `docs/CONFIG_REFERENCE.md` | Configuration schema and examples |
| `docs/TEAM_NOTIFICATIONS.md` | Notification routing and templates |
| `docs/AZURE_AUTHENTICATION.md` | GitHub OIDC and Azure setup |
| `docs/SECURITY_MODEL.md` | Security architecture and permissions |
| `docs/OPERATIONS_RUNBOOK.md` | Operational procedures and troubleshooting |

---

## Current Limitations

- Runtime-generated resource names require smart matching.
- Some complex ARM expressions cannot be fully resolved.
- Change attribution depends on available Azure activity data.
- Detection accuracy depends on the quality and completeness of Bicep definitions.

See individual documentation pages for detailed limitations.

---

## Roadmap

- Drift remediation recommendations
- Pull request annotations
- Terraform support
- Historical drift trending
- Governance dashboards

---

## Built With

- Python
- Azure Resource Graph
- Azure SDK
- Bicep
- GitHub Actions
- Azure Workload Identity Federation
- Anthropic Claude (optional report enrichment)
