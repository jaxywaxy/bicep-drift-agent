# Security Model

## Overview

Bicep Drift Agent is designed to operate in enterprise Azure environments using a security-first approach. The platform performs read-only drift analysis across Azure subscriptions and landing zones without requiring long-lived credentials, privileged access, or stored secrets.

The solution uses GitHub OpenID Connect (OIDC) and Azure Workload Identity Federation to authenticate GitHub Actions workflows directly with Azure Entra ID, eliminating the need for Azure client secrets in GitHub repositories. Authentication is short-lived, auditable, and scoped according to the principle of least privilege. 

---

# Security Principles

The security model is built around the following principles:

| Principle | Implementation |
|------------|---------------|
| Least Privilege | Reader access only by default |
| Secretless Authentication | GitHub OIDC with Azure Workload Identity Federation |
| Separation of Duties | Platform owns detection tooling while teams own infrastructure |
| Read-Only Operation | No deployment or remediation actions performed |
| Auditability | Authentication events recorded in Azure Entra ID |
| Defence in Depth | GitHub, Azure Entra ID and Azure RBAC all participate in authorisation |
| Team Isolation | Landing zones maintain independent configuration and notification settings |

---

# Authentication Model

## Architecture

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

Authentication is performed using GitHub-issued OIDC tokens rather than static credentials. When a workflow executes, GitHub issues a signed identity token which Azure Entra ID validates against a federated credential. Azure then exchanges the GitHub token for a short-lived Azure access token used by the drift agent. 

### Benefits

- No Azure client secret stored in GitHub.
- No credential rotation requirements.
- Short-lived authentication tokens.
- Full Azure Entra ID audit trail.
- Reduced credential theft risk.
- Centralised management through Azure Entra ID. 

---

# Azure Permissions Model

## Default Access Level

The recommended deployment model grants the service principal:

```text
Reader
```

at the Azure Management Group scope. 

This provides visibility into:

- Azure Resource Graph
- Resource metadata
- Activity Log entries
- Resource configurations
- Governance resources
- Landing zone subscriptions

while preventing:

- Resource creation
- Resource deletion
- Resource modification
- Role assignment changes
- Policy administration changes

### Why Management Group Scope?

Using management-group scope allows:

- Automatic onboarding of new subscriptions.
- Consistent visibility across landing zones.
- Reduced administrative overhead.
- Centralised security management.

The agent remains read-only regardless of subscription count. 

---

# Identity and Trust Boundary

The platform establishes trust between:

```text
GitHub
    ↓
Azure Entra ID
    ↓
Azure Management Group
```

Each layer independently validates access.

## GitHub

Controls:

- Repository access
- Workflow execution
- Branch protection
- Workflow permissions
- OIDC token issuance

## Azure Entra ID

Controls:

- Federated credential validation
- Token exchange
- Application identity lifecycle
- Authentication auditing

## Azure RBAC

Controls:

- Authorisation scope
- Resource visibility
- Management group inheritance
- Least privilege enforcement

A compromise of any single layer does not automatically grant unrestricted access to Azure resources.

---

# Secret Management

## Azure Credentials

No Azure passwords, client secrets, certificates, or access keys are required. The platform uses:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
```

These are identifiers rather than secrets and are used to locate the federated application registration. Authentication occurs through OIDC token exchange rather than stored credentials. 

## Notification Webhooks

Notification webhooks should be stored as GitHub Actions secrets rather than committed to source control.

Recommended pattern:

```yaml
notifications:
  platform-team:
    teams: "${DRIFT_WEBHOOK_PLATFORM}"
```

Only webhook placeholders prefixed with:

```text
DRIFT_WEBHOOK_
```

should be expandable by the platform. This prevents accidental exposure of unrelated CI/CD secrets through landing zone configuration files.

---

# Data Access Model

## Azure Data Collected

The platform collects configuration and metadata required for drift analysis, including:

- Resource definitions
- Resource properties
- Resource relationships
- Azure Policy assignments
- RBAC assignments
- Activity Log entries
- Deployment metadata

The platform does not modify resources and does not perform remediation actions.

## Write Operations

The drift detection engine does not:

- Deploy infrastructure
- Update resources
- Change resource settings
- Create role assignments
- Modify Azure Policy
- Delete resources

The solution operates as an observer rather than an administrator.

---

# Notification and Report Security

## Report Distribution

Findings may be published to:

- GitHub workflow summaries
- HTML reports
- JSON reports
- Slack channels
- Microsoft Teams channels
- Landing-zone GitHub issues

Access to reports should follow existing team access controls.

## Landing Zone Visibility

Landing-zone teams should receive findings through channels and repositories they already have permission to access.

This avoids granting broad access to the central drift-agent repository while still enabling visibility into drift findings.

---

# Governance and Compliance

## RBAC Drift Detection

The platform can identify:

- Out-of-band role assignments
- Privileged role grants
- Unmanaged access changes

Examples include:

- Owner
- Contributor
- User Access Administrator
- Role Based Access Control Administrator

These findings provide visibility into governance changes while maintaining read-only operation.

## Policy Monitoring

The platform can detect:

- Policy assignments
- Policy exemptions
- Governance exceptions
- Drift introduced through unmanaged policy changes

This allows governance teams to monitor configuration compliance without requiring elevated privileges.

---

# Auditability

The authentication flow provides end-to-end auditing.

Authentication events can be traced through:

- GitHub workflow execution history
- GitHub OIDC token issuance
- Azure Entra ID sign-in logs
- Azure Entra ID application audit logs
- Azure Activity Logs

This enables security and operations teams to determine:

- Which workflow accessed Azure
- Which repository initiated access
- Which branch executed the workflow
- When access occurred

without relying on shared credentials. 

---

# Threat Mitigations

| Risk | Mitigation |
|--------|------------|
| Credential Theft | No Azure secrets stored in GitHub |
| Secret Expiry | OIDC token exchange removes credential rotation requirements |
| Excessive Azure Permissions | Reader-only RBAC model |
| Subscription Sprawl | Management-group scoped visibility |
| Unauthorised Resource Changes | Service operates read-only |
| Secret Leakage in Config | Restricted webhook placeholder expansion |
| Limited Audit Evidence | Azure Entra ID authentication logging |
| Notification Exposure | Team-level routing and repository-based report publication |

---

# Security Considerations

Before deployment:

- Review required Azure permissions.
- Confirm management group scope is appropriate.
- Configure GitHub branch protection.
- Restrict GitHub Actions workflow modification permissions.
- Store notification endpoints in GitHub Secrets.
- Review landing zone access controls.

Regular reviews should validate:

- Service principal permissions.
- Federated credential configuration.
- Notification webhook ownership.
- Landing zone onboarding processes.
- Audit and governance requirements.

---

# Security Summary

Bicep Drift Agent is designed as a low-risk, read-only service for enterprise Azure governance and operational visibility. By combining GitHub OIDC, Azure Workload Identity Federation, Reader-only RBAC permissions, and team-owned landing zone configuration, the service minimises credential risk while providing enterprise-scale drift detection across Azure Landing Zones and Bicep-managed environments.
