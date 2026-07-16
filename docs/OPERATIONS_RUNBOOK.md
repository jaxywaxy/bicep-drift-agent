# Operations Runbook

## Overview

This runbook provides operational guidance for running, monitoring, and responding to Bicep Drift Agent scans across Azure landing zones.

It is intended for platform engineers, consultants, and landing-zone owners who need to operate the drift detection process, triage findings, resolve common issues, and support teams using the service.

Bicep Drift Agent compares Bicep-defined desired state with live Azure state, identifies drift, classifies findings, generates reports, and routes notifications to the appropriate team.

---

## Operating Principles

| Principle | Description |
|----------|-------------|
| Read-only operation | The agent detects drift but does not modify Azure resources. |
| Team-owned scope | Landing-zone teams own their Bicep code, drift configuration, ignore rules, and notification preferences. |
| Central orchestration | The drift-agent repository owns shared workflows, detection logic, reporting, and scheduling. |
| Secure authentication | Azure access uses GitHub OIDC and Azure Workload Identity Federation. |
| Owner-based routing | Findings should be routed to the team responsible for remediation. |
| Evidence-based triage | Review report evidence before deciding whether to remediate, ignore, or escalate. |

---

## Routine Operations

### Daily or Scheduled Checks

For scheduled runs, review:

- GitHub Actions workflow status
- Generated drift reports
- Slack or Teams notifications
- Landing-zone GitHub issues, if enabled
- Repeated or unresolved findings

### Manual Checks

Run a landing-zone scan manually when:

- A new landing zone is onboarded
- Bicep configuration changes significantly
- Drift is suspected
- A notification or report needs validation
- A previously failed scan has been corrected

Example:

```bash
gh workflow run drift-lz-platform.yml
```

---

## Standard Triage Workflow

Use this triage process for any drift finding.

```text
Drift notification received
        |
        v
Open report or landing-zone issue
        |
        v
Identify finding type
        |
        +--> DRIFT
        |       |
        |       v
        |   Check property difference and owner
        |
        +--> EXTRA
        |       |
        |       v
        |   Confirm whether resource is unmanaged or expected
        |
        +--> MISSING
                |
                v
            Confirm whether deployment failed or Bicep is stale
```

Then decide one of the following outcomes:

| Outcome | When to use |
|---------|-------------|
| Remediate Azure | Azure has changed out-of-band and should be returned to Bicep-defined state. |
| Update Bicep | Azure reflects the intended state and Bicep should be updated. |
| Add ignore rule | Drift is expected, documented, and not actionable. |
| Escalate | The finding indicates security, governance, access, or ownership risk. |
| Close as no action | The finding is informational or already resolved. |

---

## Responding to Finding Types

## DRIFT Findings

A `DRIFT` finding means the resource exists in Azure, but one or more properties differ from the Bicep-defined desired state.

### Triage Steps

1. Open the HTML or JSON report.
2. Identify the changed property or properties.
3. Confirm the owning team.
4. Check whether the change was expected.
5. Review change attribution, if available.
6. Decide whether to update Azure, update Bicep, or add an ignore rule.

### Common Causes

- Manual change in the Azure portal
- Emergency operational fix
- Azure Policy remediation
- Deployment parameter mismatch
- Bicep template not updated after an approved change
- Resource provider default value change

### Recommended Actions

| Scenario | Recommended action |
|----------|-------------------|
| Azure was changed manually and Bicep remains correct | Revert Azure to match Bicep. |
| Azure reflects the approved new state | Update Bicep and parameters. |
| Drift was caused by Azure Policy | Confirm whether it is expected governance behaviour. |
| Drift is known and intentionally unmanaged | Document and add a scoped ignore rule. |
| Drift weakens security controls | Escalate to the platform or security owner. |

---

## EXTRA Findings

An `EXTRA` finding means a resource exists in Azure but is not defined in the Bicep template being scanned.

### Triage Steps

1. Confirm the resource is in the expected subscription and resource group.
2. Check whether the resource should be managed by Bicep.
3. Identify who created or owns the resource, if attribution is available.
4. Determine whether the resource is temporary, unmanaged, or incorrectly scoped.
5. Decide whether to remove it, onboard it into Bicep, or ignore it.

### Common Causes

- Manual resource creation
- Temporary troubleshooting resource
- Resource deployed by another pipeline
- Auto-created Azure dependency
- Scan scope includes resources owned by another team
- Bicep template does not yet include the resource

### Recommended Actions

| Scenario | Recommended action |
|----------|-------------------|
| Resource is unmanaged and not required | Retire or delete through the approved change process. |
| Resource is required but missing from IaC | Add it to Bicep. |
| Resource is Azure-managed noise | Add a documented ignore rule. |
| Resource belongs to another team | Adjust scan scope or ownership routing. |
| Resource creates cost or security risk | Escalate for review. |

---

## MISSING Findings

A `MISSING` finding means the resource is defined in Bicep but is not present in Azure.

### Triage Steps

1. Confirm the resource should still exist.
2. Check recent deployment history.
3. Confirm the correct subscription and resource group are being scanned.
4. Validate parameters and resource naming.
5. Determine whether the resource was deleted manually or never deployed.

### Common Causes

- Deployment did not run
- Deployment failed
- Resource was deleted manually
- Template scope is incorrect
- Parameter values differ between deployment and drift scan
- Resource has been intentionally retired but Bicep was not updated

### Recommended Actions

| Scenario | Recommended action |
|----------|-------------------|
| Resource should exist | Redeploy through the normal pipeline. |
| Resource was intentionally removed | Remove it from Bicep. |
| Scan scope is wrong | Correct landing-zone configuration. |
| Parameter mismatch exists | Align scan parameters with deployment parameters. |
| Manual deletion occurred | Escalate if deletion was unauthorised. |

---

## Security and Governance Findings

Security and governance findings should receive higher scrutiny than standard configuration drift.

### RBAC Drift

Review RBAC drift when the agent reports out-of-band role assignments or privileged access changes.

Prioritise review of:

- Owner
- Contributor
- User Access Administrator
- Role Based Access Control Administrator
- Broad subscription-scope or management-scope assignments

Recommended actions:

1. Confirm whether the role assignment was approved.
2. Confirm the scope is appropriate.
3. Confirm whether the principal still requires access.
4. Remove or update the assignment through the approved access process.
5. Update Bicep only if the assignment is intended and should be managed as code.

### Policy Assignment and Exemption Drift

Review policy drift when assignments or exemptions appear outside the expected Bicep baseline.

Recommended actions:

1. Confirm whether the policy assignment or exemption was approved.
2. Check whether an exemption has an expiry and business justification.
3. Confirm whether the configuration belongs in the platform baseline.
4. Escalate unapproved exemptions or policy changes to the governance owner.

### Network and Access Boundary Drift

Treat the following as high priority:

- Open firewall rules
- Storage network ACL changes
- Key Vault network or access policy changes
- NSG rule changes that increase exposure
- Route table changes affecting traffic paths
- Private endpoint or DNS changes that alter access boundaries

Recommended actions:

1. Confirm the business reason for the change.
2. Validate whether exposure increased.
3. Check owner classification.
4. Escalate if the change weakens security boundaries.
5. Update Azure or Bicep depending on the approved target state.

---

## Handling Azure Policy Effects

The agent may identify changes associated with Azure Policy remediation.

Policy-driven changes should be reviewed differently from manual changes.

| Situation | Action |
|----------|--------|
| Policy remediation created or updated a required setting | Treat as expected governance if aligned with policy intent. |
| Policy modified a resource unexpectedly | Review the policy assignment and remediation task. |
| Policy assignment appears unmanaged | Review as governance drift. |
| Policy exemption appears unmanaged | Escalate for governance review. |

Do not suppress policy-related findings unless the behaviour is understood and documented.

---

## Handling Ignore Rules

Ignore rules should be used carefully. They are useful for expected Azure noise but can hide real drift if too broad.

### Use Ignore Rules For

- Azure-managed resources
- Auto-created dependencies
- Known and accepted platform exceptions
- Properties that are intentionally not managed by Bicep

### Avoid Ignore Rules For

- Security-sensitive properties
- Privileged access
- Network exposure
- Policy exemptions
- Resources that should be onboarded into Bicep

### Good Ignore Rule Practice

- Scope ignores as narrowly as possible.
- Include a reason for each ignore.
- Review ignores periodically.
- Prefer fixing Bicep over ignoring real drift.

---

## Landing Zone Onboarding Runbook

Use this checklist when onboarding a new landing zone.

### Checklist

- [ ] Confirm Azure authentication is configured.
- [ ] Confirm service principal has required Reader access.
- [ ] Add landing zone to `.github/lz-index.yml`.
- [ ] Create `.github/drift-lz-config.yml` in the landing-zone repository.
- [ ] Confirm Bicep path and branch are correct.
- [ ] Confirm subscription ID is correct.
- [ ] Confirm resource group selectors are correct.
- [ ] Configure notification targets.
- [ ] Configure `.drift-ignore`, if required.
- [ ] Run a manual scan.
- [ ] Review the generated report.
- [ ] Confirm notifications are delivered.
- [ ] Enable the scheduled workflow.

---

## Manual Validation Checklist

Use this after configuration changes or onboarding.

- [ ] Workflow starts successfully.
- [ ] GitHub OIDC authentication succeeds.
- [ ] Azure login succeeds.
- [ ] Target repository is accessible.
- [ ] Bicep file is found.
- [ ] Parameters are resolved.
- [ ] Azure resources are queried.
- [ ] Reports are generated.
- [ ] Notification step completes.
- [ ] Findings are routed to the expected team.

---

## Common Operational Issues

## Workflow Fails to Start

### Checks

- Workflow file exists.
- Workflow name matches the landing-zone index.
- Workflow dispatch is enabled.
- Branch name is correct.
- GitHub Actions is enabled for the repository.

---

## Landing Zone Not Found

### Checks

- Confirm the landing-zone name exists in `.github/lz-index.yml`.
- Confirm the workflow passes the same landing-zone name.
- Check spelling and casing.

---

## Config File Not Found

### Checks

- Confirm `.github/drift-lz-config.yml` exists in the landing-zone repository.
- Confirm `config_path` in `lz-index.yml` is correct.
- Confirm the branch being scanned contains the file.
- Confirm the token has access to the target repository if it is private.

---

## Repository Not Found

### Checks

- Confirm repository name and organisation are correct.
- Confirm the repository is accessible from the drift-agent workflow.
- Confirm the cross-repository token has required access.
- Confirm the repository has not been renamed or archived.

---

## Azure Authentication Failure

### Checks

- Confirm `AZURE_CLIENT_ID` is configured.
- Confirm `AZURE_TENANT_ID` is configured.
- Confirm the federated credential subject matches the workflow repository and branch.
- Confirm the service principal exists.
- Confirm the service principal has Reader access at the expected scope.

Refer to `AZURE_AUTHENTICATION.md` for setup and troubleshooting details.

---

## No Resources Returned

### Checks

- Confirm the subscription ID is correct.
- Confirm the resource group selector matches existing resource groups.
- Confirm the service principal has Reader access.
- Confirm the target resources are in the expected subscription.
- Confirm the scan is using the correct scope type.

---

## Unexpected Missing Resources

### Checks

- Confirm whether the template is subscription-scoped or resource-group-scoped.
- Confirm `subscription_scoped` is set correctly.
- Confirm the same parameters are used for deployment and drift scanning.
- Confirm the resource group exists.
- Confirm the resource was not intentionally removed.

---

## Unexpected Extra Resources

### Checks

- Confirm the scan scope is not too broad.
- Confirm the resource is not Azure-managed.
- Confirm the resource is not managed by another team or template.
- Confirm whether the resource should be added to Bicep.
- Consider a scoped ignore only if the resource is expected and documented.

---

## Notifications Not Delivered

### Checks

- Confirm webhook secret exists.
- Confirm the secret name matches the placeholder used in config.
- Confirm the placeholder uses the expected `DRIFT_WEBHOOK_` prefix.
- Confirm the Teams or Slack channel still exists.
- Confirm notification filters are not excluding all findings.
- Confirm the workflow notification step was not skipped or failed.

Refer to `TEAM_NOTIFICATIONS.md` for notification configuration.

---

## Report Access Issues

### Checks

- Confirm whether the user has access to the drift-agent repository.
- Confirm whether the report was published as a landing-zone GitHub issue.
- Confirm issue publication is enabled and the token has issue access.
- Confirm the landing-zone repository permissions are correct.

---

## Escalation Guidance

Escalate findings when they involve:

- Privileged access changes
- Policy exemptions
- Network exposure
- Key Vault access changes
- Storage firewall changes
- Resource lock removal
- Production resource deletion
- Unknown or unauthorised manual changes
- Repeated drift across multiple runs

Recommended escalation path:

1. Landing-zone owner
2. Platform engineering team
3. Security or governance owner
4. Change advisory or incident process, if required

---

## Remediation Decision Guide

| Question | If yes | If no |
|---------|--------|-------|
| Was the Azure change approved? | Update Bicep if it is the new desired state. | Revert Azure or escalate. |
| Is Bicep still correct? | Revert Azure to match Bicep. | Update Bicep. |
| Is the resource unmanaged but required? | Add it to Bicep. | Remove it through change control. |
| Is the finding expected Azure noise? | Add a scoped ignore rule. | Continue investigation. |
| Does the finding weaken security? | Escalate and prioritise remediation. | Treat through normal backlog. |

---

## Post-Remediation Validation

After remediation:

1. Re-run the relevant drift workflow.
2. Confirm the finding is resolved.
3. Confirm no new drift was introduced.
4. Confirm notifications and reports show clean or expected results.
5. Close or update any related GitHub issue.
6. Record any follow-up work required.

---

## Maintenance Activities

Perform regular maintenance on:

- Landing-zone index entries
- Workflow schedules
- GitHub secrets
- Federated credentials
- Service principal permissions
- Notification endpoints
- Ignore rules
- Report publication settings
- Repository access tokens

---

## Related Documentation

- `README.md` - Solution overview and quick start
- `ARCHITECTURE.md` - Architecture and system design
- `CAPABILITIES.md` - Supported drift detection capabilities
- `LANDING_ZONE_OPERATIONS.md` - Landing-zone onboarding and operations
- `AZURE_AUTHENTICATION.md` - GitHub OIDC configuration
- `SECURITY_MODEL.md` - Security architecture
- `TEAM_NOTIFICATIONS.md` - Notification configuration
