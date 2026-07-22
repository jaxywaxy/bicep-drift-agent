# Bicep Drift Agent Capabilities

This document describes the drift detection, governance, security and operational capabilities supported by Bicep Drift Agent.

The agent is designed for enterprise Azure environments and supports Cloud Adoption Framework (CAF) and Azure Landing Zone operating models, enabling platform and application teams to identify configuration drift, governance exceptions, unmanaged resources, and security-sensitive changes across subscriptions, resource groups, and landing zones.

Use this document to understand what the agent can detect, how findings are classified, and the level of coverage available for different Azure resource types and operating scenarios. For solution design and implementation details, see `ARCHITECTURE.md`. For onboarding and operational guidance, see `LANDING_ZONE_OPERATIONS.md`. 

---

# Capability Summary

| Category | Capability | Description |
|-----------|------------|-------------|
| Desired State Analysis | Bicep Compilation | Compiles Bicep into ARM templates for analysis |
| Desired State Analysis | Parameter Resolution | Resolves parameters from `.bicepparam`, `parameters.json`, and environment values |
| Desired State Analysis | Module Expansion | Flattens nested deployments and modules |
| Live State Collection | Azure Resource Graph | Primary source for Azure resource state |
| Live State Collection | ARM REST Augmentation | Collects resources not indexed in Resource Graph |
| Drift Detection | Property Drift | Detects configuration differences on deployed resources |
| Drift Detection | Missing Resources | Resources defined in Bicep but absent from Azure |
| Drift Detection | Unmanaged Resources | Resources present in Azure but absent from Bicep |
| Smart Matching | Runtime Generated Names | Matches resources using `uniqueString()`, `guid()` and similar patterns |
| Ownership | Platform Routing | Routes platform-owned drift to platform teams |
| Ownership | Workload Routing | Routes workload-owned drift to workload teams |
| Attribution | Activity Log Correlation | Identifies who or what changed a resource |
| Attribution | Policy Awareness | Separates Azure Policy remediation from actionable drift |
| Governance | RBAC Drift | Detects role assignment changes |
| Governance | Policy Drift | Detects policy assignments and exemptions |
| Security | Network Boundary Changes | Detects firewall and ACL changes |
| Security | Privileged Access Drift | Detects high-risk RBAC changes |
| Reporting | HTML Reports | Human-readable reports |
| Reporting | JSON Reports | Machine-readable output |
| Notifications | Slack | Slack webhook integration |
| Notifications | Teams | Microsoft Teams webhook integration |
| Operations | Multi-Landing Zone | Scan many landing zones from one repository |
| Operations | Subscription Scope | Scan entire subscriptions |
| Operations | Resource Group Scope | Scan individual resource groups |
| Security | GitHub OIDC | Secretless Azure authentication using Workload Identity Federation |

---

# Desired State Analysis

| Capability | Details |
|------------|---------|
| Bicep Compilation | Converts Bicep to ARM templates |
| Parameter Resolution | Resolves environment variables, `.bicepparam`, and `parameters.json` |
| Expression Resolution | Resolves common ARM expressions and parameter references |
| Module Expansion | Processes nested deployments and modules |
| Subscription Templates | Supports subscription-scoped deployments |
| Resource Group Templates | Supports resource-group-scoped deployments |

---

# Live State Collection

| Capability | Source |
|------------|--------|
| Azure Resources | Azure Resource Graph |
| Locks | ARM REST |
| Cosmos DB Child Resources | ARM REST |
| VNet Peerings | Expanded from Azure properties |
| AI Model Deployments | ARM REST |
| AI Safety Policies | ARM REST |
| Foundry Projects | ARM REST |
| Foundry Connections | ARM REST |
| Cross-Subscription Resources | Resource Graph and ARM REST |

---

# Drift Detection

## Drift Types

| Type | Description |
|--------|-------------|
| Property Drift | Resource exists but configuration differs |
| Missing Resource | Defined in Bicep but not deployed |
| Extra Resource | Exists in Azure but not defined in Bicep |

## Detection Characteristics

| Capability | Description |
|------------|-------------|
| Property-Level Comparison | Compares individual properties |
| Severity Classification | Security-sensitive findings flagged as critical |
| Azure Normalisation | Handles casing, defaults and Azure-generated values |
| Subset Comparison | Ignores Azure-added read-only metadata |
| Write-Only Protection | Secrets and write-only values not compared or exposed |

---

# Intelligent Matching

| Capability | Description |
|------------|-------------|
| Runtime Name Detection | Supports `uniqueString()`, `guid()` and generated names |
| Parent-Child Resource Matching | Handles nested Azure resources |
| Resource Type Normalisation | Case-insensitive type matching |
| Null vs Default Handling | Prevents false positives caused by Azure defaults |
| Ignore Profiles | Supports platform and landing-zone specific exclusions |

---

# Change Attribution

| Capability | Description |
|------------|-------------|
| Activity Log Analysis | Identifies likely origin of changes |
| User Attribution | Records who changed a resource where possible |
| Policy Attribution | Identifies Modify and DeployIfNotExists actions |
| Deployer Attribution | Recognises the IaC pipeline's own changes as authorized deployments |
| Terraform Attribution | Separates Terraform-managed activity |
| System Attribution | Identifies Azure-managed changes |

## Deployer Attribution

Changes made by the pipeline identity that deploys the estate are attributed
as **authorized deployments** (🚀 Pipeline badge, low severity) instead of
"manual change (out-of-band)". The drift itself remains actionable — a
pipeline-created orphan is still drift; only the attribution changes.

Deployer identities are never hardcoded:

| Source | How |
|--------|-----|
| Scanning identity (automatic) | The identity the scan authenticates as is read from its own access-token claims (object ID, appId, UPN). When the agent runs in the same pipeline that deploys — the common case — no configuration is needed. |
| `DRIFT_AUTHORIZED_DEPLOYERS` | Optional comma-separated allowlist (object IDs, appIds or UPNs) for estates deployed with a *different* identity than the one that scans. |

Attribution precedence: Azure Policy managed identities always classify as
policy-enforced, even if listed as deployers; deployer attribution wins over
Terraform/manual.

---

# Governance Capabilities

## RBAC Drift

| Capability | Description |
|------------|-------------|
| Role Assignment Detection | Finds out-of-band assignments |
| Privileged Role Detection | Flags Owner, Contributor, UAA and RBAC Administrator roles |
| Grant Attribution | Records who granted access and when |
| Scope Awareness | Supports RG and subscription scope |

## Policy Drift

| Capability | Description |
|------------|-------------|
| Policy Assignment Detection | Finds unmanaged policy assignments |
| Policy Exemption Detection | Detects exemption creation and expiry |
| Definition Tracking | Correlates assignments with definitions |
| Governance Classification | Separates governance changes from resource drift |

## Deployment Stack Drift

Opt-in per check. Runs only where a landing zone deploys with Azure deployment
stacks and declares one in its config.

| Capability | Description |
|------------|-------------|
| Deny Settings Posture | Detects a weakened `denySettings.mode`, and `applyToChildScopes` being off — which leaves the deny assignment on the resource groups while the resources inside stay writable |
| Deny Exclusions | Exact-set comparison of `excludedPrincipals` and `excludedActions`; an added exclusion is a hole in the deny assignment |
| Unmanage Behaviour | Detects `actionOnUnmanage` regressed from `delete` to `detach`, the orphaned-cost path |
| Stack Health | Reports a failed or incomplete stack deployment, plus its detached, failed and deleted resource lists |
| Stale Ownership | Resources the stack still claims to manage that no longer exist |
| Ownership Oracle | Tags each extra resource as stack-managed or genuinely unmanaged, replacing the resource-group-boundary inference |

### Limitations

These are deliberate, and matter when judging what a clean stack result means.

**Desired state must be declared.** A stack records no `templateLink`, tags or
description saying what it was supposed to be, so unlike every other comparator
there is no template to diff against. Enforcement posture is compared only
against the `expect` block in the landing-zone config, and **nothing is asserted
unless it is declared there**. Live values are never used as their own baseline:
a stack sitting at `mode: none` would otherwise bless its own weakness forever.
A check with no `expect` block still gets ownership and health, but its deny
settings are not evaluated at all.

**Prevention shrinks what there is to find.** On a stack running
`denyWriteAndDelete` with `applyToChildScopes` on, manual portal changes are
blocked at the source, so the rest of the engine legitimately goes quiet. What
that does *not* cover, and what still needs detecting: the deploying identity
(always excluded from the deny assignment), data-plane changes governed by the
resource's own API, resources that were never in the stack, and the stack's own
settings — an Owner can set `mode: none` and then edit freely, which ARM treats
as an ordinary stack update.

**Child resources are not checked for deletion.** Live state expands children
only for known types, so a child's absence from the live set is not evidence it
was deleted. Only top-level resources and resource groups are reported as stale
ownership, and only after a direct lookup confirms the resource is really gone.

**Template-side ownership is not compared.** Bicep-declared resources are not
matched against the managed list, because template resource ids aren't
resolvable at compile time. A resource deployed out-of-band into a stack-owned
scope is caught as an unmanaged extra, not as a stack-membership gap.

**It is inert without stacks.** Estates deployed with plain `az deployment` gain
nothing here, and the check stays silent rather than warning.

---

# Security Capabilities

| Area | Detection |
|--------|-----------|
| Key Vault | Access policies, firewall settings, network ACLs |
| Storage Accounts | Firewall configuration and network ACLs |
| RBAC | Privileged assignments |
| AI Services | Model deployments and safety policy changes |
| Networking | Added firewall rules, route changes and access paths |
| Exemptions | Policy waivers and exceptions |

Critical findings are flagged where a detected change increases exposure or reduces security controls.

---

# Ownership & Routing

| Owner | Resource Types |
|----------|---------------|
| Platform | VNets, subnets, route tables, network fabric, platform governance |
| Workload | Applications, data services, storage, Key Vaults, workloads |
| Mixed | NSG resources are platform-owned, security rules are workload-owned |

---

# Notifications

| Capability | Description |
|------------|-------------|
| Slack | Webhook-based notifications |
| Teams | Webhook-based notifications |
| Owner Routing | Send findings to responsible teams |
| Event Filtering | Filter by drift type |
| Custom Templates | Team-specific message formats |
| Consolidated Reports | Single notification per landing zone |

---

# Reporting

| Format | Purpose |
|---------|---------|
| JSON | Integration and automation |
| HTML | Human-readable reporting |
| GitHub Summary | CI/CD visibility |
| GitHub Issue Publication | Landing-zone-specific reporting |

---

# Supported Resource Coverage

## Fully Validated

- Storage Accounts
- App Services
- Key Vault
- Logic Apps
- Log Analytics
- Event Hubs
- Cosmos DB
- Azure Container Registry
- Azure Container Instances
- SQL Server
- SQL Database
- Azure OpenAI / Azure AI Services
- Azure AI Foundry
- Service Bus
- Service Bus Queues
- Traffic Manager
- DNS Zones
- Virtual Networks
- Subnets
- NSGs
- Route Tables
- NAT Gateway
- Private Endpoints
- Locks
- RBAC
- Azure Policy
- Virtual Machines
- Firewall Policies
- Azure Firewall
- NSG Rules
  
## Recently Added

- Load Balancers
- Application Gateways
- WAF Policies
- Front Door Standard/Premium
- SQL Firewall Rules
- Data Collection Rules
- DCR Associations
- Diagnostic Settings
- Defender Plans
- Container Apps
- Redis 
- Recovery Services Vault

### Recovery Services vault backup config

`vaults/backupconfig` is not indexed by Resource Graph, so it is fetched via ARM
REST and compared as `{vault}/vaultconfig`. `softDeleteFeatureState` and
`enhancedSecurityState` are rated **critical**: disabling soft delete lets
backups be purged immediately, and the change is silent until a restore is
needed.

**Caveat — reachability.** This drift is really only reachable on vaults
*without* enhanced security. When enhanced security is Enabled, Azure locks soft
delete to AlwaysON and rejects any disable request
(`BMSUserErrorDisablingSoftDeleteStateNotAllowed`), so the out-of-band flip
cannot occur on a hardened vault — the detector still confirms the hardened
posture, but there is no weakening to catch there.

Backup **policy** schedule/retention drift is not yet covered: every vault ships
built-in default policies that would need selective name-matching to avoid
`extra_in_azure` noise. That is a later increment.


---

# Operational Characteristics

| Capability | Description |
|------------|-------------|
| Multi-Team Support | Multiple teams from one agent |
| Multi-Repository Support | Scan across many Bicep repositories |
| Subscription Scanning | Whole landing-zone scans |
| RG Selectors | Explicit names, glob patterns, or wildcard selection |
| Parallel Processing | Multiple checks execute concurrently |
| Fail-Soft Collection | Partial failures do not stop scans |
| GitHub OIDC Authentication | No Azure credentials stored in GitHub |

---

# Quality & Validation

| Capability | Description |
|------------|-------------|
| Unit Test Coverage | Comprehensive automated testing |
| End-to-End Validation | Live validation of drift scenarios |
| Least Privilege Access | Reader-only Azure permissions |
| Secretless Authentication | GitHub OIDC Workload Identity Federation |
| Safe Drift Detection | Read-only operation, no remediation changes performed |
