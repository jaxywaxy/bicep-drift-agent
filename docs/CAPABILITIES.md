# Bicep Drift Agent Capabilities

This document describes the drift detection, governance, security and operational capabilities supported by Bicep Drift Agent.

The agent is designed for enterprise Azure environments and supports Cloud Adoption Framework (CAF) and Azure Landing Zone operating models, enabling platform and application teams to identify configuration drift, governance exceptions, unmanaged resources, and security-sensitive changes across subscriptions, resource groups, and landing zones.

Use this document to understand what the agent can detect, how findings are classified, and the level of coverage available for different Azure resource types and operating scenarios. For solution design and implementation details, see `ARCHITECTURE.md`. For onboarding and operational guidance, see `LANDING_ZONES_OPERATIONS.md`. 

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
| Private Endpoint DNS Zone Groups | ARM REST |
| Log Analytics Workspace Tables | ARM REST (declared tables only) |
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
| Unverified Absence | A type the collectors could not read is reported as unverified, never as deleted |
| Unreadable Scope | A resource group that does not exist aborts the scan; it is never reported as every declared resource being deleted |
| Condition-Skipped Declarations | A resource this scan gated off is a parameter mismatch, not an unmanaged resource |

**An unreadable scope is not mass deletion.** Resource Graph answers a query for
a resource group that does not exist with a *successful, empty* result set —
indistinguishable from a resource group that exists and holds nothing. Read
naively that is "every declared resource was deleted": one maximum-severity
finding per resource, routed to whoever owns the landing zone, from a single
config error (a decommissioned or renamed RG, a stale `lz-index.yml` entry, the
wrong subscription).

So an empty live set triggers an explicit ARM read of the resource group, and
only then:

- **absent, or unconfirmable** → the scan aborts with exit code **2** and writes
  no report. Exit 2 is distinct from a real error (1) and a clean scan (0), so
  CI can tell a targeting failure from drift without parsing logs. An
  inconclusive check (403, network failure) aborts too — an unverifiable scope
  is exactly as unsafe to report on as an absent one.
- **present but empty** → the scan proceeds and every declared resource *is*
  reported missing. That case is real drift and stays loud.

The check runs only on the empty result, so a normal scan pays nothing for it.
In a multi-RG (subscription) pass an unreadable RG is skipped with a warning and
named in the summary rather than sinking the whole pass — the other landing
zones still have real answers, and a skipped RG is never reported as clean.

**A declaration this scan gated off is not unmanaged.** `flatten_resources`
drops a resource whose `condition` resolves false — correct, since a gated-off
module is not deployed and comparing it would false-flag `missing_in_azure`. The
cost was that a *deployed* resource whose declaration was gated off had nothing
to match and came back `extra_in_azure`, which reads as "unmanaged resource,
consider deleting". That is the tool recommending you delete something you
deploy on purpose, and it cost a live round on 2026-07-21: a scan run with
default parameters (`deployAks=false`) reported the real AKS cluster as
unmanaged.

Skipped declarations are now retained. Because a gated **module** is a
`Microsoft.Resources/deployments` resource, the recorder descends into its
nested template — a skipped `if (deployAks)` module reports
`Microsoft.ContainerService/managedClusters`, which is what the live cluster's
row can be matched against. Matching extras carry
`details.condition_skipped`, the driving parameter and its value, and the run
persists a `condition_skipped` list. Only matching types are annotated: a
genuinely undeclared resource still reads as unmanaged.

Two defects in the same area went with it. `.bicepparam` values are now read
with their Bicep type — all-strings meant a numeric parameter feeding a resource
property could never equal what Azure returns, and `if value:` silently dropped
`false` and `0`, the two values a condition gate most needs. And Phase 1 now
**layers** the agent's baseline `.drift-ignore` with the landing zone's rather
than returning the first file it finds, which is what Phase 2 already did — the
two phases disagreeing about what is ignorable was the bug.

**Cannot collect is not the same as is not there.** Every collector
logs-and-skips so one ARM outage never sinks a scan — the documented sidecar
contract. The cost used to be silent: a declared child with no collected
counterpart is *indistinguishable* from a deleted one, so a failed listing fell
straight through to `missing_in_azure`. A local run on 2026-08-01 produced 27
such rows on an estate where all 27 resources existed, and the data-plane
expander records an earlier one — a transient `agentPools` failure reporting a
healthy declared pool as deleted.

Collectors now record the types they could not read. Rows of those types carry
`details.collection_unverified`, the run's `collection_gaps` map names every
ungathered type with the reason, and the CI summary prints `[UNVERIFIED]`
instead of `[MISSING]`.

The row is **not dropped**. Suppressing it would hide a genuine deletion behind
a transient error — the same silent-swallow that left the backup comparators
dead for a month (issue #330). It is reported, and labelled. Only the affected
types are marked: a real deletion of a type that *was* collected still reads as
a deletion.

---

# Intelligent Matching

| Capability | Description |
|------------|-------------|
| Runtime Name Detection | Supports `uniqueString()`, `guid()` and generated names |
| Parent-Child Resource Matching | Handles nested Azure resources |
| Resource Type Normalisation | Case-insensitive type matching |
| Null vs Default Handling | Prevents false positives caused by Azure defaults |
| Ignore Profiles | Supports platform and landing-zone specific exclusions |

**Nested `format()` in a child name.** A child whose parent segment is itself a
`format()` call — `format('{0}/{1}', format('st{0}drift{1}', …), 'default')`,
which is what a storage module compiles to — resolves the inner call first, so
the child's parent segment is byte-identical to the parent resource's own
resolved name (`sttestdrift[86c9cbf6]/default`) and matching lines up on it
rather than falling back to fuzzy recovery.

The template's `{i}` slots are filled in a **single pass**. Substituting one
argument at a time lets an already-inserted value be re-read by the next
argument: where the inner call cannot be fully resolved it keeps its own slots,
and the outer argument 1 overwrote the inner `{1}` — every storage child in the
2026-07-28 teardown report was named `format('st{0}drift**default**', …)/default`,
a name that matches nothing and has lost the `uniqueString()` slot needed to
recover the resource.

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

**An attribution must be able to account for the drift.** The event search falls
back to a write when no delete exists, which is useful *history* and cannot be a
*cause* — a create does not explain a resource being gone. When the matched event
can't account for the observed drift, the origin is `unknown` with a reason
saying so, and the timeline still shows what was found. `unknown` rates MEDIUM,
so an admitted gap outranks a falsely reassuring `authorized_deployment / low`.
This fires on genuine ingestion lag (a change scanned before the Activity Log
caught up) and on operation mismatches — the 2026-07-28 teardown carried four
deleted resources reading *"Deployed by authorized pipeline identity"*.

**And it must be about the right resource.** A resource whose Bicep name is a
runtime expression (`func-drift-[86c9cbf6]`) has no id to match on, so the search
falls back to resource *type* — which cannot tell two siblings apart. Events are
therefore narrowed to those whose own name fits the declared name's **shape**: a
partially resolved name is a template of literal text around placeholder holes
(`func-drift-[86c9cbf6]`, `kvdrift[86c9cbf6]/kv-audit`), compared segment by
segment so a hole cannot swallow a `/` and match across the parent/child
boundary. Aligned from the right, because an extension resource's event names
only the extension (`kv-audit`) while the declared name qualifies it with its
parent. A fully resolved name is a complete name and matches only itself.
Without this the function app adopted the App Service's deletion **and its
name**: `app-test-drift` appeared deleted twice and the function app's own
deletion never reached the report. Note this is not the operation check above —
a delete genuinely does explain a missing resource; it was the wrong resource's
delete.

Shape, not shared text. A threshold on shared prefix/suffix length accepted
`asp-test-drift` as `asp-func-drift-test` on the four characters `asp-`, and
both App Service Plans in the teardown adopted one event that way — Azure naming
conventions mean every resource of a type shares a lead like that by design, so
length discriminates nothing. A name still carrying raw expression text has no
shape to anchor on and keeps the shared-affix fallback, so attribution degrades
rather than disappearing.

**And it must have taken effect.** A `status: Failed` operation changed nothing,
so it neither explains a drift nor sets a lifecycle milestone — `deleted_at`
from a failed delete asserts a deletion that never happened. Where Azure logs
several records for one operation, the selector prefers the one that took effect
over the most recent. Only `Failed` and `Canceled` are treated this way:
`Started`/`Accepted`/`Unknown` against a resource that is demonstrably gone is
ingestion lag, and rejecting those would drop attribution the report gets right.
The failed record stays in the timeline as context.

**Method comes from the operation's type, not its verb.** An ARM deployment is
`Microsoft.Resources/deployments/*`, matched on whole type segments.
Substring-matching the operation name reported every
`Microsoft.Web/serverf`**arm**`s` operation as an ARM deployment — both plans in
the teardown carried `method: "ARM Deployment"` for manual deletions. Same trap
as `put` inside `Microsoft.Compute`; unknown stays `Unknown` rather than
guessing.

For the same reason a policy-tag claim does not inherit `changed_by`: a Modify
effect has no actor of its own, it rewrites the value inside somebody else's
write, and that writer may have been doing something unrelated. The identity is
kept as `last_write_by` / `last_write_at` — the fact is useful, the field name
was the lie.

**A resolved attribution outranks the type heuristics.** The finding classifier
otherwise reasons from resource type and drift type alone, which is right only
while the origin is unknown. Once `change_origin.expected` is set — a policy
Modify/DINE effect or an Azure service — the finding is re-rated as
**governance**, takes the attributed severity, and is never recommended for
redeploy: a Modify effect re-imposes its value inside the deploying identity's
own write, so redeploying loses the race on the very next write. The action is
`approve_exception`, not `no_action`, because there *is* a decision — reconcile
the template to the policy, or narrow the assignment.

One exception, deliberately: a **critical** property drift is never downgraded
this way. `expected` describes where the change came from, not whether its
content is safe — a DINE-created resource can still carry a genuinely critical
property, and burying it to keep the governance section tidy is the failure this
rule exists to prevent. Same reason tag claiming is per-property: a storage
account with a policy-imposed tag *and* a manual `allowBlobPublicAccess` flip
keeps its critical finding.

**Declared implies managed.** `SYSTEM_MANAGED` is a claim about *provenance* —
Azure created this as a dependent (a VM's NIC, a private endpoint's DNS zone
group) — and exists so that churn isn't reported as drift. It therefore applies
only to `extra_in_azure`. A drift type that means the template **declares** the
resource (`missing_in_azure`, `property_drift`) contradicts it outright: the
bicep asks for the resource, so it is ours. Two live rounds paid for this, both
on the same disk — first a `networkAccessPolicy DenyAll → AllowAll` flip rated
`ignore_system_managed`, then the disk being *deleted* out-of-band rated
"informational, ignore", alongside a deleted action group (alerting silently
going nowhere) and a deleted private DNS zone group (the finding issue #329
existed to surface).

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
- Function Apps
- AKS Clusters
- AKS Agent Pools
- Event Grid Topics / System Topics
- Event Grid Subscriptions
- User-Assigned Managed Identities
- Federated Identity Credentials
- Private DNS Zones
- Service Bus Topics
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
- PostgreSQL Flexible Server
- Metric Alerts
- Activity Log Alerts
- Scheduled Query Rules
- Action Groups
- Application Insights
- Public IP Addresses
- Virtual WAN
- Virtual Hub
- Virtual Hub Route Tables
- Virtual Hub VNet Connections
- Virtual Hub Routing Intent

### Virtual Hub routing

`virtualHubs/hubRouteTables`, `virtualHubs/routingIntent` and
`virtualHubs/hubVirtualNetworkConnections` are not indexed by Resource Graph, so
they are fetched via ARM REST child expansion. **Routing intent** is the security
control: its `routingPolicies` force Internet/Private traffic through the hub
firewall, so a policy removed or its `nextHop` repointed off the firewall is a
silent inspection bypass — rated **critical** (`properties.routingPolicies`).
Route-table routes carry the same weight via `properties.routes`.

Two live behaviours the detector accounts for: the built-in `defaultRouteTable`
and `noneRouteTable` (shipped with every hub, and programmed by routing intent)
are dropped so they never false-flag as extras; and the `RemoteVnetToHubPeering`
auto-created when a VNet connects to the hub is filtered from peering comparison.

**Caveat — mutually exclusive modes.** Azure rejects routing intent on a hub that
has any custom route table (`CantConfigureRoutingIntentIfCustomRouteTablesPresent`).
A hub is therefore either custom-route-table mode or routing-intent mode; the two
are never compared together on the same hub.

### Private endpoint DNS zone groups

Not indexed by Resource Graph, so they are listed per private endpoint via ARM
REST and compared as `{privateEndpoint}/{group}`.
`properties.privateDnsZoneConfigs` is rated **critical**: the zone group is what
makes a private endpoint resolvable by its own name, so deleting it or
repointing `privateDnsZoneId` at the wrong zone makes clients fall back to
public DNS — the Private Link bypass *succeeds*, nothing errors, and nothing
looks broken.

Listed rather than declared-driven (unlike the tables below): an endpoint
carries at most a handful of groups, so the payload is small, and an
**undeclared** group is worth seeing — something added the DNS integration out
of band.

`privateDnsZoneConfigs` is compared as an **exact set with resolved identities**,
not by the generic subset compare. The bicep side is
`resourceId('Microsoft.Network/privateDnsZones', '<zone>')` and the live side is
a full ARM id; the generic compare treats the unresolved expression as a match,
so it catches the config being *removed* but never a **re-point** — verified
live on 2026-07-28, where swapping the zone produced zero diffs. Both spellings
now collapse via `primitives.ref_identity`, so a re-point, a removal, and an
undeclared config added live are each drift. Same treatment, and same
`ref_identity` helper, as the monitoring alert linkages.

> **Limit:** a config whose declared zone is an opaque expression (a module
> output, with no literal name on either side) cannot be checked for a
> re-point. Its presence is still checked. Identical to the documented limit on
> monitoring linkages.

### Log Analytics workspace tables

Not indexed by Resource Graph. Fetched **only for the tables the template
declares** — one `GET {workspace}/tables/{name}` each — because a workspace
carries the entire built-in catalogue: 679 tables and 2.8 MB of JSON on the
drift-test workspace. Listing them to keep the one declared row would bloat
every report artifact with rows that get dropped again at diff time. Same
bicep-driven rationale as Defender pricings.

Matched by **leaf name** across every live workspace, because the declared
parent is normally a `uniqueString()` placeholder
(`log-[86c9cbf6]/CustomLog_CL`) and cannot be resolved at compile time. A
declared table that returns 404 is simply absent from live state, which is
precisely the `missing_in_azure` signal wanted — so 404 is handled apart from
real errors and does **not** log a warning.

Built-in tables are declarable too (setting `retentionInDays` on `Heartbeat` is
a normal retention-management pattern), so this deliberately does not filter to
custom `_CL` tables. `retention*` and `plan` are rated **critical**, type-scoped
for the same reason backup retention is: `retentionInDays` also appears on the
workspace itself, on ACR retention policies and on diagnostic settings, where
the default warning is right.

> Both types were previously suppressed by `.drift-ignore` rules standing in for
> the collection gap (issue #329). Suppressing the false positive suppressed the
> real finding too — the workspace-tables row carried a note claiming the table
> "has been deleted or was never created", and `CustomLog_CL` was present the
> whole time.

### Recovery Services vault backup config

> **Fixed 2026-07-27.** Both types below were documented as compared while the
> baseline `.drift-ignore` carried type-only rules that discarded every drift
> they produced — the rules predated the collector and outlived the problem they
> were written for. The comparators were dead in the pipeline for about a month;
> nothing looked wrong because the fixture vault happened to be clean.
> `tests/test_ignore_patterns.py::CollectedTypesAreNotBlanketIgnoredTests` now
> derives the collected types from the collectors and fails if any of them is
> blanket-ignored, so documented coverage and shipped coverage cannot diverge
> silently again.

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

**Backup policies** (`vaults/backupPolicies`) are also fetched via ARM REST and
compared. Shortening retention or loosening the schedule is rated **critical** —
it silently shrinks how far back you can restore. Every vault ships built-in
default policies (`DefaultPolicy`, `EnhancedPolicy`, `HourlyLogBackup`) even with
no protected items, so live policies the template does **not** declare are dropped
(same treatment as SQL `master`, App Service `config`, and storage `default`
containers). Trade-off: a policy added entirely out-of-band, that the template
never declared, is not surfaced — only declared policies are compared.

## Out of Scope — Static Hub Connectivity Gateways

The following network connectivity gateways are **deliberately not covered**.
They are static, deploy-once fabric: provisioned once when the platform hub is
stood up, changed rarely and only through the connectivity pipeline, and slow to
provision (tens of minutes to hours). They are not the kind of resource that
accrues out-of-band configuration drift the way workload and security resources
do, and treating them as drift candidates adds noise without adding signal.

| Resource | Why excluded |
|----------|--------------|
| ExpressRoute Circuit | Provisioned with the carrier; bandwidth/peering changes are deliberate, long-lead, and carrier-coordinated — not portal drift |
| ExpressRoute Gateway | Static hub connectivity; long provisioning time, changed only during planned connectivity work |
| VPN Gateway | Static hub connectivity; SKU/config changes are planned platform operations, not out-of-band edits |
| Route Server | Static BGP fabric in the hub; changed only during planned connectivity work |
| Bastion | Static management-access appliance; deployed once per hub, rarely reconfigured |

**Note — hub *routing* is covered, only the connectivity gateways are not.**
Virtual WAN, Virtual Hub, and — the security-relevant part — its route tables,
VNet connections and **routing intent** are all fully covered (see
[Fully Validated](#fully-validated)): a routing-intent policy repointed off the hub
firewall, or a route widened to bypass inspection, is out-of-band and carries
security consequence, so it is detected as critical. Likewise Azure Firewall and
Firewall Policies are covered. The exclusions above are limited to the static
connectivity gateways, not to the hub's routing or security surface.

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
