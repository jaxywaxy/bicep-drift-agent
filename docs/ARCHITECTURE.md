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

Collection is **fail-soft and self-declaring**. A collector that cannot read its
type records a collection gap rather than returning an empty list, and the
declared resources of a gapped type are reported as *unverified* rather than
deleted. The same principle applies to the scan scope itself (below). An
absence the agent cannot substantiate is never reported as a deletion.

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

Detected drift is enriched with ownership classification, severity, change
attribution, governance context and policy awareness. `analyze_drift.main()` is
the sole ordering authority; the stages run in this order, and the order is
load-bearing:

| # | Stage | Why here |
|---|---|---|
| 1 | `_attribute_lifecycle` | Fetches the RG's Activity Log once and matches per drift in memory |
| 2 | `_claim_policy_required_tags` | Marks tag values a policy imposes, before anything grades them. An in-flight Modify is invisible to the Activity Log by construction, so this cannot be inferred from attribution |
| 3 | `classify_drifts` | Stamps RISK `severity` + `category`. After attribution (it reads `change_origin`), before the analysis, so prompt and report agree |
| 4 | analysis | Optional; sees who/how, not "investigate the Activity Log" |
| 5 | `_split_policy_and_tag_owners` | Moves `change_origin.expected` rows to `policy_enforced_drifts`; tags the rest platform/workload |
| 6 | `_group_orphans_with_their_cause` | Keeps a deletion and its orphaned dependents in one finding rather than N scattered ones |
| 7 | `_include_placeholder_deletions` | Re-admits uniqueString-named deletions, which are invisible to name matching |
| 8 | `_finalize_drift_count` | Recomputes `drift_count` against `COUNTED_TYPES` |
| 9 | `_strip_internal_details` | Removes pipeline-internal keys before the JSON is written |

#### Two severities, and which one is which

A drift row carries both, and they answer different questions. Conflating them
is a recurring defect, not a hypothetical:

| Field | Question | Where it comes from | Default when unknown |
|---|---|---|---|
| `severity` | **Risk** — what is this resource, and what changed about it? | `agent/classification.py` policy tables, stamped by `orchestration.analysis.classify_drifts` | `unknown` |
| `change_origin.severity` | **Provenance** — how confident are we about who did it? | `tools/change_origin.py`, from the Activity Log | `medium` — a silent log, not a medium problem |

Provenance must never soften risk. Live 2026-08-09: an un-IaC'd
subscription-scope Owner grant was classified HIGH and rendered as a grey
"Unknown" badge, because the row carried nothing but `change_origin` and its
origin *and* category were both `unknown`. The classifier had the right answer
the whole time — it was reachable only through `DriftAgent`, so its verdict went
into the LLM prompt and nowhere else, and a scan with no provider never computed
it at all.

#### Evidence carried to the analysis

Each finding also carries context the *report already holds* but a per-resource
diff would not surface. Every field below exists because its absence produced a
wrong or hedged answer on a live report — the recurring failure mode is not the
model reasoning badly, it is the payload withholding something the pipeline knew.

| Field | Answers | Why it exists |
|---|---|---|
| `live_context` | "what else is true of this resource?" | Sibling properties that did NOT drift. Bounds severity and decides whether a remediation is possible |
| `unfinished_operation` | "was this deleted, or did a deploy fail?" | The latest lifecycle event that never reached `Succeeded`. A `create / Started` with no completion means the **deployment failed** — a missing Key Vault was reported as an unexplained disappearance when its redeploy had been blocked by a soft-deleted name |
| `private_endpoints` | "is closing public access safe?" | Endpoints whose `privateLinkServiceId` targets this resource. Indexed from the endpoint, not the target's `privateEndpointConnections`, because only the endpoint reliably carries the link |
| `related_policy_assignments` | "will this value come back?" | Assignments whose scope contains the resource. **Evidence, not attribution** — the payload has no definition effect, so it is a candidate cause to confirm, never proof |

`related_policy_assignments` exists because attribution recognises only Azure's
two **built-in** inherit-tag policies (`tools.policy.INHERIT_TAG_DEFINITIONS`). A
**custom** Modify policy's imposed value therefore arrives as ordinary actionable
drift attributed to whoever wrote it, and recommending a redeploy for a value the
policy re-imposes is a loop. Surfacing the assignment lets the narrative name the
risk without the pipeline having to claim an effect it cannot see.

### 6. Reporting and Notification

Results are transformed into:

- JSON reports
- HTML reports
- GitHub summaries
- Slack notifications
- Teams notifications
- Landing-zone GitHub issues

---

## Scope Semantics

A resource group is a different kind of object depending on the deployment scope,
and the agent treats it accordingly. Enterprise estates run both shapes.

| Scope | A resource group is… | Missing → |
|-------|----------------------|-----------|
| Resource group | the **frame** of the scan — an RG-scoped template cannot declare one | Scan aborts (exit 2): a targeting failure, not drift |
| Subscription | a **declared resource** the template owns, as in a CAF platform landing zone | Reported as drift on the resource group, with its orphaned contents attributed to it |

The abort exists because Resource Graph answers a query for a non-existent
resource group with a *successful, empty* result set — indistinguishable from an
empty one. Read naively that is "every declared resource was deleted": the
loudest possible alarm from a single configuration error, routed to whoever owns
the landing zone. An unreadable — or merely unconfirmable — scope therefore
produces no drift conclusion at all.

At subscription scope the equivalent abort is an empty *subscription*: one
resource group missing out of many is drift, none of them present is a wrong
subscription, a credential without read access, or an environment never deployed.

See [RESOURCE_GROUP_TARGETING.md](RESOURCE_GROUP_TARGETING.md) for selector
resolution and [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) for triage.

---

## Code Structure

The logical stages map onto packages as follows. Each package is split by
responsibility rather than by resource type, except the collectors, which are
deliberately one module per resource family.

| Stage | Package | Notes |
|-------|---------|-------|
| Orchestration | `orchestration/` | Targeting, detection, reconciliation, attribution, analysis, reporting. `analyze_drift.main()` is the sole ordering authority |
| Desired state | `tools/compile_bicep.py`, `tools/normalizer/` | Compile, flatten, resolve expressions |
| Live state | `tools/live_state/` | Resource Graph plus `tools/live_state/collectors/`, one module per family |
| Comparison | `tools/property_drift/` | Comparator, matcher, severity, and per-domain modules (security, firewall, monitoring, private DNS) |
| Sidecars | `tools/rbac.py`, `tools/policy.py`, `tools/deployment_stacks.py` | Identity-matched, fail-soft |
| Attribution | `tools/activity_log.py`, `tools/change_origin.py` | Who, when, how |
| Output | `tools/html_report.py`, `tools/send_notifications.py`, `tools/publish_lz_issue.py` | |
| Agent | `agent/` | Narrative analysis behind a provider seam (`agent/llm/`), prompts as a mixin |

**`tools/live_state/collectors/` is load-bearing.** A structural test derives the
set of collected types from that directory and fails if any of them is discarded
by a type-only ignore rule — the failure mode that once left two comparators
running but silently ineffective. A collector placed elsewhere sits outside that
guard.

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

## Implementation Invariants

Properties the pipeline relies on. Each was learned from a defect, and breaking
one produces a failure that a passing test suite will not catch.

| Invariant | Why it exists |
|-----------|---------------|
| **A new `drift_type` must be registered in `tools/count_drifts.COUNTED_TYPES`** (or explicitly reconciled, as `matched_unresolvable` is) | Otherwise it is detected, written to the JSON, and silently absent from every count and summary |
| **Stage ordering is load-bearing.** Smart matching runs *before* ignore filtering; attribution runs *before* the Claude call; the grep-able CI summary is emitted *after* the policy split | Reordering any of these changes the result rather than just the sequence — reconciled resources get swallowed by ignore rules, the analysis prompt loses who/how, or the summary disagrees with the report |
| **Report filenames go through `tools/rg_selector.rg_label`** — never concatenate `resource_group` | A subscription scan's selector may be `"*"` or a glob, neither of which is a valid filename |
| **Secrets never reach disk.** `tools/redact.py` scrubs secret-bearing values from the raw ARM/live dump written to the JSON | Property comparison already ignores write-only secrets, but the raw dump would otherwise carry them into an artifact |
| **Every text read and write names `encoding="utf-8"`** — enforced by `tests/test_encoding_hygiene.py`, which parses the AST rather than grepping | Without it Python uses the *locale's* encoding. A developer machine is UTF-8 and passes; a CI container with `LC_ALL=C` is US-ASCII, and a report whose narrative contains an em-dash raises `UnicodeDecodeError` — the verifier crashes instead of verifying. Reports carry LLM-written prose, so non-ASCII is routine, not exotic |
| **Log-and-skip is acceptable in sidecar comparators only** (RBAC, policy, deployment stacks) | Their failure should not sink a scan that still has real answers. Anywhere else, a swallowed error is a silent wrong answer |
| **The JSON report is the single source of truth** | The HTML report, the CI summary and every downstream consumer read it. A drift absent from the final `drifts` array is reported nowhere |
| **The bracketed `[MISSING]`/`[EXTRA]`/`[DRIFT]`/`[UNVERIFIED]` tokens belong to `_print_drift_summary` alone.** Phase 1's `format_drift_report` deliberately does not use them | Both used to appear in one CI log ~370 lines apart in the identical format, and Phase 1's list was already wrong by then — it named 13 extras of which six were reconciled away by smart matching, including a storage account the final summary correctly reported as *deleted*. Nothing machine-readable parses them (counts come from the JSON, see `tests/test_count_drifts.py`); the cost is that a human cannot answer "extra or deleted?" from the log |
| **A drift row must be shown WITH the finding that explains it, not merely linked to it** | `orphaned_by_missing_resource_group` was populated correctly while rows were emitted in creation order, so one resource-group deletion read as three unrelated deletions with six role assignments in between. Linkage in the data is not the same as one finding in the report; `verify_lz_report.py` asserts adjacency |
| **The narrative is optional** | Every deterministic stage runs with no LLM credential at all; only the narrative is lost. Which provider supplies it is a config choice (`DRIFT_LLM_PROVIDER`), and nothing above `agent/llm/` touches a vendor SDK |
| **Living in `agent/` does not make something LLM-dependent** | `agent/classification.py` is pure policy tables with no client and no network, but it was reachable only as a `DriftAgent` mixin — so severity was computed for the prompt and discarded, and never computed at all without a provider. Anything deterministic in `agent/` must be callable, and called, from the deterministic path |
| **Provenance must never soften risk.** `severity` (what the resource is) and `change_origin.severity` (how sure we are who did it) stay separate fields | `change_origin.severity` defaults to MEDIUM whenever the Activity Log is silent — a statement about attribution, not danger. Merged into one number, "we could not attribute it" reads as "it matters less": a standing subscription-scope Owner grant absent from Bicep, classified HIGH, rendered as a grey Unknown |

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
| Unsubstantiated absence is never a deletion | A type or scope the agent could not read is reported as unverified. The alternative — treating "we saw nothing" as "it is gone" — produces the loudest possible alarm from a configuration error |
| Scope-dependent resource-group semantics | A resource group is the frame of an RG-scoped scan and a declared resource of a subscription-scoped one, so its absence is a pipeline failure in the first case and drift in the second |
| Collectors split by resource family | Keeps a structural test able to derive collected types from the directory, so a comparator cannot be silently discarded by an ignore rule |

---

## Related Documentation

- [README.md](../README.md)
- [CAPABILITIES.md](CAPABILITIES.md) — What the agent detects
- [VALIDATION_STATUS.md](VALIDATION_STATUS.md) — What each capability has been proven to detect
- [TEST_ESTATE.md](TEST_ESTATE.md) — The verification estate and round procedure
- [CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md) — Configuration schema
- [RESOURCE_GROUP_TARGETING.md](RESOURCE_GROUP_TARGETING.md) — Selector resolution and scope semantics
- [TEAM_NOTIFICATIONS.md](TEAM_NOTIFICATIONS.md) - Teams and Slack Notification configuration
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone configuration
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY.md](SECURITY.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
