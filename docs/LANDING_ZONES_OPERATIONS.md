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

> **One repo can hold several landing zones, and they must not be confused.**
> `subscription_id` lives at the top of a config file, so a second estate in a
> different subscription needs its **own** config, its own index entry and its
> own workflow — even when it shares the repo and the template lineage
> (`envs/dev` and `envs/prod` of the same landing zone, for instance).
>
> Do not reach for the `subscription_id` **workflow_dispatch override** to point
> one at the other's subscription. There is no matching *path* override, so the
> check still compiles its original template: every declared resource reads as
> `missing_in_azure` and every deployed one as `extra_in_azure`. The report is
> not obviously broken — it is confidently wrong, which is worse.
>
> Where one subscription hosts more than one registered scope, scope each check
> with a resource-group glob rather than `"*"`, or each will report the other's
> resources as unmanaged on every run.

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

## Step 4a – Enable the drift issue in the landing zone repo (recommended)

Skipping this step is **silent**: notifications still send, and their report
link points at the Actions run in the drift-agent repo — which the workload team
usually cannot read. Granting them that read is not the fix, because it would
expose every landing zone's reports to every team.

Instead the run publishes the drift result as a rolling issue in the landing
zone's **own** repo (`Drift Report — <lz>`, label `drift-report`), created and
updated as drift is found and closed with a "✅ Drift resolved" comment when the
scan comes back clean. When an issue exists, every team's `{{ report_url }}`
becomes the issue link.

To enable it:

1. Give `BICEP_REPO_TOKEN` **`issues: write`** on the repo named by `repo` in
   `lz-index.yml` — the same repo the configuration is read from.
2. Nothing else. There is no enable flag; publication is attempted whenever the
   token allows it.

**How you know it did not work.** A missing or read-only token is *not* an
error — publication is an enhancement, never a gate, so it logs a warning and
the run still succeeds. Confirm it by looking for the issue in the landing zone
repo after the first run with drift, not by looking for a failure.

See `TEAM_NOTIFICATIONS.md` for the issue body format and template variables.

## Step 4b – (Optional) Run the analysis on Azure OpenAI instead of Anthropic

Only the narrative analysis is affected; every deterministic stage is
provider-independent, and a clean estate skips the call entirely.

The reason to do it is **not cost** — at one call per scan the difference is
cents. It is that Azure OpenAI authenticates with the workflow's existing OIDC
identity, so there is **no LLM key anywhere**.

Three repo **variables** switch it, and leaving them unset keeps Anthropic:

| Variable | Value |
|---|---|
| `DRIFT_LLM_PROVIDER` | `azure_openai` |
| `AZURE_OPENAI_ENDPOINT` | `https://<resource>.openai.azure.com/` |
| `AZURE_OPENAI_DEPLOYMENT` | the **deployment** name, not the model name |

Azure side, once:

1. Grant the workflow's OIDC identity **`Cognitive Services OpenAI User`** on the
   account. Subscription Contributor is *not* enough — that is control plane;
   inference is data plane.
2. Size the deployment capacity. Capacity N = N,000 TPM, one analysis call is
   ~14K tokens and grows with drift count, and concurrent landing zones share
   the budget. Check headroom with
   `az cognitiveservices usage list -l <region>` before assuming a support
   request is needed — the limit is often far above what is allocated.
3. Optionally set `disableLocalAuth: true` so keys cannot be used at all.

**Do not set `AZURE_OPENAI_API_KEY`.** It works, but silently takes the key path
and gives up the only reason to be here. The provider logs a warning if you do.

**Rolling back is instant**: clear `DRIFT_LLM_PROVIDER`. The Anthropic secret is
still passed, so nothing else changes.

**Set the price, or the cost line goes dark.** Every report carries the run's
token usage and an estimated cost, priced from a built-in table that is
Anthropic-only. The moment you switch — or change deployment — the report reads
`unknown (no price for model)`: tokens still counted, no rate to multiply by.

```bash
gh variable set DRIFT_MODEL_PRICING --body '{"gpt-5.6-sol": [5.00, 30.00]}'
```

The key is a model-id **prefix**, the pair is `[input, output]` in USD per
**million** tokens, and the longest matching prefix wins. No Azure OpenAI rate
ships by default on purpose: rates vary by region, tier and agreement, so the
report should never state a number nobody checked. See
[Model pricing](CONFIGURATION_REFERENCE.md#model-pricing) for finding the real
rate — Azure publishes list prices anonymously, under **Foundry Models** rather
than Cognitive Services.

A malformed value is discarded with a warning and the cost falls back to
`unknown`; a pricing typo never fails a scan. `validate_config()` warns when the
variable is set but yields no usable rows, so an ignored override cannot look
like a missing one.

**Running it locally is different.** Repo *variables* exist only inside Actions —
a local shell does not see them, and silently falls back to the default provider.
For local runs put the same three values in `.env` (gitignored), which both
`analyze_drift.py` and `evals/run.py` load. Auth locally is your own `az login`
identity, so it needs `Cognitive Services OpenAI User` on the account too — the
workflow's identity having it is not enough.

**Before you switch, compare the two.** `.github/workflows/evals.yml` ("Narrative
evals") runs the fixture corpus through both providers and checks what each one
*wrote* — section shape, length, whether findings carry remediation, whether an
actor was invented. It is `workflow_dispatch` only, because it makes real API
calls; run it when `agent/prompts.py` changes, before flipping
`DRIFT_LLM_PROVIDER`, and after a provider version bump. Each leg uploads its
output as an artifact so the two can be diffed. The Azure leg uses the same OIDC
identity as everything else and needs no key; the Anthropic leg reads
`ANTHROPIC_API_KEY` from secrets.

Note that a prompt tuned against one provider is not automatically neutral: the
output-shape rules in `agent/prompts.py` were written only after a provider swap
exposed conventions the previous model had been following without being told.

## Step 5 – Execute Validation

Run the workflow manually:

```bash
gh workflow run drift-lz-platform.yml
```

Confirm:

- Azure authentication succeeds
- **The scan read its scope** — a first run that exits **2** means the resource
  group or subscription is wrong, not that the estate has drifted. This is the
  most common onboarding failure: a typo in `subscription_id` or a resource-group
  name produces the same empty Resource Graph result as a deleted estate. See
  [When the Scope Is Wrong](#when-the-scope-is-wrong)
- Bicep is discovered
- Drift analysis completes
- Notifications are delivered — and note that a scope failure notifies **nobody**,
  so a silent channel on the first run is a reason to check the workflow

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

# When the Scope Is Wrong

**A landing zone pointed at a resource group or subscription that cannot be read
fails the pipeline. It does not report drift.**

This is deliberate, and it is the behaviour to understand before onboarding or
retiring a landing zone. Azure Resource Graph answers a query for a resource
group that does not exist with a **successful, empty result set** —
indistinguishable from a resource group that exists and holds nothing. Read
naively, "we saw nothing" becomes "everything was deleted": one maximum-severity
finding per declared resource, routed to whoever owns the landing zone, from a
single typo. So the agent refuses to draw a drift conclusion it cannot support.

## What happens, per scope

| Situation | Result |
|-----------|--------|
| **RG scope** — the target RG does not exist | Scan aborts, **exit 2** |
| **RG scope** — the RG exists but is empty | Scan proceeds; every declared resource *is* reported missing. Real drift, stays loud |
| **RG scope** — existence cannot be confirmed (403, network failure) | Scan aborts, **exit 2** — an unverifiable scope is as unsafe to report on as an absent one |
| **Subscription scope** — one RG of many is missing | **Drift** on the resource group, with its orphaned contents attributed to it |
| **Subscription scope** — no resources at all | Scan aborts, **exit 2** — wrong subscription, no read access, or never deployed |
| **Multi-RG pass** — one RG unreadable | That RG is skipped with a warning and named in the summary; the others scan normally. The counting step still fails, naming the skipped RG |

The asymmetry is not arbitrary. At resource-group scope the RG is the **frame**
of the scan — an RG-scoped template cannot declare one, so its absence is a
targeting failure. At subscription scope the RG is a **declared resource** the
template owns, so its absence is drift like any other resource's. See
[RESOURCE_GROUP_TARGETING.md](RESOURCE_GROUP_TARGETING.md).

## Nuances worth knowing before they bite

- **A wrong subscription looks exactly like a deleted estate.** Both produce an
  empty result. Only the explicit existence check separates them, which is why
  `subscription_id` in the landing-zone config is required in practice.
- **Exit 2 is not exit 1.** `0` = scan completed (drift may or may not exist),
  `1` = error, `2` = scope not found. CI can distinguish a targeting failure from
  drift without parsing logs.
- **The run still writes a report**, carrying `scope_status: "not_found"` and the
  reason. It is deliberately kept out of the drift tallies: "no report" and
  "zero drift" must never be confused, and the counting step fails naming the
  resource group rather than reporting a clean estate.
- **Nobody is notified.** The report has no findings, so no events are generated
  and no channel is messaged. **Channel silence does not mean "no drift"** for a
  landing zone whose scheduled run is failing — check the workflow, not the
  channel.
- **A skipped RG in a multi-RG pass is never reported as clean.** The other
  landing zones still produce real answers; the skipped one produces none, and
  says so.
- **A `workflow_dispatch` run can override the subscription and resource group**,
  which is the quickest way to test whether a failing scheduled scan is a config
  problem or a real one.

## Triage

1. `az group show -n <rg>` — decommissioned or renamed is the most common cause.
2. Check `subscription_id` in the landing-zone config against the subscription
   the estate actually lives in.
3. Confirm the scanning identity has Reader on that scope.
4. If the environment is genuinely gone, **remove the landing zone from
   `lz-index.yml`** — otherwise every scheduled run fails from here on.

Full triage steps are in [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md),
"Scan aborted".

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

```yaml
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

**Order matters.** De-register the landing zone *before* the Azure environment is
torn down. A registered landing zone whose resource group no longer exists fails
every scheduled run with exit 2 — correctly, since a scan of a scope that cannot
be read has no valid result, but it produces a recurring red build that says
nothing useful.

1. Remove the landing zone from `lz-index.yml`.
2. Disable associated workflows.
3. **Then** decommission the Azure environment.
4. Archive historical reports if required.
5. Remove notification routing.

If the environment was torn down first, the fix is the same — remove it from
`lz-index.yml` — and the failing runs in between are expected, not a defect.

The same applies to a **temporarily** torn-down environment (a test estate
between rounds): either de-register it or accept failing scheduled runs until it
is redeployed.

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

## Scan Aborted (Exit 2)

The scan could not read the resource group or subscription it was pointed at, so
it produced no drift conclusion. **This is a targeting or permissions problem,
not drift.**

| Symptom | Likely cause |
|---------|--------------|
| Exit 2 on a newly onboarded LZ | Wrong `subscription_id`, or a mistyped resource-group name |
| Exit 2 on a previously working LZ | The resource group was renamed, decommissioned, or the estate was torn down |
| Exit 2 across every landing zone | Scanning identity lost Reader, or the federated credential broke |
| `Scope not found: <rg>` in the counting step | The named RG is unreadable; other RGs in the same pass still reported normally |

Run `az group show -n <rg>`, check `subscription_id`, confirm the identity has
Reader, and if the environment is genuinely gone remove it from `lz-index.yml`.
Full detail in [When the Scope Is Wrong](#when-the-scope-is-wrong).

---

## Landing Zone Not Found

Verify:

```yaml
landing_zones:
```

contains the expected entry in:

```text
.github/lz-index.yml
```

---

## Configuration File Not Found

Verify:

```text
.github/drift-lz-config.yml
```

exists in the target repository.

---

## Authentication Failure
Review:

```text
AZURE_AUTHENTICATION.md
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
- [RESOURCE_GROUP_TARGETING.md](RESOURCE_GROUP_TARGETING.md) — How the agent chooses which resource groups to scan
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY.md](SECURITY.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
