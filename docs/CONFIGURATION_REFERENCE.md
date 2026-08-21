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
| `repo` | Yes | Repository containing landing zone configuration. **Drift issues are also published here** (see Step 4a in `LANDING_ZONES_OPERATIONS.md`), so `BICEP_REPO_TOKEN` needs `issues: write` on it — the same field decides where the config is read FROM and where the report is written TO |
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
| `subscription_id` | **Required in practice** | Azure subscription ID being scanned. The reusable workflow passes it through as `AZURE_SUBSCRIPTION_ID`, and the scan fails at live-state collection without it. It defaults to empty rather than erroring at config-validation time, so an omission surfaces as a failed scan rather than a clear config error. A `workflow_dispatch` run can override it |
| `notifications` | No | Notification destinations and routing rules |
| `checks` | Yes | List of Bicep scans to perform |
| `resource_group` | — | **Not supported.** Scan scope comes from each check's `resource_groups`. The loader used to read a root-level key and a matching `resource_group` dispatch override, neither of which reached the scan; both were removed rather than left looking functional |

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
| `deployment_stack` | No | Deployment stack to evaluate. Omit unless the estate is deployed with `az stack` |
| `params` | No | JSON object of Bicep parameter overrides for this check, e.g. `{"deployVirtualHub": true}`. Use it to scan a conditional module that is gated off by default — without it those declarations are skipped and their live resources read as unmanaged |
| `ownership_model` | No | `platform` or `workload`. Who owns a resource nothing else classifies. Default `workload`; a platform landing zone wants `platform` — see [Ownership](#ownership) |
| `module_owners` | No | Map of Bicep module glob → owner, e.g. `{apps: workload}`. Consulted BEFORE the type rules, because it is evidence rather than inference |

---

# Deployment Stacks

Optional, per check. Add this only where the infrastructure is deployed as an
Azure deployment stack. Omitting it disables the check silently.

## Schema

```yaml
checks:
  - name: Platform Connectivity
    repo: myorg/platform-bicep
    path: bicep/main.bicep
    subscription_scoped: true
    resource_groups: ["*"]
    deployment_stack:
      name: platform-stack
      scope: subscription        # subscription | resource_group | management_group
      expect:
        deny_settings:
          mode: denyWriteAndDelete
          apply_to_child_scopes: true
          excluded_principals: []
          excluded_actions: []
        action_on_unmanage:
          resources: delete
          resource_groups: delete
```

## Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | The stack's name in Azure |
| `scope` | No | Where the stack lives. Default: `subscription` |
| `resource_group` | No | Resource group holding the stack, for `resource_group` scope. Defaults to the scanned group |
| `management_group` | Only for `management_group` scope | Management group holding the stack |
| `expect` | No | Enforcement posture to assert. See below |

## Why `expect` is required for posture checks

A deployment stack records nothing about what it was *supposed* to be — no
template link, tags or description. There is therefore no desired state to
compare against unless you write one down here.

**Only the keys you declare are compared.** Everything else is left unasserted.
Live values are never adopted as a baseline, so a stack sitting at `mode: none`
is not treated as correct merely because that is how it currently stands.

The practical consequence: a check with no `expect` block still reports
ownership and stack health, but **its deny settings are never evaluated**. If
the stack exists to enforce something, declare it.

| Key | Compared as |
| --- | ----------- |
| `deny_settings.mode` | By strength. Weaker than declared is critical; stricter is reported as info |
| `deny_settings.apply_to_child_scopes` | Exact. When off, the deny assignment covers the resource groups but not the resources inside them |
| `deny_settings.excluded_principals` | Exact set. An added exclusion is critical, a removed one a warning |
| `deny_settings.excluded_actions` | Exact set, as above |
| `action_on_unmanage.*` | Exact. `delete` regressed to `detach` is a warning — nothing is exposed, but orphaned resources keep billing |
| `provisioning_state` | Defaults to `succeeded`; asserted with or without an `expect` block |

Set `INCLUDE_DEPLOYMENT_STACKS=false` to force the check off even where
configured.

Limitations are documented in
[CAPABILITIES.md](CAPABILITIES.md#deployment-stack-drift).

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

## Required

| Variable | Purpose |
|-----------|---------|
| `AZURE_SUBSCRIPTION_ID` | Subscription to query. **The scan fails at live-state collection without it** — an `az login` session is not enough, because the Resource Graph client reads this variable rather than the CLI's active subscription. The reusable workflow sets it from the landing zone's configuration |

## Optional

| Variable | Default | Purpose |
|-----------|---------|---------|
| `ANTHROPIC_API_KEY` | — | Required **only when `DRIFT_LLM_PROVIDER=anthropic`** (the default). Irrelevant under `azure_openai`, which authenticates with Entra. With no usable credential every deterministic stage still runs and the run logs the skip; only the narrative is lost |
| `ARM_PARAMETERS` | — | JSON blob of parameter overrides. Takes precedence over `.bicepparam` and `parameters.json` |
| `DRIFT_AUTHORIZED_DEPLOYERS` | — | Additional deployer identities (see below) |
| `INCLUDE_ROLE_ASSIGNMENTS` | `true` | Set `false` to disable the RBAC sidecar |
| `INCLUDE_POLICY_ASSIGNMENTS` | `true` | Set `false` to disable the policy sidecar |
| `INCLUDE_DEPLOYMENT_STACKS` | `true` | Set `false` to force the stack sidecar off even where `DRIFT_DEPLOYMENT_STACK` is configured |
| `DRIFT_DEPLOYMENT_STACK` | — | Deployment-stack name. Stack comparison is opt-in and stays off unless set |
| `DRIFT_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `DRIFT_BICEP_TIMEOUT` | `120` | Seconds allowed for `az bicep build`. Raise for very large templates |
| `DRIFT_WEBHOOK_TIMEOUT` | `10` | Seconds allowed per webhook POST |
| `DRIFT_MODEL_PRICING` | — | JSON `{"<model-prefix>": [input, output]}` in USD per **million** tokens, overriding and extending the built-in price table (see below) |
| `DRIFT_OWNERSHIP_MODEL` | `workload` | `platform` or `workload` — who owns a resource nothing else classifies (see [Ownership](#ownership)) |
| `DRIFT_MODULE_OWNERS` | — | JSON `{"<module-glob>": "platform"\|"workload"}` mapping Bicep modules to owners |
| `DRIFT_PLATFORM_TYPES` | built-in set | Comma-separated resource types treated as platform-owned, **replacing** the built-in list. Rarely needed — prefer `DRIFT_MODULE_OWNERS` |
| `DRIFT_AGENT_MODEL` | the provider's own default | Model id for the analysis. Left unset it follows `DRIFT_LLM_PROVIDER`, so choosing a provider does not also force you to name one of its models |
| `DRIFT_LLM_PROVIDER` (repo **variable** in CI) | `anthropic` | `anthropic` or `azure_openai` — **both ship**; see [Choosing a provider](#choosing-a-provider). The seam lives in `agent/llm/` and nothing above it touches a vendor SDK or response shape. An unrecognised value **fails loudly** rather than falling back — running against a provider you did not choose, and reporting it as if you had, is the failure this tool exists to prevent one level up |
| `AZURE_OPENAI_ENDPOINT` | — | Required when `DRIFT_LLM_PROVIDER=azure_openai`. The resource endpoint, `https://<resource>.openai.azure.com/` |
| `AZURE_OPENAI_DEPLOYMENT` | — | Required for Azure. The **deployment** name, which is not necessarily the model name — this is the single most common misconfiguration and surfaces as `DeploymentNotFound` |
| `AZURE_OPENAI_API_VERSION` | `2024-10-21` | Azure data-plane API version |
| `AZURE_OPENAI_TOKEN_SCOPE` | public cloud | Entra audience for the data plane. Only set it for US Gov or China clouds, whose audiences differ — the default fails there with an opaque auth error |
| `AZURE_OPENAI_API_KEY` | — | **Omit this.** Left unset, the provider uses `DefaultAzureCredential`, which is the entire reason to run Azure OpenAI: the workload identity CI already holds needs `Cognitive Services OpenAI User` on the account, and no LLM key is stored anywhere. Setting a key works, but trades that away |

### Record / replay (development only)

These three are **deliberately not passed by the production scan workflow**, and
`tests/test_workflow_env_coverage.py` asserts they never are. A scan that could
be talked into recording would write a client's raw ARM payloads into a CI
artifact. Recording is a developer action against a verification estate.

| Variable | Default | Notes |
| --- | --- | --- |
| `DRIFT_RECORD_CASSETTE` | — | Path to write recorded Azure payloads to. The scan runs normally and every ARM REST and SDK read is captured, sanitised, on the way past. Appends to an existing cassette, so a corpus builds up over several scans |
| `DRIFT_REPLAY_CASSETTE` | — | Path to serve every Azure read from. **No network calls are made at all.** A request the cassette does not cover raises `CassetteMiss` — it never returns empty, because an empty collection means *deleted* to everything downstream |
| `DRIFT_CASSETTE_NOTE` | — | Free-text provenance stamped on each recorded interaction (which estate, which round) |
| `DRIFT_CASSETTE_MAX_BYTES` | `1000000` | Largest single response body that may enter a cassette. Oversize responses are skipped, logged, and listed under `oversize_skipped` in the cassette metadata; a replay needing one misses loudly rather than replaying a truncated lie |
| `DRIFT_CASSETTE_BUDGET_BYTES` | `20000000` | Total bytes a cassette may reach before recording stops and stamps `budget_exhausted` into its metadata. The per-response cap alone is **not** sufficient: the Activity Log arrives through the Monitor SDK's pager as hundreds of responses individually well under 1MB, and the first two full-pipeline recordings each came to 174MB because of it. The Activity Log endpoint is now excluded outright — it is unbounded, time-varying, and already covered by hand-written attribution fixtures — and this budget is the backstop for whatever does the same thing next |

Setting both `DRIFT_RECORD_CASSETTE` and `DRIFT_REPLAY_CASSETTE` is an error
rather than a precedence rule.

Recorded ids carry a **pseudonymised** subscription — the real GUID is hashed
one-way and never written to disk, so a committed cassette is safe to ship. A
test replaying one must drive the pipeline with the alias, which
`python -m tools.recording.decay --aliases <cassette>` prints.

To check a live API for decay, re-record and diff:

```bash
DRIFT_RECORD_CASSETTE=fresh.json python analyze_drift.py ./infra/main.bicep "lz-*"
python -m tools.recording.decay tests/cassettes/lz-prod-subscription.json fresh.json   # exit 1 if the shape moved
```

## Ownership

Every actionable drift is tagged `platform` or `workload`, and notifications
route on that tag. Get it wrong and the right finding reaches the wrong team.

By default ownership is inferred from the **resource type** — the network fabric
is platform, everything else is workload. That is correct for a workload landing
zone and **wrong for a platform one**: on an enterprise LZ the platform team owns
the whole subscription, so type inference tags its Key Vaults, Cosmos, storage,
workspaces and even its resource groups as `workload` and pages the app team for
the platform estate.

Type cannot decide this on its own. The same Key Vault is platform-owned in a
connectivity subscription and workload-owned in an app team's spoke, so no
curated type list is right in both places.

Two settings fix it, and both are per-check keys in the landing zone's
`.github/drift-lz-config.yml`:

```yaml
checks:
  - name: Platform Landing Zone
    path: envs/prod/main.bicep
    subscription_scoped: true
    resource_groups: ["*"]

    # Everything the type rules don't classify belongs to the platform team.
    ownership_model: platform

    # ...except the modules that genuinely are a workload.
    module_owners:
      apps: workload
      storage-apps: workload
```

Resolution order — the first rule that decides, wins:

| | Rule | Source |
|---|---|---|
| 1 | `module_owners` match | evidence: which codebase declares it |
| 2 | Structural cases (policy assignments, deployment stacks, role assignments) | inherent |
| 3 | NSG `securityRules` → workload | built-in carve-out |
| 4 | Resource type in the platform set | heuristic |
| 5 | `ownership_model` | your declared default |

`module_owners` is first because it is the only rule backed by evidence rather
than inference — it therefore also overrides the `securityRules` carve-out, since
an LZ mapping its networking module to `platform` is stating its own rules are
not delegated, and it knows that better than a default written here.

Notes:

- **Both settings are optional and inert when unset.** An LZ that configures
  neither behaves exactly as before, so this changes nothing for existing zones.
- **Module names are Bicep's symbolic names** — `module networking './modules/networking/main.bicep'`
  matches `networking`. A module nested in a module matches on its path
  (`apps/keyvault`), and globs work (`storage-*`).
- **Longest matching pattern wins**, so `apps/*` carves an exception out of `*`
  regardless of the order the config is written in.
- **Only resources Bicep declares have a module.** An `extra_in_azure` finding
  has none by definition and falls through to the rules below.
- **A malformed `module_owners` is ignored with a warning, never half-applied** —
  a partially honoured map routes some findings correctly and others silently to
  the wrong team, which is harder to notice than no map at all.

## Choosing a provider

Both providers ship. Only the narrative analysis is affected — every
deterministic stage (compile, live state, smart matching, ignore filtering,
property drift, attribution, ownership) is provider-independent, and a clean
estate skips the call entirely.

| | `anthropic` | `azure_openai` |
|---|---|---|
| credential | `ANTHROPIC_API_KEY` secret | **none** — Entra via the workflow's existing OIDC identity |
| extra config | — | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` |
| Azure prerequisite | — | `Cognitive Services OpenAI User` on the account (data plane; subscription Contributor is **not** enough) |
| SDK | `anthropic` (in `requirements.txt`) | `openai` (installed only when selected) |

**The reason to run Azure OpenAI is not cost — it is that there is no LLM key
anywhere.** At one analysis call per scan the price difference is cents either
way; the OIDC identity CI already holds does the authentication.

### Switching

Three repo **variables**, and leaving them unset keeps Anthropic:

```bash
gh variable set DRIFT_LLM_PROVIDER      --body azure_openai
gh variable set AZURE_OPENAI_ENDPOINT   --body 'https://<resource>.openai.azure.com/'
gh variable set AZURE_OPENAI_DEPLOYMENT --body '<deployment-name>'
```

`AZURE_OPENAI_DEPLOYMENT` is the **deployment** name, not the model name. That is
the most common misconfiguration and surfaces as `DeploymentNotFound`.

**Rolling back is instant**: clear `DRIFT_LLM_PROVIDER`. The Anthropic secret is
still passed, so nothing else changes.

**Do not set `AZURE_OPENAI_API_KEY`.** It works, and it silently gives up the
only reason to be here. The provider logs a warning if you do.

### What a provider swap actually costs you

The prompt was implicitly tuned to whichever model it grew up with. When the
provider first changed, the **domain** rules ported cleanly — the new model
correctly refused locks-as-prevention and knew a redeploy will not remove a role
assignment — while the **output-shape** conventions ported not at all, because
they had never been written down. They are written down now (`agent/prompts.py`),
but budget a round of shape rules per new vendor and expect the same split.

Do not assess a swap by reading one report. `evals/checks.py` scores a narrative
mechanically, and `.github/workflows/evals.yml` runs the fixture corpus through
both providers so the comparison is a number rather than an impression. To
compare candidate **models** on one provider, point `AZURE_OPENAI_DEPLOYMENT` at
each in turn and score the same corpus — deployments on a pay-per-token SKU cost
nothing while idle, so several can sit side by side.

## Model pricing

Every report carries the run's token usage and an estimated cost. The built-in
price table is **Anthropic-only**, so after switching `DRIFT_LLM_PROVIDER` the
cost line reads `unknown (no price for model)` — tokens are still counted, but
there is no rate to multiply them by.

`DRIFT_MODEL_PRICING` supplies one. It maps a model-id **prefix** to
`[input, output]` in USD per **million** tokens, and overrides the built-in
table where they overlap:

```bash
export DRIFT_MODEL_PRICING='{"gpt-5.6-sol": [5.00, 30.00]}'
```

In CI, set it as a repository variable so prices can be corrected without a code
change:

```bash
gh variable set DRIFT_MODEL_PRICING --body '{"gpt-5.6-sol": [5.00, 30.00]}'
```

Setting the variable is not enough on its own — it also has to reach the scan.
It did not for a day: the variable was set, the cost line still read `unknown`,
and that looked exactly like the designed "no price for this model" behaviour.
`tests/test_workflow_env_coverage.py` now fails if a tunable the code reads is
missing from `.github/workflows/drift-check-lz-hybrid.yml`.

Notes:

- **No Azure OpenAI rate ships by default, deliberately.** Those prices vary by
  region and tier, so there is no single correct row — use the rate on your own
  agreement rather than have the report state a number nobody checked.
- **Keys are prefixes, and the longest match wins.** Pricing both `gpt-5` and
  `gpt-5-mini` does the right thing; dated ids like
  `claude-haiku-4-5-20251001` match their alias row.
- **A malformed row is discarded with a warning, never half-parsed.** The cost
  falls back to `unknown`, which is honest; a scan is never failed over a pricing
  typo, since the drift result is the product and dollars are a reporting
  nicety. `validate_config()` warns when the variable is set but yields no
  usable rows, so an ignored override cannot look like a missing one.

### Finding the real rate

Azure publishes list prices anonymously, and the meters are under **Foundry
Models** rather than Cognitive Services:

```bash
curl -s "https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview&\$filter=contains(meterName,'5.6%20sol')"
```

Meter names encode the tier: `ShortCo`/`LongCo` is context length, `Inp`/`Opt`
input/output, `Cd Inp`/`Cd Wr` cached-read/cache-write, `Std`/`PP` the purchasing
mode, and `Gl`/`DZ` Global/DataZone. A **GlobalStandard** deployment wants the
`Std` + `Gl` rows. For `gpt-5.6-sol` in australiaeast those are **$5.00 in /
$30.00 out** per 1M tokens (short context), with cached input at $0.50.

That is **list price**. The endpoint is anonymous and knows nothing about an EA,
CSP or MACC discount, so treat it as an upper bound and use your agreement's rate
if you have one — the whole point of this being configurable is that the report
should never state a number nobody checked.

One analysis call on a typical payload (~8,500 in / ~2,600 out) is about
**$0.12** at those rates. Cost was never the argument for running Azure OpenAI;
keyless Entra auth was.

## Notification variables

| Variable | Purpose |
|-----------|---------|
| `DRIFT_NOTIFICATIONS` | JSON team-routing configuration (owners, channels, filters) — see [Notifications](#notifications) |
| `WEBHOOK_SECRETS` | JSON blob of secrets that webhook placeholders resolve against. CI injects `toJSON(secrets)`; a direct environment variable of the same name wins over the blob |
| `DRIFT_ISSUE_URL` | Landing-zone issue URL, included in the notification payload |
| `DRIFT_ISSUE_TOKEN` | Token for publishing issues to a landing-zone repository. Falls back to `GITHUB_TOKEN` |
| `SLACK_WEBHOOK_URL` | **Legacy** single-channel fallback, used only when no team routing is configured |
| `TEAMS_WEBHOOK_URL` | **Legacy** single-channel fallback, as above |

Webhook URLs are bearer secrets — anyone holding one can post to the channel — so
they are never committed in plaintext. See [Secret-Backed Webhooks](#secret-backed-webhooks).

`GITHUB_TOKEN`, `GITHUB_API_URL` and `GITHUB_OUTPUT` are supplied by GitHub
Actions and need no configuration.

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
| `ANTHROPIC_API_KEY` | Narrative analysis, when `DRIFT_LLM_PROVIDER=anthropic` (the default). Not used by `azure_openai` |
| *(none — Entra)* | With `DRIFT_LLM_PROVIDER=azure_openai` and no `AZURE_OPENAI_API_KEY`, the analysis needs **no stored secret at all**: it authenticates with the same OIDC workload identity used for every other Azure call. Requires `pip install openai` and the `Cognitive Services OpenAI User` role |

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
- [RESOURCE_GROUP_TARGETING.md](RESOURCE_GROUP_TARGETING.md) — How the agent chooses which resource groups to scan
- [AZURE_AUTHENTICATION.md](AZURE_AUTHENTICATION.md) - Azure authentication configuration
- [SECURITY.md](SECURITY.md) - Security 
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) - Runbook for Operations team
