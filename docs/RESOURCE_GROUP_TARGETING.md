# Resource Group Targeting

How the agent decides **which resource groups to scan** for a given Bicep template.

Getting this wrong is the single most common cause of noisy reports — a template diffed against a resource group it doesn't own surfaces every other resource as `extra_in_azure`, and a template diffed against a resource group that never held it surfaces everything as `missing_in_azure`. Neither is drift.

---

## The rule

> **The agent determines the resource groups from the Bicep when the Bicep knows them (subscription scope); otherwise the resource groups must be configured, because an RG-scoped template genuinely doesn't know where it lives.**

Everything below follows from that one distinction.

| Template scope | Does the template know its RGs? | How targets are chosen |
|----------------|--------------------------------|------------------------|
| Subscription-scoped (`targetScope = 'subscription'`) | **Yes** — it declares `resourceGroups` resources and sets module `scope:` | Discovered from the template. One subscription-wide pass matches across all of them. Config `resource_groups` acts only as an optional **filter**. |
| Resource-group-scoped (default) | **No** — `resourceGroup()` resolves at deploy time | **Must be configured.** The template contains no RG name to discover, so targets come from config (or an override). |

---

## Subscription-scoped templates

The template already names its resource groups, so the agent runs **one subscription-wide pass** and matches resources across all of them.

`resource_groups` in the config is a **filter, not a target list** — a glob like `contosodev-*` narrows the pass to matching RGs. The reusable workflow (`drift-check-lz-hybrid.yml`) deliberately passes the selector through **unexpanded** for this case: expanding it into individual RGs would compare each RG against the *whole* template and manufacture false `missing_in_azure`.

---

## RG-scoped templates

`resourceGroup()` is resolved by Azure at deploy time, so the template has no idea where it lives. Targets **must** be configured. The config chain, from the caller inward:

```
caller workflow (e.g. drift-lz-landingzone.yml)
  names a landing zone
        │
        ▼
bicep-drift-agent/.github/lz-index.yml
  maps  landing-zone name → { repo, config_path, workflow }
        │
        ▼
<LZ repo>/.github/drift-lz-config.yml   (lives NEXT TO the bicep, owned by the LZ team)
  carries  path (bicep entry point) + resource_groups (list or globs)
        │
        ▼
tools/rg_selector.py
  expands the selectors against the live `az group list`
```

Design intent: **the RG mapping lives next to the Bicep, owned by the landing-zone team** — not centrally in the agent.

For RG-scoped templates the selectors *are* expanded (unlike the subscription-scoped case): each resolved RG becomes its own scan target.

### Escape hatches

| Mechanism | Use |
|-----------|-----|
| `override_resource_group` workflow_dispatch input | Overrides the configured RG for a single manual run. |
| Local CLI argument | `python analyze_drift.py <template> <resource-group>` targets one RG directly for local runs. |

---

## Worked example — a Virtual WAN hub check

`bicep/vhub.bicep` in `myorg/platform-bicep` is **RG-scoped**, so its resource groups must be configured. It also uses **static resource names** (no `uniqueString`), so it can live in a dedicated RG safely.

`lz-index.yml`:

```yaml
hub-routing:
  repo: myorg/platform-bicep
  config_path: .github/drift-lz-vhub-config.yml
  workflow: drift-lz-hub-routing.yml
```

`platform-bicep/.github/drift-lz-vhub-config.yml`:

```yaml
checks:
  - name: Virtual Hub Routing
    path: bicep/vhub.bicep
    params:
      deployVirtualHub: true
      deployHubFirewall: true
    resource_groups:
      - rg-hub-routing       # dedicated RG — NOT the shared platform RG
```

`vhub.bicep` is a **subset** template. Pointing it at the shared `rg-platform` (which holds the full `main.bicep` estate) makes every non-vHub resource surface as `extra_in_azure` — a scope mismatch, not drift. Giving it its own resource group is the fix.

---

## What a resource group *is*, per scope

Enterprise estates run both shapes, and a resource group means something
different in each. This is not a detail — it decides whether a missing RG is a
pipeline failure or a finding.

| Scope | A resource group is… | Missing → |
|---|---|---|
| Resource group | the **frame** of the scan. An RG-scoped template cannot declare one | Scan aborts, **exit 2** — a targeting failure, not drift |
| Subscription | a **declared resource** the template owns (CAF platform landing zones declare theirs) | Reported as **drift** on the resource group, with its orphaned contents attributed to it |

At subscription scope the empty case is the abort case instead: a scan that
returns **no resources at all** is a wrong subscription, a credential without read
access, or an environment never deployed — not a landing zone that was deleted
wholesale. One RG missing out of many is drift; none of them present aborts.

The reasoning behind the abort, and why an *unconfirmable* scope aborts as well as
an absent one, is in [CAPABILITIES.md](CAPABILITIES.md). Triage steps are in
[OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md).

## Caveats

- **`'*'` with an RG-scoped template compares the template against *every* RG in the subscription** → pure false-`missing` noise for RGs that never held it. (Local `'*'` mode skips the narrative analysis; workflow expansion runs the full pipeline — and cost — per RG. The estate-wipe guard makes all-missing RGs cheap to process, but the reports are still wrong-headed.) Prefer an explicit glob.
- **N resource groups listed for one RG-scoped template = N independent full pipelines.** Correct **only** when each RG is a full instance of the template (e.g. per-environment copies), not when they collectively make up one landing zone.
- **Deploy/scan name mismatch is a live footgun.** If the deploy targets `platform-<environment>` but the config says `rg-platform`, every resource reads as `missing_in_azure`. Keep the config selector in step with where the deploy actually lands — a glob such as `resource_groups: ['platform-*']` is more robust than a hard-coded name.
- **`uniqueString(resourceGroup().id)` changes with the RG name.** Moving an RG-scoped template to a different RG renames every `uniqueString`-seeded resource, which the agent reads as a full delete-and-recreate. Expected and harmless *if intentional* — but check whether a template uses `uniqueString` before relocating it. (`vhub.bicep` does not, so its move is name-safe.)

---

## Not yet built

**Deployment-history auto-targeting.** `az deployment group list` per RG reveals which template was last deployed there, so the agent could auto-discover targets for RG-scoped templates — and make "scan the whole subscription" safe by skipping RGs with no matching deployment. Backlog only.

---

## Related Documentation

- [README.md](../README.md)
- [CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md) — LZ config schema and options
- [LANDING_ZONES_OPERATIONS.md](LANDING_ZONES_OPERATIONS.md) — Landing Zone onboarding and operations
- [CAPABILITIES.md](CAPABILITIES.md)
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md)
