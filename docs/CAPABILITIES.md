# Bicep Drift Agent — Capabilities & Features

An automated agent that detects **configuration drift** between Bicep templates
(desired state) and live Azure (actual state), attributes each change to who or
what made it, routes findings to the team that owns them, and delivers
AI-generated remediation guidance. Runs as scheduled GitHub Actions against any
number of landing zones from one central repo.

## Core Pipeline

1. **Compile & resolve** — Bicep → ARM, parameter resolution
   (`.bicepparam` / `parameters.json` / env), subscription- or RG-scoped
   templates auto-detected.
2. **Live state** — Azure Resource Graph for speed, augmented via ARM REST for
   everything the Graph doesn't index: management locks, Cosmos SQL
   databases/containers, AI model deployments / RAI policies / Foundry
   projects & connections, VNet peerings (expanded from properties),
   cross-subscription resources (vending templates).
3. **Deterministic diff** — three drift classes: `missing_in_azure`,
   `extra_in_azure` (incl. orphaned/unmanaged cost), `property_drift`
   (property-level, severity-rated, security paths flagged **critical**).
4. **AI analysis (optional)** — Claude-generated per-drift remediation
   recommendations and a narrative report; all deterministic detection runs
   without an API key.
5. **Report & notify** — JSON + styled HTML reports, grep-able CI summaries,
   Slack/Teams notifications.

## Intelligent Matching (no false positives from generated names)

- **Smart matching** for runtime-generated names (`uniqueString`, `guid`,
  placeholders) — matched by type + prefix/suffix, then property-compared.
- Parent-qualified child names, case-insensitive types/locations/resource ids,
  null-vs-default normalization (networkAcls), Azure read-only augmentation
  tolerated via bicep-driven subset comparison, write-only secrets never
  compared (or leaked into reports).
- **Layered ignore profiles** — agent baseline (universal Azure noise) merged
  with each landing zone's own `.drift-ignore` (type-, name-, and
  property-scoped patterns).

## Change Attribution (Phase 3)

- Activity Log correlation: **who changed it, when, and how** for each drift.
- Azure Policy awareness: DINE/Modify/remediation writes (by policy managed
  identities) are split out as *expected governance*, not actionable drift —
  while a human writing a policy object stays actionable.
- Terraform/system-managed callers identified.

## Governance & Security Drift (identity-matched, not name-matched)

- **RBAC role assignments** — out-of-band grants with grantor + timestamp from
  the RBAC API (no log-retention limit); privileged roles (Owner, Contributor,
  UAA, RBAC Admin) flagged `⚠️ PRIVILEGED`.
- **Policy assignments & exemptions** — out-of-band assignments with
  provenance; exemptions flagged as audit-critical waivers with expiry.
- **Key Vault / Storage / AI accounts** — networkAcls (defaultAction flips,
  hand-added ipRules/vnet rules as exact sets), Key Vault access policies
  (per-principal, permissions as sets).
- **AI resources** — model deployments (version pinning, TPM capacity bumps),
  custom content-filter (RAI) policy loosening per name+source, Foundry
  projects/connections.

## Landing-Zone Operations (CAF/ALZ)

- One central agent scans many LZs (`lz-index.yml`): per-LZ repo, config,
  schedule; subscription-scoped scans with RG wildcards/globs.
- **Owner routing** — every drift tagged `platform` or `workload` (network
  fabric vs app resources, with NSG-rule and grant-scope nuances) and routed
  to the right team's channel.
- **Notifications** — multi-team Slack/Teams with per-team drift-type +
  owner filters, custom templates, webhook URLs referenced as
  `${DRIFT_WEBHOOK_*}` secrets (never plaintext; redirects treated as
  delivery failures).

## Quality & Safety

- 216 unit tests (stdlib, no Azure needed); every capability additionally
  verified live end-to-end (introduce drift → detect → notify → revert → clean).
- Fail-soft data collection (a blocked API never kills the scan); kill
  switches per subsystem (`INCLUDE_ROLE_ASSIGNMENTS`,
  `INCLUDE_POLICY_ASSIGNMENTS`); GitHub OIDC to Azure (no stored credentials).

## Coverage Summary

Everything in Azure Resource Graph plus expanded children — live-validated on:
storage, App Service, Key Vault, Logic Apps, Log Analytics, Event Hubs,
Cosmos DB (+children), ACR, ACI, SQL Server/DB, Azure OpenAI / AI Services /
Foundry (+children), Service Bus, Traffic Manager, DNS zones, Monitor
action groups & metric alerts, VNets/subnets/peerings/NSGs/route tables/NAT,
private endpoints, locks, RBAC, and Azure Policy. Newer additions handled but
not yet live-verified: load balancers and Application Gateways (+ WAF policy;
owner-tagged platform, WAF mode / SSL-min-version critical), Front Door
Standard/Premium (+ endpoints/origin groups/origins/routes/security policies;
route TLS-downgrade flagged critical), SQL firewall rules, Data Collection
Rules + DCR associations (silenced-telemetry drift), diagnostic settings,
Defender pricings, and Container Apps (ingress exposure flagged critical).
