# Test Estate

The Azure resources the agent is verified against, and how to run a verification
round. Companion to `VALIDATION_STATUS.md`, which records what each round proved.

> **Reference only — this estate is a separate repository and does not move with
> the agent.**
>
> `drift-test-resources` is deliberately kept apart from the agent: it is a
> throwaway estate for verification, not a deliverable, and it is not migrated
> alongside this repo. What is portable here is the **method** — the round
> procedure below, and the composition principles that make an estate useful for
> verification. An adopting organisation needs its own estate, registered in its
> own `lz-index.yml`.
>
> Treat the specific module names, resource groups and landing-zone entries below
> as a worked example of an estate that has exercised these capabilities, not as
> something to expect in this repository.

**Repository:** `drift-test-resources` (registered in `.github/lz-index.yml` as
`test-resources`, `vhub-test`, `test-stack-resources` and `database-testing`).

**Resource group:** `rg-drift-test` — a throwaway estate, deployed for a round and
torn down afterwards. It is not always up: a scan against a torn-down estate now
aborts with exit 2 rather than reporting the template as deleted (see
`OPERATIONS_RUNBOOK.md`).

---

## Composition

`bicep/main.bicep` composes 34 modules. Roughly two-thirds deploy on every round;
the rest are gated behind parameters because they are slow, expensive, or both.

### Always deployed

| Module | Exercises |
|---|---|
| `storage.bicep` | Storage account, blob/file services, container, share |
| `appservice.bicep` | App Service plan + site + `config/appsettings` |
| `functionapp.bicep` | Consumption plan, function app, `siteConfig` |
| `keyvault.bicep` | Key Vault, `networkAcls`, access policies, `CanNotDelete` lock, diagnostic settings |
| `sql.bicep` | SQL server, database, firewall rules |
| `postgres.bicep` | PostgreSQL flexible server |
| `storage.bicep` / `loganalytics.bicep` | Workspace + declared custom table |
| `eventhub.bicep` | Namespace, hub, consumer group, auth rule |
| `eventgrid.bicep` | Topic + system topic, both with subscriptions |
| `messaging-dns.bicep` | Service Bus queue/topic, VNet, NSG, route table, DNS zones |
| `privateendpoints.bicep` | Private endpoint, private DNS zone, zone group |
| `identity.bicep` | User-assigned identity, federated credential |
| `rbac.bicep` | Role assignments (incl. policy remediation grants) |
| `policy.bicep` | Policy assignments — audit + two inherit-tag Modify effects |
| `monitoring.bicep` | Action group, metric alert, data collection rule |
| `recoveryservices.bicep` | Recovery Services vault, backup config, backup policy |
| `containerapp.bicep` | Container Apps environment + app |
| `acr.bicep`, `aci.bicep` | Container registry, container group |
| `ai.bicep` | AI Services account, model deployment, RAI policy, Foundry project |
| `logicapp.bicep` | Logic App workflow |
| `waf.bicep` | WAF policy (standalone — free) |
| `firewall.bicep` | Firewall **policy** + rule collection groups (policy only, no firewall) |
| `compute.bicep` | VMSS at capacity 0, managed disk, availability set |
| `publicip.bicep` | Public IP |
| `storage.bicep` | Traffic Manager profile, public DNS zone |

### Condition-gated (off by default)

From `parameters.json`; they appear in every scan's `condition_skipped` list,
which is why a gated module is **not** reported as an unmanaged extra:

| Parameter | Gates | Why off |
|---|---|---|
| `deployAks` | AKS cluster + agent pools | Cost, slow provisioning |
| `deployCosmos` | Cosmos account, SQL database, containers | Cost |
| `deployVirtualMachine` | VM + extensions, NIC | Cost |
| `deployNetworkAppliances` | App Gateway, Load Balancer, Front Door, CDN | Cost, slow |
| `deployFirewall` | Azure Firewall + its VNet | Expensive |
| `deployHubFirewall` / `deployVirtualHub` | Virtual WAN, hub, route tables, routing intent | Expensive, tens of minutes |

Gated modules still have comparators and unit tests; they are **not established**
live (see `VALIDATION_STATUS.md`).

### Separate fixtures

- `bicep/test-stack/` — deployment-stack fixture. Needs an `az stack` deploy path
  that does not exist yet, which is why stacks are unit-tested only.
- `bicep/vhub.bicep` — Virtual WAN hub routing, run as its own landing zone
  (`vhub-test`) on a branch, with its own config.

---

## Running a verification round

The round is what promotes a capability from *live-clean* to *live-proven*.

Deploy the estate (from the estate repository root):

```bash
az group create --name rg-drift-test --location australiaeast
az deployment group create \
  --resource-group rg-drift-test \
  --template-file bicep/main.bicep \
  --parameters @bicep/parameters.json
```

Add any gating parameter the capability under test needs, e.g.
`--parameters deployAks=true`. Tear down with
`az group delete --name rg-drift-test --yes`.

CI equivalents live in the estate repo: `.github/workflows/drift-lz-deploy.yml`
(deploy on push to `main`) and `.github/workflows/deploy-stack.yml`
(deployment-stack fixture, deploy and teardown via `workflow_dispatch`).

1. **Deploy** the estate (and set any gating parameter the capability needs).
2. **Baseline scan** — confirm zero drift. A non-empty baseline means the estate
   or the ignore profile is wrong; fix that before injecting.
3. **Inject** one drift, out of band (portal or CLI, *not* the pipeline identity,
   so attribution is exercised too).
4. **Detect** — run `analyze_drift.py`, confirm the finding, its severity, its
   owner tag and its attribution.
5. **Notify** — confirm the finding routed to the expected channel.
6. **Revert** the injection.
7. **Clean** — re-scan and confirm the estate returns to zero drift. Skipping this
   step is how a comparator that fires on *everything* passes a round.
8. Record the date and outcome in `VALIDATION_STATUS.md`.

Set `DRIFT_AUTHORIZED_DEPLOYERS` to the pipeline principal for local runs, or the
deploying identity's own writes are misclassified as manual changes.

---

## The platform landing-zone estate

`rg-drift-test` cannot exercise everything. Three capabilities are only
observable on a **subscription-scoped landing zone composed of Bicep modules**,
because they are properties of that shape rather than of any resource type:

| Capability | Why `rg-drift-test` cannot show it |
|---|---|
| Ownership by declaring module | Needs a module-composed template; the fixture estate is flat |
| Platform-vs-workload routing on a platform LZ | Needs an estate whose owner is *not* the type-heuristic default |
| Private-endpoint evidence on a drifted resource | Needs a resource with a live PE terminating on it |

Estate: `azure-landingzone-bicep`, `envs/prod`, deployed to `sub-lz-bicep` and
registered as the `landingzone-prod` landing zone. Deploy with the repo's own
`prod.yml` workflow rather than a local `az deployment sub create` — it runs as
the pipeline identity, so `authorized_deployment` attribution is exercised the
way a real run sees it.

### The five-injection set

Chosen so the *correct remediation differs per case*, which is what tests advice
rather than detection. All are free-tier and reversible.

| # | Injection | Correct remediation | The plausible wrong answer |
|---|---|---|---|
| 1 | Create an NSG not in the template | Explicit `az network nsg delete` — **a redeploy does nothing** | "redeploy to remove it" |
| 2 | Add an allow-any RDP rule to a declared NSG | A redeploy **does** remove it: `securityRules` is a declared set | Treating it like #1 |
| 3 | Storage `allowBlobPublicAccess=true` + `httpsOnly=false` | Redeploy. Two properties, ONE resource, so one finding | Splitting it into two findings |
| 4 | Key Vault `publicNetworkAccess=Enabled` | Redeploy — and the private endpoint makes closing it safe | Hedging, or missing the PE |
| 5 | A custom Modify policy that rewrites a declared tag | **Reverting is futile** — fix the template or the policy | "redeploy to restore the tag" |

**1 versus 2 is the discriminating pair.** Both read as "an NSG thing appeared"
and their correct fixes are opposites.

**TLS 1.0/1.1 is no longer injectable.** Azure retired it platform-wide on
2026-02-03 and silently coerces to TLS1_2; `httpsOnly=false` is the working
substitute for a transport-security downgrade.

**Force a Modify effect with a resource WRITE, not a remediation task.** A
compliance scan can take tens of minutes; touching a tag on the resource applies
the effect in seconds, and is how the effect fires in production anyway.

### Estate state, 2026-08-08

Verified against Azure at the time of writing, because this page tells you what
to deploy and a stale claim here wastes a round:

| Estate | State |
|---|---|
| `jacquiprod-*` (prod LZ, `sub-lz-bicep`) | **Partial** — `rg-platform` and `rg-networking` only. `rg-apps` and `rg-logging` were deleted 03:43-04:02; a `rg-networking` delete was attempted and FAILED, which is why it survives |
| `jacquidev-*` (dev LZ, `bd48a22c`) | **Gone** |
| `rg-drift-test` | **Gone** |

Any round starts by redeploying. A partially-deleted estate is the worst
starting point of the three, because a scan against it returns plausible-looking
`missing_in_azure` findings that are all true and none of them the thing under
test.

Key Vault names block redeployment after teardown: the name is reserved for the
soft-delete retention window, and `take(uniqueString(resourceGroup().id), 6)` is
deterministic, so recreating the resource group regenerates the identical name.
`az keyvault list-deleted` then `purge` (or `recover`) before redeploying, or the
deployment fails with the vault half-created — which is exactly the
`create / Started` with no completion that `unfinished_operation` exists to
explain.

### The estate must hold still

Two attempts at this round produced nothing because the estate was torn down
mid-test — which makes "the report said something wrong" indistinguishable from
"the estate moved". The procedure above already says baseline first and re-scan
last; the point worth adding is that **a round whose estate changes underneath
it is void, not inconclusive.** Take the clean baseline immediately before
injecting, and treat any finding outside the injected set as a false positive
with nowhere to hide.

---

## Pending injections

The current backlog, highest value first. Each corresponds to a *live-clean* or
*unit-tested* row in `VALIDATION_STATUS.md`.

Items 1–5 were **run on 2026-08-02**; results in `VALIDATION_STATUS.md`. Only 6
and 7 remain.

| # | Injection | Proves | Status |
|---|---|---|---|
| 1 | Shorten `drift-vm-daily` retention 30 → 7 days | Backup **policy** detection — the capability that was silently dead | ✅ **live-proven** 2026-08-02 |
| 2 | Disable vault soft delete | Backup **config** detection | ⛔ **unreachable** — Azure rejected (`BMSUserErrorDisablingSoftDeleteStateNotAllowed`), as predicted. Needs a non-hardened vault to ever prove |
| 3 | Delete a rule from `rcg-network`, or drop its priority | Firewall rule collection group detection | ✅ **live-proven** 2026-08-02 |
| 4 | VMSS `sku.capacity` 0 → 1, or remove a zone | Compute detection, incl. the zones-subset trap | ⚠️ detection proven (zones correctly silent); **attribution defect** found |
| 5 | Grant a role to `id-drift-test` out of band | RBAC detection + grantor provenance | ❌ **failed** — false negative + false positive; `privileged` and `created_by` do work |
| 6 | Delete one RG from a **subscription-scoped** LZ | One RG finding with attributed orphans, not N loose deletions (#369) | ✅ **live-proven 2026-08-04** — after fixing **seven** defects it exposed (PRs #382/#384/#385/#387/#388). See VALIDATION_STATUS. |
| 7 | Leave both policy remediation grants unresolved | Colliding role-assignment rows render distinctly (#370) | ⛔ attempted 2026-08-03 — **blocked**, see "Resource Graph keeps phantoms" |

Item 6 needs a subscription-scoped landing zone (`azure-landingzone-bicep`,
`envs/dev`), not `rg-drift-test`. **That LZ was torn down on 2026-08-04** once
item 6 passed; re-running it (or item 7 against a sub-scoped estate) means
`az deployment sub create` against `envs/dev/main.bicep` first. The bicep is all
committed, including the platform RG contents added in LZ PR #7.

**First contact with a new SCOPE behaves like first contact with a new resource
type.** Every prior round here was resource-group scoped. The first
subscription-scoped run found seven defects, one of which (attribution dead for
every `*` selector) had been silently wrong for both landing zones in
`lz-index.yml` since they were configured. Assume defects, not confirmation.

**Item 7 does not.** It was parked here for a long time on the assumption that it
needed a subscription-scoped LZ, and that is wrong: what it needs is *two
colliding role-assignment declarations whose principals are unresolvable*, and
`rg-drift-test` has had exactly that all along — the two policy-remediation
Contributors for `drift-inherit-costcentre` and `drift-inherit-environment`. Both
compile to an unresolvable `guid()`, both grant the same role, and both take
`principalId` from `reference(...).identity.principalId`. Delete both live grants
and they should surface as two `missing_in_azure` rows sharing one name.

Neither `azure-landingzone-bicep` nor `azure-alz-avm` can run item 7 at all —
**neither declares a single role assignment.**

Note on 4: a live VMSS's `zones` are immutable, so "remove a zone" is not
performable in-place — capacity is the only usable compute injection here.

### Resource Graph keeps phantoms — RBAC injections race the index

**The RBAC sidecar does not read the API you verify with.** `tools/rbac.py`
queries Resource Graph's `authorizationresources`; `az role assignment list`
queries ARM. They disagree, and Resource Graph keeps assignments **after ARM has
dropped them**.

This blocked item 7 on 2026-08-03. Both policy-remediation Contributors were
deleted and `az` confirmed one assignment left. The scan still reported three:

| Principal | Role | ARM | Resource Graph |
|---|---|---|---|
| current `id-drift-test` | Monitoring Reader | yes | yes |
| **previous** `id-drift-test` | Monitoring Reader | no | **still indexed** |
| **previous** `id-drift-test` | Contributor | no | **still indexed** |

Both phantoms pointed at a principal a redeploy had replaced ~21 hours earlier.
The phantom Contributor matched one of the two unresolved declarations through
the role-only fallback, so only **one** row came back missing — and one row
cannot collide, so the disambiguation under test never ran. Every number in the
log (`3 in scan scope`, `1 extra, 1 missing`, `Ignoring 1 RBAC drift`) was
correct for the data the comparator was handed.

The phantoms cannot be cleared by hand. `az` cannot even resolve the principal
("Cannot find user or service principal in graph database") and the ARM REST call
at scope does not list them; there is nothing to delete. They age out.

**Before any RBAC injection, check the sidecar's own data source:**

```bash
az graph query -q "authorizationresources
  | where tolower(properties.scope) contains '/resourcegroups/rg-drift-test'
  | project tostring(properties.principalId), tostring(properties.roleDefinitionId)"
```

`az role assignment list` reflecting your injection is **not** evidence the scan
will see it. This is also why PR #299 exists — orphans from prior deploy cycles
are a standing feature of this estate, not an anomaly.

### Two estate gotchas found running this round

- **The tag fixture is time-dependent.** The inherit-tag Modify only imposes
  `environment=production` at write time, and a freshly recreated policy
  assignment's identity needs its remediation role to propagate first. Straight
  after a deploy, 29 of 44 resources still read `environment=test` and the
  policy-vs-Bicep conflict simply had not been imposed yet. The
  policy-enforced count is therefore **not a stable number** to assert a baseline
  against — gate the baseline on *actionable* drift only.
- **Runtime identities change across deploys.** A redeploy recreated
  `id-drift-test` with a new `principalId`. Any snapshot or fixture keyed on a
  principal ID goes stale; re-read it at injection time.
