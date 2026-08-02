# Test Estate

The Azure resources the agent is verified against, and how to run a verification
round. Companion to `VALIDATION_STATUS.md`, which records what each round proved.

**Repository:** `jaxywaxy/drift-test-resources` (registered in
`.github/lz-index.yml` as `test-resources`, `vhub-test`, `test-stack-resources`
and `database-testing`).

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
Deploy and teardown commands live in the estate repo's `CLAUDE.md`.

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

## Pending injections

The current backlog, highest value first. Each corresponds to a *live-clean* or
*unit-tested* row in `VALIDATION_STATUS.md`.

| # | Injection | Proves |
|---|---|---|
| 1 | Shorten `drift-vm-daily` retention 30 → 7 days | Backup **policy** detection — the capability that was silently dead |
| 2 | Disable vault soft delete | Backup **config** detection. Expect Azure to *reject* this on a hardened vault (`BMSUserErrorDisablingSoftDeleteStateNotAllowed`) — confirm the rejection rather than assuming coverage |
| 3 | Delete a rule from `rcg-network`, or drop its priority | Firewall rule collection group detection |
| 4 | VMSS `sku.capacity` 0 → 1, or remove a zone | Compute detection, incl. the zones-subset trap |
| 5 | Grant a role to `id-drift-test` out of band | RBAC detection + grantor provenance |
| 6 | Delete one RG from a **subscription-scoped** LZ | One RG finding with attributed orphans, not N loose deletions (#369) |
| 7 | Leave both policy remediation grants unresolved | Colliding role-assignment rows render distinctly (#370) |

Items 6 and 7 need a subscription-scoped landing zone (`azure-landingzone-bicep`,
`envs/dev`), not `rg-drift-test`.
