# Validation Status

What has actually been proven, and how. This page exists because "validated" was
being used for three different things.

`CAPABILITIES.md` describes what the agent *can* detect. This page states, per
capability, **what evidence backs that claim** — so a platform team can tell a
comparator that has caught real drift from one that has only ever been run
against a clean estate.

---

## Why this page exists

A comparator can ship, be documented as covered, and produce nothing — silently.
Both Recovery Services backup comparators were dead in the pipeline for roughly a
month: baseline `.drift-ignore` rules discarded every drift they produced, and
**nothing looked wrong because the fixture vault happened to be clean**
(see `CAPABILITIES.md`, "Recovery Services vault backup config"). A flat
"Fully Validated" list cannot express that failure, so it hid it.

The structural guard added afterwards
(`tests/test_ignore_patterns.py::CollectedTypesAreNotBlanketIgnoredTests`) stops
that *specific* recurrence by deriving the collected types from the collectors
themselves. This page is the other half: it refuses to record an unproven
capability as proven.

---

## Tiers

| Tier | Means | Evidence |
|---|---|---|
| **Live-proven** | Drift introduced → detected → reverted → clean, against real Azure | A dated round or PR |
| **Live-clean** | Deployed and compared against real Azure; no drift found | A dated scan. Proves **no false positives** — proves nothing about detection |
| **Unit-tested** | Comparator plus tests; never exercised against live Azure | A test module |
| **Not established** | No evidence located | — |

**Live-clean is not a weaker version of live-proven — it is a different claim.**
A comparator that is silently dead and a comparator that is working correctly both
produce zero findings against a clean estate. Only an injected drift separates
them.

> **Provenance.** Entries below were reconstructed from commit and PR history plus
> the 2026-08-01 live run. Where a PR number is cited it is the best available
> reference, not an audit. If an entry is disputed, the resolution is to run the
> injection round for that capability — not to argue about the citation.

> **Most of the estates these rounds ran against were not migrated with this
> repository.** Every claim below remains true — the drift *was* injected and
> detected on the date given — but most of it cannot be re-verified until the
> estate in question is rebuilt. Estate names, resource groups and subscriptions
> are retained deliberately: an unciteable claim is indistinguishable from an
> unproven one, and stripping them would leave a tier table that cannot be
> audited.
>
> The exception is the `test-resources` fixture, re-registered on 2026-08-14
> (#434) for the schema-flag round below, and the prod landing zone, which is a
> standing estate. Both are scannable; the fixture's estate is deployed per round
> and torn down after.
>
> Read the evidence column as *what was done and when*, not as somewhere you can
> go and look. `TEST_ESTATE.md` is the method for rebuilding an estate capable of
> re-proving any row here.

---

## Detection — resource coverage

### Live-proven

| Capability | Evidence |
|---|---|
| Storage accounts (`accessTier` and related) | 2026-08-01 run — Hot→Cold detected |
| App Service (`kind`, `siteConfig`, plan, appsettings) | 2026-08-01 run — wrong-kind + missing plan detected |
| Management locks | 2026-08-01 run — `CanNotDelete` deletion detected |
| Azure OpenAI / AI Services, deployments, RAI policies, Foundry projects | PRs #181–182 |
| WAF policies | PR #232 |
| Virtual Hub routing (`hubRouteTables`, `routingIntent`) | PR #304 |
| Key Vault `networkAcls` + access policies (exact-set) | PR #178 |
| Policy assignments and exemptions | PRs #187–188 |
| AKS security posture + 9 generalised types | PRs #210–217 |
| Private DNS zone groups, Log Analytics workspace tables | #329 |
| NSGs and route tables | PR #229 |
| Event Grid, Service Bus, Container Apps, federated credentials | PR #231 round (6/6 injections detected) |
| Function Apps | #233 / #234 round |
| Recovery Services vault backup **policies** | 2026-08-02 round — retention 30→7 detected `critical`, attributed to the out-of-band actor, reverted clean |
| Azure Firewall rule collection groups | 2026-08-02 round — `ruleCollections[net-deny-smb]` removal detected `critical`, name-keyed (not positional), `owner: platform`, reverted clean |
| Compute — VMSS capacity | 2026-08-02 round — `sku.capacity` 0→1 detected `critical`; `zones` correctly stayed silent (no subset false positive). Attribution failed on that round and was fixed in #375; **re-proven adversarially 2026-08-03** — actor named correctly with a caller-less health event newer than the write |
| SQL databases (child deletion) | 2026-08-11 RG round — `sqldrift…/driftdb` deleted, reported `missing_in_azure` / `high` / `manual_change` under **its own name** with the real `deleted_at`. Took three PRs (#425–427) to get there; see the round below |
| Storage `supportsHttpsTrafficOnly`, Firewall `threatIntelMode`, WAF `policySettings.mode` | 2026-08-11 RG round — all three detected `critical`, attributed to the out-of-band actor |

### Live-clean only — detection unproven

| Capability | Live resources compared |
|---|---|
| Compute — disks, availability sets | 1 each |

### Unreachable — cannot be proven on this estate

| Capability | Why |
|---|---|
| Recovery Services vault backup **config** | 2026-08-02: Azure **rejects** the injection — `BMSUserErrorDisablingSoftDeleteStateNotAllowed`. The template declares `enhancedSecurityState: Enabled` and `softDeleteFeatureState: Enabled`; both are already at hardened values Azure refuses to lower, so no permitted write makes this drift exist. Proving it needs a deliberately non-hardened vault in the estate. |

Note: `isSoftDeleteFeatureStateEditable` reports `true` on this vault and does
**not** predict whether the operation is permitted. Do not use it to decide
whether this test is runnable.

### RBAC — both grantee shapes now live-proven

| Grantee | Result |
|---|---|
| A principal the template does **not** reference | **Live-proven 2026-07-06** — `Contributor -> User:70afebf7…`, privileged + provenance + routing all correct |
| A deployed MI the template **already declares another role for** | **Failure mode found and fixed 2026-08-02.** Granting `Contributor` to `id-drift-test` (which the template declares `Monitoring Reader` for) produced a false negative *and* a false positive. Fixed by the `created_by` preference tier; **live-verified on the identical condition**: exactly one role row, naming the real grant, `privileged: true`, `created_by` the human actor, `owner: workload`, neither policy-remediation Contributor flagged, zero ignored role rows |

Why the second shape was hard: the template declares its policy-remediation
Contributors with `principalId: reference(...).identity.principalId`, unresolvable
at compile time, so Pass 2 matches on role GUID alone. PR #299 taught it to prefer
a *deployed* principal over a *deleted* one — which cannot disambiguate when every
candidate is deployed. Pass 2 now prefers a live assignment whose `created_by` is
an authorized deployer first, using evidence already on the emitted row.

Still ambiguous by construction: a grant made **through** the pipeline identity
itself. No ordering can separate that from a declared one, and the fix does not
pretend to.

### Defects found by the 2026-08-02 injection round — all fixed

All the same recurring shape (cf. #325 / #327 / #336 / #343): **a heuristic
overrides evidence the pipeline already holds**. Each has a reproducer.

| # | Defect | Fix | Live status |
|---|---|---|---|
| 1 | Health telemetry outranks the real write | **#375** | **Adversarially proven** 2026-08-03 |
| 1b | `manual_change` with a blank actor | **#377** | Invariant holds; **no positive trigger** — see below |
| 2 | RBAC mis-binds among deployed principals | **#376** | **Adversarially proven** 2026-08-03, locally and in CI |

**1. Health telemetry outranks the real write, erasing the actor.**
*(fixed by #375; **adversarially live-proven 2026-08-03**)*
`select_relevant_activity` (`tools/change_origin.py`) classifies an operation as
a config write with `"update" in op`. That substring matches
`Microsoft.Resourcehealth/healthevent/**Updated**/action` — platform telemetry
emitted continuously by every VM and scale-set instance, carrying `caller: None`.
It is newer than the user's `virtualMachineScaleSets/write`, wins the latest-first
sort, and the drift is reported `manual_change` / `out_of_band` / severity `high`
with a **blank actor** — while the correct actor sits in the same event list.
Defeats out-of-band attribution and owner-routing on any compute resource.

```python
events = [
  {'operation':'Microsoft.Compute/virtualMachineScaleSets/write','timestamp':'...14.288Z','actor':'user@example.com','status':'Succeeded'},
  {'operation':'Microsoft.Resourcehealth/healthevent/Updated/action','timestamp':'...19.608Z','actor':None,'status':'Succeeded'},
]
select_relevant_activity(events, 'property_drift')  # -> the healthevent, actor None
```

**How it was finally proven (2026-08-03).** Two earlier attempts failed to be
adversarial: Azure emitted `healthevent/Resolved/action`, which contains none of
the matched keywords, so the *old* code would have rejected it too — a passing
scan there proved only that nothing regressed. **Which health verb fires is
Azure's choice, not ours**, so the round has to wait for the condition rather
than assume it. Poll the Activity Log until a caller-less `.../Updated/action`
is **newer than** the write, then scan.

Once the condition held, both branches were replayed over the *same captured
events* — the strongest available evidence, because nothing but the predicate
differs:

| Selection logic | Candidates | Selected | Actor |
|---|---|---|---|
| OLD (substring) | 8 | `Resourcehealth/healthevent/Updated/action` | `None` |
| NEW (segments) | 3 | `virtualMachineScaleSets/write` | `jacqui.anker@gmail.com` |

The end-to-end scan agreed: `sku.capacity 0→1 critical`, attributed to the real
actor at the write's timestamp, not the health event 11 minutes later.

**1b. …and re-ordering events is not enough on its own.**
*(follow-up, fixed by #377)* The 2026-08-02 CI run still produced
`"reason": "Manual change by  (out-of-band)"` — note the blank — on
`sqldrift…/driftdb`, at severity `high` with `changed_by: ""`. The #375 fix only
re-orders *candidate* events; it cannot help when the single event that explains
the drift carries no caller at all. `manual_change` asserts a **person** acted,
so the actor claim is now withdrawn (`origin: unknown`, `changed_by: null`) while
category `out_of_band` and severity `high` are kept — an out-of-band change we
cannot attribute is still out-of-band. Dropping it to `medium` would hide a real
finding and collide with the #327 invariant that classification never downgrades.
The HTML badge was fixed in the same change: it keyed off `origin` alone, so
these rows would have rendered a neutral grey "Unknown" despite the row carrying
`high` / `out_of_band`.

**This one is NOT live-proven, and cannot be injected.** Its trigger is *Azure
declining to log a caller on a config write* — not something an operator can
cause. The 2026-08-03 round confirmed only the negative: across `drifts`,
`policy_enforced_drifts` and `ignored_drifts`, **no row** carried
`manual_change` with a blank actor. An absence is not a detection.

Two facts make a scheduled injection pointless. The original trigger
(`sqldrift…/driftdb`) had **aged out of the Activity Log window** — 50 events
retained, all SQL ones gone. And of the 43 caller-less events present, every one
was a health or `repairVM` action, none of which passes `is_write` after #375 —
so none can ever be selected as an explaining event. **Catch this one
opportunistically instead:** it appeared on a fresh deploy, when Azure writes SQL
children on your behalf, so check the first post-deploy report for
`changed_by: ""` rather than scheduling a round for it.

**2. Role assignments mis-bind among several *deployed* principals.**
The template declares its policy-remediation Contributors with
`principalId: reference(...).identity.principalId`, unresolvable at compile time,
so Pass 2 matches on role GUID alone. PR #299 made Pass 2 prefer a live
assignment whose principal is a currently-deployed managed identity — which
resolves deployed-vs-*deleted*, but **cannot disambiguate between several
deployed ones**. With 3 live Contributors at a scope (all deployed MIs) and 2
declared, it pairs two first-come-first-served and calls the leftover
`extra_in_azure`: it named a **declared, pipeline-created** assignment while the
genuine out-of-band grant went unreported.

The emitted row carries its own disproof — `created_by` is the authorized
pipeline identity and `created_on` is the deploy timestamp. Acting on it revokes
a role the tag-remediation policy needs, while the real privilege escalation
stays invisible. Confirmed by the clean re-scan: with live count back to 2 =
declared 2, the false positive disappears.

**Fixed by #376** and **live-verified against
the identical condition** (3 live Contributors, all deployed MIs, 2 declared):
Pass 2 gained a tier that prefers a live assignment whose `created_by` is an
authorized deployer, ahead of PR #299's deployed-principal tier. The result named
the real out-of-band grant and no declared one.

Two things the fix deliberately does not do. It passes `AUTHORIZED_DEPLOYERS`
**only** — never the scanning identity, because if whoever runs the scan counted
as a deployer, a role *they* granted out of band would be adopted as declared and
the finding would vanish. And with `DRIFT_AUTHORIZED_DEPLOYERS` unset the tier is
inert, so behaviour is unchanged for anyone not configuring it.

### Unit-tested only

| Capability | Tests |
|---|---|
| Subscription-scope resource groups (declared RG missing → drift, orphan attribution) | `tests/test_subscription_scope_resource_groups.py` |
| Role-assignment row identity (colliding unresolved principals) | `tests/test_rbac.py` |
| Unreadable scope / empty subscription guards | `tests/test_scope_not_found.py` |
| Deployment stacks | `tests/test_deployment_stacks.py` — the estate has no `az stack` deploy path yet |

### Not established

Cosmos DB children, Defender plans, Front Door, Application Gateway, Load
Balancers and the other condition-gated modules listed in `TEST_ESTATE.md`. They
have comparators and tests, but the estate gates them off, so no live scan has
exercised them.

---

## Pipeline capabilities

| Capability | Tier | Evidence |
|---|---|---|
| Activity Log attribution (who / when / how) | Live-proven | 2026-08-01 run — actors and timestamps matched the CI run event-for-event |
| Policy-enforced split (DINE/Modify vs actionable) | Live-proven | 2026-08-01 run — 5 actionable vs 35 policy-enforced |
| Smart matching (`uniqueString`/`guid`) | Live-proven | 2026-08-01 run — 34 resources reconciled |
| Owner routing (platform/workload → channel) | Live-proven | Phase 4, 2026-07-06; **re-proven 2026-08-08 after the ownership model changed** — `platform-team: 3 event(s)` / `app-team: 2 event(s)`, matching the module split exactly. The July evidence predated `ownership_model`/`module_owners`, which rewires the tag routing keys off |
| Deployer attribution (`DRIFT_AUTHORIZED_DEPLOYERS`) | Live-proven | 2026-08-01 — an unset variable reclassified two findings, confirming the path |
| Notifications (Slack/Teams) | Live-proven | Phase 4 owner-routing round |
| Narrative analysis | Live-proven | Present in the 2026-08-01 CI report (Anthropic) and the 2026-08-08 prod runs (Azure OpenAI) |
| Scope integrity (unreadable RG, empty subscription) | Unit-tested + partial live | The abort path was verified end-to-end against a deleted RG on 2026-08-02; the *recovery* path was not |

---

## Known unproven behaviours

Stated here rather than left implicit:

- **Backup detection.** Comparators run, have never caught anything live.
- **Custom Modify policy attribution.** Only Azure's two BUILT-IN inherit-tag
  definitions are recognised, so a custom Modify policy's imposed value is
  reported as ordinary actionable drift attributed to whoever wrote it
  (2026-08-08). The assignment is now surfaced to the narrative as evidence,
  which is a mitigation, not attribution.
- **A deleted resource group at subscription scope.** Implemented with tests and
  an orphan-attribution pass; no landing zone has been deleted to prove it.
- **Row-level attribution for colliding role assignments.** Rows are now distinct,
  but both still fall to the Activity Log type fallback and may adopt the same
  event. Identity is fixed; attribution is not.
- **The `revert → clean` half of several rounds.** Where a round is cited as
  detecting drift, re-verifying the *revert* is not always recorded. Now
  recorded for 2026-08-08: five injections reverted and `drift_count` returned
  to exactly the 3-grant baseline, no residue. Earlier rounds remain unverified
  on this half.

---

## Promoting a capability

Run the injection round in [TEST_ESTATE.md](TEST_ESTATE.md) — noting that the
estate it describes lives in a **separate repository that does not move with this
one**; an adopting organisation supplies its own. Deploy the estate, introduce the
drift, confirm detection and severity in the report, confirm the notification
routed, revert, confirm the scan returns clean. Then move the row here and cite
the date.

A capability moves **down** a tier if its comparator changes materially without a
new round.

---

## The 2026-08-03/04 subscription-scope round — seven defects

The agent's **first live run against a subscription-scoped landing zone**
(`azure-landingzone-bicep`, `envs/dev`). Every prior round was resource-group
scoped. Backlog item 6 — *delete one resource group, expect ONE finding with its
contents attributed to it* — now **passes**, after seven defects it exposed.

**The one to remember is #2.** Both landing zones in `lz-index.yml` are
subscription-scoped, so *every scheduled run of both* had been returning
completely unattributed reports — 15 of 15 rows `origin: unknown` behind
*"No activity log entries found (logs may have expired)"*, which is exactly what
a genuinely quiet subscription looks like. The suite was green throughout.

| # | Defect | PR |
|---|---|---|
| 1 | Top-level variables resolved WITHOUT their parameters, so a resource group named the ordinary way (`var loggingRgName = '${prefix}-rg-logging'`) stamped `_target_rg: 'None-rg-logging'` — matching no real group | #382 |
| 2 | **Attribution dead on every subscription-scoped scan** — the selector (`*` or a glob) went into the Activity Log `$filter` as a literal resource group name | #382 |
| 3 | Resource names rendered as their own ARM source (`toLower(format(...))`). Three layers: no `toLower`/`replace` branch, `resolve_expression` never routed there, and `extract_variables` resolved each variable against an EMPTY dict so one variable could never reference another | #382 |
| 4 | Smart matching's lone-candidate short-circuit paired ACROSS resource groups at `high` confidence — hiding a real deletion *and* orphaning the live resource into a false `missing_in_azure` | #382 |
| 5 | Orphan attribution ran in Phase 1; smart matching creates placeholder-named missing rows in Phase 2, so those could never be attributed | #384 |
| 6 | **A deleted resource group could never name its actor** — the scan selector was baked into the synthetic id, AND a resource group's real id has no `providers/` segment, so the exact match and the type fallback were both guaranteed to miss | #385 |
| 7 | Presentation: rows emitted in CREATION order split one deletion into three scattered findings; and `property_drifts` dropped placeholder-named rows, so the deleted storage account rendered once where literal-named findings rendered twice | #387 |

### Why resource-group scope was fine and subscription scope was not

Azure requires unique names **within** a resource group, so at RG scope the
discriminator is always in the NAME — which is what smart matching compares. At
subscription scope the same module deploys into several groups, producing
declarations with an identical name shape; the discriminator moves out of the
name and into `_target_rg`. And deleting a resource group — the very thing under
test — collapses the candidate pool from two to one, routing execution around the
guarded tie-breaker into the unchecked short-circuit.

RG scope is not immune to the family: #233 was the same shape (wrong sibling),
fixed with the leaf guard.

### What this round says about the guards

**Unit tests were green for all seven.** Three of them produced perfectly
plausible reports. The fixtures for #369 passed `variables={}` explicitly (so the
defaulting branch never ran) AND used a literal resource group name where
production uses a parameter — the reason 15 tests and a mutation check all passed
while the feature could not work.

`.github/workflows/drift-lz-verify.yml` + `.github/scripts/verify_lz_report.py`
exist because of this: they assert invariants on a **live report**, which unit
tests cannot. The guard then failed to catch #7 — it asserted orphans were
LINKED, never that they were SHOWN together or shown in every section — and was
itself untested until #388. Both gaps are closed.


---

## The 2026-08-08 platform-LZ round — first clean baseline, and a completed injection round

The first round run against a **verified-clean estate**. Two previous attempts at
grading remediation advice were destroyed when the estate was torn down
mid-test, so "the report said something wrong" could never be separated from
"the estate moved". This one held still.

Estate: `azure-landingzone-bicep` `envs/prod` in `sub-lz-bicep`, registered as
the `landingzone-prod` landing zone.

### Proven

| Property | Evidence |
|---|---|
| **Zero false positives on a clean estate** | Fresh deploy → `drift_count: 3`, being exactly the three standing subscription Owner grants. 0 `missing_in_azure`, 0 property drift, 6 `matched_unresolvable` correctly excluded |
| **Detection of five injected drifts** | 6/6 found, including both storage properties collapsed into ONE finding and both policy-tagged resources |
| **Revert symmetry** | After reverting, `drift_count` returned to exactly 3 — no residue. Detection and revert agree in both directions, which is what makes a baseline trustworthy across rounds |
| **Ownership by declaring module** | `{'workload': 16, 'platform': 5}` → `{'platform': 26, 'workload': 2}`, the two survivors being precisely the resources declared in the `apps` module |
| **Remediation advice correct on a live case** | The agent diagnosed the missing Key Vault as *"a failed deployment, not evidence that somebody deleted it"* and recommended checking for a soft-deleted name collision. Purging the soft-deleted vault unblocked the deploy — the vault and its private endpoint returned |
| **`private_endpoints` changes the answer** | Same injection, before: *"proves public reachability was enabled but not that anonymous access is possible."* After: *"the approved `jacquiprod-pe-kv` private endpoint provides a working private path. Closing public access is therefore safe … only consumers currently using the public endpoint will break"* |
| **`related_policy_assignments` used without overclaiming** | *"a candidate explanation for values that return after deployment. The payload does not contain the definition effect"* — then the conditional loop warning |

### Defects found

| # | Defect | Fix |
|---|---|---|
| 1 | Module lookup missed every **uniqueString-named** resource: the drift carries the resolved name, the template the expression, and `bicep_name_expression` (the field that bridges them) exists only on drift rows — the index was reading it off `arm_resources`. Five apps-module resources were tagged `platform` | #408 |
| 2 | The **column-0 fence rule was never checked**. All 22 fences in one report were indented; every check passed and the rendered HTML contained zero `<pre>` blocks | #408 |
| 3 | Findings could not see their **private endpoints**, so no `publicNetworkAccess` finding could conclude | #412 |
| 4 | Attribution recognises only the two **built-in** inherit-tag policies, so a **custom** Modify policy's imposed value arrives as ordinary actionable drift attributed to the writer | #412 (evidence) |
| 5 | **Seven documented tunables never reached a CI scan**, including all three sidecar disable switches. `DRIFT_MODEL_PRICING` was set as a repo variable and did nothing; the cost line read `unknown`, indistinguishable from the designed "no price for this model" | #413 |
| 6 | `platform_types` had been advertised in its own comment as the config escape hatch since it was written, and no call site ever passed one | this round |

### Two lessons worth keeping

**The limiting factor was the payload, three times out of four.** The Key Vault
cause, the private endpoint, and the policy candidate were all *in the report*
and simply not handed to the analysis. Each time the narrative behaved correctly
within its evidence and said so. Before treating a hedged or wrong answer as a
model failure, check what the finding actually carried.

**A knob that cannot be turned is worse than no knob**, because the
documentation says otherwise. Two instances landed on the same day —
`DRIFT_MODEL_PRICING` unplumbed and `platform_types` unpassed — so
`tests/test_workflow_env_coverage.py` now fails if a tunable the code reads is
missing from the reusable workflow. Its scanner has a guard-the-guard test,
which immediately caught the scanner itself missing `DRIFT_MODEL_PRICING`.

---

## The 2026-08-11 deployed-estate round — both scopes, and one bug in three modules

The first round since 2026-07 against a genuinely **deployed** estate. Everything
between had been verified on torn-down or empty estates, which is why two paths
below had never actually executed.

Eleven runs: subscription scope × {clean, drifted} × {gpt-5.6-sol,
claude-opus-4-8}, the same four at RG scope, and three fix-verification runs.
All reports produced in GitHub Actions, not locally.

### Proven

| Property | Evidence |
|---|---|
| **Property-drift severity, against real property drift** | The path existed but had never run live — every prior round was on a torn-down estate, so every `property_drifts` entry had `property_diffs: []`. Key Vault `publicNetworkAccess` `Disabled`→`Enabled` → **critical / security_drift**, diff exactly the injected property |
| **Nested-type attribution on DELETES (#421)** | Previously proven only for *creates*. VNet peering `…/hub-to-apps` and Cosmos `sqlDatabases/appdb` both `missing_in_azure` / `high` / `manual_change`, actor named |
| **Risk classification ungated from the LLM (#422)** | Severity now stamped on every row regardless of provider — confirmed identical across both providers on both scopes |
| **RG-scope clean baseline** | `drift_count: 0` across **75 declared resources / ~38 types**, `collection_gaps: {}`, 27 `matched_unresolvable` correctly excluded, 17 policy-enforced rows correctly split out. The broadest false-positive surface in the fixture, clean |
| **Provider independence, strictly compared** | Not just the drift list — `(type, name, drift_type, severity, category, origin, changed_by, changed_property_paths)` identical across providers on clean **and** drifted estates, at both scopes. Only the narrative differs. Cost within 4% |
| **Four RG-scope injections** | WAF `policySettings.mode`, Firewall `threatIntelMode`, Storage `supportsHttpsTrafficOnly`, SQL database deletion — all detected, all attributed |

### DO NOT "fix" the unattributed Cosmos grandchild

`…/appdb/items` reported `origin: unknown` / `changed_by: null` and that is
**correct**. Deleting a Cosmos `sqlDatabase` makes Azure emit exactly one event —
`sqlDatabases/delete` — and none for the container; verified by querying the
Activity Log directly. The pipeline attributed the two children that have events
and declined on the one that does not, rather than inheriting the parent's actor.
That is the "an absence we cannot substantiate is never asserted" invariant
working. A future round that "fixes" this into naming an actor has reintroduced
the sibling-adoption bug.

### The defect: one bug, three modules, and two fixes that changed nothing

The RG-scope drifted run returned 3 of 4. The deleted SQL database was matched to
`sqldrift…/master` — the system database the template never declares — so the
deletion vanished **and** the undeclared extra was absorbed. Neither side of the
discrepancy was reported, which `drift_count` cannot reveal.

The same expression existed in three modules:

```python
prefix = bicep_name.split("[")[0]     # 'sqldrift[hash]/driftdb' -> 'sqldrift'
```

`split("[")` stops at the first placeholder, so for a CHILD name it discards the
leaf and the test collapses onto the parent — which every sibling shares.

| PR | Module | Real bug | Moved the report |
|---|---|---|---|
| #425 | `smart_matching`, unguarded single-candidate branch | yes | **no** |
| #426 | `property_drift.matcher`, two sites | yes | **no** |
| #427 | `reconciliation._find_deployed_resource` | yes | **yes** |

#425 and #426 both hold — post-#426 the `smart_matched` list had no SQL database
entry and the detector emitted a correct missing+extra — but neither was
*reached first*. `_find_deployed_resource` ran earliest: it resolved the deleted
child to `master`, attribution took that row's real ARM id, matched master's own
events, and `_recover_deployed_name` renamed the drift. Hence a **live resource
reported missing**.

#427 collapses all three onto one definition,
`tools.smart_matching.names_plausibly_correspond`, with a test asserting that any
module deriving a `split("[")[0]` prefix also imports the guard.

### Two lessons worth keeping

**A count moving in the right direction is not evidence the right thing moved.**
After #425 `drift_count` went 3→4 and that was read as the fix landing; the row's
*name* was still wrong. Trace a symptom to its source before calling it fixed.

**Verify an injection against live state, never the command's exit code.**
`az storage account update --min-tls-version TLS1_0` reported success, printed a
warning, and changed nothing — Azure retired TLS 1.0/1.1 on 2026-02-03, so a TLS
downgrade is now useless as an injection and would read as an agent false
negative. Separately, `az storage account show --query supportsHttpsTrafficOnly`
returned `null` for a flip that *had* worked; the raw ARM GET showed `false`. The
CLI misled in both directions.

### Not proven by this round

- **Revert symmetry.** Both estates were left drifted; the `revert → clean` half
  was not run.
- **The RG-scope drifted run on Anthropic post-fix** was re-run and matched
  gpt-5.6-sol exactly, but the three fix-verification runs themselves were
  single-provider.

---

## The 2026-08-14 schema-flag round — a suppression, not a detection

`tools/schema/` (#433–#435) is the first capability here whose entire job is to
**stop** something being reported. The tier table above is built for detection
claims, so read this round against a different bar: the question is not "was drift
caught" but "did the suppression act only where it should".

> **Evidence for this section is the commit record of #433–#435, not a separate
> written-up run.** It is recorded because the round changed two shipped
> behaviours; if it is disputed, re-run it against a rebuilt fixture rather than
> arguing the citation.

### What the round established

| Claim | Evidence |
|---|---|
| The checks are correctly **inert** on well-formed templates | Prod LZ: 23 resources, 59 declared paths, every `type@apiVersion` covered, **zero** suppressed by either check (#433). Fixture estate after the coverage fix: 268 checkable paths, full type coverage, still zero judged absent (#434) |
| The API-version check acts on a **real** case | After #435 the fixture scan emitted exactly one suppression line, and that one was the genuine injected case |
| Partial coverage disables itself rather than guessing | `property_declared` returns `None` for an uncovered `type@apiVersion`; only an explicit `False` suppresses |

This does **not** upgrade any detection row above. A suppression proven not to
fire on 327 well-formed paths is a false-positive result, in the same family as
"live-clean" — it says the check is safe, not that it is useful.

### The defect this round found, and why it is the important part

The first cut of the coverage seed was built from latest-stable plus the
landing-zone repo's pins. On the fixture estate that left **38 of 75 resources'
declared paths checkable** — every other `type@apiVersion` fell through to "not
covered" and disabled itself. The round would have reported a clean pass while
exercising almost nothing.

That is the same shape as the backup comparators this page opens with: the check
ran, the suite was green, and the thing under test was never reached. It is worth
stating as a general rule, because `tools/schema/` will not be the last capability
with a coverage seed:

**A capability with a coverage list has two failure modes, and only one of them is
visible.** "The check ran and found nothing" and "the check silently disabled
itself" produce identical output. Any such capability needs a coverage assertion —
`flags.coverage_size()` and the pinned-apiVersion test exist for exactly this —
and a round against it must report *how much was checkable*, not just the result.

### The noise defect (#435)

The API-version check originally ran near the top of the removed-property branch,
ahead of the emptiness filters, and judged keys the normaliser **synthesises**
rather than keys a human wrote — every resource gets a top-level `zones`, null on
types that have no such concept. A fixture scan emitted 26 suppression lines, 25
of them telling the operator to go audit an `apiVersion` for a property their
template never mentions. Moving the check last cut it to 1.

Worth keeping as a design rule: **a suppression that logs should run last**, after
every cheaper filter, so it can only ever speak about something that was actually
about to be reported.

### Not proven by this round

- **The suppression acting on a property an operator genuinely mis-versioned in
  their own template**, end to end, with the operator then fixing the
  `apiVersion` and the line disappearing. The one live case was injected.
- **Decay behaviour.** `.github/workflows/schema-decay.yml` has not yet caught a
  real upstream move; it has only been run against a fresh snapshot.
- **Any estate whose templates are not well formed.** Every path judged so far
  came from templates that compile clean, which is the easy case.
