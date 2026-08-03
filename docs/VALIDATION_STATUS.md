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
| Compute — VMSS capacity | 2026-08-02 round — `sku.capacity` 0→1 detected `critical`; `zones` correctly stayed silent (no subset false positive). **Detection only** — attribution failed, see below |

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

### Known defects — found by the 2026-08-02 injection round

Both are the same recurring shape (cf. #325 / #327 / #336 / #343): **a heuristic
overrides evidence the pipeline already holds**. Each has a reproducer.

**1. Health telemetry outranks the real write, erasing the actor.** *(fixed —
`fix/attribution-health-telemetry`; live re-verify pending)*
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

**1b. …and re-ordering events is not enough on its own.** *(follow-up —
`fix/manual-change-needs-an-actor`)* The 2026-08-02 CI run still produced
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

**Fixed** on `fix/rbac-deployed-principal-collision` and **live-verified against
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
| Owner routing (platform/workload → channel) | Live-proven | Phase 4, 2026-07-06 |
| Deployer attribution (`DRIFT_AUTHORIZED_DEPLOYERS`) | Live-proven | 2026-08-01 — an unset variable reclassified two findings, confirming the path |
| Notifications (Slack/Teams) | Live-proven | Phase 4 owner-routing round |
| Claude analysis | Live-proven | Present in the 2026-08-01 CI report |
| Scope integrity (unreadable RG, empty subscription) | Unit-tested + partial live | The abort path was verified end-to-end against a deleted RG on 2026-08-02; the *recovery* path was not |

---

## Known unproven behaviours

Stated here rather than left implicit:

- **Backup detection.** Comparators run, have never caught anything live.
- **A deleted resource group at subscription scope.** Implemented with tests and
  an orphan-attribution pass; no landing zone has been deleted to prove it.
- **Row-level attribution for colliding role assignments.** Rows are now distinct,
  but both still fall to the Activity Log type fallback and may adopt the same
  event. Identity is fixed; attribution is not.
- **The `revert → clean` half of several rounds.** Where a round is cited as
  detecting drift, re-verifying the *revert* is not always recorded.

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
