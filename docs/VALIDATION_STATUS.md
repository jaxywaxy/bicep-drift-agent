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

### Live-clean only — detection unproven

All five were compared against live resources in the 2026-08-01 run and produced
no findings. **None has had a drift injected.**

| Capability | Live resources compared |
|---|---|
| Recovery Services vault backup config | 1 |
| Recovery Services vault backup policies | 4 |
| Azure Firewall policy + rule collection groups | 1 + 2 |
| Compute — VMSS, disks, availability sets | 1 each |
| RBAC role assignments | 3 in scope |

Backup is the highest priority of these: it is the capability that was previously
dead, and its documented reachability caveat (Azure rejects a soft-delete disable
on a hardened vault) means part of it may not be reachable at all.

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
