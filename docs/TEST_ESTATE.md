# Verification Estates

How to build an Azure estate the agent can be *proven* against, and how to run a
verification round. Companion to `VALIDATION_STATUS.md`, which records what each
round proved.

> **No estate ships with this repository.** The estates these rounds were run
> against were deliberately separate throwaway repos and were not migrated. What
> is portable is the **method** below: the composition principles, the round
> procedure, and the traps — every one of which cost a wasted round to find.
>
> An adopting organisation builds its own estate and registers it in its own
> `.github/lz-index.yml`.

---

## Why an estate is needed at all

A comparator that is silently dead and a comparator that works correctly both
produce zero findings against a clean estate. Only an injected drift separates
them, and only a real Azure estate can hold a real injection. That is the entire
argument for the cost and effort here.

---

## What a verification estate needs

**Two shapes, because they prove different things.**

*A resource-group-scoped fixture* — a flat template with many resource types in
one RG. Cheap, fast to deploy and tear down, and the workhorse for proving a
*type's* comparator.

*A subscription-scoped, module-composed landing zone* — needed for three things
that are properties of the estate's **shape**, not of any resource type, and
which a flat fixture can never show:

| Capability | Why a flat fixture cannot show it |
|---|---|
| Ownership by declaring module | Needs a module-composed template |
| Platform-vs-workload routing on a platform LZ | Needs an estate whose owner is *not* the type-heuristic default |
| Private-endpoint evidence on a drifted resource | Needs a resource with a live private endpoint terminating on it |

**Gate the expensive resources behind parameters.** The useful pattern is a
template where roughly two-thirds of the modules deploy on every round and the
slow or costly ones (AKS, VMs, App Gateway, Front Door, Virtual WAN, Cosmos) sit
behind `deployX bool = false`, switched on only for the round that needs them.

**Prefer free standalone forms where they exist.** A WAF policy attached to no
gateway, and a firewall policy attached to no firewall, are free and still give
you the full governance-drift surface of those types. The billed appliance is
rarely what you are testing.

**Deploy through the pipeline identity, not locally**, so
`authorized_deployment` attribution is exercised the way a real run sees it.

---

## Running a round

The round is what promotes a capability from *live-clean* to *live-proven*.

1. **Deploy** the estate, setting any gating parameter the capability needs.
2. **Baseline scan** — confirm zero actionable drift. A non-empty baseline means
   the estate or the ignore profile is wrong; fix that before injecting.
3. **Inject** one drift, out of band — portal or CLI, *not* the pipeline
   identity, so attribution is exercised too.
4. **Verify the injection landed**, against live state rather than the command's
   exit code. See the traps below; this is not paranoia.
5. **Detect** — run `analyze_drift.py` and confirm the finding, its severity, its
   owner tag and its attribution.
6. **Notify** — confirm it routed to the expected channel.
7. **Revert**, then **re-scan** and confirm zero. Skipping this is how a
   comparator that fires on *everything* passes a round.
8. **Record** the date and outcome in `VALIDATION_STATUS.md`.

Set `DRIFT_AUTHORIZED_DEPLOYERS` to the pipeline principal for local runs, or the
deploying identity's own writes are misclassified as manual changes.

---

## Designing an injection set

Detection is the easy half. To test the *advice*, choose injections whose
**correct remediation differs per case** — otherwise a narrative that always says
"redeploy" scores full marks.

A worked set, all free-tier and reversible:

| Injection | Correct remediation | The plausible wrong answer |
|---|---|---|
| Create an NSG the template does not declare | Explicit delete — **a redeploy does nothing** | "redeploy to remove it" |
| Add an allow-any RDP rule to a *declared* NSG | A redeploy **does** remove it: `securityRules` is a declared set | Treating it like the case above |
| Two security properties on one storage account | Redeploy. Two properties, ONE resource, so ONE finding | Splitting it into two findings |
| Key Vault `publicNetworkAccess=Enabled` | Redeploy — and a private endpoint makes closing it safe | Hedging, or missing the PE |
| A custom Modify policy rewriting a declared tag | **Reverting is futile** — fix the template or the policy | "redeploy to restore the tag" |

The first two are the discriminating pair: both read as "an NSG thing appeared"
and their correct fixes are opposites.

**Cover deletions of nested children explicitly.** Deleting a child whose parent
name contains a `uniqueString()` placeholder is the single most defect-prone path
in the pipeline — it has produced false negatives repeatedly, and a false
negative on a deletion is invisible in `drift_count`.

---

## Traps

Each of these cost a round.

**Verify an injection against live state, never the command's exit code.**
`az storage account update --min-tls-version TLS1_0` reports success, prints a
warning and changes nothing — Azure retired TLS 1.0/1.1 platform-wide on
2026-02-03, so a TLS downgrade is no longer injectable at all and reads as an
agent false negative. Separately, `az storage account show --query
supportsHttpsTrafficOnly` has returned `null` for a flip that *had* worked, where
the raw ARM GET showed `false`. The CLI misleads in both directions; confirm with
`az rest`.

**The estate must hold still.** A round whose estate changes underneath it is
**void, not inconclusive** — "the report said something wrong" becomes
indistinguishable from "the estate moved". Take the clean baseline immediately
before injecting, and treat any finding outside the injected set as a false
positive with nowhere to hide.

**Force a Modify effect with a resource write, not a remediation task.** A
compliance scan can take tens of minutes; touching a tag applies the effect in
seconds, and is how it fires in production anyway.

**Policy-enforced counts are not a stable baseline.** An inherit-tag Modify only
imposes its value at write time, and a freshly recreated assignment's identity
needs its remediation role to propagate. Straight after a deploy, most resources
still carry the template's value and the conflict has simply not been imposed
yet. Gate the baseline on *actionable* drift only.

**Runtime identities change across deploys.** A redeploy recreates a
user-assigned identity with a new `principalId`. Any fixture keyed on a principal
ID goes stale — re-read it at injection time.

**Key Vault names block redeployment after teardown.** The name is reserved for
the soft-delete retention window, and `take(uniqueString(resourceGroup().id), 6)`
is deterministic, so recreating the resource group regenerates the identical
name. `az keyvault list-deleted` then purge or recover first, or the deployment
fails with the vault half-created — exactly the `create / Started` with no
completion that `unfinished_operation` exists to explain.

**Resource Graph keeps RBAC phantoms after ARM has dropped them.** The RBAC
sidecar reads Resource Graph's `authorizationresources`; `az role assignment
list` reads ARM. They disagree, and stale assignments stay indexed for hours
after deletion — pointing at principals `az` can no longer even resolve. They
cannot be cleared by hand; they age out. Before any RBAC injection, check the
sidecar's own source:

```bash
az graph query -q "authorizationresources
  | where tolower(properties.scope) contains '/resourcegroups/<your-rg>'
  | project tostring(properties.principalId), tostring(properties.roleDefinitionId)"
```

`az role assignment list` reflecting your injection is **not** evidence the scan
will see it.

**First contact with a new SCOPE behaves like first contact with a new resource
type.** The first subscription-scoped run found seven defects, one of which —
attribution dead for every wildcard selector — had been silently wrong for every
configured landing zone since it was set up. Assume defects, not confirmation.

---

## See Also

- [VALIDATION_STATUS.md](VALIDATION_STATUS.md) — what each round actually proved
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) — scanning a torn-down estate
  aborts (exit 2) rather than reporting the template as deleted
