"""
Unit tests for the analysis-prompt slimming: matched_unresolvable entries are
NOT drift (runtime-named resources reconciled to deployed counterparts) and
must not reach the Claude analysis as findings - on real estates they dominated
~30:3, inflating cost and making the model caveat "unresolved" rows instead of
analysing actionable drift. They are reduced to a count in the context.
"""

import json
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.drift_agent import DriftAgent
from agent.llm import LLMResponse
from tools.models import Drift, DriftReport


def _report(n_reconciled, n_actionable):
    drifts = []
    for i in range(n_reconciled):
        drifts.append(Drift(
            resource_type="microsoft.storage/storageaccounts",
            resource_name=f"reconciled{i:02d}xyz",
            drift_type="matched_unresolvable",
        ))
    for i in range(n_actionable):
        drifts.append(Drift(
            resource_type="microsoft.containerregistry/registries",
            resource_name=f"acrdrifted{i:02d}",
            drift_type="modified",
            severity="critical",
            details={"changed_properties": {"properties.adminUserEnabled": {}}},
        ))
    return DriftReport(bicep_file="bicep/main.bicep", resource_group="rg-x",
                       drifts=drifts, total_modified=n_actionable)


class AnalysisPromptTests(unittest.TestCase):
    def _agent_and_prompt(self, report):
        agent = DriftAgent(api_key="test-key", model="claude-opus-4-8")
        captured = {}

        def fake_create(**kwargs):
            captured.update(kwargs)
            return LLMResponse(
                text="analysis",
                usage=SimpleNamespace(input_tokens=1, output_tokens=1),
            )

        agent._create_message = fake_create
        agent.analyze_drift(report)
        return json.loads(
            captured["messages"][0]["content"].split("\n\n", 1)[1]
        )

    def test_reconciled_entries_excluded_from_findings(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=30, n_actionable=3))
        self.assertEqual(len(ctx["findings"]), 3)
        names = json.dumps(ctx["findings"])
        self.assertNotIn("reconciled00xyz", names)
        self.assertEqual(ctx["reconciled_resources"]["count"], 30)

    def test_prompt_shrinks_substantially(self):
        big = self._agent_and_prompt(_report(30, 3))
        # Reconstruct what the old behavior would have sent: same report with
        # the reconciled entries relabeled so they pass the filter.
        rpt = _report(0, 3)
        for i in range(30):
            rpt.drifts.append(Drift(
                resource_type="microsoft.storage/storageaccounts",
                resource_name=f"reconciled{i:02d}xyz",
                drift_type="extra"))
        old = self._agent_and_prompt(rpt)
        self.assertLess(len(json.dumps(big)), len(json.dumps(old)) / 2)

    def test_no_reconciled_key_when_none(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=0, n_actionable=2))
        self.assertNotIn("reconciled_resources", ctx)
        self.assertEqual(len(ctx["findings"]), 2)

    def test_all_reconciled_yields_empty_findings_with_count(self):
        ctx = self._agent_and_prompt(_report(n_reconciled=5, n_actionable=0))
        self.assertEqual(ctx["findings"], [])
        self.assertEqual(ctx["reconciled_resources"]["count"], 5)

    def test_original_report_object_not_mutated(self):
        report = _report(4, 1)
        agent = DriftAgent(api_key="test-key")
        agent._create_message = lambda **kw: LLMResponse(text="x", usage=None)
        agent.analyze_drift(report)
        self.assertEqual(len(report.drifts), 5)


class AttributionInPromptTests(unittest.TestCase):
    """The report already resolves who/how (change_origin) and the ARM id
    (lifecycle.resource_id). Both must reach the agent so it cites them instead
    of re-deriving attribution or caveating a 'null resource_id'."""

    CHANGE_ORIGIN = {
        "origin": "manual_change",
        "category": "out_of_band",
        "changed_by": "someone@example.com",
        "reason": "Manual change by someone@example.com (out-of-band)",
    }
    RID = ("/subscriptions/xxx/resourceGroups/rg-x/providers/"
           "Microsoft.Network/firewallPolicies/fwpol-drift-test")

    def _prompt_ctx(self):
        report = DriftReport(
            bicep_file="bicep/main.bicep", resource_group="rg-x", total_modified=1,
            drifts=[Drift(
                resource_type="Microsoft.Network/firewallPolicies",
                resource_name="fwpol-drift-test",
                drift_type="property_drift",
                severity="critical",
                details={"changed_properties": {"properties.threatIntelMode": {}}},
                resource_id=self.RID,
                change_origin=self.CHANGE_ORIGIN,
            )],
        )
        return AnalysisPromptTests()._agent_and_prompt(report)

    def test_change_origin_reaches_prompt(self):
        finding = self._prompt_ctx()["findings"][0]
        self.assertEqual(finding["change_origin"], self.CHANGE_ORIGIN)

    def test_resource_id_reaches_prompt(self):
        finding = self._prompt_ctx()["findings"][0]
        self.assertEqual(finding["resource_id"], self.RID)


class RemediationGuidanceTests(unittest.TestCase):
    """The system prompt must carry the Azure-specific remediation rules that
    Opus previously got wrong (locks, redeploy scope, using existing attribution)."""

    def test_prompt_encodes_azure_remediation_rules(self):
        sp = DriftAgent._get_system_prompt()
        # Locks don't stop config drift
        self.assertIn("CanNotDelete", sp)
        self.assertIn("blocks deletion", sp)
        # Prefer the narrowest redeploy scope
        self.assertIn("NARROWEST", sp)
        # Don't tell the user to pull Activity Logs — attribution is provided
        self.assertIn("Activity Logs", sp)
        self.assertIn("change_origin", sp)
        # Rogue top-level child needs explicit delete, not redeploy
        self.assertIn("TOP-LEVEL child", sp)

    def test_prompt_warns_that_platform_enforced_hardening_survives_redeploy(self):
        # A live round drifted encryptionAtHost false -> true and the analysis
        # said a redeploy would turn it back off. If the subscription enforces
        # encryption (policy Modify/DINE, default disk encryption set), the
        # redeploy lands and the setting comes straight back - so the analysis
        # must send the reader to check the enforcement scope first.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("encryptionAtHost", sp)
        self.assertIn("MORE secure", sp)
        self.assertIn("management-group scope", sp)
        self.assertIn("az policy assignment list", sp)
        # And must offer the "make the template declare the enforced value" branch.
        self.assertIn("declare the enforced value", sp)

    def test_prompt_splits_the_three_policy_effects(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("`Deny`", sp)
        self.assertIn("FAILS outright", sp)
        self.assertIn("`Modify` / `deployIfNotExists`", sp)
        self.assertIn("back on the next run", sp)

    def test_prompt_leads_with_audit_as_default_and_silent(self):
        # I first told the model Deny was "the effect of most built-in hardening
        # policies"; it faithfully repeated that. Built-ins expose effect as a
        # PARAMETER defaulting to Audit - under which the redeploy SUCCEEDS and
        # silently downgrades the hardening. That is the case the whole warning
        # exists for, and it was the one branch missing.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("the DEFAULT for most built-ins", sp)
        self.assertIn("DANGEROUS one because nothing stops you", sp)
        self.assertIn("silently downgraded", sp)
        # And the check must read the assignment's parameter, not the name.
        self.assertIn("parameters.effect.value", sp)
        self.assertNotIn("the effect of most built-in hardening policies", sp)

    def test_prompt_rejects_the_bogus_subscription_encryption_default(self):
        # EncryptionAtHost is a subscription FEATURE REGISTRATION (permits the
        # setting, never applies it); the default disk encryption set governs a
        # different property. Sending the reader to either explains nothing.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("FEATURE REGISTRATION", sp)
        self.assertIn("Microsoft.Compute/EncryptionAtHost", sp)
        self.assertIn("properties.encryption.type", sp)

    def test_prompt_carries_the_deallocation_constraint(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("cannot be changed while instances are allocated", sp)
        self.assertIn("sku.capacity", sp)


class EvidenceDisciplineTests(unittest.TestCase):
    """A live round invented a disk-to-VMSS attachment and reported an opened
    networkAccessPolicy without saying publicNetworkAccess was still Disabled."""

    def test_prompt_forbids_inventing_relationships(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Never assert a RELATIONSHIP that is not in the data", sp)
        self.assertIn("unverified", sp)

    def test_prompt_requires_mitigating_fields(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("MITIGATING fields", sp)
        self.assertIn("publicNetworkAccess", sp)

    def test_prompt_denies_treating_missing_policy_attribution_as_proof(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("policy_enforced_drifts", sp)
        self.assertIn("confirmed manual", sp)

    def test_prompt_forbids_reading_live_context_as_drift(self):
        # A VMSS whose zones never drifted arrived with zones in its
        # live_context; the TL;DR then announced "both resources drifted a
        # zones value that is immutable", contradicting its own body. Context
        # values are, by construction, the ones that MATCH.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("BY CONSTRUCTION did not drift", sp)
        self.assertIn("never read a live_context entry as a mismatch", sp)
        self.assertIn("carry it into the remediation plan", sp)

    def test_prompt_points_at_live_context_before_hedging(self):
        # The evidence rules are only answerable if the model knows where the
        # evidence IS - otherwise it correctly refuses to assert, and hedges
        # about values the report holds.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("live_context", sp)
        self.assertIn("hedging on a value that was handed to you", sp)


class InteractingDriftTests(unittest.TestCase):
    """A live AKS round reported four independent critical findings. Two of
    them composed: enableAzureRBAC true->false moved authorization off the
    auditable Azure path, and adminGroupObjectIDs [] -> ["<group>"] then made a
    cluster-admin grant down that now-invisible path. Both facts were in the
    report; the line between them was not."""

    def test_prompt_requires_joining_drifts_on_one_resource(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Interacting drift", sp)
        self.assertIn("COMPOSE", sp)
        self.assertIn("group them by `resource_id`", sp)

    def test_prompt_names_both_composition_shapes(self):
        # (a) one drift hides another; (b) one relaxes a boundary another crosses.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("audit path", sp)
        self.assertIn("SURFACED another", sp)
        self.assertIn("relaxes a boundary while another widens what crosses it", sp)

    def test_prompt_carries_the_aks_evidence(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("enableAzureRBAC", sp)
        self.assertIn("adminGroupObjectIDs", sp)
        self.assertIn("sees LESS than before", sp)

    def test_prompt_makes_the_combination_lead(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("worse than the sum of its parts", sp)
        self.assertIn("TL;DR", sp)

    def test_prompt_guards_against_over_firing(self):
        # The failure mode of this rule is inventing a story for drifts that
        # merely share a resource. Co-location is not interaction.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Do NOT over-fire", sp)
        self.assertIn("Co-location on one resource is not interaction", sp)
        self.assertIn("state the mechanism", sp)

    def test_prompt_guards_against_over_unifying_across_time(self):
        """The mirror failure, seen live on 2026-08-01: an analysis called
        deletions spanning 00:34-01:44 "a coherent single event" when they were
        two operations ~40 minutes apart. Merging them conceals that someone
        acted more than once."""
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Do NOT over-unify across TIME", sp)
        self.assertIn("read the timestamps for a GAP", sp)
        self.assertIn("distinct operations", sp)


class InternalConsistencyTests(unittest.TestCase):
    """A live analysis called the same 34 tag findings "the same benign
    policy-driven tag change" in its TL;DR and "none are benign" in its body.
    A reader acting on the summary and a reader acting on the detail reached
    opposite conclusions from one document."""

    def test_prompt_requires_the_tldr_to_agree_with_the_body(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("ONE document and must agree", sp)

    def test_prompt_names_the_softening_words_that_get_acted_on(self):
        # The failure is asymmetric: a softening adjective in the TL;DR is what
        # a busy reader acts on without scrolling to the contradiction.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("delete any characterisation the body contradicts", sp)
        self.assertIn("benign", sp)


class PlanConsistencyTests(unittest.TestCase):
    """A live plan's step 2 redeployed the disk module to revert
    networkAccessPolicy, while its step 3 said the same module could not be
    redeployed because zones are immutable. The plan could not execute."""

    def test_prompt_binds_constraints_to_later_steps(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("BINDS every later step", sp)
        self.assertIn("immutable", sp)
        self.assertIn("re-read your own findings", sp)

    def test_prompt_calls_immutable_drift_a_build_blocker(self):
        # Proven in CI: a disk zones drift injected days earlier failed an
        # unrelated deploy that was adding an AKS cluster. The report had rated
        # it critical and said a redeploy would be rejected, but never said the
        # next pipeline run would fail - which is the sentence an operator acts
        # on, and a different priority class from a remediation footnote.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("BUILD BLOCKER", sp)
        self.assertIn("EVERY future deployment of the module", sp)
        self.assertIn("name the module that can no longer deploy", sp)

    def test_prompt_says_idle_means_cheap_fix_not_low_priority(self):
        # The counterintuitive half: "Unattached"/"capacity 0" is an argument
        # about COST of the fix, not about urgency. An idle 4GB disk held the
        # whole estate's pipeline hostage.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("outranks a cosmetic drift on a busy one", sp)
        self.assertIn("never for LOW priority", sp)

    def test_prompt_keeps_reconcile_as_a_first_class_option(self):
        # The round that finally ordered the steps correctly also dropped
        # "update the Bicep to zones: [2]" and offered only snapshot-recreate -
        # the laborious option, for an Unattached 4GB test disk.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("ALWAYS offer BOTH ways out", sp)
        self.assertIn("RECONCILE", sp)
        self.assertIn("MIGRATE", sp)
        self.assertIn("diskState: Unattached", sp)
        self.assertIn("not \"giving up\"", sp)

    def test_prompt_demands_ordering_not_annotation(self):
        # The next round stated the dependency but left the failing deploy at
        # step 3 and its blocker at step 4 - an operator working top to bottom
        # still hits the failure. Disclosure is not sequencing.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("NUMBERED EARLIER", sp)
        self.assertIn("top to bottom", sp)
        self.assertIn("do not annotate", sp)


class OutputShapeTests(unittest.TestCase):
    """The first gpt-5-mini report on the subscription-scope LZ was correct and
    unreadable: `1)` numbering the markdown parser does not recognise, the
    request's own question list promoted to headings, every remediation stated
    three times, and a closing offer to produce the Bicep snippet it should
    simply have written."""

    def test_prompt_forbids_the_numbering_the_parser_drops(self):
        # Not cosmetic. python-markdown has no `1)` list marker, so the number
        # AND the bullets under it fold into one <p> - the entire priority
        # findings section rendered as prose in the HTML artifact.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("MUST use `1.`, never `1)`", sp)
        self.assertIn("does not recognise `1)` as a list", sp)

    def test_prompt_requires_a_short_heading_not_the_resource_id(self):
        # Round 2: headings became the full 120-char resource ID, and the first
        # bullet under each repeated it verbatim - twice the width, no extra fact.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("`###` heading that is a SHORT LABEL", sp)
        self.assertIn("NEVER put the resource ID in the heading", sp)
        self.assertIn("exactly ONE bullet beneath the heading", sp)

    def test_prompt_states_the_heading_limit_the_eval_enforces(self):
        # The first CI eval run flagged a 94-char heading against a 90-char cap
        # the prompt never stated - it said only "SHORT LABEL". A limit that is
        # enforced but not published is a guessing game, so the number lives in
        # both places and this keeps them equal.
        from evals.checks import _MAX_HEADING_CHARS
        self.assertIn(f"UNDER {_MAX_HEADING_CHARS} CHARACTERS",
                      DriftAgent._get_system_prompt())

    def test_the_prompts_own_example_heading_obeys_the_limit(self):
        # An example violating its own rule would teach the wrong thing.
        from evals.checks import _MAX_HEADING_CHARS
        example = "39 resources: environment tag rewritten by policy"
        self.assertIn(example, DriftAgent._get_system_prompt())
        self.assertLess(len(example), _MAX_HEADING_CHARS)

    def test_prompt_makes_the_four_sections_an_allowlist(self):
        # Round 1 said the four sections "ARE the document" and the model still
        # emitted five extra `##` question headings. Naming them individually and
        # calling it an allowlist is the escalation.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("are an ALLOWLIST", sp)
        self.assertIn("a checklist to cover INSIDE them, never headings", sp)
        for banned in (
            "## Which findings are likely Azure-managed resources?",
            "## Which findings should be remediated by redeploying Bicep?",
            "## What should be fixed first",
        ):
            self.assertIn(banned, sp)

    def test_prompt_keeps_remediation_out_of_the_findings(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("Say each thing ONCE", sp)
        self.assertIn("it does NOT say what to do about it", sp)
        self.assertIn("Three sections, three jobs, no repetition", sp)

    def test_prompt_budgets_the_length(self):
        # The round-1 rules added structure but no budget, and the report grew
        # 27% (4,861 -> 6,195 output tokens) by restating itself.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("LENGTH is a feature", sp)
        self.assertIn("600-900 words", sp)
        self.assertIn("at most six bullets under any finding", sp)

    def test_prompt_forbids_a_sign_off(self):
        sp = DriftAgent._get_system_prompt()
        self.assertIn("No sign-off", sp)
        self.assertIn("End of report", sp)

    def test_prompt_forbids_closing_on_an_offer(self):
        # The whole point: the run is over when the file is written, so an
        # offer of further work is the deliverable being withheld.
        sp = DriftAgent._get_system_prompt()
        self.assertIn("writing a FILE, not a chat turn", sp)
        self.assertIn("NEVER close by offering further work", sp)
        self.assertIn("That offer IS the remediation, withheld", sp)
        self.assertIn("WRITE IT into the remediation plan", sp)

    def test_context_labels_the_questions_as_a_checklist(self):
        # The rule above only holds if the payload agrees with it: a key named
        # "questions_to_answer" reads as an outline however the prompt words it.
        report = _report(n_reconciled=0, n_actionable=1)
        context = AnalysisPromptTests()._agent_and_prompt(report)
        self.assertIn("questions_to_answer_within_those_sections", context)
        self.assertNotIn("questions_to_answer", context)

    def test_context_demands_artifacts_not_offers(self):
        report = _report(n_reconciled=0, n_actionable=1)
        context = AnalysisPromptTests()._agent_and_prompt(report)
        requirements = " ".join(context["response_requirements"])
        self.assertIn("Write out every artifact you reference", requirements)
        self.assertIn("never on an offer of further work", requirements)


class LiveContextTests(unittest.TestCase):
    """details carries only the CHANGED paths. The siblings that bound a
    finding's severity (publicNetworkAccess) or decide whether remediation is
    possible (sku.capacity, diskState) have to be attached separately."""

    @staticmethod
    def _report(live, **drift_kwargs):
        drift = Drift(
            resource_type=drift_kwargs.pop("resource_type", "Microsoft.Compute/disks"),
            resource_name=drift_kwargs.pop("resource_name", "disk-1"),
            drift_type="property_drift",
            details=drift_kwargs.pop("details", {"changed_properties": {
                "properties.networkAccessPolicy": {"desired": "DenyAll", "actual": "AllowAll"}}}),
            **drift_kwargs,
        )
        return DriftReport(bicep_file="m.bicep", resource_group="rg",
                           drifts=[drift], live_resources=live)

    def _finding(self, live, **kw):
        return DriftAgent(api_key="k")._build_findings(self._report(live, **kw))[0]

    def test_mitigating_sibling_is_attached(self):
        f = self._finding([{
            "type": "Microsoft.Compute/disks", "name": "disk-1",
            "properties": {"networkAccessPolicy": "AllowAll",
                           "publicNetworkAccess": "Disabled",
                           "diskState": "Unattached"},
        }])
        self.assertEqual(f.live_context["properties.publicNetworkAccess"], "Disabled")
        self.assertEqual(f.live_context["properties.diskState"], "Unattached")

    def test_changed_properties_are_not_repeated_in_context(self):
        # The drifted path already appears in details with desired+actual;
        # echoing it here would read as a second, contradictory value.
        f = self._finding([{
            "type": "Microsoft.Compute/disks", "name": "disk-1",
            "properties": {"networkAccessPolicy": "AllowAll", "publicNetworkAccess": "Disabled"},
        }])
        self.assertNotIn("properties.networkAccessPolicy", f.live_context)

    def test_capacity_reaches_the_finding(self):
        # The deallocation caveat is unresolvable without this.
        f = self._finding(
            [{"type": "Microsoft.Compute/virtualMachineScaleSets", "name": "vmss-1",
              "sku": {"name": "Standard_D2s_v3", "capacity": 0}}],
            resource_type="Microsoft.Compute/virtualMachineScaleSets",
            resource_name="vmss-1",
        )
        self.assertEqual(f.live_context["sku.capacity"], 0)

    def test_matches_by_resource_id_when_names_differ(self):
        rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/disks/disk-1"
        f = self._finding(
            [{"id": rid, "type": "microsoft.compute/disks", "name": "runtime-named-xyz",
              "properties": {"diskState": "Attached"}}],
            resource_name="disk-placeholder", resource_id=rid,
        )
        self.assertEqual(f.live_context["properties.diskState"], "Attached")

    def test_zones_is_not_context(self):
        # zones is a drift TARGET: it bounds no blast radius and decides no
        # remediation, but its presence in a payload reads as a mismatch.
        self.assertNotIn("zones", DriftAgent.LIVE_CONTEXT_PROPERTIES)

    def test_context_never_repeats_a_drifted_path(self):
        # The general form of the same bug: whatever is in the allowlist, a
        # path that drifted must appear only in details, with desired+actual.
        for path in DriftAgent.LIVE_CONTEXT_PROPERTIES:
            f = self._finding(
                [{"type": "Microsoft.Compute/disks", "name": "disk-1",
                  "sku": {"capacity": 3},
                  "properties": {"provisioningState": "Succeeded", "publicNetworkAccess": "Enabled",
                                 "networkAccessPolicy": "AllowAll", "diskState": "Attached",
                                 "managedBy": "/vm/x", "encryption": {"type": "CMK"},
                                 "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": True,
                                 "enableRbacAuthorization": True, "enablePurgeProtection": True,
                                 "disableLocalAuth": True}}],
                details={"changed_properties": {path: {"desired": "x", "actual": "y"}}},
            )
            self.assertNotIn(path, f.live_context or {},
                             f"{path} drifted but was also echoed as context")

    def test_no_live_resources_yields_none(self):
        self.assertIsNone(self._finding(None).live_context)

    def test_unmatched_resource_yields_none(self):
        self.assertIsNone(self._finding([{"type": "Microsoft.Web/sites", "name": "other"}]).live_context)

    def test_context_stays_small(self):
        # The whole live payload is thousands of tokens; only the allowlist may
        # travel. A resource carrying a huge irrelevant block must not bloat it.
        f = self._finding([{
            "type": "Microsoft.Compute/disks", "name": "disk-1",
            "properties": {"publicNetworkAccess": "Disabled",
                           "callRateLimit": {"rules": [{"k": "v"} for _ in range(500)]}},
        }])
        self.assertNotIn("properties.callRateLimit", f.live_context)
        self.assertLess(len(json.dumps(f.live_context)), 500)


if __name__ == "__main__":
    unittest.main()
