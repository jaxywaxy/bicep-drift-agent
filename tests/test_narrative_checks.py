"""Mechanical checks on the analysis OUTPUT.

Everything in `tests/test_analysis_prompt.py` asserts the INPUT - finding
counts, redaction, payload size. Nothing has ever checked what the model wrote
back. The only quality signal today is a human reading one report, which does
not scale to two providers and is exactly how a provider could produce quietly
worse analysis for months (cf. the backup comparators, silently dead for a
month while the stage above them looked healthy).

The judgement lives here, as pure functions over (report, analysis_text), so it
is deterministic and runs free in the normal suite. Only `evals/run.py` needs an
API key. That split is what makes "is provider B worse than provider A?" a
mechanical question instead of a reading exercise.

Every check below encodes a failure OBSERVED in a live report, not a
hypothetical.
"""

import unittest

from evals.checks import (
    check_critical_findings_are_mentioned,
    check_findings_do_not_carry_remediation,
    check_finding_headings_are_labels,
    check_length_within_budget,
    check_no_fabricated_actor,
    check_one_story_is_one_finding,
    check_no_sign_off,
    check_no_unearned_attribution,
    check_only_allowlisted_sections,
    check_commands_are_fenced,
    check_fences_start_at_column_zero,
    check_does_not_delete_the_deployer,
    check_snippets_use_the_declared_location,
    check_plan_is_flat,
    check_tldr_does_not_soften_what_the_body_confirms,
    check_does_not_over_unify_across_time,
    run_all_checks,
)


def _report(**kw):
    base = {"drifts": [], "drift_count": 0}
    base.update(kw)
    return base


def _drift(name, *, actor=None, origin="manual_change", severity="high",
           ts="2026-08-03T22:05:47+00:00", dtype="missing_in_azure"):
    return {
        "type": "Microsoft.Storage/storageAccounts", "name": name,
        "drift_type": dtype, "details": {},
        "change_origin": {"origin": origin, "changed_by": actor, "severity": severity,
                          "timestamp": ts},
        "lifecycle": {"events": [{"timestamp": ts, "actor": actor, "operation": "delete"}]},
    }


class NoFabricatedActorTests(unittest.TestCase):
    """The report names who did it or says it does not know. An analysis that
    introduces a NEW actor has invented evidence - the worst failure available
    to a tool whose output people act on."""

    def test_an_actor_absent_from_the_report_is_flagged(self):
        r = _report(drifts=[_drift("st1", actor="jacqui.anker@gmail.com")])
        v = check_no_fabricated_actor(r, "Deleted by devops@contoso.com during the change window.")
        self.assertTrue(v)
        self.assertIn("devops@contoso.com", v[0])

    def test_the_real_actor_is_not_flagged(self):
        r = _report(drifts=[_drift("st1", actor="jacqui.anker@gmail.com")])
        self.assertEqual(
            check_no_fabricated_actor(r, "Deleted by jacqui.anker@gmail.com out of band."), [])

    def test_a_principal_guid_from_the_report_is_accepted(self):
        r = _report(drifts=[_drift("st1", actor="f0a1968f-8124-4f28-9e59-a769971214e8")])
        self.assertEqual(
            check_no_fabricated_actor(r, "Created by f0a1968f-8124-4f28-9e59-a769971214e8."), [])


class NoUnearnedAttributionTests(unittest.TestCase):
    """Live 2026-08-03: every row came back `origin: unknown` because attribution
    was dead. An analysis that names a culprit anyway would have been confidently
    wrong, and nothing would have caught it."""

    def test_naming_anyone_when_everything_is_unknown_is_flagged(self):
        r = _report(drifts=[_drift("st1", actor=None, origin="unknown")])
        self.assertTrue(check_no_unearned_attribution(
            r, "This was changed by the platform team on Tuesday."))

    def test_saying_it_is_unknown_is_fine(self):
        r = _report(drifts=[_drift("st1", actor=None, origin="unknown")])
        self.assertEqual(check_no_unearned_attribution(
            r, "No actor is recorded; the activity log does not cover this change."), [])

    def test_it_does_not_fire_when_the_report_does_name_someone(self):
        r = _report(drifts=[_drift("st1", actor="jacqui.anker@gmail.com")])
        self.assertEqual(check_no_unearned_attribution(
            r, "Deleted by jacqui.anker@gmail.com."), [])


class CriticalFindingsMustBeMentionedTests(unittest.TestCase):
    """A critical finding the narrative never names is a finding the reader will
    not act on. Coverage is the one quality dimension that IS mechanical."""

    def test_an_unmentioned_critical_resource_is_flagged(self):
        r = _report(drifts=[_drift("jacquidevstla7m6et", severity="critical")])
        v = check_critical_findings_are_mentioned(r, "Some resources drifted. Review the report.")
        self.assertTrue(v)
        self.assertIn("jacquidevstla7m6et", v[0])

    def test_mentioning_it_passes(self):
        r = _report(drifts=[_drift("jacquidevstla7m6et", severity="critical")])
        self.assertEqual(check_critical_findings_are_mentioned(
            r, "`jacquidevstla7m6et` was deleted out of band."), [])

    def test_low_severity_findings_are_not_required_to_appear(self):
        r = _report(drifts=[_drift("noisy1", severity="low")])
        self.assertEqual(check_critical_findings_are_mentioned(r, "Nothing urgent."), [])


class TldrMustNotSoftenWhatTheBodyConfirmsTests(unittest.TestCase):
    """Observed live: 34 findings described as 'benign' in the TL;DR while the
    body said 'none are benign'. The softening line is the one a busy reader
    acts on without scrolling."""

    def test_benign_tldr_over_critical_findings_is_flagged(self):
        r = _report(drifts=[_drift("st1", severity="critical")])
        self.assertTrue(check_tldr_does_not_soften_what_the_body_confirms(
            r, "## TL;DR\nAll findings are benign and need no action.\n\n## Findings\ncritical..."))

    def test_an_honest_tldr_passes(self):
        r = _report(drifts=[_drift("st1", severity="critical")])
        self.assertEqual(check_tldr_does_not_soften_what_the_body_confirms(
            r, "## TL;DR\nA critical deletion needs attention.\n\n## Findings\n..."), [])

    def test_benign_is_fine_when_nothing_is_critical(self):
        r = _report(drifts=[_drift("st1", severity="low")])
        self.assertEqual(check_tldr_does_not_soften_what_the_body_confirms(
            r, "## TL;DR\nThese are benign and need no action."), [])


class DoesNotOverUnifyAcrossTimeTests(unittest.TestCase):
    """Observed live: deletions spanning 00:34-01:44 called 'a coherent single
    event'. Merging them conceals that someone acted more than once, which is
    usually the fact the reader needed. The prompt forbids it (#365); this
    checks the model obeyed."""

    def test_calling_a_40_minute_span_one_event_is_flagged(self):
        r = _report(drifts=[
            _drift("a", ts="2026-08-03T00:34:00+00:00"),
            _drift("b", ts="2026-08-03T01:44:00+00:00"),
        ])
        self.assertTrue(check_does_not_over_unify_across_time(
            r, "These deletions were a single event carried out by one operator."))

    def test_a_tight_cluster_may_be_called_one_event(self):
        r = _report(drifts=[
            _drift("a", ts="2026-08-03T22:05:17+00:00"),
            _drift("b", ts="2026-08-03T22:05:47+00:00"),
        ])
        self.assertEqual(check_does_not_over_unify_across_time(
            r, "A single event: the resource group deletion cascaded."), [])

    def test_a_wide_span_described_as_separate_passes(self):
        r = _report(drifts=[
            _drift("a", ts="2026-08-03T00:34:00+00:00"),
            _drift("b", ts="2026-08-03T01:44:00+00:00"),
        ])
        self.assertEqual(check_does_not_over_unify_across_time(
            r, "Two distinct operations, roughly forty minutes apart."), [])


class RunAllChecksTests(unittest.TestCase):
    def test_it_reports_every_violation_not_just_the_first(self):
        r = _report(drifts=[_drift("st1", actor=None, origin="unknown", severity="critical")])
        results = run_all_checks(r, "Deleted by devops@contoso.com. All benign, no action needed.")
        failing = [name for name, violations in results.items() if violations]
        self.assertGreaterEqual(len(failing), 2, f"expected several violations, got {results}")

    def test_a_good_analysis_passes_everything(self):
        r = _report(drifts=[_drift("st1", actor="jacqui.anker@gmail.com", severity="critical")])
        # Section names are the mandated four: the shape checks are part of
        # "passes everything" now, so this fixture has to be a report the prompt
        # would actually accept.
        good = ("## TL;DR\n`st1` was deleted out of band by jacqui.anker@gmail.com "
                "and needs restoring.\n\n## Priority findings\nOne critical deletion.")
        self.assertEqual({k: v for k, v in run_all_checks(r, good).items() if v}, {})


class CoverageMustOnlyDemandWhatTheAgentWasGivenTests(unittest.TestCase):
    """Caught on first contact with a REAL analysis, 2026-08-04.

    The coverage check flagged six `matched_unresolvable` rows as "never
    mentioned". They are resources that EXIST in Azure and were reconciled by
    smart matching; they carry `severity: high` only because their creation was
    out of band. The pipeline excludes reconciled entries from the findings sent
    to the agent - the analysis said so itself - so the check was demanding the
    model discuss rows it never received.

    A check that fires on correct output is worse than no check: it gets muted,
    and a muted check still looks like coverage.
    """

    def test_reconciled_rows_are_not_required_to_be_mentioned(self):
        r = _report(drifts=[_drift("kv-live", severity="high", dtype="matched_unresolvable")])
        self.assertEqual(check_critical_findings_are_mentioned(r, "Nothing to report."), [])

    def test_a_real_missing_row_is_still_required(self):
        r = _report(drifts=[_drift("st-gone", severity="high", dtype="missing_in_azure")])
        self.assertTrue(check_critical_findings_are_mentioned(r, "Nothing to report."))

    def test_extra_rows_still_count(self):
        # extra_in_azure IS actionable - an unmanaged resource the reader must judge.
        r = _report(drifts=[_drift("rogue", severity="high", dtype="extra_in_azure")])
        self.assertTrue(check_critical_findings_are_mentioned(r, "Nothing to report."))


class IdentifiersInsideResourceIdsAreNotFabricationsTests(unittest.TestCase):
    """My own review of this check called `assignment_id` a false NEGATIVE - a
    resource id accepted as proof of an identity. Writing the test showed the
    opposite: `_known_actors` stores the FULL ARM path while `_GUID` extracts
    BARE guids, so they never match and an analysis quoting a resource id
    straight from the report is flagged for inventing an actor.

    A false positive is the worse direction. A check that fires on correct
    output gets muted, and a muted check still looks like coverage - the failure
    this module's docstring warns about, arrived at from the other side.
    """

    def _report_with(self, details):
        return {"drifts": [{"type": "Microsoft.Authorization/roleAssignments",
                            "name": "r", "drift_type": "extra_in_azure",
                            "details": details,
                            "change_origin": {"origin": "manual_change",
                                              "changed_by": "someone@example.com"}}]}

    ASSIGNMENT = ("/subscriptions/s/providers/Microsoft.Authorization/"
                  "RoleAssignments/5ea31b9e-618d-4adc-a6a4-ab2fe23c6d87")

    def test_quoting_a_resource_id_from_the_report_is_not_a_fabrication(self):
        r = self._report_with({"assignment_id": self.ASSIGNMENT})
        self.assertEqual(
            check_no_fabricated_actor(r, f"The assignment {self.ASSIGNMENT} is unmanaged."), [],
            "an identifier taken straight from the report was called invented")

    def test_the_bare_guid_of_a_reported_resource_is_also_accepted(self):
        r = self._report_with({"assignment_id": self.ASSIGNMENT})
        self.assertEqual(
            check_no_fabricated_actor(r, "Assignment 5ea31b9e-618d-4adc-a6a4-ab2fe23c6d87."), [])

    def test_a_guid_that_appears_nowhere_is_still_flagged(self):
        r = self._report_with({"assignment_id": self.ASSIGNMENT})
        v = check_no_fabricated_actor(r, "Granted by 00000000-1111-2222-3333-444444444444.")
        self.assertTrue(v, "the check must still catch a genuinely invented identity")

    def test_a_real_principal_is_still_accepted(self):
        r = self._report_with({"principal_id": "ef83bff1-c6c1-4cb1-84be-9bd758e8fc41"})
        self.assertEqual(
            check_no_fabricated_actor(r, "Held by ef83bff1-c6c1-4cb1-84be-9bd758e8fc41."), [])


class SectionAllowlistTests(unittest.TestCase):
    """Two live reports promoted the request's own question list to `##`
    headings, which reads as an exam script and buries the plan among
    meta-questions nobody asked. It survived the first, softer prompt wording -
    hence a mechanical check."""

    GOOD = ("## TL;DR\nx\n\n## Priority findings\nx\n\n"
            "## Remediation plan\nx\n\n## Caveats\nx\n")

    def test_the_four_sections_pass(self):
        self.assertEqual(check_only_allowlisted_sections(_report(), self.GOOD), [])

    def test_a_subtitle_on_an_allowed_section_still_passes(self):
        # Observed and acceptable: "## Caveats, confidence, and data-quality
        # notes". Matching on the phrase, not equality, is what permits it.
        text = ("## TL;DR\nx\n## Priority findings (by impact)\nx\n"
                "## Remediation plan (ordered)\nx\n## Caveats, confidence and data quality\nx\n")
        self.assertEqual(check_only_allowlisted_sections(_report(), text), [])

    def test_the_question_headings_are_flagged(self):
        for heading in (
            "## Which findings are likely Azure-managed resources?",
            "## Which findings indicate unmanaged/manual changes?",
            "## What should be fixed first",
        ):
            with self.subTest(heading=heading):
                self.assertTrue(
                    check_only_allowlisted_sections(_report(), self.GOOD + heading + "\nx\n"),
                    f"{heading!r} should not be an allowed section")

    def test_a_remediation_question_is_not_mistaken_for_the_plan(self):
        # The trap this check is built around: "remediated"/"remediation"
        # appear in two banned headings, so only the full phrase can match.
        for heading in ("## Which should be remediated by redeploying Bicep?",
                        "## Which should be handled by Azure Policy remediation or exception tracking?"):
            with self.subTest(heading=heading):
                self.assertTrue(check_only_allowlisted_sections(_report(), heading + "\nx\n"))

    def test_h3_findings_are_not_treated_as_sections(self):
        self.assertEqual(
            check_only_allowlisted_sections(_report(), "## TL;DR\n### Owner on the subscription\nx\n"), [])


class FindingHeadingTests(unittest.TestCase):
    """Live: six headings were the full 120-char ARM path, each followed by a
    `- Resource ID:` bullet repeating the identical string."""

    ARM = ("### /subscriptions/bd48a22c-91b9-46e6-a2ff-15893e348d83/providers/"
           "Microsoft.Authorization/RoleAssignments/79565f05-62fc-437a-bc0e-d82baccc6ccb\n"
           "- Resource ID: /subscriptions/bd48a22c-.../RoleAssignments/79565f05-...\n")

    def test_a_resource_id_heading_is_flagged(self):
        self.assertTrue(check_finding_headings_are_labels(_report(), self.ARM))

    def test_a_short_label_passes(self):
        text = "### Owner granted to user 70afebf7 at subscription scope\n- Resource ID: /subscriptions/x\n"
        self.assertEqual(check_finding_headings_are_labels(_report(), text), [])

    def test_a_long_prose_heading_is_flagged_even_without_an_id(self):
        self.assertTrue(check_finding_headings_are_labels(_report(), "### " + "word " * 30 + "\n"))


class FindingsMustNotCarryRemediationTests(unittest.TestCase):
    """Live: every finding ended 'Immediate action: verify this principal', the
    plan said verify, and a third section said verify again."""

    def test_an_action_line_inside_a_finding_is_flagged(self):
        text = ("### Owner on the subscription\n- Why it matters: full control\n"
                "- Immediate action: Verify that principal 70afebf7 is expected.\n")
        self.assertTrue(check_findings_do_not_carry_remediation(_report(), text))

    def test_evidence_only_findings_pass(self):
        text = ("### Owner on the subscription\n- Resource ID: /subscriptions/x\n"
                "- Why it matters: Owner at subscription scope grants full control.\n")
        self.assertEqual(check_findings_do_not_carry_remediation(_report(), text), [])

    def test_the_plan_may_still_say_what_to_do(self):
        # The rule is about WHERE remediation lives, not that it is forbidden.
        text = ("### Owner on the subscription\n- Evidence: created 2024-12-03\n\n"
                "## Remediation plan\n1. Immediate action: verify the principal.\n")
        self.assertEqual(check_findings_do_not_carry_remediation(_report(), text), [])


class LengthBudgetTests(unittest.TestCase):
    """Adding structure rules without a budget grew the report 27%
    (4,861 -> 6,195 output tokens) on restatement alone."""

    def test_a_long_report_is_flagged(self):
        self.assertTrue(check_length_within_budget(_report(), "word " * 1500))

    def test_a_normal_report_passes(self):
        self.assertEqual(check_length_within_budget(_report(), "word " * 800), [])

    def test_fenced_code_does_not_count(self):
        # Critical: the prompt REQUIRES writing the Bicep snippet inline rather
        # than offering it. A budget that punished that would pull the two rules
        # against each other.
        analysis = "word " * 900 + "\n```bicep\n" + "resource x 'y' = {}\n" * 400 + "```\n"
        self.assertEqual(check_length_within_budget(_report(), analysis), [])

    def test_the_budget_grows_with_the_finding_count(self):
        big = _report(drifts=[_drift(f"r{i}", dtype="extra_in_azure") for i in range(20)])
        self.assertEqual(check_length_within_budget(big, "word " * 1900), [])
        self.assertTrue(check_length_within_budget(_report(), "word " * 1900))

    def test_reconciled_rows_do_not_buy_extra_budget(self):
        # matched_unresolvable is not a finding, so it must not raise the
        # allowance - on real estates it outnumbered actionable drift ~30:3.
        noise = _report(drifts=[_drift(f"r{i}", dtype="matched_unresolvable") for i in range(20)])
        self.assertTrue(check_length_within_budget(noise, "word " * 1900))


class SignOffTests(unittest.TestCase):
    def test_end_of_report_is_flagged(self):
        self.assertTrue(check_no_sign_off(_report(), "## Caveats\nLogs expired.\n\nEnd of report."))

    def test_ending_on_a_caveat_passes(self):
        self.assertEqual(check_no_sign_off(_report(), "## Caveats\nActivity logs had expired."), [])


class RoleDefinitionGuidIsNotFabricatedTests(unittest.TestCase):
    """Caught against the real 2026-08-06 subscription report: `_known_actors`
    read a hand-listed set of detail keys, which missed `role_definition_guid`,
    so an analysis correctly naming the custom role it was shown was accused of
    inventing an identity. A check that fires on correct output gets muted."""

    ROLE = "53ca6127-db72-4b80-b1b0-d745d6d5456d"

    def _report_with_role(self):
        row = _drift("custom-role-assignment", dtype="extra_in_azure")
        row["details"] = {"role_name": self.ROLE, "role_definition_guid": self.ROLE,
                          "principal_id": "70afebf7-5bdd-45d9-9cfc-534af9a95589"}
        return _report(drifts=[row])

    def test_citing_the_custom_role_guid_is_not_a_fabrication(self):
        self.assertEqual(
            check_no_fabricated_actor(self._report_with_role(), f"Custom role {self.ROLE} is assigned."),
            [], "a GUID the report carries in details was called invented")

    def test_an_invented_guid_is_still_caught(self):
        self.assertTrue(check_no_fabricated_actor(
            self._report_with_role(), "Granted by 00000000-1111-2222-3333-444444444444."))


class SubscriptionGuidIsNotFabricatedTests(unittest.TestCase):
    """The THIRD miss of the same shape, caught by the first CI eval run
    (2026-08-07). The subscription guid sits in `lifecycle.resource_id` of all
    42 `policy_enforced_estate` rows - 198 occurrences, the most repeated
    identifier in the fixture - and `_known_actors` walked neither that key nor
    the row's own `resource_id`, so an analysis quoting the subscription was
    accused of inventing an identity.

    Two earlier fixes each enumerated one more key. `_known_actors` now reads
    the whole report, so there is no next key to miss."""

    SUB = "594e0bd0-2a8d-4419-b281-87869c20fd03"

    def _report_with_sub_guid_only_in_lifecycle(self):
        row = _drift("rg-drift-test-storage")
        row["lifecycle"] = {"resource_id": f"/subscriptions/{self.SUB}/resourceGroups/rg-drift-test"}
        return _report(drifts=[row])

    def test_citing_the_subscription_is_not_a_fabrication(self):
        self.assertEqual(
            check_no_fabricated_actor(
                self._report_with_sub_guid_only_in_lifecycle(),
                f"Run `az account set --subscription {self.SUB}` first."),
            [], "a GUID the report carries in lifecycle.resource_id was called invented")

    def test_a_guid_nowhere_in_the_report_is_still_caught(self):
        # The widened denominator must not make the check vacuous.
        self.assertTrue(check_no_fabricated_actor(
            self._report_with_sub_guid_only_in_lifecycle(),
            "Granted by 00000000-1111-2222-3333-444444444444."))


class PlanIsFlatTests(unittest.TestCase):
    """Round 2 capped bullets per FINDING and the plan blew the budget anyway:
    six items with five nested sub-steps each, and `az role assignment show`
    re-pasted once per assignment. Nesting is where the duplication hid."""

    NESTED = ("## Remediation plan\n"
              "1. Investigate the Owner assignment\n"
              "   1. Show the assignment:\n"
              "   2. Resolve the principal:\n"
              "2. Remove it\n")

    FLAT = ("## Remediation plan\n"
            "1. Investigate the Owner assignment, then the two Contributors.\n"
            "2. Remove any that are unwanted:\n"
            "   - `az role assignment delete --ids <id>` for each of:\n"
            "   - 79565f05, 5ea31b9e, e6107770\n")

    def test_nested_sub_steps_are_flagged(self):
        v = check_plan_is_flat(_report(), self.NESTED)
        self.assertTrue(v)
        self.assertIn("nested sub-step", v[0])

    def test_a_flat_plan_with_bullets_passes(self):
        # Bullets under a step are fine - it is ordered sub-STEPS that nest.
        self.assertEqual(check_plan_is_flat(_report(), self.FLAT), [])

    def test_indented_numbers_inside_code_do_not_count(self):
        # A snippet may legitimately contain indented numbering.
        analysis = ("## Remediation plan\n1. Deploy this:\n\n```bicep\n"
                    "  1. not a step\n```\n")
        self.assertEqual(check_plan_is_flat(_report(), analysis), [])

    def test_nesting_outside_the_plan_is_not_the_plans_problem(self):
        # Findings are governed by the six-bullet cap, not this check.
        analysis = "## Priority findings\n1. A finding\n   1. nested\n"
        self.assertEqual(check_plan_is_flat(_report(), analysis), [])

    def test_no_plan_section_is_silent(self):
        self.assertEqual(check_plan_is_flat(_report(), "## TL;DR\nClean.\n"), [])


class PlanDepthPromptTests(unittest.TestCase):
    def test_prompt_demands_a_flat_plan_and_one_command_per_action(self):
        from agent.drift_agent import DriftAgent
        sp = DriftAgent._get_system_prompt()
        self.assertIn("The PLAN IS FLAT", sp)
        self.assertIn("never sub-steps", sp)
        self.assertIn("give each command ONCE", sp)


class CommandsAreFencedTests(unittest.TestCase):
    """Live: `az role assignment show ...` written as an indented line under a
    `- Command:` bullet rendered as proportional prose folded into the step."""

    def test_a_bare_command_line_is_flagged(self):
        analysis = ("1. Inspect it.\n   - Command:\n"
                    "     az role assignment show --ids /subscriptions/x\n")
        v = check_commands_are_fenced(_report(), analysis)
        self.assertTrue(v)
        self.assertIn("az role assignment show", v[0])

    def test_a_fenced_command_passes(self):
        analysis = "1. Inspect it.\n\n```bash\naz role assignment show --ids /subscriptions/x\n```\n"
        self.assertEqual(check_commands_are_fenced(_report(), analysis), [])

    def test_an_inline_mention_is_not_a_command_line(self):
        # Prose referring to a command mid-sentence is fine.
        analysis = "Removing it needs an explicit `az role assignment delete`, not a redeploy.\n"
        self.assertEqual(check_commands_are_fenced(_report(), analysis), [])

    def test_a_bulleted_command_is_still_flagged(self):
        self.assertTrue(check_commands_are_fenced(_report(), "- az group delete --name x\n"))


class FenceMustBeAtColumnZeroTests(unittest.TestCase):
    """Pins the renderer quirk the prompt rule depends on: an INDENTED fence
    inside a list item is not a code block at all."""

    @staticmethod
    def _html(md):
        from tools.html_report import _render_agent_analysis_section
        return _render_agent_analysis_section(md)

    def test_indented_fence_is_not_a_code_block(self):
        md = "1. Step\n\n   ```bash\n   az group list\n   ```\n"
        self.assertNotIn("<pre>", self._html(md))

    def test_column_zero_fence_is_a_code_block_and_numbering_resumes(self):
        md = "1. Step\n\n```bash\naz group list\n```\n\n2. Next\n"
        html = self._html(md)
        self.assertIn("<pre>", html)
        self.assertIn('<ol start="2">', html)

    def test_the_check_catches_what_the_renderer_drops(self):
        # The renderer quirk above was pinned but nothing CHECKED for it, so on
        # the first live prod report all 22 fences were indented, every check
        # passed, and the HTML had zero <pre> blocks. A rule stated but
        # unchecked is worth as little as one checked but unstated.
        md = "1. Step\n\n   ```bash\n   az group list\n   ```\n"
        violations = check_fences_start_at_column_zero(_report(), md)
        self.assertTrue(violations)
        self.assertIn("inline span", violations[0])

    def test_a_column_zero_fence_passes(self):
        md = "1. Step\n\n```bash\naz group list\n```\n"
        self.assertEqual(check_fences_start_at_column_zero(_report(), md), [])

    def test_every_indented_fence_is_reported_not_just_the_first(self):
        # Both the opening and closing fence of each block count; the operator
        # needs the line numbers to find them.
        md = "1. a\n\n  ```bash\n  x\n  ```\n\n2. b\n\n  ```bash\n  y\n  ```\n"
        self.assertEqual(len(check_fences_start_at_column_zero(_report(), md)), 4)


def _policy_row(name, policy="drift-inherit-environment"):
    return {"type": "Microsoft.Web/sites", "name": name, "drift_type": "property_drift",
            "details": {}, "change_origin": {"origin": "policy_modify", "policy_name": policy,
                                             "severity": "low", "changed_by": None}}


class OneStoryIsOneFindingTests(unittest.TestCase):
    """39 resources whose tag was rewritten by ONE policy Modify effect is ONE
    finding - "LOW x 39, one story, many resources" - which is the insight. The
    word budget cannot catch the alternative: it scales with the finding count,
    so 39 near-identical headings sit comfortably inside it."""

    def _report39(self):
        rows = [_policy_row(f"res{i:02d}") for i in range(39)]
        rows.append(_drift("rogue-grant", dtype="extra_in_azure"))
        return _report(drifts=rows)

    def test_one_heading_per_row_is_flagged(self):
        sprawl = "".join(f"### tags.environment on res{i:02d}\n" for i in range(39))
        v = check_one_story_is_one_finding(self._report39(), sprawl)
        self.assertTrue(v)
        self.assertIn("2 distinct cause", v[0])

    def test_grouping_the_policy_rows_passes(self):
        good = ("### Contributor granted out of band\n"
                "### Policy-imposed environment tag (LOW x 39)\n")
        self.assertEqual(check_one_story_is_one_finding(self._report39(), good), [])

    def test_an_extra_narrative_heading_is_within_slack(self):
        # The previous provider added "### No composed/interacting drift".
        good = ("### Contributor granted out of band\n"
                "### Policy-imposed environment tag (LOW x 39)\n"
                "### No composed/interacting drift\n")
        self.assertEqual(check_one_story_is_one_finding(self._report39(), good), [])

    def test_distinct_causes_each_earn_a_heading(self):
        rows = [_policy_row("a", "policy-one"), _policy_row("b", "policy-two"),
                _policy_row("c", "policy-three"), _policy_row("d", "policy-four"),
                _policy_row("e", "policy-five"), _policy_row("f", "policy-six")]
        headings = "".join(f"### cause {i}\n" for i in range(6))
        self.assertEqual(check_one_story_is_one_finding(_report(drifts=rows), headings), [])

    def test_reconciled_rows_are_not_causes(self):
        # matched_unresolvable is not a finding, so it must not inflate the budget.
        rows = [_policy_row("a")] + [_drift(f"r{i}", dtype="matched_unresolvable") for i in range(20)]
        self.assertTrue(check_one_story_is_one_finding(
            _report(drifts=rows), "".join(f"### h{i}\n" for i in range(10))))

    def test_a_clean_report_is_silent(self):
        self.assertEqual(check_one_story_is_one_finding(_report(), "## TL;DR\nClean.\n"), [])


class OneStoryPromptTests(unittest.TestCase):
    def test_prompt_says_one_heading_per_story(self):
        from agent.drift_agent import DriftAgent
        sp = DriftAgent._get_system_prompt()
        self.assertIn("One `###` heading per STORY, not per row", sp)
        self.assertIn("one story, many resources", sp)
        self.assertIn("Split only where the CAUSE differs", sp)


def _deployer_report(deployer="ef83bff1-c6c1-4cb1-84be-9bd758e8fc41"):
    """A report where one Owner grant belongs to the identity that deploys it -
    the shape of the first live prod scan."""
    return _report(drifts=[
        {"type": "Microsoft.Storage/storageAccounts", "name": "stg1",
         "drift_type": "matched_unresolvable", "details": {},
         "change_origin": {"origin": "authorized_deployment", "changed_by": deployer,
                           "severity": "low"}},
        {"type": "Microsoft.Authorization/roleAssignments",
         "name": f"Owner -> ServicePrincipal:{deployer}", "drift_type": "extra_in_azure",
         "details": {"principal_id": deployer, "role_name": "Owner",
                     "assignment_id": "/subscriptions/s/providers/Microsoft.Authorization/"
                                      "RoleAssignments/82af86cc-a782-4dfd-aa65-6da956955a41"},
         "change_origin": {"origin": "unknown", "changed_by": None, "severity": "medium"}},
    ])


class DoesNotDeleteTheDeployerTests(unittest.TestCase):
    """Observed live: three subscription Owner grants listed for deletion, one
    of them the service principal the SAME report credits with five
    authorized_deployment changes. Running it breaks every future deploy,
    including the remediation proposed two steps earlier."""

    def test_deleting_the_deployers_grant_is_flagged(self):
        analysis = ("```bash\naz role assignment delete --ids /subscriptions/s/providers/"
                    "Microsoft.Authorization/RoleAssignments/82af86cc-a782-4dfd-aa65-6da956955a41\n```")
        v = check_does_not_delete_the_deployer(_deployer_report(), analysis)
        self.assertTrue(v)
        self.assertIn("ef83bff1", v[0])

    def test_flagging_the_grant_without_deleting_it_passes(self):
        # Questioning a standing Owner is CORRECT - only the bare delete is not.
        analysis = ("This Owner grant belongs to the deployment pipeline. Narrow it to "
                    "Contributor or declare it in Bicep rather than removing it.")
        self.assertEqual(check_does_not_delete_the_deployer(_deployer_report(), analysis), [])

    def test_deleting_an_unrelated_grant_is_not_flagged(self):
        analysis = ("```bash\naz role assignment delete --ids /subscriptions/s/providers/"
                    "Microsoft.Authorization/RoleAssignments/00000000-0000-0000-0000-000000000000\n```")
        self.assertEqual(check_does_not_delete_the_deployer(_deployer_report(), analysis), [])

    def test_no_deployer_in_the_report_means_nothing_to_protect(self):
        report = _report(drifts=[{"type": "Microsoft.Authorization/roleAssignments",
                                  "name": "Owner -> User:x", "drift_type": "extra_in_azure",
                                  "details": {"principal_id": "abc"}, "change_origin": {}}])
        self.assertEqual(check_does_not_delete_the_deployer(
            report, "az role assignment delete --ids abc"), [])


class SnippetsUseTheDeclaredLocationTests(unittest.TestCase):
    """A snippet is applied, so a guessed region is a defect. Live: replacement
    Bicep for an australiaeast estate hardcoded eastus, twice."""

    REPORT = {"drifts": [], "drift_count": 0,
              "arm_resources": [{"type": "Microsoft.KeyVault/vaults", "name": "kv",
                                 "location": "australiaeast"}]}

    def test_a_guessed_region_is_flagged(self):
        v = check_snippets_use_the_declared_location(self.REPORT, "  location: 'eastus'\n")
        self.assertTrue(v)
        self.assertIn("australiaeast", v[0])

    def test_the_declared_region_passes(self):
        self.assertEqual(check_snippets_use_the_declared_location(
            self.REPORT, "  location: 'australiaeast'\n"), [])

    def test_unknown_locations_are_not_treated_as_declared(self):
        # Child resources carry location 'unknown'; that must not authorise it.
        report = {"drifts": [], "arm_resources": [
            {"type": "x", "name": "y", "location": "unknown"},
            {"type": "z", "name": "w", "location": "australiaeast"}]}
        self.assertTrue(check_snippets_use_the_declared_location(report, "location: 'unknown'"))

    def test_a_report_without_arm_resources_cannot_judge(self):
        self.assertEqual(check_snippets_use_the_declared_location(
            _report(), "location: 'eastus'"), [])
