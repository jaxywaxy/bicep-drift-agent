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
    check_no_fabricated_actor,
    check_no_unearned_attribution,
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
        good = ("## TL;DR\n`st1` was deleted out of band by jacqui.anker@gmail.com "
                "and needs restoring.\n\n## Findings\nOne critical deletion.")
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
