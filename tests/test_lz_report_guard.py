"""The live-report guard, and what it failed to catch.

verify_lz_report.py asserts invariants on a REAL report because unit tests
cannot: every defect of 2026-08-03/04 produced a plausible-looking report.

It has itself been wrong twice. It passed both presentation defects fixed in
#387, because it asserted orphans were LINKED and never that they were shown
TOGETHER or shown in EVERY section. A guard nobody tests is a guard nobody can
trust, so these tests exist as much for the guard as for the pipeline.
"""

import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "verify_lz_report",
    Path(__file__).resolve().parent.parent / ".github" / "scripts" / "verify_lz_report.py",
)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

RG = "Microsoft.Resources/resourceGroups"


def _rg(name, drift_type="missing_in_azure"):
    return {"type": RG, "name": name, "drift_type": drift_type, "details": {}}


def _orphan(name, group, rtype="Microsoft.Storage/storageAccounts"):
    return {"type": rtype, "name": name, "drift_type": "missing_in_azure",
            "details": {"orphaned_by_missing_resource_group": group}}


class OrphansMustBeShownWithTheirCauseTests(unittest.TestCase):
    """Linkage is not enough. Rows are emitted in creation order, and an orphan
    is created a stage after its group, so one deletion read as three unrelated
    ones with six role assignments in between - while every `orphaned_by` link
    was correctly populated and the guard passed.
    """

    def test_an_orphan_separated_from_its_group_fails(self):
        report = {"drifts": [
            _rg("rg-logging"),
            {"type": "Microsoft.Authorization/roleAssignments", "name": "Owner -> User:x",
             "drift_type": "extra_in_azure", "details": {}},
            _orphan("stla7m6et", "rg-logging"),
        ]}
        bad, _ = guard.check_orphans_are_shown_with_their_cause(report)
        self.assertTrue(bad, "an orphan stranded away from its resource group passed the guard")

    def test_adjacent_orphans_pass(self):
        report = {"drifts": [
            _rg("rg-logging"),
            _orphan("law", "rg-logging", "Microsoft.OperationalInsights/workspaces"),
            _orphan("stla7m6et", "rg-logging"),
            {"type": "Microsoft.Authorization/roleAssignments", "name": "Owner -> User:x",
             "drift_type": "extra_in_azure", "details": {}},
        ]}
        bad, _ = guard.check_orphans_are_shown_with_their_cause(report)
        self.assertEqual(bad, [])

    def test_an_orphan_whose_group_is_not_reported_is_not_faulted(self):
        # Nothing to sit under - the report is not wrong, so the guard must not
        # manufacture a failure.
        report = {"drifts": [_orphan("stla7m6et", "rg-not-in-this-report")]}
        bad, _ = guard.check_orphans_are_shown_with_their_cause(report)
        self.assertEqual(bad, [])

    def test_a_report_with_no_orphans_passes(self):
        self.assertEqual(guard.check_orphans_are_shown_with_their_cause({"drifts": []})[0], [])


class EveryDeletionMustReachTheReportSectionTests(unittest.TestCase):
    """`property_drifts` feeds a report section built from a bicep set that
    filters out unresolvable-named declarations, so a deleted uniqueString-named
    resource rendered once where literal-named findings rendered twice. The
    finding existed; the section that lists missing resources omitted it.
    """

    def test_a_missing_row_absent_from_property_drifts_fails(self):
        report = {
            "drifts": [_orphan("stla7m6et", "rg-logging"), _rg("rg-logging")],
            "property_drifts": [
                {"resource_type": RG, "resource_name": "rg-logging", "drift_type": "missing"},
            ],
        }
        bad, _ = guard.check_deletions_reach_the_report_section(report)
        self.assertTrue(bad, "a deleted resource missing from the report section passed the guard")

    def test_all_present_passes(self):
        report = {
            "drifts": [_rg("rg-logging"), _orphan("stla7m6et", "rg-logging")],
            "property_drifts": [
                {"resource_type": RG, "resource_name": "rg-logging", "drift_type": "missing"},
                {"resource_type": "Microsoft.Storage/storageAccounts",
                 "resource_name": "stla7m6et", "drift_type": "missing"},
            ],
        }
        self.assertEqual(guard.check_deletions_reach_the_report_section(report)[0], [])

    def test_a_report_with_no_property_drifts_at_all_is_skipped(self):
        # Phase-1-only output has no such section; absence is not a violation.
        report = {"drifts": [_rg("rg-logging")], "property_drifts": []}
        self.assertEqual(guard.check_deletions_reach_the_report_section(report)[0], [])


class TheGuardsAreActuallyRegisteredTests(unittest.TestCase):
    """A check that exists but is never called is the same as no check. Both of
    #387's defects were catchable by a function nobody had written; the next
    failure mode is writing one and forgetting to register it."""

    def test_both_new_checks_run(self):
        names = {c.__name__ for c in guard.CHECKS}
        self.assertIn("check_orphans_are_shown_with_their_cause", names)
        self.assertIn("check_deletions_reach_the_report_section", names)


if __name__ == "__main__":
    unittest.main()
