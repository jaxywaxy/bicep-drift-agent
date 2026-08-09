"""
A scan scope that cannot be read is a targeting failure, not mass deletion.

Resource Graph answers a query for a non-existent resource group with a
SUCCESSFUL, empty result set - identical to an RG that exists and is empty.
Verified live 2026-08-02 against a torn-down RG:

    Resources | where resourceGroup =~ 'rg-drift-test'
    -> {"count": 0, "data": [], "total_records": 0}

Without a guard the pipeline read that as "all 75 declared resources were
deleted" and produced 74 findings at maximum severity, routed to the LZ owner.
"""

import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration import phase1
from orchestration.detection import _run_phase1
from tools.live_state.common import ScopeNotFoundError, resource_group_exists


def _http_error(code):
    return urllib.error.HTTPError("https://management.azure.com", code, "", {}, None)


class ResourceGroupExistsTests(unittest.TestCase):
    """Tri-state by design: True, False, and 'could not tell'."""

    def _with_response(self, status):
        resp = mock.MagicMock()
        resp.status = status
        resp.__enter__.return_value = resp
        return mock.patch("tools.live_state.common.arm_urlopen", return_value=resp)

    def test_200_is_exists(self):
        with self._with_response(200):
            self.assertIs(resource_group_exists("rg-a", "sub", token="t"), True)  # nosec B106

    def test_404_is_absent(self):
        with mock.patch("tools.live_state.common.arm_urlopen", side_effect=_http_error(404)):
            self.assertIs(resource_group_exists("rg-a", "sub", token="t"), False)  # nosec B106

    def test_403_is_inconclusive_not_absent(self):
        # A permissions failure must never be read as "the RG is gone".
        with mock.patch("tools.live_state.common.arm_urlopen", side_effect=_http_error(403)):
            self.assertIsNone(resource_group_exists("rg-a", "sub", token="t"))  # nosec B106

    def test_transport_failure_is_inconclusive(self):
        with mock.patch("tools.live_state.common.arm_urlopen", side_effect=OSError("no route")):
            self.assertIsNone(resource_group_exists("rg-a", "sub", token="t"))  # nosec B106

    def test_missing_inputs_are_inconclusive(self):
        self.assertIsNone(resource_group_exists("", "sub"))
        self.assertIsNone(resource_group_exists("rg-a", ""))


class _IsolatedReportsDir(unittest.TestCase):
    """Run in a scratch cwd: the guard WRITES a marker report, so a test calling
    it from the repo root drops junk reports into reports/ - which the CI
    counting step then reads as real scopes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, self._cwd)


class GuardUnverifiableScopeTests(_IsolatedReportsDir):
    """The guard fires only on the ambiguous case, and errs toward silence."""

    def test_absent_scope_raises(self):
        with mock.patch("orchestration.phase1.resource_group_exists", return_value=False):
            with self.assertRaises(ScopeNotFoundError) as ctx:
                phase1._guard_unverifiable_scope("rg-gone")
        self.assertIn("does not exist", str(ctx.exception))

    def test_unconfirmable_scope_also_raises(self):
        # An unverifiable scope is exactly as unsafe to report on as an absent
        # one - reporting deletions we cannot substantiate is the failure mode.
        with mock.patch("orchestration.phase1.resource_group_exists", return_value=None):
            with self.assertRaises(ScopeNotFoundError) as ctx:
                phase1._guard_unverifiable_scope("rg-unknown")
        self.assertIn("could not be confirmed", str(ctx.exception))

    def test_existing_but_empty_scope_is_allowed_through(self):
        # This one IS real drift: the RG is there and everything declared is
        # genuinely gone. It must stay loud.
        with mock.patch("orchestration.phase1.resource_group_exists", return_value=True):
            self.assertIsNone(phase1._guard_unverifiable_scope("rg-empty"))


class GuardIsNotCalledOnTheHappyPathTests(_IsolatedReportsDir):
    """No ARM round-trip when the scan found resources - the check exists for
    the empty result only, so a normal scan pays nothing for it."""

    def test_no_existence_check_when_resources_returned(self):
        with mock.patch("orchestration.phase1.get_live_state", return_value=[{"name": "x"}]), \
             mock.patch("orchestration.phase1.fetch_cross_subscription_resources", return_value=[]), \
             mock.patch("orchestration.phase1.fetch_declared_defender_pricings", return_value=[]), \
             mock.patch("orchestration.phase1.fetch_declared_workspace_tables", return_value=[]), \
             mock.patch("orchestration.phase1.qualify_extension_resource_names"), \
             mock.patch("orchestration.phase1.resource_group_exists") as exists:
            phase1._fetch_live_state("rg-a", "resource_group", [], None)
        exists.assert_not_called()

    def test_existence_check_runs_when_live_set_is_empty(self):
        with mock.patch("orchestration.phase1.get_live_state", return_value=[]), \
             mock.patch("orchestration.phase1.resource_group_exists", return_value=False) as exists:
            with self.assertRaises(ScopeNotFoundError):
                phase1._fetch_live_state("rg-a", "resource_group", [], None)
        exists.assert_called_once()


class MultiRgPassSurvivesOneDeadScopeTests(unittest.TestCase):
    """A stale entry in the LZ index must not cost the whole subscription pass."""

    def test_dead_rg_is_skipped_and_the_rest_still_run(self):
        ran = []

        def fake_run(_bicep, rg):
            if rg == "rg-gone":
                raise ScopeNotFoundError("rg-gone does not exist")
            ran.append(rg)

        with mock.patch("orchestration.detection.run_phase1", side_effect=fake_run):
            _run_phase1("main.bicep", ["rg-a", "rg-gone", "rg-b"])

        self.assertEqual(ran, ["rg-a", "rg-b"])

    def test_single_rg_scan_still_exits(self):
        # Nothing to salvage, and exiting 0 here would read as "clean".
        with mock.patch("orchestration.detection.run_phase1",
                        side_effect=ScopeNotFoundError("gone")):
            with self.assertRaises(SystemExit) as ctx:
                _run_phase1("main.bicep", ["rg-only"])
        self.assertEqual(ctx.exception.code, 2)



class ScopeNotFoundReportTests(_IsolatedReportsDir):
    """The artifact must exist even when the scan cannot proceed.

    The pipeline guarantees a report always exists, and count_drifts fails on an
    empty reports dir because "no report" must never read as "no drift".
    Aborting without a report traded a wrong answer for an unreadable one - CI
    failed with "the drift check produced no report" instead of naming the RG.
    """

    def test_marker_report_is_written_before_raising(self):
        import json

        with mock.patch("orchestration.phase1.resource_group_exists", return_value=False):
            with self.assertRaises(ScopeNotFoundError):
                phase1._guard_unverifiable_scope("rg-gone", "main.bicep")
        written = os.path.join("reports", "rg-gone-drift.json")
        self.assertTrue(os.path.exists(written))
        with open(written) as f:
            report = json.load(f)

        self.assertEqual(report["scope_status"], "not_found")
        self.assertEqual(report["drifts"], [])
        self.assertIn("does not exist", report["scope_status_reason"])


class CountDriftsRejectsUnreadableScopeTests(unittest.TestCase):
    """A zero-drift report from a scope that does not exist is not a clean scan."""

    def _reports_dir(self, tmp, payload):
        import json
        d = os.path.join(tmp, "reports")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "rg-gone-drift.json"), "w") as f:
            json.dump(payload, f)
        return d

    def test_not_found_report_does_not_tally_as_clean(self):
        import tempfile
        from tools.count_drifts import count_drifts

        with tempfile.TemporaryDirectory() as tmp:
            d = self._reports_dir(tmp, {
                "resource_group": "rg-gone", "scope_status": "not_found",
                "drift_count": 0, "drifts": [],
            })
            counts = count_drifts(d)

        self.assertEqual(counts["unreadable_scope_count"], 1)
        self.assertEqual(counts["total_issues"], 0)
        self.assertEqual(counts["unreadable_scopes"], ["rg-gone"])

    def test_main_exits_nonzero_and_names_the_scope(self):
        import io
        import tempfile
        from contextlib import redirect_stderr
        from tools.count_drifts import main

        with tempfile.TemporaryDirectory() as tmp:
            d = self._reports_dir(tmp, {
                "resource_group": "rg-gone", "scope_status": "not_found",
                "drift_count": 0, "drifts": [],
            })
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["count_drifts.py", d])

        self.assertEqual(rc, 1)
        self.assertIn("Scope not found", err.getvalue())
        self.assertIn("rg-gone", err.getvalue())

    def test_a_real_report_alongside_still_counts(self):
        import json
        import tempfile
        from tools.count_drifts import count_drifts

        with tempfile.TemporaryDirectory() as tmp:
            d = self._reports_dir(tmp, {
                "resource_group": "rg-gone", "scope_status": "not_found",
                "drift_count": 0, "drifts": [],
            })
            with open(os.path.join(d, "rg-live-drift.json"), "w") as f:
                json.dump({"resource_group": "rg-live", "drifts": [
                    {"drift_type": "missing_in_azure", "details": {}},
                ]}, f)
            counts = count_drifts(d)

        # The readable scope's drift is still reported; the unreadable one is
        # flagged separately rather than diluting or hiding it.
        self.assertEqual(counts["missing_count"], 1)
        self.assertEqual(counts["unreadable_scope_count"], 1)

if __name__ == "__main__":
    unittest.main()
