"""Cannot collect is not the same as is not there.

Every collector logs-and-skips so one ARM outage never sinks a scan. The cost is
silent: a declared child with no collected counterpart is INDISTINGUISHABLE from
a deleted one, so a failed listing falls straight through to `missing_in_azure`.
A local run on 2026-08-01 reported 27 such rows for resources that all existed
(a TLS trust-store fault, fixed separately); the data-plane expander's own
comment records an earlier one - a transient agentPools failure reporting a
healthy declared pool as deleted.

The rows are NOT dropped. Suppressing them would hide a genuine deletion behind
a transient error, which is the silent-swallow that left the backup comparators
dead for a month (#330). They are reported, and marked unverified.

Three layers, because each can pass while the next is broken:
  1. the collector records the gap for the type it failed to list
  2. the marking annotates exactly those rows and no others
  3. run() actually calls it - the unit tests pass either way
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_drift_check
from run_drift_check import _mark_unverified_missing
from tools.diff_states import ResourceDrift
from tools.live_state import CollectionGaps
from tools.live_state.collectors.data_plane import _expand_data_plane_children

BLOB = "Microsoft.Storage/storageAccounts/blobServices"
STORAGE_ACCOUNT = {
    "type": "microsoft.storage/storageaccounts",
    "name": "st1",
    "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1",
    "resource_group": "rg",
}


class TheCollectorRecordsWhatItCouldNotReadTests(unittest.TestCase):
    def test_a_failed_listing_is_recorded_against_its_child_type(self):
        gaps = CollectionGaps()
        with mock.patch("urllib.request.urlopen", side_effect=OSError("ARM 503")), \
                mock.patch("time.sleep"):  # the collector retries once
            _expand_data_plane_children([dict(STORAGE_ACCOUNT)], token="t", gaps=gaps)
        self.assertTrue(gaps.covers(BLOB))
        self.assertIn("503", gaps.reason_for(BLOB))

    def test_a_successful_listing_records_nothing(self):
        def ok(req, timeout=0, **_):
            return io.BytesIO(json.dumps({"value": []}).encode())

        gaps = CollectionGaps()
        with mock.patch("urllib.request.urlopen", side_effect=ok):
            _expand_data_plane_children([dict(STORAGE_ACCOUNT)], token="t", gaps=gaps)
        self.assertFalse(gaps, f"clean run recorded a gap: {gaps.as_dict()}")


class BothLiveStatePathsCarryTheRecorderTests(unittest.TestCase):
    """get_live_state has two paths and the slow one is rarely exercised - it
    reached review with `gaps` undefined, a NameError that only fires when
    Resource Graph is unavailable, which is exactly when a scan is already
    degraded."""

    def test_the_resourcemanagementclient_fallback_forwards_gaps(self):
        import tools.live_state.resource_graph as rg

        gaps = CollectionGaps()
        with mock.patch.object(rg, "_augment_untracked_resources") as augment, \
                mock.patch("azure.mgmt.resource.resources.ResourceManagementClient") as client:
            client.return_value.resources.list_by_resource_group.return_value = []
            rg._get_live_state_fallback("rg", "sub", "resource_group", gaps=gaps)
        self.assertIs(augment.call_args.kwargs.get("gaps"), gaps)


class OnlyTheUngatheredTypesAreMarkedTests(unittest.TestCase):
    def setUp(self):
        self.gaps = CollectionGaps()
        self.gaps.record(BLOB, "listing blobServices failed: ARM 503")
        self.drifts = [
            ResourceDrift(BLOB, "st1/default", "missing_in_azure"),
            ResourceDrift("Microsoft.Web/sites", "app-1", "missing_in_azure"),
            ResourceDrift(BLOB, "st1/default", "property_drift"),
        ]

    def test_the_ungathered_row_is_marked_unverified(self):
        _mark_unverified_missing(self.drifts, self.gaps)
        self.assertTrue(self.drifts[0].details["collection_unverified"])
        self.assertIn("NOT evidence of deletion", self.drifts[0].details["note"])

    def test_a_type_that_WAS_collected_still_reads_as_deleted(self):
        """The precision that makes this worth doing - a real deletion of a
        type the collectors read fine must not be softened."""
        _mark_unverified_missing(self.drifts, self.gaps)
        self.assertNotIn("collection_unverified", self.drifts[1].details)

    def test_only_missing_rows_are_touched(self):
        # A property drift was computed from live state that DID arrive.
        _mark_unverified_missing(self.drifts, self.gaps)
        self.assertNotIn("collection_unverified", self.drifts[2].details)

    def test_no_row_is_ever_dropped(self):
        before = len(self.drifts)
        _mark_unverified_missing(self.drifts, self.gaps)
        self.assertEqual(len(self.drifts), before)

    def test_no_gaps_means_no_annotation_at_all(self):
        _mark_unverified_missing(self.drifts, CollectionGaps())
        for drift in self.drifts:
            self.assertNotIn("collection_unverified", drift.details)


class ThePipelineActuallyCallsItTests(unittest.TestCase):
    """The unit tests above pass whether or not run() wires the marking in -
    deleting the call site leaves them all green. This drives run()."""

    def _run(self, gapped_type):
        captured = {}

        def fake_fetch(resource_group, scope, arm_resources, gaps=None, bicep_file=""):
            if gapped_type and gaps is not None:
                gaps.record(gapped_type, "collector down")
            return []

        # **_ deliberately: a fake narrower than what it replaces breaks the
        # moment the real signature grows, which says nothing about this test.
        def fake_save(bicep_file, resource_group, arm, live, drifts,
                      policy_required_tags=None, collection_gaps=None, **_):
            captured["drifts"] = drifts
            captured["collection_gaps"] = collection_gaps

        with mock.patch.object(run_drift_check, "_resolve_parameter_overrides", return_value={}), \
                mock.patch.object(run_drift_check, "_compile_and_extract",
                                  return_value=([{"type": BLOB, "name": "st1/default"}], "resourceGroup")), \
                mock.patch.object(run_drift_check, "_fetch_live_state", side_effect=fake_fetch), \
                mock.patch.object(run_drift_check, "_load_ignore_patterns", return_value=None), \
                mock.patch.object(run_drift_check, "_diff_states",
                                  return_value=[ResourceDrift(BLOB, "st1/default", "missing_in_azure")]), \
                mock.patch.object(run_drift_check, "_run_rbac_sidecar"), \
                mock.patch.object(run_drift_check, "_run_policy_sidecar", return_value=({}, [])), \
                mock.patch.object(run_drift_check, "_run_stack_sidecar"), \
                mock.patch.object(run_drift_check, "format_drift_report", return_value=""), \
                mock.patch.object(run_drift_check, "_save_phase1_report", side_effect=fake_save):
            run_drift_check.run("main.bicep", "rg-x")
        return captured

    def test_a_gapped_type_reaches_the_report_marked(self):
        captured = self._run(BLOB)
        self.assertTrue(captured["drifts"][0].details.get("collection_unverified"))

    def test_the_gaps_are_persisted_so_the_run_is_auditable(self):
        captured = self._run(BLOB)
        self.assertIn(BLOB.lower(), captured["collection_gaps"])

    def test_a_clean_run_marks_nothing_and_reports_no_gaps(self):
        captured = self._run(None)
        self.assertNotIn("collection_unverified", captured["drifts"][0].details)
        self.assertEqual(captured["collection_gaps"], {})


if __name__ == "__main__":
    unittest.main()
