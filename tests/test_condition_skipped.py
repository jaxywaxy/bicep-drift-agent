"""A declaration this scan gated off is not an unmanaged resource.

`flatten_resources` drops a resource whose `condition` resolves false, so the
DEPLOYED resource has nothing to match and comes back `extra_in_azure` - which
reads as "unmanaged resource, consider deleting". That is the tool recommending
you delete something you deploy on purpose.

It cost a live round on 2026-07-21: a scan run with default params
(deployAks=false) reported the real AKS cluster as unmanaged. The analysis
declined to delete it, but only by INFERRING a contradiction from the
attribution - the fact was known at compile time and thrown away.

Also covers the two defects that live in the same area:
  - .bicepparam values were all strings, so a numeric parameter feeding a
    resource property could never equal what Azure returns
  - Phase 1 loaded the FIRST .drift-ignore it found instead of layering the
    agent's baseline with the landing zone's, disagreeing with Phase 2
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration import phase1
from orchestration.phase1 import (
    _annotate_condition_skipped,
    _coerce_bicepparam_value,
    _load_ignore_patterns,
)
from tools.compile_bicep import extract_resources_from_arm
from tools.diff_states import ResourceDrift
from tools.normalizer.flatten import SkippedDeclarations

AKS = "Microsoft.ContainerService/managedClusters"
POOLS = "Microsoft.ContainerService/managedClusters/agentPools"


def _gated_module_template(deploy_aks=False):
    """The deployAks shape: a MODULE gated off, declaring AKS inside."""
    return {
        "parameters": {"deployAks": {"type": "bool", "defaultValue": deploy_aks}},
        "resources": [{
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2022-09-01",
            "name": "deploy-aks",
            "condition": "[parameters('deployAks')]",
            "properties": {"template": {"resources": [
                {"type": AKS, "name": "aks-1"},
                {"type": POOLS, "name": "aks-1/pool"},
            ]}},
        }],
    }


class ASkippedModuleRecordsWhatItWouldHaveDeployedTests(unittest.TestCase):
    """Recording the module's own type would be useless - a live cluster's row
    is Microsoft.ContainerService/managedClusters, not .../deployments."""

    def test_the_inner_types_are_recorded_not_the_deployments_wrapper(self):
        skipped = SkippedDeclarations()
        extract_resources_from_arm(_gated_module_template(), skipped=skipped)
        self.assertTrue(skipped.covers(AKS))
        self.assertTrue(skipped.covers(POOLS))
        self.assertFalse(skipped.covers("Microsoft.Resources/deployments"))

    def test_the_driving_parameter_and_its_value_are_kept(self):
        skipped = SkippedDeclarations()
        extract_resources_from_arm(_gated_module_template(), skipped=skipped)
        self.assertEqual(skipped.entry_for(AKS)["parameters"], {"deployAks": False})

    def test_a_module_that_is_NOT_gated_off_records_nothing(self):
        skipped = SkippedDeclarations()
        resources = extract_resources_from_arm(
            _gated_module_template(deploy_aks=True), skipped=skipped)
        self.assertFalse(skipped, f"deployed module recorded as skipped: {skipped.as_list()}")
        self.assertTrue(any(r["type"] == AKS for r in resources))

    def test_the_declaration_is_still_dropped_from_the_desired_state(self):
        """Recording must not resurrect it - a gated-off resource that stayed in
        the desired set would false-flag missing_in_azure, which is the
        behaviour the skip exists to prevent."""
        skipped = SkippedDeclarations()
        resources = extract_resources_from_arm(_gated_module_template(), skipped=skipped)
        self.assertEqual(resources, [])


class TheExtraIsAnnotatedNotAccusedTests(unittest.TestCase):
    def setUp(self):
        self.skipped = SkippedDeclarations()
        extract_resources_from_arm(_gated_module_template(), skipped=self.skipped)
        self.drifts = [
            ResourceDrift(AKS, "aks-drift-test", "extra_in_azure"),
            ResourceDrift("Microsoft.Storage/storageAccounts", "stray1", "extra_in_azure"),
            ResourceDrift(AKS, "aks-drift-test", "missing_in_azure"),
        ]

    def test_the_gated_off_type_is_marked_a_parameter_mismatch(self):
        _annotate_condition_skipped(self.drifts, self.skipped)
        details = self.drifts[0].details
        self.assertTrue(details["condition_skipped"])
        self.assertEqual(details["skipped_parameters"], {"deployAks": False})
        self.assertIn("NOT an unmanaged resource", details["note"])

    def test_a_genuinely_undeclared_resource_is_left_accused(self):
        """The precision that makes this worth doing - a real unmanaged
        resource must still read as one."""
        _annotate_condition_skipped(self.drifts, self.skipped)
        self.assertNotIn("condition_skipped", self.drifts[1].details)

    def test_only_extras_are_touched(self):
        _annotate_condition_skipped(self.drifts, self.skipped)
        self.assertNotIn("condition_skipped", self.drifts[2].details)

    def test_nothing_skipped_means_no_annotation(self):
        _annotate_condition_skipped(self.drifts, SkippedDeclarations())
        for drift in self.drifts:
            self.assertNotIn("condition_skipped", drift.details)


class ThePipelineActuallyCallsItTests(unittest.TestCase):
    """The unit tests pass whether or not run() wires the annotation in."""

    def _run(self, skip_it):
        captured = {}

        def fake_compile(bicep_file, overrides, skipped=None):
            if skip_it and skipped is not None:
                skipped.record(
                    {"type": "Microsoft.Resources/deployments",
                     "properties": {"template": {"resources": [{"type": AKS}]}}},
                    "[parameters('deployAks')]", {"deployAks": False},
                )
            return [], "resourceGroup"

        # *_ / **kwargs deliberately: a fake narrower than what it replaces
        # breaks when the real signature grows, which says nothing about the
        # behaviour under test.
        def fake_save(bicep_file, rg, arm, live, drifts, *_, **kwargs):
            captured["drifts"] = drifts
            captured["condition_skipped"] = kwargs.get("condition_skipped")

        with mock.patch.object(phase1, "_resolve_parameter_overrides", return_value={}), \
                mock.patch.object(phase1, "_compile_and_extract", side_effect=fake_compile), \
                mock.patch.object(phase1, "_fetch_live_state", return_value=[]), \
                mock.patch.object(phase1, "_load_ignore_patterns", return_value=None), \
                mock.patch.object(phase1, "_diff_states",
                                  return_value=[ResourceDrift(AKS, "aks-1", "extra_in_azure")]), \
                mock.patch.object(phase1, "_run_rbac_sidecar"), \
                mock.patch.object(phase1, "_run_policy_sidecar", return_value=({}, [])), \
                mock.patch.object(phase1, "_run_stack_sidecar"), \
                mock.patch.object(phase1, "format_drift_report", return_value=""), \
                mock.patch.object(phase1, "_save_phase1_report", side_effect=fake_save):
            phase1.run("main.bicep", "rg-x")
        return captured

    def test_the_gated_off_extra_reaches_the_report_annotated(self):
        captured = self._run(skip_it=True)
        self.assertTrue(captured["drifts"][0].details.get("condition_skipped"))

    def test_the_skipped_declarations_are_persisted(self):
        captured = self._run(skip_it=True)
        self.assertEqual([e["type"] for e in captured["condition_skipped"]], [AKS])

    def test_a_run_with_nothing_gated_off_annotates_nothing(self):
        captured = self._run(skip_it=False)
        self.assertNotIn("condition_skipped", captured["drifts"][0].details)
        self.assertEqual(captured["condition_skipped"], [])


class BicepparamValuesKeepTheirTypeTests(unittest.TestCase):
    """All-strings is wrong the moment a parameter feeds a resource PROPERTY:
    a declared capacity of '3' never equals the 3 Azure returns."""

    def test_booleans_and_numbers_are_not_strings(self):
        self.assertIs(_coerce_bicepparam_value("true"), True)
        self.assertIs(_coerce_bicepparam_value("False"), False)
        self.assertEqual(_coerce_bicepparam_value("3"), 3)
        self.assertEqual(_coerce_bicepparam_value("2.5"), 2.5)

    def test_a_quoted_value_stays_a_string_even_when_it_looks_numeric(self):
        self.assertEqual(_coerce_bicepparam_value("'3'"), "3")
        self.assertEqual(_coerce_bicepparam_value('"true"'), "true")

    def test_anything_unparseable_survives_as_the_raw_string(self):
        self.assertEqual(_coerce_bicepparam_value("json('0.25')"), "json('0.25')")

    def test_a_false_parameter_is_kept_not_dropped_as_empty(self):
        """`if value:` dropped False and 0 - the two values a condition gate
        most needs."""
        with mock.patch("pathlib.Path.exists", return_value=True), \
                mock.patch("builtins.open",
                           mock.mock_open(read_data="param deployAks = false\nparam count = 0\n")):
            params = phase1._load_bicepparam_file("x/bicep/main.bicep", "rg-test")
        self.assertIs(params["deployAks"], False)
        self.assertEqual(params["count"], 0)


class PhaseOneLayersTheIgnoreProfileTests(unittest.TestCase):
    """Phase 1 returned the FIRST .drift-ignore it found, so a landing zone's
    own file REPLACED the agent's baseline instead of adding to it - and Phase 2
    layers them, so the two phases disagreed about what is ignorable."""

    def test_both_the_baseline_and_the_repo_profile_are_loaded(self):
        with mock.patch.object(phase1, "_find_repo_ignore",
                               return_value=Path("/lz/.drift-ignore")), \
                mock.patch.object(phase1.IgnorePatternList, "from_files") as from_files:
            from_files.return_value.patterns = []
            _load_ignore_patterns("lz/bicep/main.bicep")
        self.assertEqual([str(a) for a in from_files.call_args.args],
                         [".drift-ignore", "/lz/.drift-ignore"])

    def test_the_baseline_still_loads_when_the_repo_has_no_profile(self):
        with mock.patch.object(phase1, "_find_repo_ignore", return_value=None), \
                mock.patch.object(phase1.IgnorePatternList, "from_files") as from_files:
            from_files.return_value.patterns = []
            _load_ignore_patterns("lz/bicep/main.bicep")
        self.assertEqual([str(a) for a in from_files.call_args.args], [".drift-ignore"])


if __name__ == "__main__":
    unittest.main()
