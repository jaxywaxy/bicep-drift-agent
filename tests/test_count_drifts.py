"""
CI's headline drift counts come from the JSON report, not from grepping a log.

Production failure this replaces: the Anthropic key ran out of credit, the
exception aborted Phase 2 before _print_drift_summary ran, so no "[DRIFT]" /
"[MISSING]" lines were ever printed - and

    DRIFT_COUNT=$(grep -c "^\\[DRIFT\\]" "$DRIFT_FILE")

dutifully returned 0. CI reported total_issues=0 while the JSON report held 37
actionable drifts, two of them critical network drifts. Reporting an estate
clean when it is not is the worst failure this tool has.

Verified against the real artifacts: the four healthy runs produce counts
IDENTICAL to the old grep (5, 4, 1, 61), and the credit-exhausted run produces
37 where grep produced 0.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.count_drifts import count_drifts, main


def _write(d, name="rg-x-drift.json", **report):
    base = {"resource_group": "rg-x", "bicep_file": "b.bicep", "drifts": []}
    base.update(report)
    (Path(d) / name).write_text(json.dumps(base))


def _drift(t, n="r"):
    return {"type": "microsoft.storage/storageaccounts", "name": n,
            "drift_type": t, "details": {}}


class CountDriftsTests(unittest.TestCase):
    def test_counts_each_actionable_type(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[_drift("property_drift", "a"), _drift("property_drift", "b"),
                              _drift("extra_in_azure", "c"), _drift("missing_in_azure", "e")])
            c = count_drifts(d)
        self.assertEqual((c["drift_count"], c["extra_count"], c["missing_count"]), (2, 1, 1))
        self.assertEqual(c["total_issues"], 4)

    def test_matched_unresolvable_is_not_drift(self):
        # A runtime-named resource reconciled to its deployed counterpart is
        # informational; the old log summary never printed it either.
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[_drift("matched_unresolvable", f"m{i}") for i in range(34)]
                             + [_drift("property_drift", "real")])
            c = count_drifts(d)
        self.assertEqual(c["total_issues"], 1)

    def test_property_changes_counted_separately_from_records(self):
        """The live compute round: 5 changes across 2 resources read as "2".

        drift_count counts RECORDS, which is correct but understates a record
        carrying several changes - and the CI table labelled it "Configuration
        Changes". Both numbers are now reported; total_issues is unchanged so
        existing gates do not move.
        """
        disk = _drift("property_drift", "disk-drift-data")
        disk["details"] = {"changed_properties": {
            "zones": {"desired": ["1"], "actual": ["2"], "severity": "critical"},
            "properties.networkAccessPolicy": {
                "desired": "DenyAll", "actual": "AllowAll", "severity": "critical"},
        }}
        vmss = _drift("property_drift", "vmss-drift-test")
        vmss["details"] = {"changed_properties": {
            "properties.upgradePolicy.mode": {"severity": "critical"},
            "properties.automaticRepairsPolicy.enabled": {"severity": "critical"},
            "properties.virtualMachineProfile.securityProfile.encryptionAtHost": {
                "severity": "critical"},
        }}

        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[disk, vmss])
            c = count_drifts(d)

        self.assertEqual(c["drift_count"], 2)
        self.assertEqual(c["changed_property_count"], 5)
        self.assertEqual(c["critical_count"], 5)
        self.assertEqual(c["total_issues"], 2)  # gating semantics unchanged

    def test_severity_mix_is_not_flattened(self):
        """2 cosmetic edits and 2 security regressions must not read alike."""
        noisy = _drift("property_drift", "a")
        noisy["details"] = {"changed_properties": {"tags.owner": {"severity": "warning"}}}

        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[noisy])
            c = count_drifts(d)

        self.assertEqual(c["changed_property_count"], 1)
        self.assertEqual(c["critical_count"], 0)

    def test_extra_and_missing_count_as_one_change_each(self):
        """Presence/absence IS the change - those records carry no properties."""
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[_drift("extra_in_azure", "x"), _drift("missing_in_azure", "y")])
            c = count_drifts(d)

        self.assertEqual(c["changed_property_count"], 2)
        self.assertEqual(c["critical_count"], 0)

    def test_clean_report_is_zero_not_error(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[])
            self.assertEqual(count_drifts(d)["total_issues"], 0)

    def test_policy_enforced_not_counted(self):
        # Already split into its own report key - detected, not actionable.
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[], policy_enforced_drifts=[_drift("property_drift", "p")])
            self.assertEqual(count_drifts(d)["total_issues"], 0)

    def test_sums_across_multiple_resource_groups(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "rg-one-drift.json", drifts=[_drift("missing_in_azure")])
            _write(d, "rg-two-drift.json", drifts=[_drift("property_drift"),
                                                   _drift("extra_in_azure")])
            c = count_drifts(d)
        self.assertEqual(c["total_issues"], 3)
        self.assertEqual(c["reports"], 2)

    # --- the whole point: never turn "no report" into "0 issues" ---

    def test_missing_report_raises_not_zero(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                count_drifts(d)

    def test_missing_directory_raises_not_zero(self):
        with self.assertRaises(FileNotFoundError):
            count_drifts("/nonexistent/reports/dir")

    def test_corrupt_report_raises_not_zero(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "rg-x-drift.json").write_text("{ truncated")
            with self.assertRaises(json.JSONDecodeError):
                count_drifts(d)

    def test_cli_fails_loudly_when_no_report(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["count_drifts.py", d]), 1)

    def test_cli_fails_loudly_on_corrupt_report(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "rg-x-drift.json").write_text("not json")
            self.assertEqual(main(["count_drifts.py", d]), 1)

    def test_cli_writes_github_output(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, drifts=[_drift("property_drift"), _drift("missing_in_azure")])
            out = Path(d) / "gh_output"
            os.environ["GITHUB_OUTPUT"] = str(out)
            try:
                rc = main(["count_drifts.py", d])
            finally:
                del os.environ["GITHUB_OUTPUT"]
            self.assertEqual(rc, 0)
            written = out.read_text()
        self.assertIn("drift_count=1", written)
        self.assertIn("missing_count=1", written)
        self.assertIn("total_issues=2", written)
        self.assertNotIn("reports=", written)  # internal, not a step output


if __name__ == "__main__":
    unittest.main()
