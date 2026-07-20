#!/usr/bin/env python3
"""
Count actionable drift from the JSON reports - the CI's headline numbers.

CI used to derive these by grepping the run LOG:

    DRIFT_COUNT=$(grep -c "^\\[DRIFT\\]" "$DRIFT_FILE")

which couples the headline number to log-line formatting and cannot tell "no
drift" apart from "no report". It failed exactly that way in production: when
the Anthropic key ran out of credit, the exception aborted Phase 2 before
_print_drift_summary ran, so no grep-able lines were printed and CI reported
total_issues=0 while the JSON report held 37 actionable drifts - two of them
critical network drifts. Reporting an estate clean when it is not is this
tool's worst possible failure.

The same facts are already structured in reports/<label>-drift.json, so read
them from there. A missing/unreadable report is an ERROR, never a zero.

Counting matches what the log summary printed, so CI numbers are unchanged for
a healthy run:
  - property_drift    -> drift_count
  - extra_in_azure    -> extra_count
  - missing_in_azure  -> missing_count
  - matched_unresolvable is NOT drift (a runtime-named resource reconciled to
    its deployed counterpart) and is excluded.
  - policy/system-enforced changes are already split into their own report key
    (policy_enforced_drifts) and so are naturally excluded.

drift_count counts RECORDS - one per drifted resource - while a single record
can carry many changed properties. A live round injected 5 property changes
across 2 resources and the summary read "2 drift(s)", which is true but reads
as though three of the five findings did not exist. Two derived counts make the
gap explicit without moving total_issues (so existing CI thresholds are
unaffected):
  - changed_property_count: individual property changes across all records
  - critical_count: how many of those rate critical
Severity is the one thing an operator needs from a headline and the record
count cannot express it: 2 cosmetic tag edits and 2 resources with their
security posture stripped both printed as "2".

Usage:
    python3 tools/count_drifts.py <reports_dir>
"""

import json
import pathlib
import sys
from typing import Dict

# drift_type -> GITHUB_OUTPUT key. Mirrors _print_drift_summary's [DRIFT] /
# [EXTRA] / [MISSING] lines, which these counts replace.
_COUNTED_TYPES = {
    "property_drift": "drift_count",
    "extra_in_azure": "extra_count",
    "missing_in_azure": "missing_count",
}


def count_drifts(reports_dir: str) -> Dict[str, int]:
    """Sum actionable drift across every *-drift.json in reports_dir.

    Raises FileNotFoundError when the directory holds no report at all: that
    means the drift check produced nothing, which must surface as a failure
    rather than a silent "0 issues".
    """
    counts = {k: 0 for k in _COUNTED_TYPES.values()}
    counts["changed_property_count"] = 0
    counts["critical_count"] = 0
    counts["reports"] = 0

    d = pathlib.Path(reports_dir)
    reports = sorted(d.glob("*-drift.json")) if d.is_dir() else []
    if not reports:
        raise FileNotFoundError(
            f"No *-drift.json found in {reports_dir!r} - the drift check produced no "
            "report. Refusing to report 0 issues: that is indistinguishable from a "
            "clean estate."
        )

    for report_file in reports:
        with open(report_file) as f:
            report = json.load(f)  # a corrupt report must raise, not count as 0
        counts["reports"] += 1
        for drift in report.get("drifts") or []:
            key = _COUNTED_TYPES.get(drift.get("drift_type"))
            if not key:
                continue
            counts[key] += 1
            # Per-property detail, so a record carrying five changes does not
            # read as one finding. extra/missing records have no
            # changed_properties and count as a single change each - the
            # resource's presence IS the change.
            changed = ((drift.get("details") or {}).get("changed_properties") or {})
            counts["changed_property_count"] += len(changed) or 1
            counts["critical_count"] += sum(
                1 for c in changed.values()
                if isinstance(c, dict) and str(c.get("severity", "")).lower() == "critical"
            )

    counts["total_issues"] = sum(counts[k] for k in _COUNTED_TYPES.values())
    return counts


def main(argv) -> int:
    if len(argv) < 2:
        print("Usage: python3 tools/count_drifts.py <reports_dir>", file=sys.stderr)
        return 2
    try:
        counts = count_drifts(argv[1])
    except FileNotFoundError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"::error::Drift report is not valid JSON ({e}) - refusing to report 0 issues.",
              file=sys.stderr)
        return 1

    import os
    lines = [f"{k}={v}" for k, v in counts.items() if k != "reports"]
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write("\n".join(lines) + "\n")
    critical = f", {counts['critical_count']} CRITICAL" if counts["critical_count"] else ""
    print(
        f"Results ({counts['reports']} report(s)): {counts['drift_count']} drifted "
        f"resource(s) / {counts['changed_property_count']} change(s){critical}, "
        f"{counts['extra_count']} extra, {counts['missing_count']} missing "
        f"-> {counts['total_issues']} total"
    )
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
