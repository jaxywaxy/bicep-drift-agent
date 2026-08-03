#!/usr/bin/env python3
"""Assert invariants on a LIVE drift report.

The unit suite cannot catch these. Each check below corresponds to a defect that
shipped green: the fixtures used literal resource group names and pre-resolved
variables, while production uses parameters, so the resolution gaps never
appeared until an actual landing zone was scanned.

Usage:  verify_lz_report.py <reports-dir>
Exit 0 when every invariant holds, 1 otherwise (with the offending rows printed).
"""

import json
import os
import sys
from pathlib import Path

# ARM source that must never survive into a resource NAME. A finding titled with
# its own template expression cannot be acted on, and the placeholder that smart
# matching keys off has been destroyed.
ARM_SOURCE_TOKENS = ("format(", "toLower(", "toUpper(", "replace(", "concat(",
                     "parameters(", "variables(", "uniqueString(", "if(")


def _rows(report):
    """Every drift row carrying a name, across all buckets."""
    for bucket in ("drifts", "policy_enforced_drifts", "ignored_drifts"):
        for row in report.get(bucket) or []:
            yield bucket, row


def check_names_are_not_source_code(report):
    bad = [
        (bucket, str(row.get("name")))
        for bucket, row in _rows(report)
        if any(tok in str(row.get("name") or "") for tok in ARM_SOURCE_TOKENS)
    ]
    return bad, "resource names rendered as raw ARM source"


def check_no_none_baked_into_names(report):
    """'None-rg-logging' - a Python None formatted into a name reads as a real
    resource that cannot exist, and matches nothing."""
    bad = []
    for bucket, row in _rows(report):
        name = str(row.get("name") or "")
        target = str((row.get("details") or {}).get("orphaned_by_missing_resource_group") or "")
        if name.startswith("None-") or "-None-" in name or target.startswith("None-"):
            bad.append((bucket, name or target))
    return bad, "a literal 'None' was baked into a name"


def check_attribution_is_alive(report):
    """Attribution silently died for every subscription-scoped scan: the selector
    ('*' or a glob) went into the Activity Log $filter as a literal resource
    group name, so nothing matched and every row read 'unknown'.

    A clean estate legitimately has no rows, so this only fires when there ARE
    rows and not one of them names an actor.
    """
    rows = [row for _, row in _rows(report)]
    if not rows:
        return [], "attribution (no rows to attribute - not a failure)"
    named = [
        r for r in rows
        if ((r.get("change_origin") or {}).get("changed_by") or "").strip()
    ]
    if named:
        return [], "attribution"
    reasons = {
        ((r.get("change_origin") or {}).get("reason") or "")[:70]
        for r in rows
    }
    return [("all rows", f"{len(rows)} row(s), none with an actor; reasons={sorted(reasons)}")], \
        "no drift row names an actor"


def check_orphans_name_their_resource_group(report):
    """When a resource group is missing, its contents must be attributed to it -
    one finding with named orphans, not N unrelated deletions."""
    missing_rgs = {
        str(row.get("name", "")).lower()
        for _, row in _rows(report)
        if row.get("type") == "Microsoft.Resources/resourceGroups"
        and row.get("drift_type") == "missing_in_azure"
    }
    if not missing_rgs:
        return [], "orphan attribution (no missing resource groups)"
    unattributed = [
        (bucket, str(row.get("name")))
        for bucket, row in _rows(report)
        if row.get("drift_type") == "missing_in_azure"
        and row.get("type") != "Microsoft.Resources/resourceGroups"
        and not (row.get("details") or {}).get("orphaned_by_missing_resource_group")
    ]
    return unattributed, (
        f"missing resources not tied back to the deleted group(s) {sorted(missing_rgs)}"
    )


def check_collection_gaps_are_declared(report):
    gaps = report.get("collection_gaps") or {}
    return ([("collection_gaps", json.dumps(gaps))] if gaps else []), \
        "collectors could not read some types (absence here is unverified, not drift)"


CHECKS = [
    check_names_are_not_source_code,
    check_no_none_baked_into_names,
    check_orphans_name_their_resource_group,
    check_collection_gaps_are_declared,
]


def main(argv):
    if len(argv) < 2:
        print("usage: verify_lz_report.py <reports-dir>", file=sys.stderr)
        return 2
    reports = sorted(Path(argv[1]).glob("*-drift.json"))
    if not reports:
        # An empty reports dir must never read as "no drift" - the same reasoning
        # count_drifts uses.
        print(f"FAIL: no drift report found in {argv[1]}", file=sys.stderr)
        return 1

    checks = list(CHECKS)
    if os.environ.get("EXPECT_ATTRIBUTION", "true").lower() != "false":
        checks.append(check_attribution_is_alive)

    failed = 0
    for path in reports:
        report = json.loads(path.read_text())
        print(f"\n=== {path.name} "
              f"(drift_count={report.get('drift_count')}) ===")
        for check in checks:
            bad, label = check(report)
            if bad:
                failed += 1
                print(f"  FAIL  {label}")
                for bucket, detail in bad[:10]:
                    print(f"          [{bucket}] {detail}")
                if len(bad) > 10:
                    print(f"          ... and {len(bad) - 10} more")
            else:
                print(f"  ok    {label}")

    if failed:
        print(f"\n{failed} invariant(s) violated", file=sys.stderr)
        return 1
    print("\nAll invariants hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
