"""
_find_deployed_resource must not resolve a deleted child to its live sibling.

Live 2026-08-11, third and final location of the same defect. The declared SQL
database `sqldrift[86c9cbf6]/driftdb` had been deleted out of band. This lookup
resolved it to the live `sqldrift<hash>/master` - the system database the
template never declares - because of

    name_prefix = bicep_name.split("[")[0]      # -> 'sqldrift'
    live_name.startswith(name_prefix)           # 'sqldrift<hash>/master' -> True

Attribution then takes that row's REAL ARM id, matches `master`'s own activity
events against it, and `_recover_deployed_name` renames the drift. So the report
claimed `master` - which still exists - was MISSING, while the genuine driftdb
deletion was mislabelled and the extra was never reported.

This is the site that actually produced the symptom. #425 (smart_matching) and
#426 (property_drift) each fixed a real, independent instance of the identical
`split("[")[0]` bug, and both hold - but neither was reached first, so the
visible report did not change. All three now share ONE definition
(tools.smart_matching.names_plausibly_correspond).

A FOURTH copy was found afterwards in `tools/diff_states.py`, which the guard
added here could not see because it named two files instead of scanning. It is
fixed and the guard now walks the source tree - see OneDefinitionTests.
"""

import os
import pathlib
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.reconciliation import _find_deployed_resource
from tools.smart_matching import names_plausibly_correspond

ROOT = pathlib.Path(__file__).resolve().parent.parent

SQLDB = "Microsoft.Sql/servers/databases"


def _source_files() -> list[pathlib.Path]:
    """Every production module. Tests are excluded deliberately: a test may
    legitimately spell the broken expression out to assert it is gone."""
    return sorted(
        p for package in ("tools", "orchestration", "agent")
        for p in (ROOT / package).rglob("*.py")
        if "__pycache__" not in p.parts
    )


def live(name, rtype=SQLDB):
    return {"type": rtype.lower(), "name": name,
            "id": f"/subscriptions/s/resourceGroups/rg/providers/{rtype}/{name}"}


class ADeletedChildMustNotResolveToItsSiblingTests(unittest.TestCase):
    def test_the_live_defect(self):
        got = _find_deployed_resource(SQLDB, "sqldrift[86c9cbf6]/driftdb",
                                      [live("sqldrift3s7c7weddxr3s/master")])
        self.assertIsNone(got,
                          "the deleted child resolved to the undeclared system database, "
                          "which renames the drift and reports a live resource as missing")

    def test_the_real_counterpart_still_resolves(self):
        got = _find_deployed_resource(SQLDB, "sqldrift[86c9cbf6]/driftdb",
                                      [live("sqldrift3s7c7weddxr3s/driftdb")])
        self.assertEqual((got or {}).get("name"), "sqldrift3s7c7weddxr3s/driftdb")

    def test_the_right_sibling_is_picked_when_both_exist(self):
        got = _find_deployed_resource(
            SQLDB, "sqldrift[86c9cbf6]/driftdb",
            [live("sqldrift3s7c7weddxr3s/master"), live("sqldrift3s7c7weddxr3s/driftdb")])
        self.assertEqual((got or {}).get("name"), "sqldrift3s7c7weddxr3s/driftdb")

    def test_a_flat_placeholder_name_still_resolves(self):
        """Regression guard for what this lookup exists to do."""
        got = _find_deployed_resource("Microsoft.Sql/servers", "sqldrift[86c9cbf6]",
                                      [live("sqldrift3s7c7weddxr3s", "Microsoft.Sql/servers")])
        self.assertEqual((got or {}).get("name"), "sqldrift3s7c7weddxr3s")

    def test_an_exact_name_still_wins(self):
        got = _find_deployed_resource(SQLDB, "sqldrift3s7c7weddxr3s/driftdb",
                                      [live("sqldrift3s7c7weddxr3s/driftdb")])
        self.assertIsNotNone(got)


class OneDefinitionTests(unittest.TestCase):
    """Three modules grew their own broken copy of this rule. Pin that they now
    share one, so fixing it in a single place cannot leave another behind."""

    def test_property_drift_delegates_to_the_shared_rule(self):
        from tools.property_drift.matcher import ResourceMatcher
        for b, c in (("sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/master"),
                     ("sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/driftdb"),
                     ("stalpha/default/data", "stbravo/default/data"),
                     ("acrtestdrift[86c9cbf6]", "acrtestdrift3s7c7wed")):
            with self.subTest(f"{b} vs {c}"):
                self.assertEqual(ResourceMatcher._names_plausibly_correspond(b, c),
                                 names_plausibly_correspond(b, c))

    def test_no_module_still_uses_the_truncating_prefix_test(self):
        """Every module deriving a static prefix must also carry the shared rule.

        Scans the SOURCE TREE. The version of this guard added with the original
        fix named two files and asserted on neither - it built an `offenders`
        list it never checked, then re-walked the same two paths. So it could
        only ever confirm that the two files already fixed stayed fixed.

        `tools/diff_states.py` had the same truncating prefix test the whole
        time, invisible to it, and had drifted further than the originals: it
        discarded prefixes shorter than three characters instead of treating
        them as undiscriminating, so a disk declared `d-[uniqueString()]` caused
        every live disk to be filtered out and reported missing. A guard scoped
        to the files you already fixed is not a guard.
        """
        offenders = []
        for path in _source_files():
            src = path.read_text(encoding="utf-8")
            if 'split("[")[0]' not in src:
                continue
            if "names_plausibly_correspond" not in src:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            offenders, [],
            "these derive a static name prefix without the shared correspondence "
            "rule, which is how the same defect grew four independent copies. "
            f"Import tools.smart_matching.names_plausibly_correspond: {offenders}")

    def test_the_scanner_actually_reaches_the_modules_it_claims_to(self):
        # Guards the guard. The previous version passed because it looked at
        # almost nothing; a scan that finds no files would do the same.
        scanned = {str(p.relative_to(ROOT)) for p in _source_files()}
        for expected in ("tools/diff_states.py", "tools/smart_matching.py",
                         "tools/property_drift/matcher.py",
                         "orchestration/reconciliation.py"):
            self.assertIn(expected, scanned)
        self.assertGreater(len(scanned), 40, f"only scanned {len(scanned)} files")


if __name__ == "__main__":
    unittest.main()
