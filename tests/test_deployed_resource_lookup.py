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
(tools.smart_matching.names_plausibly_correspond) so a future fix cannot leave
a fourth copy behind.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.reconciliation import _find_deployed_resource
from tools.smart_matching import names_plausibly_correspond

SQLDB = "Microsoft.Sql/servers/databases"


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
        """The exact expression that caused all three instances. It is legitimate
        for deriving a prefix, but never as the whole correspondence test."""
        import pathlib
        offenders = []
        for rel in ("orchestration/reconciliation.py", "tools/property_drift/matcher.py"):
            src = pathlib.Path(rel).read_text(encoding="utf-8")
            for i, line in enumerate(src.splitlines(), 1):
                if 'split("[")[0]' in line and "names_plausibly_correspond" not in src[:src.index(line)][-400:]:
                    offenders.append(f"{rel}:{i}")
        # A bare prefix derivation is fine as long as the guard runs alongside it;
        # assert the guard is imported in every module that derives one.
        for rel in ("orchestration/reconciliation.py", "tools/property_drift/matcher.py"):
            src = pathlib.Path(rel).read_text(encoding="utf-8")
            if 'split("[")[0]' in src:
                self.assertIn("names_plausibly_correspond", src,
                              f"{rel} derives a static prefix without the correspondence guard")


if __name__ == "__main__":
    unittest.main()
