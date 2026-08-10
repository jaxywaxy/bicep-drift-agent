"""
property_drift's single-candidate fallback must see the CHILD LEAF.

Live 2026-08-11, found while verifying the smart_matching fix for the same
defect one module over. The deleted SQL database `sqldrift[86c9cbf6]/driftdb`
was reported missing under its SIBLING'S name:

    name:                  sqldrift3s7c7weddxr3s/master     <- still exists!
    bicep_name_expression: sqldrift[86c9cbf6]/driftdb

So the report asserted that `master` was gone (a false positive about a live
resource) while the real deletion was mislabelled, and the genuine extra was
consumed by the pairing so it never surfaced either.

Cause: the plausibility test was

    static_prefix = bicep_name.split("[")[0]        # 'sqldrift'
    cand_name.startswith(static_prefix)             # 'sqldrift<hash>/master' -> True

`split("[")` stops at the first placeholder, so for a child name shaped
`parent[hash]/leaf` it discards the leaf entirely and the check collapses onto
the parent. The guard's own comment said it existed to stop exactly this
("hide BOTH a missing_in_azure and an extra_in_azure") - it simply could not
see the segment that carries the identity.

Third instance of this family in one day: smart_matching's unguarded
single-candidate branch, then this. When fixing one, check every other module
that pairs a declared resource to a live one.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift.matcher import ResourceMatcher

SQLDB = "Microsoft.Sql/servers/databases"


def _res(rtype, name):
    return {"type": rtype, "name": name, "properties": {}}


class PlausibilityMustSeeTheLeafTests(unittest.TestCase):
    def test_the_live_defect_a_deleted_child_vs_its_surviving_sibling(self):
        self.assertFalse(ResourceMatcher._names_plausibly_correspond(
            "sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/master"))

    def test_the_real_counterpart_still_corresponds(self):
        self.assertTrue(ResourceMatcher._names_plausibly_correspond(
            "sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/driftdb"))

    def test_a_placeholder_inside_the_leaf_is_still_prefix_matched(self):
        """A leaf may itself be runtime-named; it is compared the way a
        top-level name is rather than demanded to be literally equal."""
        self.assertTrue(ResourceMatcher._names_plausibly_correspond(
            "kv[86c9cbf6]/secret-[86c9cbf6]", "kv123/secret-abc"))

    def test_a_literal_parent_must_still_correspond(self):
        """Regression guard: narrowing to the leaf must not throw away the
        parent check - 'stalpha/default/data' is not 'stbravo/default/data'."""
        self.assertFalse(ResourceMatcher._names_plausibly_correspond(
            "stalpha/default/data", "stbravo/default/data"))

    def test_a_flat_placeholder_name_is_unaffected(self):
        self.assertTrue(ResourceMatcher._names_plausibly_correspond(
            "acrtestdrift[86c9cbf6]", "acrtestdrift3s7c7wed"))
        self.assertFalse(ResourceMatcher._names_plausibly_correspond(
            "acrtestdrift[86c9cbf6]", "totallyunrelated"))


class ThroughTheMatcherTests(unittest.TestCase):
    """Enter through match_resources - the plausibility helper is not the stage
    the pipeline calls."""

    def test_a_deleted_database_is_not_paired_with_master(self):
        matches = ResourceMatcher.match_resources(
            [_res(SQLDB, "sqldrift[86c9cbf6]/driftdb")],
            [_res(SQLDB, "sqldrift3s7c7weddxr3s/master")])
        self.assertEqual(matches, [],
                         "the deleted child was paired with the surviving sibling, "
                         "which reports the sibling as missing and hides the extra")

    def test_the_database_still_pairs_with_its_own_counterpart(self):
        matches = ResourceMatcher.match_resources(
            [_res(SQLDB, "sqldrift[86c9cbf6]/driftdb")],
            [_res(SQLDB, "sqldrift3s7c7weddxr3s/driftdb")])
        self.assertEqual(len(matches), 1)


if __name__ == "__main__":
    unittest.main()
