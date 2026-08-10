"""
A deletion must not be able to disable the guard that would catch it.

Live 2026-08-11 (RG-scope round, rg-drift-test): the declared SQL database
`sqldrift[86c9cbf6]/driftdb` was deleted out of band. It was NOT reported
missing. smart_match_resources paired it to `sqldrift<hash>/master` - the
system database the template never declares - at `match_confidence: high`.

The mechanism is the point. smart_match_resources had two paths:

  len(candidates) == 1  ->  "perfect match", taken unconditionally
  len(candidates) >  1  ->  _find_best_match, which enforces the child-leaf
                            guard ("an 'appsettings' config is never a 'web'
                            config") and refuses `master`

Deleting the declared child is precisely what drops the pool to one, so the
deletion routed the match around the guard - and upgraded confidence from
medium to high while doing it. Two harms at once: the deletion vanished, and
an undeclared extra was silently absorbed, so neither side of the discrepancy
was reported. `drift_count` cannot reveal that.

These tests enter through smart_match_resources, not _find_best_match: the
guard was always correct in the function under it: what was wrong was that the
pipeline stopped calling it.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.smart_matching import smart_match_resources

RG = "rg-drift-test"
DECLARED_DB = {
    "type": "Microsoft.Sql/servers/databases",
    "name": "sqldrift[86c9cbf6]/driftdb",
    "_target_rg": RG,
}


def live(name, rtype="microsoft.sql/servers/databases"):
    return {"type": rtype, "name": name, "resource_group": RG}


class ADeletionMustNotDisableTheGuardTests(unittest.TestCase):
    def test_a_deleted_child_does_not_adopt_its_lone_surviving_sibling(self):
        matched, unmatched_bicep, _ = smart_match_resources(
            [DECLARED_DB], [live("sqldrift3s7c7weddxr3s/master")], {})
        self.assertEqual(matched, [], "declared 'driftdb' matched the undeclared 'master'")
        self.assertIn(DECLARED_DB, unmatched_bicep,
                      "the deleted child must stay unmatched so it reports missing_in_azure")

    def test_the_undeclared_sibling_is_not_absorbed(self):
        """The other half of the harm: a wrong match consumes the live row too,
        so the extra resource disappears from the report as well."""
        master = live("sqldrift3s7c7weddxr3s/master")
        _, _, unmatched_azure = smart_match_resources([DECLARED_DB], [master], {})
        self.assertIn(master, unmatched_azure)

    def test_the_real_child_still_matches_when_it_exists(self):
        """The fix must not cost us the case that was already working - a sole
        candidate whose leaf DOES correspond still matches, still at 'high'."""
        matched, unmatched_bicep, _ = smart_match_resources(
            [DECLARED_DB], [live("sqldrift3s7c7weddxr3s/driftdb")], {})
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["matched_to"], "sqldrift3s7c7weddxr3s/driftdb")
        self.assertEqual(matched[0]["match_confidence"], "high")
        self.assertEqual(unmatched_bicep, [])

    def test_the_right_sibling_is_chosen_when_both_are_present(self):
        matched, _, _ = smart_match_resources(
            [DECLARED_DB],
            [live("sqldrift3s7c7weddxr3s/master"), live("sqldrift3s7c7weddxr3s/driftdb")], {})
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["matched_to"], "sqldrift3s7c7weddxr3s/driftdb")
        self.assertEqual(matched[0]["match_confidence"], "medium")

    def test_a_flat_name_with_one_candidate_is_unaffected(self):
        """Regression guard for the ordinary case this path exists to serve: a
        top-level uniqueString-named resource with a single live counterpart."""
        declared = {"type": "Microsoft.Storage/storageAccounts",
                    "name": "sttestdrift[86c9cbf6]", "_target_rg": RG}
        matched, unmatched_bicep, _ = smart_match_resources(
            [declared], [live("sttestdrift3s7c7weddxr3s",
                              "microsoft.storage/storageaccounts")], {})
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["match_confidence"], "high")
        self.assertEqual(unmatched_bicep, [])

    def test_a_grandchild_leaf_is_compared_too(self):
        """Three-level names: the leaf is still the identity."""
        declared = {"type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers",
                    "name": "cosmos-[86c9cbf6]/appdb/items", "_target_rg": RG}
        wrong = live("cosmos-m4fg23/appdb/other",
                     "microsoft.documentdb/databaseaccounts/sqldatabases/containers")
        matched, unmatched_bicep, _ = smart_match_resources([declared], [wrong], {})
        self.assertEqual(matched, [])
        self.assertIn(declared, unmatched_bicep)


if __name__ == "__main__":
    unittest.main()
