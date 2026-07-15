"""
Smart matching must not pair a child with the wrong sibling leaf.

Live bug (found by adding a Function App - a SECOND Microsoft.Web/sites/config
to the estate): the bicep child
    "format('func-drift-{0}', uniqueString(resourceGroup().id))/appsettings"
matched the live 'app-test-drift/web' - a different site AND a different config
kind. It fabricated property drift (FUNCTIONS_* desired vs None) against the
App Service and orphaned the real func-drift-<hash>/appsettings, which then
false-flagged extra_in_azure.

Two causes, both fixed here:
  1. No leaf correspondence: an 'appsettings' config matched a 'web' config.
  2. The winner was SELECTED on prefix+suffix but VALIDATED on prefix alone.
     A bicep name leading with an unresolved expression ("format('func-drift-
     {0}'...") shares only 'f' with 'func-drift-<hash>', so the correct winner
     was discarded and candidates[0] - an arbitrary resource - returned.

The candidates[0] fallback is retained ONLY for genuinely signal-free names
(two resources sharing one unresolved name expression), where pairing in order
is correct because each match consumes its candidate.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.smart_matching import _find_best_match

FUNC_CFG = "format('func-drift-{0}', uniqueString(resourceGroup().id))/appsettings"


def _c(*names):
    return [{"name": n} for n in names]


def _match(bicep_name, *cand_names):
    r = _find_best_match({"name": bicep_name}, _c(*cand_names))
    return r["name"] if r else None


class SmartMatchLeafTests(unittest.TestCase):
    def test_live_bug_appsettings_does_not_match_web(self):
        self.assertEqual(
            _match(FUNC_CFG, "app-test-drift/web", "app-test-drift/appsettings",
                   "func-drift-3s7c7weddxr3s/web", "func-drift-3s7c7weddxr3s/appsettings"),
            "func-drift-3s7c7weddxr3s/appsettings",
        )

    def test_leaf_must_correspond_else_no_match(self):
        # No candidate shares the leaf -> a wrong match is worse than none.
        self.assertIsNone(_match("foo[86c9cbf6]/appsettings", "bar1/web", "bar2/web"))

    def test_unresolved_parent_still_picks_right_sibling(self):
        # Only the leaf disambiguates; the parent is an unresolved expression.
        self.assertEqual(
            _match(FUNC_CFG, "app-test-drift/appsettings",
                   "func-drift-3s7c7weddxr3s/appsettings"),
            "func-drift-3s7c7weddxr3s/appsettings",
        )

    def test_sql_child_leaf_disambiguation_preserved(self):
        # The case the prefix+suffix scoring was originally built for.
        self.assertEqual(
            _match("sqldrift[86c9cbf6]/driftdb",
                   "sqldrift3s7c7weddxr3s/master", "sqldrift3s7c7weddxr3s/driftdb"),
            "sqldrift3s7c7weddxr3s/driftdb",
        )

    def test_top_level_prefix_matching_preserved(self):
        # Literal lead distinguishes 'general' storage from 'logging' storage.
        self.assertEqual(
            _match("jacquidevstgtake(uniqueString(resourceGroup().id), 6)",
                   "jacquidevstl0001", "jacquidevstg0002"),
            "jacquidevstg0002",
        )

    def test_signal_free_name_still_pairs_in_order(self):
        # Two storage accounts sharing ONE unresolved expression: no signal to
        # match on, so pairing in order is correct (each match consumes its
        # candidate). This fallback is load-bearing - do not remove it.
        expr = "toLower(format('{0}st{1}', parameters('prefix'), take(uniqueString(x),6)))"
        self.assertEqual(_match(expr, "jacquidevstgm4fg23", "jacquidevstla7m6et"),
                         "jacquidevstgm4fg23")

    def test_single_candidate_is_credible(self):
        self.assertEqual(_match(FUNC_CFG, "func-drift-3s7c7weddxr3s/appsettings"),
                         "func-drift-3s7c7weddxr3s/appsettings")

    def test_no_candidates_returns_none(self):
        self.assertIsNone(_find_best_match({"name": FUNC_CFG}, []))


if __name__ == "__main__":
    unittest.main()
