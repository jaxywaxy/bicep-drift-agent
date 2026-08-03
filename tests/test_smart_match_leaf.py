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
            _match("contosodevstgtake(uniqueString(resourceGroup().id), 6)",
                   "contosodevstl0001", "contosodevstg0002"),
            "contosodevstg0002",
        )

    def test_signal_free_name_still_pairs_in_order(self):
        # Two storage accounts sharing ONE unresolved expression: no signal to
        # match on, so pairing in order is correct (each match consumes its
        # candidate). This fallback is load-bearing - do not remove it.
        expr = "toLower(format('{0}st{1}', parameters('prefix'), take(uniqueString(x),6)))"
        self.assertEqual(_match(expr, "contosodevstgm4fg23", "contosodevstla7m6et"),
                         "contosodevstgm4fg23")

    def test_single_candidate_is_credible(self):
        self.assertEqual(_match(FUNC_CFG, "func-drift-3s7c7weddxr3s/appsettings"),
                         "func-drift-3s7c7weddxr3s/appsettings")

    def test_no_candidates_returns_none(self):
        self.assertIsNone(_find_best_match({"name": FUNC_CFG}, []))


if __name__ == "__main__":
    unittest.main()


class ADeclarationCannotMatchOutsideItsResourceGroupTests(unittest.TestCase):
    """A subscription-scoped declaration records the resource group it deploys
    into (`_target_rg`). Smart matching ignored it and paired on name shape
    alone.

    Live, 2026-08-03: `jacquidev-rg-logging` was deleted, taking its storage
    account with it. The logging declaration (`jacquidevstl[...]`,
    _target_rg=jacquidev-rg-logging) then matched the APPS storage account
    (`jacquidevstgm4fg23`, in jacquidev-rg-apps) with "high" confidence, because
    with its own account gone the apps one was the only candidate left and won on
    shared prefix.

    Two failures at once, the familiar pair: the real deletion was HIDDEN (the
    declaration looked satisfied), and the live apps account was orphaned and
    reported missing_in_azure. It also broke orphan attribution, since the
    surviving row pointed at a resource group that still exists.

    The prefix heuristic only separates 'stl' from 'stg' while BOTH are alive.
    `_target_rg` separates them regardless - and the pipeline already has it.
    """

    def _declared(self, target_rg):
        return {"type": "Microsoft.Storage/storageAccounts",
                "name": "jacquidevstl[86c9cbf6]", "_target_rg": target_rg}

    def _live(self, name, rg):
        return {"type": "Microsoft.Storage/storageAccounts", "name": name,
                "resource_group": rg}

    def test_a_candidate_in_another_resource_group_is_not_matched(self):
        match = _find_best_match(
            self._declared("jacquidev-rg-logging"),
            [self._live("jacquidevstgm4fg23", "jacquidev-rg-apps")],
        )
        self.assertIsNone(
            match,
            "a declaration matched a live resource in a different resource group",
        )

    def test_the_candidate_in_the_right_group_still_matches(self):
        match = _find_best_match(
            self._declared("jacquidev-rg-logging"),
            [self._live("jacquidevstgm4fg23", "jacquidev-rg-apps"),
             self._live("jacquidevstla7m6et", "jacquidev-rg-logging")],
        )
        self.assertIsNotNone(match)
        self.assertEqual(match["name"], "jacquidevstla7m6et")

    def test_without_a_target_rg_behaviour_is_unchanged(self):
        # RG-scoped templates never stamp _target_rg; they must keep matching.
        match = _find_best_match(
            {"type": "Microsoft.Storage/storageAccounts", "name": "jacquidevstl[86c9cbf6]"},
            [self._live("jacquidevstla7m6et", "jacquidev-rg-logging")],
        )
        self.assertIsNotNone(match)

    def test_a_lone_candidate_in_the_wrong_group_is_not_matched(self):
        """The live failure. smart_match_resources short-circuits when exactly
        ONE candidate of the type is unmatched - 'perfect match', confidence
        high, no checks. Deleting the logging RG left exactly one storage
        account, so the logging declaration paired with the APPS account through
        that shortcut, never reaching _find_best_match."""
        from tools.smart_matching import smart_match_resources
        declared = self._declared("jacquidev-rg-logging")
        matched, unmatched_bicep, unmatched_azure = smart_match_resources(
            [declared],
            [self._live("jacquidevstgm4fg23", "jacquidev-rg-apps")],
            {},
        )
        self.assertEqual(matched, [], "the lone-candidate shortcut matched across resource groups")
        self.assertEqual(len(unmatched_bicep), 1)
        self.assertEqual(len(unmatched_azure), 1, "the live resource must stay available to match")

    def test_a_lone_candidate_in_the_right_group_still_matches(self):
        from tools.smart_matching import smart_match_resources
        matched, _, _ = smart_match_resources(
            [self._declared("jacquidev-rg-logging")],
            [self._live("jacquidevstla7m6et", "jacquidev-rg-logging")],
            {},
        )
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["matched_to"], "jacquidevstla7m6et")

    def test_candidates_without_a_known_group_are_not_discarded(self):
        # Collectors that do not populate resource_group must not cause every
        # declaration to read as missing.
        match = _find_best_match(
            self._declared("jacquidev-rg-logging"),
            [{"type": "Microsoft.Storage/storageAccounts", "name": "jacquidevstla7m6et"}],
        )
        self.assertIsNotNone(match)
