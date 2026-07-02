"""
Unit tests for tools.rg_selector — subscription-scope / glob resolution (Phase 4 #4).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.rg_selector import resolve_resource_groups, needs_expansion, is_glob

AVAILABLE = ["rg-hub", "rg-conn-dns", "rg-conn-fw", "rg-app-spoke", "rg-data-spoke"]


class IsGlobTests(unittest.TestCase):
    def test_detects_glob_chars(self):
        self.assertTrue(is_glob("*"))
        self.assertTrue(is_glob("rg-conn-*"))
        self.assertTrue(is_glob("rg-?-spoke"))
        self.assertFalse(is_glob("rg-hub"))

    def test_needs_expansion(self):
        self.assertTrue(needs_expansion(["rg-hub", "rg-conn-*"]))
        self.assertFalse(needs_expansion(["rg-hub", "rg-data-spoke"]))


class ResolveTests(unittest.TestCase):
    def test_wildcard_returns_all_sorted(self):
        self.assertEqual(
            resolve_resource_groups(["*"], AVAILABLE),
            sorted(AVAILABLE, key=str.lower),
        )

    def test_glob_matches_subset(self):
        self.assertEqual(
            resolve_resource_groups(["rg-conn-*"], AVAILABLE),
            ["rg-conn-dns", "rg-conn-fw"],
        )

    def test_glob_is_case_insensitive(self):
        self.assertEqual(
            resolve_resource_groups(["RG-CONN-*"], AVAILABLE),
            ["rg-conn-dns", "rg-conn-fw"],
        )

    def test_mix_of_explicit_and_glob_dedupes_preserving_order(self):
        # explicit rg-hub first, then the glob (which doesn't include hub)
        self.assertEqual(
            resolve_resource_groups(["rg-hub", "*-spoke"], AVAILABLE),
            ["rg-hub", "rg-app-spoke", "rg-data-spoke"],
        )

    def test_explicit_name_kept_even_if_not_available(self):
        # An explicitly named but undeployed RG must still be checked (missing drift).
        self.assertEqual(
            resolve_resource_groups(["rg-not-deployed"], AVAILABLE),
            ["rg-not-deployed"],
        )

    def test_glob_matching_nothing_yields_nothing(self):
        self.assertEqual(resolve_resource_groups(["rg-nomatch-*"], AVAILABLE), [])

    def test_duplicate_across_selectors_removed(self):
        self.assertEqual(
            resolve_resource_groups(["rg-conn-*", "rg-conn-dns"], AVAILABLE),
            ["rg-conn-dns", "rg-conn-fw"],
        )

    def test_empty_and_blank_selectors_ignored(self):
        self.assertEqual(resolve_resource_groups(["", "  ", "rg-hub"], AVAILABLE), ["rg-hub"])


if __name__ == "__main__":
    unittest.main()
