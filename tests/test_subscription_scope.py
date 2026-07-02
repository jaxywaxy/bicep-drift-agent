"""
Unit tests for subscription-scoped landing-zone scanning helpers.

A subscription-scoped LZ template spans several resource groups; the agent scans
it in one pass, optionally filtered to an RG glob (one LZ instance). Covers the
RG selector filter (get_live_state) and the filesystem-safe report label.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.get_live_state import _filter_by_rg_selector, _is_rg_glob, _rg_of
from tools.rg_selector import rg_label

RESOURCES = [
    {"resource_group": "jacquidev-rg-networking", "name": "vnet-dev"},
    {"resource_group": "jacquidev-rg-apps", "name": "app-dev"},
    {"resource_group": "jacquitest-rg-networking", "name": "vnet-test"},
    {"id": "/subscriptions/s/resourceGroups/NetworkWatcherRG/providers/x/y/nw", "name": "nw"},
]


class IsRgGlobTests(unittest.TestCase):
    def test_glob_detection(self):
        self.assertTrue(_is_rg_glob("jacquidev-*"))
        self.assertTrue(_is_rg_glob("*"))
        self.assertFalse(_is_rg_glob("rg-exact"))
        self.assertFalse(_is_rg_glob(None))
        self.assertFalse(_is_rg_glob(""))


class RgOfTests(unittest.TestCase):
    def test_uses_field_then_id(self):
        self.assertEqual(_rg_of({"resource_group": "rg-a"}), "rg-a")
        self.assertEqual(
            _rg_of({"id": "/subscriptions/s/resourceGroups/rg-b/providers/x/y/z"}), "rg-b"
        )
        self.assertEqual(_rg_of({}), "")


class FilterByRgSelectorTests(unittest.TestCase):
    def test_glob_keeps_matching_instance_only(self):
        kept = _filter_by_rg_selector(RESOURCES, "jacquidev-*")
        self.assertEqual({r["name"] for r in kept}, {"vnet-dev", "app-dev"})

    def test_glob_is_case_insensitive(self):
        kept = _filter_by_rg_selector(RESOURCES, "JACQUIDEV-*")
        self.assertEqual({r["name"] for r in kept}, {"vnet-dev", "app-dev"})

    def test_non_glob_selector_is_noop(self):
        # '*'/None/exact are handled by the KQL query, so the filter passes through.
        self.assertEqual(_filter_by_rg_selector(RESOURCES, "*"), RESOURCES)
        self.assertEqual(_filter_by_rg_selector(RESOURCES, None), RESOURCES)
        self.assertEqual(_filter_by_rg_selector(RESOURCES, "rg-exact"), RESOURCES)

    def test_filter_matches_by_id_when_no_rg_field(self):
        kept = _filter_by_rg_selector(RESOURCES, "networkwatcher*")
        self.assertEqual({r["name"] for r in kept}, {"nw"})


class RgLabelTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(rg_label("*"), "subscription")
        self.assertEqual(rg_label(None), "subscription")
        self.assertEqual(rg_label(""), "subscription")
        self.assertEqual(rg_label("jacquidev-*"), "jacquidev-all")
        self.assertEqual(rg_label("rg-networking"), "rg-networking")

    def test_label_is_filesystem_safe(self):
        for sel in ["*", "jacquidev-*", "a/b*c", "x?y"]:
            self.assertNotIn("*", rg_label(sel))
            self.assertNotIn("/", rg_label(sel))
            self.assertNotIn("?", rg_label(sel))


if __name__ == "__main__":
    unittest.main()
