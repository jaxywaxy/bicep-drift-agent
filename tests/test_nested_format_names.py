"""
Unit tests for resolving a child resource name whose parent segment is a
NESTED format() call.

A storage child compiles to
format('{0}/{1}', format('st{0}drift{1}', parameters('environment'),
uniqueString(resourceGroup().id)), 'default'). Two defects met there:

1. Corruption. Each format arg was substituted with its own str.replace pass,
   so an already-inserted value was re-read by the next arg. The unresolved
   inner call still carried its own {0}/{1}, and the outer arg 1 overwrote the
   inner {1} - the name resolved to "format('st{0}driftdefault', ...)/default".
2. No resolution. _resolve_function_call had no format() branch, so even
   uncorrupted the inner call came back as its own source text and the child
   name stayed an expression only fuzzy matching could rescue.

The assertions enter through extract_resources_from_arm - the stage that owns
name resolution - rather than the resolver alone, so a fix that works only when
called directly cannot pass them.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.compile_bicep import extract_resources_from_arm
from tools.normalizer.expressions import _apply_format_args

STORAGE_NAME = (
    "[format('st{0}drift{1}', parameters('environment'), "
    "uniqueString(resourceGroup().id))]"
)


def _template(resources: list) -> dict:
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/"
                   "deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"environment": {"type": "string", "defaultValue": "test"}},
        "resources": resources,
    }


def _names_by_type(resources: list) -> dict:
    return {r["type"]: r["name"] for r in resources}


class NestedFormatChildNameTests(unittest.TestCase):
    def setUp(self):
        self.resources = extract_resources_from_arm(_template([
            {
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2023-01-01",
                "name": STORAGE_NAME,
            },
            {
                "type": "Microsoft.Storage/storageAccounts/blobServices",
                "apiVersion": "2023-01-01",
                "name": (
                    "[format('{0}/{1}', format('st{0}drift{1}', "
                    "parameters('environment'), "
                    "uniqueString(resourceGroup().id)), 'default')]"
                ),
            },
            {
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                "apiVersion": "2023-01-01",
                "name": (
                    "[format('{0}/{1}/{2}', format('st{0}drift{1}', "
                    "parameters('environment'), "
                    "uniqueString(resourceGroup().id)), 'default', 'drift-data')]"
                ),
            },
        ]))
        self.names = _names_by_type(self.resources)

    def test_inner_template_is_not_overwritten_by_an_outer_argument(self):
        """The corruption signature: the inner {1} filled with the outer arg."""
        for name in self.names.values():
            self.assertNotIn("driftdefault", name)
            self.assertNotIn("format(", name)

    def test_child_resolves_to_parent_plus_child_segment(self):
        self.assertEqual(
            self.names["Microsoft.Storage/storageAccounts/blobServices"],
            "sttestdrift[86c9cbf6]/default",
        )

    def test_grandchild_keeps_all_three_segments(self):
        self.assertEqual(
            self.names["Microsoft.Storage/storageAccounts/blobServices/containers"],
            "sttestdrift[86c9cbf6]/default/drift-data",
        )

    def test_child_parent_segment_equals_the_parent_name(self):
        """The invariant matching depends on: a child's first segment IS its
        parent's resolved name, placeholder and all."""
        parent = self.names["Microsoft.Storage/storageAccounts"]
        for res_type, name in self.names.items():
            if res_type == "Microsoft.Storage/storageAccounts":
                continue
            self.assertEqual(name.split("/")[0], parent, res_type)

    def test_an_unfilled_inner_slot_survives_the_outer_substitution(self):
        """The corruption, reachable through the pipeline.

        _parse_format_call drops an argument it cannot resolve, leaving the
        inner template with an unfilled slot. Substituting the outer args one
        at a time then fills that slot with the outer arg 1 ('default') instead
        of leaving it for smart matching: 'sttestdriftdefault/default'.
        """
        resources = extract_resources_from_arm(_template([{
            "type": "Microsoft.Storage/storageAccounts/blobServices",
            "apiVersion": "2023-01-01",
            "name": (
                "[format('{0}/{1}', format('st{0}drift{1}', "
                "parameters('environment')), 'default')]"
            ),
        }]))
        self.assertEqual(resources[0]["name"], "sttestdrift{1}/default")

    def test_nested_format_with_only_a_placeholder_argument(self):
        """No parameter to resolve, just uniqueString - the func app's config."""
        resources = extract_resources_from_arm(_template([{
            "type": "Microsoft.Web/sites/config",
            "apiVersion": "2023-01-01",
            "name": (
                "[format('{0}/{1}', format('func-drift-{0}', "
                "uniqueString(resourceGroup().id)), 'appsettings')]"
            ),
        }]))
        self.assertEqual(
            resources[0]["name"], "func-drift-[86c9cbf6]/appsettings"
        )


class ApplyFormatArgsTests(unittest.TestCase):
    def test_an_inserted_value_is_not_rescanned(self):
        self.assertEqual(
            _apply_format_args("{0}/{1}", ["keeps-{1}-intact", "default"]),
            "keeps-{1}-intact/default",
        )

    def test_a_slot_with_no_argument_keeps_its_placeholder(self):
        self.assertEqual(_apply_format_args("{0}-{1}", ["only"]), "only-{1}")

    def test_repeated_slot_is_filled_everywhere(self):
        self.assertEqual(_apply_format_args("{0}/{0}", ["x"]), "x/x")


if __name__ == "__main__":
    unittest.main()
