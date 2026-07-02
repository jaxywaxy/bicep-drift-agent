"""
Unit tests for normalizer.resolve_expression parameter resolution.

Regression: an object/array parameter (e.g. `tags`) must resolve to the actual
value, not its str() repr - otherwise it can never equal the live dict and every
resource shows a false `tags` drift.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.normalizer import resolve_expression, _resolve_value


class ResolveExpressionTests(unittest.TestCase):
    def setUp(self):
        self.params = {
            "prefix": "jacquidev",
            "tags": {"environment": "dev", "owner": "jacqui"},
            "cidrs": ["10.0.0.0/16", "10.1.0.0/16"],
            "count": 3,
        }
        self.vars = {"suffixObj": {"a": 1}}

    def test_object_param_resolves_to_dict_not_string(self):
        out = resolve_expression("[parameters('tags')]", self.params, {})
        self.assertEqual(out, {"environment": "dev", "owner": "jacqui"})
        self.assertIsInstance(out, dict)

    def test_array_param_resolves_to_list(self):
        out = resolve_expression("[parameters('cidrs')]", self.params, {})
        self.assertEqual(out, ["10.0.0.0/16", "10.1.0.0/16"])

    def test_scalar_params_unchanged(self):
        self.assertEqual(resolve_expression("[parameters('prefix')]", self.params, {}), "jacquidev")
        self.assertEqual(resolve_expression("[parameters('count')]", self.params, {}), 3)

    def test_object_variable_resolves_to_dict(self):
        out = resolve_expression("[variables('suffixObj')]", {}, self.vars)
        self.assertEqual(out, {"a": 1})

    def test_resolve_value_on_tags_field(self):
        # The whole tags field is the expression string; _resolve_value must yield a dict.
        out = _resolve_value("[parameters('tags')]", self.params, {})
        self.assertEqual(out, {"environment": "dev", "owner": "jacqui"})

    def test_format_still_stringifies_args(self):
        # A scalar param inside format() is still interpolated as a string.
        out = resolve_expression("[format('{0}-natgw', parameters('prefix'))]", self.params, {})
        self.assertEqual(out, "jacquidev-natgw")

    def test_unresolved_param_falls_back_to_name(self):
        self.assertEqual(resolve_expression("[parameters('missing')]", self.params, {}), "missing")


if __name__ == "__main__":
    unittest.main()
