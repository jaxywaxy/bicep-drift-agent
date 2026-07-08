"""Regression tests for ARM json() resolution.

Bicep templates wrap literals in json() to force a typed value (e.g. Container
Apps CPU: json('0.25')). Azure returns the typed value (0.25), so without
resolving json() the comparison string-vs-number false-positives.
"""

import unittest

from tools.normalizer import resolve_expression
from tools.property_drift import PropertyComparator


class TestJsonExpressionResolution(unittest.TestCase):
    def test_numeric_literal(self):
        self.assertEqual(resolve_expression("[json('0.25')]", {}, {}), 0.25)

    def test_integer_literal(self):
        self.assertEqual(resolve_expression("[json('10')]", {}, {}), 10)

    def test_bool_and_null_literals(self):
        self.assertIs(resolve_expression("[json('true')]", {}, {}), True)
        self.assertIsNone(resolve_expression("[json('null')]", {}, {}))

    def test_non_literal_arg_falls_through(self):
        # A json() wrapping a non-literal can't be resolved; left as-is so the
        # comparator treats it as an unresolved expression.
        self.assertEqual(
            resolve_expression("[json(variables('x'))]", {}, {}),
            "json(variables('x'))",
        )
        self.assertTrue(
            PropertyComparator._has_unresolved_expressions("json(variables('x'))")
        )


class TestContainerAppCpuNoFalseDrift(unittest.TestCase):
    def _aca(self, cpu, extra=None):
        container = {
            "name": "hello",
            "image": "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest",
            "resources": {"cpu": cpu, "memory": "0.5Gi"},
        }
        if extra:
            container["resources"].update(extra)
        return {"type": "Microsoft.App/containerApps",
                "properties": {"template": {"containers": [container]}}}

    def test_json_cpu_matches_numeric_live_value(self):
        # Bicep json('0.25') resolves to 0.25 (done by the normalizer upstream);
        # Azure returns 0.25 plus platform-injected fields that subset-compare away.
        bicep = self._aca(0.25)
        azure = self._aca(0.25, {"ephemeralStorage": "1Gi", "imageType": "ContainerImage"})
        self.assertEqual(PropertyComparator.compare_properties(bicep, azure), [])

    def test_real_cpu_change_still_detected(self):
        bicep = self._aca(0.25)
        azure = self._aca(0.5)
        diffs = PropertyComparator.compare_properties(bicep, azure)
        self.assertEqual([d.property_path for d in diffs], ["properties.template.containers"])


if __name__ == "__main__":
    unittest.main()
