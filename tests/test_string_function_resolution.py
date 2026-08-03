"""
ARM string functions in a resource NAME must resolve, or the finding is titled
with source code.

Live, 2026-08-03, subscription-scoped landing zone: a storage account whose
Bicep name is the ordinary

    toLower('${replace(prefix, '-', '')}st${purposeCode}${take(uniqueString(...), 6)}')

was reported as a drift named

    toLower(format('{0}st{1}{2}', replace('jacquidev', '-', ''),
                   variables('purposeCode'), take(uniqueString(...), 6)))

`toLower`, `toUpper` and `replace` had no branch in _resolve_function_call, so
the whole expression fell through as its own source text. Contrast the same
estate's RG-scoped report, which renders `sttestdrift[86c9cbf6]` - a readable
prefix plus the placeholder that smart matching keys off.

All three are pure string transforms: given resolved arguments they are exactly
computable at compile time, unlike uniqueString() which legitimately cannot be.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.normalizer.expressions import resolve_expression

# Verbatim from the live report.
LIVE_NAME = ("[toLower(format('{0}st{1}{2}', replace('jacquidev', '-', ''), "
             "variables('purposeCode'), take(uniqueString(resourceGroup().id), 6)))]")


class StringFunctionsInNamesResolveTests(unittest.TestCase):

    def _live(self):
        return resolve_expression(LIVE_NAME, {}, {"purposeCode": "l"})

    def test_the_name_is_not_rendered_as_source_code(self):
        out = self._live()
        for token in ("toLower(", "format(", "replace(", "variables("):
            self.assertNotIn(token, out, f"unresolved ARM source in the name: {out}")

    def test_the_readable_part_survives(self):
        # The point of resolving is that a human can recognise the resource.
        self.assertIn("jacquidevstl", self._live())

    def test_the_unresolvable_part_becomes_a_placeholder(self):
        # uniqueString genuinely cannot resolve; it must degrade to the [hash]
        # slot smart matching looks for, not leak its own call text.
        out = self._live()
        self.assertNotIn("uniqueString", out)
        self.assertRegex(out, r"\[[0-9a-f]{8}\]")

    def test_tolower_and_toupper(self):
        self.assertEqual(resolve_expression("[toLower('ABC-Def')]", {}, {}), "abc-def")
        self.assertEqual(resolve_expression("[toUpper('abc')]", {}, {}), "ABC")

    def test_replace_removes_and_substitutes(self):
        self.assertEqual(resolve_expression("[replace('a-b-c', '-', '')]", {}, {}), "abc")
        self.assertEqual(resolve_expression("[replace('a-b', '-', '_')]", {}, {}), "a_b")

    def test_replace_resolves_a_parameter_argument(self):
        out = resolve_expression("[replace(parameters('prefix'), '-', '')]",
                                 {"prefix": "my-lz"}, {})
        self.assertEqual(out, "mylz")


class ConditionalNamesResolveWithoutTouchingGatingTests(unittest.TestCase):
    """The live storage module derives its name through a ternary:

        var purposeCode = storagePurpose == 'logging' ? 'l' : 'g'

    compiling to if(equals(parameters('storagePurpose'), 'logging'), 'l', 'g').
    Unresolved, it leaked into the name as the literal text
    "variables('purposecode')".

    _resolve_boolean deliberately excludes equals() - its docstring explains
    that an unresolved argument returns its BARE NAME, which would compare equal
    to another bare name and manufacture a false True. That matters there because
    _resolve_boolean gates resource `condition:`, where a false True silently
    DROPS a declared resource.

    So this resolves if()/equals() only on the NAME path, and only when every
    argument fully resolves - _resolve_string_arg returns unresolved arguments as
    their original call text, so "still unresolved" stays detectable. Gating
    behaviour is unchanged.
    """

    def test_ternary_resolves_on_the_true_branch(self):
        expr = "[if(equals(parameters('storagePurpose'), 'logging'), 'l', 'g')]"
        self.assertEqual(resolve_expression(expr, {"storagePurpose": "logging"}, {}), "l")

    def test_ternary_resolves_on_the_false_branch(self):
        expr = "[if(equals(parameters('storagePurpose'), 'logging'), 'l', 'g')]"
        self.assertEqual(resolve_expression(expr, {"storagePurpose": "general"}, {}), "g")

    def test_an_unresolved_condition_does_not_pick_a_branch(self):
        # The failure the _resolve_boolean docstring warns about: two unresolved
        # arguments must NOT compare equal and silently select 'l'.
        expr = "[if(equals(parameters('missing'), 'logging'), 'l', 'g')]"
        out = resolve_expression(expr, {}, {})
        self.assertNotIn(out, ("l", "g"), f"a branch was chosen from an unresolved condition: {out}")

    def test_resource_condition_gating_is_untouched(self):
        # equals() must still NOT resolve as a boolean condition, or a gated-off
        # resource could be dropped on a manufactured True.
        from tools.normalizer.expressions import _resolve_boolean
        self.assertIsNone(_resolve_boolean("equals(parameters('a'), 'x')", {"a": "x"}, {}))


class VariablesResolveAgainstEachOtherTests(unittest.TestCase):
    """extract_variables resolved every variable against an EMPTY variables dict,
    so a variable built from another variable could never resolve.

    Live: the storage module derives
        purposeCode       = if(equals(...), 'l', 'g')
        storageAccountName = toLower(format('...', ..., variables('purposeCode'), ...))
    and the name kept the literal text "variables('purposecode')" even once
    purposeCode itself resolved correctly - the resolver simply never had it.

    Resolution is also order-independent: ARM does not require a variable to be
    declared before the one that uses it.
    """

    def _vars(self, template_vars, params):
        from tools.normalizer import extract_variables
        return extract_variables({"variables": template_vars}, params)

    def test_a_variable_can_reference_another_variable(self):
        out = self._vars({
            "code": "[if(equals(parameters('purpose'), 'logging'), 'l', 'g')]",
            "name": "[toLower(format('st{0}', variables('code')))]",
        }, {"purpose": "logging"})
        self.assertEqual(out["name"], "stl")

    def test_declaration_order_does_not_matter(self):
        # The dependent variable declared FIRST - a single forward pass would
        # leave it holding source text.
        out = self._vars({
            "name": "[toUpper(variables('code'))]",
            "code": "[parameters('p')]",
        }, {"p": "abc"})
        self.assertEqual(out["name"], "ABC")

    def test_an_unresolvable_variable_does_not_fabricate(self):
        out = self._vars({"name": "[toUpper(variables('missing'))]"}, {})
        self.assertNotEqual(out["name"], "")


if __name__ == "__main__":
    unittest.main()
