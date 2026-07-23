"""
Unit tests for condition evaluation in flatten_resources: a module or resource
gated behind `if (...)` whose condition resolves to false is not deployed, so
it must not be compared (previously every gated-off module surfaced as
missing_in_azure - 11 false positives on the drift-test estate).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.normalizer import flatten_resources


def nested_deployment(name, condition, inner_resources):
    return {
        "type": "Microsoft.Resources/deployments",
        "name": name,
        "condition": condition,
        "properties": {
            "mode": "Incremental",
            "template": {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "resources": inner_resources,
            },
        },
    }


STORAGE = {"type": "Microsoft.Storage/storageAccounts", "name": "st1",
           "location": "australiaeast", "properties": {}}
LB = {"type": "Microsoft.Network/loadBalancers", "name": "lb-gated",
      "location": "australiaeast", "properties": {}}


class ConditionalResourceTests(unittest.TestCase):
    def _template(self, resources, params=None):
        return {
            "parameters": {
                k: {"type": "bool", "defaultValue": v} for k, v in (params or {}).items()
            },
            "resources": resources,
        }

    def test_false_condition_module_is_skipped(self):
        tpl = self._template(
            [STORAGE, nested_deployment(
                "deploy-lb", "[parameters('deployNetworkAppliances')]", [LB])],
            params={"deployNetworkAppliances": False},
        )
        names = {r["name"] for r in flatten_resources(tpl)}
        self.assertIn("st1", names)
        self.assertNotIn("lb-gated", names)

    def test_true_condition_module_is_kept(self):
        tpl = self._template(
            [nested_deployment("deploy-lb", "[parameters('deployNetworkAppliances')]", [LB])],
            params={"deployNetworkAppliances": True},
        )
        self.assertIn("lb-gated", {r["name"] for r in flatten_resources(tpl)})

    def test_parameter_override_controls_condition(self):
        tpl = self._template(
            [nested_deployment("deploy-lb", "[parameters('deployAks')]", [LB])],
            params={"deployAks": False},
        )
        kept = flatten_resources(tpl, parameters={"deployAks": True})
        self.assertIn("lb-gated", {r["name"] for r in kept})

    def test_literal_false_condition_on_plain_resource(self):
        gated = {**STORAGE, "name": "st-gated", "condition": False}
        tpl = self._template([STORAGE, gated])
        names = {r["name"] for r in flatten_resources(tpl)}
        self.assertEqual(names, {"st1"})

    def test_unresolvable_condition_is_kept_conservatively(self):
        gated = nested_deployment(
            "deploy-lb", "[not(empty(parameters('someList')))]", [LB])
        tpl = self._template([gated])
        self.assertIn("lb-gated", {r["name"] for r in flatten_resources(tpl)})

    # Compound boolean conditions - and()/or()/not(). The vHub route table gates on
    # `deployVirtualHub && !deployHubFirewall` (route-table mode vs routing-intent
    # mode are mutually exclusive); a Tier-2 scan must resolve that to False and
    # NOT false-flag the excluded route table as missing.
    def test_and_not_compound_false_is_skipped(self):
        gated = {**STORAGE, "name": "rt-gated",
                 "condition": "[and(parameters('deployVirtualHub'), not(parameters('deployHubFirewall')))]"}
        tpl = self._template([STORAGE, gated],
                             params={"deployVirtualHub": True, "deployHubFirewall": True})
        names = {r["name"] for r in flatten_resources(tpl)}
        self.assertNotIn("rt-gated", names)  # and(true, not(true)) == false
        self.assertIn("st1", names)

    def test_and_not_compound_true_is_kept(self):
        gated = {**STORAGE, "name": "rt-gated",
                 "condition": "[and(parameters('deployVirtualHub'), not(parameters('deployHubFirewall')))]"}
        tpl = self._template([gated],
                             params={"deployVirtualHub": True, "deployHubFirewall": False})
        self.assertIn("rt-gated", {r["name"] for r in flatten_resources(tpl)})  # and(true, not(false))

    def test_or_compound_resolves(self):
        gated = {**STORAGE, "name": "st-gated",
                 "condition": "[or(parameters('a'), parameters('b'))]"}
        tpl = self._template([gated], params={"a": False, "b": False})
        self.assertNotIn("st-gated", {r["name"] for r in flatten_resources(tpl)})

    def test_unresolvable_arg_keeps_compound_conservative(self):
        # empty() is unresolvable, so and(...) must stay unresolved and KEEP the resource
        gated = {**STORAGE, "name": "st-gated",
                 "condition": "[and(parameters('a'), not(empty(parameters('list'))))]"}
        tpl = self._template([gated], params={"a": True})
        self.assertIn("st-gated", {r["name"] for r in flatten_resources(tpl)})


if __name__ == "__main__":
    unittest.main()
