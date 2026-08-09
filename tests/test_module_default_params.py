"""
Regression tests for nested-module parameter DEFAULT resolution.

A module parameter the parent omits (relying on the module's defaultValue,
e.g. postgres.bicep `param adminUsername string = 'pgadmin'`) previously never
resolved: _extract_nested_parameters only read parent-passed values, so
resolve_expression fell back to the parameter NAME ("adminUsername") and every
property bound to that param flagged false drift against the live value.

Also covers `createMode` as write-only: it is a provisioning-only input that
Azure never returns, so it always diffed as desired-vs-null.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.activity_log import could_be_same_resource
from tools.normalizer import flatten_resources
from tools.property_drift import PropertyComparator


def _nested_deployment_template(passed_params: dict) -> dict:
    """Parent template containing one nested deployment (module) whose inner
    template declares params with defaults, mirroring compiled Bicep output."""
    return {
        "parameters": {
            "location": {"type": "string", "defaultValue": "australiaeast"},
            "environment": {"type": "string", "defaultValue": "test"},
        },
        "resources": [
            {
                "type": "Microsoft.Resources/deployments",
                "apiVersion": "2025-04-01",
                "name": "deploy-postgres",
                "properties": {
                    "mode": "Incremental",
                    "parameters": passed_params,
                    "template": {
                        "parameters": {
                            "location": {"type": "string"},
                            "adminUsername": {"type": "string", "defaultValue": "pgadmin"},
                            "adminPassword": {"type": "securestring"},
                        },
                        "resources": [
                            {
                                "type": "Microsoft.DBforPostgreSQL/flexibleServers",
                                "apiVersion": "2024-08-01",
                                "name": "pgflex-drift",
                                "location": "[parameters('location')]",
                                "properties": {
                                    "createMode": "Default",
                                    "administratorLogin": "[parameters('adminUsername')]",
                                    "administratorLoginPassword": "[parameters('adminPassword')]",
                                },
                            }
                        ],
                    },
                },
            }
        ],
    }


class ModuleDefaultParamTests(unittest.TestCase):
    def test_omitted_param_resolves_to_module_default(self):
        # Parent passes location/adminPassword but NOT adminUsername.
        template = _nested_deployment_template({
            "location": {"value": "[parameters('location')]"},
            "adminPassword": {"value": "***REDACTED***"},
        })
        resources = flatten_resources(template)
        pg = next(r for r in resources if r["type"] == "Microsoft.DBforPostgreSQL/flexibleServers")
        # Previously resolved to the param NAME "adminUsername" (false drift vs live "pgadmin").
        self.assertEqual(pg["properties"]["administratorLogin"], "pgadmin")

    def test_parent_passed_value_overrides_module_default(self):
        template = _nested_deployment_template({
            "location": {"value": "[parameters('location')]"},
            "adminUsername": {"value": "customadmin"},
            "adminPassword": {"value": "***REDACTED***"},
        })
        resources = flatten_resources(template)
        pg = next(r for r in resources if r["type"] == "Microsoft.DBforPostgreSQL/flexibleServers")
        self.assertEqual(pg["properties"]["administratorLogin"], "customadmin")

    def test_param_without_default_still_falls_back_to_name(self):
        # adminPassword has no default and is not passed: unchanged fallback behavior.
        template = _nested_deployment_template({
            "location": {"value": "[parameters('location')]"},
        })
        resources = flatten_resources(template)
        pg = next(r for r in resources if r["type"] == "Microsoft.DBforPostgreSQL/flexibleServers")
        self.assertEqual(pg["properties"]["administratorLoginPassword"], "adminPassword")


class ModuleVariableResolutionTests(unittest.TestCase):
    """A module VARIABLE built from a parent-passed required param (no default).

    `var name = 'driftAppPlan${suffix}'`, suffix passed from a parent
    uniqueString, previously resolved against the module's own defaults only -
    where suffix is None - and baked in the literal 'driftAppPlanNone', which
    false-flagged as a missing/extra pair. It must instead keep a runtime marker
    so smart matching pairs it to the live resource - today the canonical
    '[hex]' placeholder rather than the raw uniqueString() source text.
    """

    def _template(self, plan_var: str) -> dict:
        return {
            "parameters": {"location": {"type": "string", "defaultValue": "australiaeast"}},
            "variables": {"suffix": "[uniqueString(resourceGroup().id)]"},
            "resources": [{
                "type": "Microsoft.Resources/deployments",
                "apiVersion": "2025-04-01",
                "name": "deploy-rg",
                "properties": {
                    "mode": "Incremental",
                    "parameters": {
                        "location": {"value": "[parameters('location')]"},
                        "suffix": {"value": "[variables('suffix')]"},
                    },
                    "template": {
                        "parameters": {
                            "location": {"type": "string"},
                            "suffix": {"type": "string"},
                        },
                        "variables": {"appServicePlanName": plan_var},
                        "resources": [{
                            "type": "Microsoft.Web/serverfarms",
                            "apiVersion": "2022-03-01",
                            "name": "[variables('appServicePlanName')]",
                            "location": "[parameters('location')]",
                        }],
                    },
                },
            }],
        }

    def _plan_name(self, plan_var: str) -> str:
        resources = flatten_resources(self._template(plan_var))
        return next(r["name"] for r in resources
                    if r["type"] == "Microsoft.Web/serverfarms")

    def test_bare_format_name_keeps_a_matchable_runtime_marker(self):
        # The invariant is that the name stays PAIRABLE with whatever the
        # uniqueString resolved to live - not that any particular text survives.
        # It asserted the literal 'uniquestring' until take()/uniqueString()
        # joined the resolvable transforms and the marker became the canonical
        # '[hex]' placeholder, which is the form smart matching and
        # could_be_same_resource are built around.
        name = self._plan_name("[format('driftAppPlan{0}', parameters('suffix'))]")
        self.assertNotIn("None", name)          # the original defect
        self.assertRegex(name, r"^driftAppPlan\[[0-9a-f]{8}\]$")
        self.assertTrue(could_be_same_resource(name, "driftAppPlan3s7c7wed"))

    def test_matches_the_tolower_wrapped_sibling_behavior(self):
        # The toLower-wrapped form was always kept unresolvable; the bare form
        # must behave the same rather than collapsing to a literal.
        name = self._plan_name("[toLower(format('driftplan{0}', parameters('suffix')))]")
        self.assertNotIn("None", name)
        self.assertRegex(name, r"^driftplan\[[0-9a-f]{8}\]$")

    def test_the_marker_still_separates_prefix_siblings(self):
        # Why the placeholder form matters beyond legibility: raw expression
        # text sends could_be_same_resource to its 3-character shared-affix
        # fallback, where 'jacquidev-kv-...' adopted the deletion event of
        # 'jacquidev-kvp-e4zzsl'. Resolved, the trailing '-' is literal and the
        # two are distinguishable.
        raw = "jacquidev-kv-take(uniqueString(resourceGroup().id), 6)"
        self.assertTrue(could_be_same_resource(raw, "jacquidev-kvp-e4zzsl"))
        self.assertFalse(could_be_same_resource("jacquidev-kv-[86c9cbf6]",
                                                "jacquidev-kvp-e4zzsl"))
        self.assertTrue(could_be_same_resource("jacquidev-kvp-[86c9cbf6]",
                                               "jacquidev-kvp-e4zzsl"))


class CreateModeWriteOnlyTests(unittest.TestCase):
    def test_createmode_is_write_only(self):
        self.assertTrue(PropertyComparator._is_write_only_property("properties.createMode"))
        self.assertTrue(PropertyComparator._is_write_only_property("properties.createmode"))

    def test_createmode_not_reported_as_diff(self):
        diffs = PropertyComparator.compare_properties(
            {"properties": {"createMode": "Default", "version": "16"}},
            {"properties": {"version": "16"}},
        )
        self.assertEqual([d for d in diffs if "createmode" in d.property_path.lower()], [])


if __name__ == "__main__":
    unittest.main()
