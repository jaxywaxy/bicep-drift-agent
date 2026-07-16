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
