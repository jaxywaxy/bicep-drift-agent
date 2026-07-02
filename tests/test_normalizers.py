"""
Unit tests for get_live_state normalizers that suppress array-of-object false
positives (Cosmos account locations, ACI container groups).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.get_live_state import (
    _normalize_cosmos_account_locations,
    _normalize_aci_container_groups,
)


class CosmosLocationsNormalizeTests(unittest.TestCase):
    def test_locationname_and_injected_fields(self):
        resources = [{
            "type": "microsoft.documentdb/databaseaccounts",
            "properties": {"locations": [{
                "locationName": "Australia East", "failoverPriority": 0,
                "isZoneRedundant": False, "id": "x", "documentEndpoint": "y",
                "provisioningState": "Succeeded",
            }]},
        }]
        _normalize_cosmos_account_locations(resources)
        loc = resources[0]["properties"]["locations"][0]
        self.assertEqual(loc, {"locationName": "australiaeast", "failoverPriority": 0, "isZoneRedundant": False})


class AciContainerNormalizeTests(unittest.TestCase):
    def _aci(self, container_props):
        return [{
            "type": "microsoft.containerinstance/containergroups",
            "properties": {"containers": [{"name": "hello", "properties": container_props}]},
        }]

    def test_strips_runtime_and_empty_fields_and_coerces_numbers(self):
        resources = self._aci({
            "image": "img:latest",
            "instanceView": {"currentState": {"state": "Running"}},
            "environmentVariables": [],
            "ports": [],
            "configMap": {"keyValuePairs": {}},
            "resources": {"requests": {"cpu": 1.0, "memoryInGB": 1.0}},
        })
        _normalize_aci_container_groups(resources)
        cprops = resources[0]["properties"]["containers"][0]["properties"]
        self.assertEqual(cprops, {
            "image": "img:latest",
            "resources": {"requests": {"cpu": 1, "memoryInGB": 1}},
        })

    def test_preserves_real_values(self):
        # a genuine image + non-empty env must be preserved (real drift still detectable)
        resources = self._aci({
            "image": "img:v2",
            "environmentVariables": [{"name": "FOO", "value": "bar"}],
            "resources": {"requests": {"cpu": 2, "memoryInGB": 4}},
        })
        _normalize_aci_container_groups(resources)
        cprops = resources[0]["properties"]["containers"][0]["properties"]
        self.assertEqual(cprops["image"], "img:v2")
        self.assertEqual(cprops["environmentVariables"], [{"name": "FOO", "value": "bar"}])
        self.assertEqual(cprops["resources"]["requests"], {"cpu": 2, "memoryInGB": 4})


if __name__ == "__main__":
    unittest.main()
