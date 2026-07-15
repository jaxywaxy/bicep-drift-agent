"""
Every App Service / Function App app setting VALUE is a secret.

Found by auditing a real drift report: a function app's AzureWebJobsStorage
held a full storage connection string with a LIVE AccountKey, and it was
written verbatim into reports/<rg>-drift.json - which CI uploads as an
artifact. redact_secrets matched on KEY NAMES (accountKey,
administratorLoginPassword, *connectionString), and 'AzureWebJobsStorage' is
none of those.

App setting names are arbitrary and user-chosen - AzureWebJobsStorage,
APPINSIGHTS_INSTRUMENTATIONKEY, DOCKER_REGISTRY_SERVER_PASSWORD, MY_DB_CONN -
so key-name matching can NEVER be complete for them. Every value is redacted.

Safe because the comparator reduces both sides to KEY SETS and never reads a
value; these tests pin that the key set survives.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.redact import redact_secrets, REDACTED
from tools.property_drift import PropertyComparator

CONN = "DefaultEndpointsProtocol=https;AccountName=st1;AccountKey=cI7rgfcIsecret==;EndpointSuffix=core.windows.net"


def _appsettings(name="func-drift/appsettings", **settings):
    return {"type": "Microsoft.Web/sites/config", "name": name,
            "location": None, "properties": dict(settings)}


class RedactAppSettingsTests(unittest.TestCase):
    def test_live_connection_string_value_is_redacted(self):
        out = redact_secrets([_appsettings(AzureWebJobsStorage=CONN)])
        self.assertEqual(out[0]["properties"]["AzureWebJobsStorage"], REDACTED)
        self.assertNotIn("AccountKey=cI7rgfcI", str(out))

    def test_arbitrary_setting_names_are_redacted(self):
        # None of these key names match any secret-key rule.
        out = redact_secrets([_appsettings(
            MY_DB_CONN="Server=x;Pwd=p", STRIPE_KEY="sk_live_abc",
            APPINSIGHTS_INSTRUMENTATIONKEY="00000000-0000-0000-0000-000000000000")])
        for v in out[0]["properties"].values():
            self.assertEqual(v, REDACTED)

    def test_key_set_is_preserved(self):
        # The comparator compares KEY SETS - they must survive redaction.
        original = _appsettings(AzureWebJobsStorage=CONN, FUNCTIONS_WORKER_RUNTIME="node")
        out = redact_secrets([original])[0]
        self.assertEqual(sorted(out["properties"]), sorted(original["properties"]))

    def test_redacted_appsettings_still_compare_correctly(self):
        # Phase 2 reads the REDACTED report from disk; comparison must still work.
        bicep = redact_secrets(_appsettings(A="1", B="2"))
        live_same = redact_secrets(_appsettings(A="different", B="values"))
        self.assertEqual(PropertyComparator.compare_properties(bicep, live_same), [])

        live_diff = redact_secrets(_appsettings(A="1", C="3"))
        diffs = PropertyComparator.compare_properties(bicep, live_diff)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].property_path, "properties.appSettingKeys")
        # The diff carries KEYS only - never values.
        self.assertEqual(diffs[0].desired_value, ["A", "B"])
        self.assertEqual(diffs[0].actual_value, ["A", "C"])

    def test_resource_metadata_untouched(self):
        out = redact_secrets([_appsettings(A="1")])[0]
        self.assertEqual(out["type"], "Microsoft.Web/sites/config")
        self.assertEqual(out["name"], "func-drift/appsettings")

    def test_web_config_child_is_not_appsettings(self):
        # config/web is the non-secret runtime surface - must NOT be blanked.
        web = {"type": "Microsoft.Web/sites/config", "name": "func-drift/web",
               "properties": {"ftpsState": "FtpsOnly", "minTlsVersion": "1.2"}}
        out = redact_secrets([web])[0]
        self.assertEqual(out["properties"]["ftpsState"], "FtpsOnly")

    def test_none_properties_tolerated(self):
        r = {"type": "Microsoft.Web/sites/config", "name": "x/appsettings",
             "properties": None}
        self.assertIsNone(redact_secrets([r])[0]["properties"])

    def test_existing_key_name_redaction_still_works(self):
        sql = {"type": "Microsoft.Sql/servers", "name": "s",
               "properties": {"administratorLoginPassword": "hunter2", "version": "12.0"}}
        out = redact_secrets([sql])[0]
        self.assertEqual(out["properties"]["administratorLoginPassword"], REDACTED)
        self.assertEqual(out["properties"]["version"], "12.0")


if __name__ == "__main__":
    unittest.main()
