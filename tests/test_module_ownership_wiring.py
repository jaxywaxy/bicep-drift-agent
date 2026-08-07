"""
The plumbing behind module-based ownership: the `_module` label stamped during
flattening, the config that maps it, and the index that ties a drift row back to
the ARM resource that declared it.

Entered through the stages ABOVE the units where possible - a test that calls
`_module_label` alone would pass while the label never reached a drift row.
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration.attribution import _declared_module_index, _split_policy_and_tag_owners
from tools.config import module_owners, ownership_default_owner
from tools.normalizer.flatten import flatten_resources


def _module_deployment(name, inner):
    return {"type": "Microsoft.Resources/deployments", "name": name,
            "apiVersion": "2021-04-01",
            "properties": {"template": {"resources": inner}}}


def _vault(name="kv1"):
    return {"type": "Microsoft.KeyVault/vaults", "name": name, "apiVersion": "2023-07-01"}


class ModuleLabelStampingTests(unittest.TestCase):
    """Bicep names a module's deployment after its symbolic name, suffixed for
    uniqueness: format('networking-{0}', uniqueString(...)). uniqueString cannot
    be evaluated, so the resolver leaves 'networking-[401dbdfe]' and the stable
    part is what precedes the placeholder."""

    def test_placeholder_suffix_is_stripped(self):
        arm = {"resources": [_module_deployment(
            "[format('networking-{0}', uniqueString(subscription().id))]", [_vault()])]}
        self.assertEqual(flatten_resources(arm)[0]["_module"], "networking")

    def test_a_hyphenated_module_name_survives(self):
        # 'storage-logs' must not be truncated to 'storage' - two modules in the
        # same LZ differ only by that suffix.
        arm = {"resources": [_module_deployment(
            "[format('storage-logs-{0}', uniqueString(subscription().id))]", [_vault()])]}
        self.assertEqual(flatten_resources(arm)[0]["_module"], "storage-logs")

    def test_a_plain_module_name_is_used_as_is(self):
        arm = {"resources": [_module_deployment("networking", [_vault()])]}
        self.assertEqual(flatten_resources(arm)[0]["_module"], "networking")

    def test_nested_modules_build_a_path_outermost_first(self):
        inner = _module_deployment("keyvault", [_vault()])
        arm = {"resources": [_module_deployment("apps", [inner])]}
        self.assertEqual(flatten_resources(arm)[0]["_module"], "apps/keyvault")

    def test_a_top_level_resource_has_no_module(self):
        # Declared outside any module, so there is no module boundary to read.
        arm = {"resources": [_vault()]}
        self.assertIsNone(flatten_resources(arm)[0].get("_module"))

    def test_an_entirely_unresolvable_name_yields_no_label(self):
        # The resolver returns 'subscription-context' here - a description of an
        # expression it could not evaluate, not a name. None falls through to the
        # type rules; a wrong label would route drift to a team that does not own
        # it, and would match a `*` glob as if it were real.
        arm = {"resources": [_module_deployment(
            "[uniqueString(subscription().id)]", [_vault()])]}
        self.assertIsNone(flatten_resources(arm)[0].get("_module"))

    def test_a_variable_named_module_declines_rather_than_guesses(self):
        # Accepted cost of the rule above: the value appears nowhere in the
        # declaration, so it cannot be told apart from a resolver stand-in.
        # Losing the evidence is safe; inventing it is not.
        arm = {"resources": [_module_deployment("[variables('moduleName')]", [_vault()])]}
        self.assertIsNone(flatten_resources(arm)[0].get("_module"))


class DeclaredModuleIndexTests(unittest.TestCase):
    def test_lookup_is_case_insensitive_on_type_and_name(self):
        # Azure echoes types back in a different case than the template declares
        # them; a case-sensitive index silently finds nothing.
        report = {"arm_resources": [
            {"type": "Microsoft.KeyVault/vaults", "name": "KV1", "_module": "apps"}]}
        index = _declared_module_index(report)
        self.assertEqual(index[("microsoft.keyvault/vaults", "kv1")], "apps")

    def test_placeholder_named_resources_are_indexed_under_their_expression(self):
        # A missing_in_azure drift for a uniqueString-named resource carries the
        # expression, not the deployed name.
        report = {"arm_resources": [{
            "type": "Microsoft.Storage/storageAccounts", "name": "stg[86c9cbf6]",
            "bicep_name_expression": "stg[86c9cbf6]", "_module": "storage-logs"}]}
        index = _declared_module_index(report)
        self.assertEqual(index[("microsoft.storage/storageaccounts", "stg[86c9cbf6]")],
                         "storage-logs")

    def test_resources_without_a_module_are_absent_rather_than_null(self):
        report = {"arm_resources": [{"type": "Microsoft.KeyVault/vaults", "name": "kv1"}]}
        self.assertEqual(_declared_module_index(report), {})


class OwnerTaggingEndToEndTests(unittest.TestCase):
    """Enters at _split_policy_and_tag_owners, the stage that actually assigns
    `owner`, so the label has to survive the whole path to count."""

    def _report(self):
        return {
            "arm_resources": [
                {"type": "Microsoft.KeyVault/vaults", "name": "kv1", "_module": "apps"},
                {"type": "Microsoft.OperationalInsights/workspaces", "name": "law",
                 "_module": "logging"},
            ],
            "drifts": [
                {"type": "Microsoft.KeyVault/vaults", "name": "kv1",
                 "drift_type": "missing_in_azure"},
                {"type": "Microsoft.OperationalInsights/workspaces", "name": "law",
                 "drift_type": "missing_in_azure"},
            ],
        }

    def _owners(self, env):
        with mock.patch.dict(os.environ, env, clear=False):
            for key in ("DRIFT_OWNERSHIP_MODEL", "DRIFT_MODULE_OWNERS"):
                if key not in env:
                    os.environ.pop(key, None)
            report = self._report()
            _split_policy_and_tag_owners(report)
            return [d["owner"] for d in report["drifts"]]

    def test_unconfigured_behaviour_is_unchanged(self):
        self.assertEqual(self._owners({}), ["workload", "workload"])

    def test_platform_model_claims_the_whole_estate(self):
        self.assertEqual(self._owners({"DRIFT_OWNERSHIP_MODEL": "platform"}),
                         ["platform", "platform"])

    def test_module_map_carves_the_workload_back_out(self):
        self.assertEqual(
            self._owners({"DRIFT_OWNERSHIP_MODEL": "platform",
                          "DRIFT_MODULE_OWNERS": json.dumps({"apps": "workload"})}),
            ["workload", "platform"])


class OwnershipConfigParsingTests(unittest.TestCase):
    def test_unset_is_workload(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DRIFT_OWNERSHIP_MODEL", None)
            self.assertEqual(ownership_default_owner(), "workload")

    def test_an_invalid_model_warns_and_keeps_the_safe_default(self):
        with mock.patch.dict(os.environ, {"DRIFT_OWNERSHIP_MODEL": "platfrom"}):
            with self.assertLogs("tools.config", level="WARNING"):
                self.assertEqual(ownership_default_owner(), "workload")

    def test_model_is_case_and_space_insensitive(self):
        with mock.patch.dict(os.environ, {"DRIFT_OWNERSHIP_MODEL": " Platform "}):
            self.assertEqual(ownership_default_owner(), "platform")

    def test_null_from_a_workflow_yaml_lookup_is_treated_as_unset(self):
        # The reusable workflow passes toJson(...) of an absent config key, which
        # is the literal string 'null' - the same shape DRIFT_DEPLOYMENT_STACK has.
        with mock.patch.dict(os.environ, {"DRIFT_MODULE_OWNERS": "null"}):
            self.assertEqual(module_owners(), {})

    def test_malformed_module_owners_is_ignored_not_half_applied(self):
        # A partially honoured map routes some findings correctly and others
        # silently to the wrong team, which is harder to notice than no map.
        for bad in ("{oops", '["apps"]', '{"apps": "platfrom"}', '{"": "platform"}'):
            with self.subTest(bad=bad):
                with mock.patch.dict(os.environ, {"DRIFT_MODULE_OWNERS": bad}):
                    with self.assertLogs("tools.config", level="WARNING"):
                        self.assertEqual(module_owners(), {})

    def test_a_valid_map_parses_and_normalises(self):
        with mock.patch.dict(os.environ, {"DRIFT_MODULE_OWNERS":
                                          '{" apps ": "Workload", "logging": "platform"}'}):
            self.assertEqual(module_owners(), {"apps": "workload", "logging": "platform"})


if __name__ == "__main__":
    unittest.main()
