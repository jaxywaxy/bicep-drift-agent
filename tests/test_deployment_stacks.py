"""
Unit tests for deployment stack drift detection (tools/deployment_stacks.py).

Two behaviours carry most of the risk and most of the tests:

  * NOTHING is asserted about enforcement posture unless the config declares it.
    A stack sitting at `mode: none` with no `expect` block must be silent - the
    alternative (treating live values as a baseline) blesses the weak setting.
  * managed-but-missing must never fabricate a deletion. Out-of-scan-scope ids,
    child resources, and confirm-lookup failures all have to stay quiet.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.deployment_stacks import (
    STACK_TYPE,
    annotate_stack_ownership,
    compare_deployment_stack,
    dedupe_against,
    load_stack_config,
    managed_ids,
    stack_drift_enabled,
    _in_scan_scope,
    _is_top_level,
    _stack_url,
)

SUB = "00000000-0000-0000-0000-000000000001"
RG = "rg-app"


def stack(deny=None, unmanage=None, state="succeeded", resources=(), **props):
    return {
        "id": f"/subscriptions/{SUB}/providers/{STACK_TYPE}/platform-stack",
        "name": "platform-stack",
        "properties": {
            "provisioningState": state,
            "denySettings": deny if deny is not None else {
                "mode": "denyWriteAndDelete", "applyToChildScopes": True,
                "excludedPrincipals": [], "excludedActions": [],
            },
            "actionOnUnmanage": unmanage if unmanage is not None else {
                "resources": "delete", "resourceGroups": "delete",
                "managementGroups": "detach",
            },
            "resources": list(resources),
            **props,
        },
    }


def managed(rid):
    return {"id": rid, "status": "managed", "denyStatus": "denyWriteAndDelete"}


def rid_of(name, rg=RG, rtype="Microsoft.Storage/storageAccounts"):
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{rtype}/{name}"


def paths(drifts):
    """The changed_properties paths of the single posture drift, if any."""
    for d in drifts:
        if d["drift_type"] == "property_drift":
            return d["details"]["changed_properties"]
    return {}


class TestConfigLoading(unittest.TestCase):
    def test_absent_config_disables_the_check(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(load_stack_config())
            self.assertFalse(stack_drift_enabled())

    def test_malformed_config_is_skipped_not_raised(self):
        # 'null' is what the workflow's toJson() yields for a check with no
        # deployment_stack block - by far the most common case, and it must be
        # silent rather than warn on every ordinary check.
        for raw in ("not json", "null", "[]", "{}", '{"scope": "subscription"}'):
            with mock.patch.dict(os.environ, {"DRIFT_DEPLOYMENT_STACK": raw}, clear=True):
                self.assertIsNone(load_stack_config(), raw)
                self.assertFalse(stack_drift_enabled(), raw)

    def test_env_toggle_forces_off_even_when_configured(self):
        env = {"DRIFT_DEPLOYMENT_STACK": '{"name": "s"}', "INCLUDE_DEPLOYMENT_STACKS": "false"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(stack_drift_enabled())

    def test_scope_urls(self):
        sub_url = _stack_url({"name": "s", "scope": "subscription"}, SUB, None)
        self.assertIn(f"/subscriptions/{SUB}/providers/{STACK_TYPE}/s", sub_url)

        rg_url = _stack_url({"name": "s", "scope": "resource_group"}, SUB, RG)
        self.assertIn(f"/resourceGroups/{RG}/providers/{STACK_TYPE}/s", rg_url)

        mg_url = _stack_url({"name": "s", "scope": "management_group", "management_group": "mg1"}, SUB, None)
        self.assertIn("/managementGroups/mg1/", mg_url)

        with self.assertRaises(ValueError):
            _stack_url({"name": "s", "scope": "management_group"}, SUB, None)


class TestNothingAssertedWithoutExpectations(unittest.TestCase):
    """The central rule: live values are never their own baseline."""

    def test_wide_open_stack_is_silent_without_an_expect_block(self):
        wide_open = stack(deny={"mode": "none", "applyToChildScopes": False,
                                "excludedPrincipals": [], "excludedActions": []})
        drifts = compare_deployment_stack({"name": "platform-stack"}, wide_open, [], SUB, RG)
        self.assertEqual(drifts, [])

    def test_undeclared_keys_are_not_compared(self):
        cfg = {"name": "platform-stack", "expect": {"deny_settings": {"mode": "none"}}}
        s = stack(deny={"mode": "none", "applyToChildScopes": False,
                        "excludedPrincipals": ["p1"], "excludedActions": []})
        # Only mode was declared; applyToChildScopes and exclusions stay unasserted.
        self.assertEqual(paths(compare_deployment_stack(cfg, s, [], SUB, RG)), {})

    def test_failed_state_is_reported_without_any_expect_block(self):
        """Provisioning health needs no declaration - success is the only sane
        default, and a half-applied template makes 'no drift' misleading."""
        drifts = compare_deployment_stack(
            {"name": "platform-stack"},
            stack(state="failed", error={"message": "ResourceGroupNotFound"}),
            [], SUB, RG,
        )
        p = paths(drifts)
        self.assertEqual(p["provisioningState"]["actual"], "failed")
        self.assertEqual(p["provisioningState"]["severity"], "critical")
        self.assertIn("ResourceGroupNotFound", p["error.message"]["actual"])


class TestDenySettings(unittest.TestCase):
    def cfg(self, **expect):
        return {"name": "platform-stack", "expect": {"deny_settings": expect}}

    def test_weakened_mode_is_critical(self):
        p = paths(compare_deployment_stack(
            self.cfg(mode="denyWriteAndDelete"), stack(deny={"mode": "none"}), [], SUB, RG))
        self.assertEqual(p["denySettings.mode"]["severity"], "critical")
        self.assertEqual(p["denySettings.mode"]["actual"], "none")

    def test_stricter_than_asked_is_info_not_critical(self):
        p = paths(compare_deployment_stack(
            self.cfg(mode="denyDelete"), stack(deny={"mode": "denyWriteAndDelete"}), [], SUB, RG))
        self.assertEqual(p["denySettings.mode"]["severity"], "info")

    def test_matching_mode_is_clean_regardless_of_case(self):
        p = paths(compare_deployment_stack(
            self.cfg(mode="denywriteanddelete"), stack(deny={"mode": "denyWriteAndDelete"}), [], SUB, RG))
        self.assertEqual(p, {})

    def test_apply_to_child_scopes_off_is_its_own_critical_finding(self):
        """Deny lands on the resource GROUPS only; resources inside stay writable
        while the mode still reads as enforcing."""
        p = paths(compare_deployment_stack(
            self.cfg(mode="denyWriteAndDelete", apply_to_child_scopes=True),
            stack(deny={"mode": "denyWriteAndDelete", "applyToChildScopes": False}),
            [], SUB, RG))
        self.assertEqual(p["denySettings.applyToChildScopes"]["severity"], "critical")
        self.assertNotIn("denySettings.mode", p)

    def test_added_exclusion_is_critical_removed_is_warning(self):
        added = paths(compare_deployment_stack(
            self.cfg(excluded_principals=[]),
            stack(deny={"mode": "denyWriteAndDelete", "excludedPrincipals": ["abc-123"]}),
            [], SUB, RG))
        self.assertEqual(added["denySettings.excludedPrincipals"]["severity"], "critical")

        removed = paths(compare_deployment_stack(
            self.cfg(excluded_principals=["abc-123"]),
            stack(deny={"mode": "denyWriteAndDelete", "excludedPrincipals": []}),
            [], SUB, RG))
        self.assertEqual(removed["denySettings.excludedPrincipals"]["severity"], "warning")

    def test_exclusion_compare_is_order_and_case_insensitive(self):
        p = paths(compare_deployment_stack(
            self.cfg(excluded_principals=["ABC-123", "def-456"]),
            stack(deny={"mode": "denyWriteAndDelete", "excludedPrincipals": ["def-456", "abc-123"]}),
            [], SUB, RG))
        self.assertEqual(p, {})


class TestApiCasingVaries(unittest.TestCase):
    """Azure is not consistent about casing across these endpoints: a live GET
    returns `"mode": "none"` and `"detach"`, while the validate endpoint returns
    `"DenyWriteAndDelete"` and `"Delete"` for the same fields. Every comparison
    here must therefore be case-insensitive, or a correctly-configured stack
    reports drift depending on which call produced the data."""

    def test_pascal_case_live_values_compare_clean(self):
        cfg = {"name": "platform-stack", "expect": {
            "deny_settings": {"mode": "denyWriteAndDelete", "apply_to_child_scopes": True},
            "action_on_unmanage": {"resources": "delete", "resource_groups": "delete"},
        }}
        s = stack(
            deny={"mode": "DenyWriteAndDelete", "applyToChildScopes": True,
                  "excludedPrincipals": [], "excludedActions": []},
            unmanage={"resources": "Delete", "resourceGroups": "Delete",
                      "managementGroups": "Delete", "resourcesWithoutDeleteSupport": "Fail"},
            state="Succeeded",
        )
        self.assertEqual(paths(compare_deployment_stack(cfg, s, [], SUB, RG)), {})


class TestActionOnUnmanage(unittest.TestCase):
    def test_delete_regressed_to_detach_is_warning(self):
        cfg = {"name": "platform-stack", "expect": {"action_on_unmanage": {"resources": "delete"}}}
        p = paths(compare_deployment_stack(cfg, stack(unmanage={"resources": "detach"}), [], SUB, RG))
        self.assertEqual(p["actionOnUnmanage.resources"]["severity"], "warning")
        self.assertEqual(p["actionOnUnmanage.resources"]["actual"], "detach")


class TestStackHealth(unittest.TestCase):
    def test_outcome_lists_are_reported_by_severity(self):
        s = stack(
            failedResources=[{"id": rid_of("sa1")}],
            detachedResources=[{"id": rid_of("sa2")}],
            deletedResources=[{"id": rid_of("sa3")}],
        )
        p = paths(compare_deployment_stack({"name": "platform-stack"}, s, [], SUB, RG))
        self.assertEqual(p["failedResources"]["severity"], "critical")
        self.assertEqual(p["detachedResources"]["severity"], "warning")
        self.assertEqual(p["deletedResources"]["severity"], "info")

    def test_empty_outcome_lists_are_silent(self):
        p = paths(compare_deployment_stack({"name": "platform-stack"}, stack(), [], SUB, RG))
        self.assertEqual(p, {})

    def test_nested_error_leaf_message_is_surfaced_not_the_generic_wrapper(self):
        """Regression: a failed KV deploy reported only 'One or more resources
        could not be deployed. Correlation id: ...'; the soft-delete cause sat
        unread in error.details[].details[]. This is the exact live shape from
        the test-stack round on 2026-07-21."""
        soft_delete = ("A vault with the same name already exists in deleted state. "
                       "You need to either recover or purge existing key vault.")
        s = stack(state="failed", error={
            "code": "DeploymentStackDeploymentFailed",
            "message": "One or more resources could not be deployed. Correlation id: '890b570d'.",
            "details": [{
                "code": "DeploymentFailed",
                "message": "At least one resource deployment operation failed.",
                "details": [{"code": "ConflictError", "message": soft_delete, "details": None}],
            }],
        })
        p = paths(compare_deployment_stack({"name": "platform-stack"}, s, [], SUB, RG))
        self.assertEqual(p["error.message"]["actual"], soft_delete)
        self.assertNotIn("Correlation id", p["error.message"]["actual"])

    def test_failed_resource_carries_its_own_error_not_just_an_id(self):
        soft_delete = "A vault with the same name already exists in deleted state."
        s = stack(state="failed", failedResources=[{
            "id": rid_of("kv1", rtype="Microsoft.KeyVault/vaults"),
            "error": {"code": "ConflictError", "message": soft_delete, "details": None},
        }])
        p = paths(compare_deployment_stack({"name": "platform-stack"}, s, [], SUB, RG))
        entry = p["failedResources"]["actual"][0]
        self.assertEqual(entry["code"], "ConflictError")
        self.assertEqual(entry["message"], soft_delete)
        self.assertTrue(entry["id"].endswith("kv1"))

    def test_flatten_collects_multiple_leaves(self):
        from tools.deployment_stacks import _flatten_error_messages
        err = {"message": "top", "details": [
            {"message": "midA", "details": [{"message": "leafA", "details": None}]},
            {"message": "leafB", "details": []},
        ]}
        self.assertEqual(_flatten_error_messages(err), ["leafA", "leafB"])

    def test_flatten_falls_back_to_top_message_when_no_details(self):
        from tools.deployment_stacks import _flatten_error_messages
        self.assertEqual(_flatten_error_messages({"message": "only"}), ["only"])


class TestMissingStack(unittest.TestCase):
    def test_absent_stack_is_missing_in_azure(self):
        drifts = compare_deployment_stack({"name": "platform-stack"}, None, [], SUB, RG)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "missing_in_azure")
        self.assertEqual(drifts[0]["type"], STACK_TYPE)


class TestManagedButMissing(unittest.TestCase):
    """No fabricated deletions. A candidate is reported only after a direct
    lookup confirms it is really gone."""

    def compare(self, resources, live, exists=False, scope="resource_group", raises=False):
        s = stack(resources=resources)
        cfg = {"name": "platform-stack"}
        target = "tools.deployment_stacks._resource_exists"
        side = Exception("transient") if raises else None
        with mock.patch(target, side_effect=side, return_value=exists) as ex, \
             mock.patch("tools.deployment_stacks._arm_get",
                        side_effect=side,
                        return_value={"id": "x"} if exists else None):
            self.ex = ex
            return compare_deployment_stack(cfg, s, live, SUB, RG, scope=scope, token="t")

    def test_confirmed_deleted_resource_is_reported(self):
        drifts = self.compare([managed(rid_of("sa1"))], live=[], exists=False)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "missing_in_azure")
        self.assertEqual(drifts[0]["name"], "sa1")
        self.assertEqual(drifts[0]["type"], "Microsoft.Storage/storageAccounts")

    def test_resource_present_in_live_state_is_not_reported(self):
        drifts = self.compare([managed(rid_of("sa1"))], live=[{"id": rid_of("sa1")}])
        self.assertEqual(drifts, [])

    def test_resource_absent_from_live_but_still_existing_is_not_reported(self):
        """Live state expansion is partial; absence is not proof of deletion."""
        self.assertEqual(self.compare([managed(rid_of("sa1"))], live=[], exists=True), [])

    def test_failed_confirmation_stays_silent(self):
        self.assertEqual(self.compare([managed(rid_of("sa1"))], live=[], raises=True), [])

    def test_out_of_scan_scope_resource_is_not_reported(self):
        """A sub-scoped stack spans RGs an RG-scoped scan never looked at."""
        drifts = self.compare([managed(rid_of("sa1", rg="rg-elsewhere"))], live=[], exists=False)
        self.assertEqual(drifts, [])

    def test_child_resources_are_skipped(self):
        child = rid_of("sa1") + "/blobServices/default"
        self.assertEqual(self.compare([managed(child)], live=[], exists=False), [])

    def test_detached_resources_are_not_treated_as_managed(self):
        s = [{"id": rid_of("sa1"), "status": "detached"}]
        self.assertEqual(self.compare(s, live=[], exists=False), [])

    def test_deleted_resource_group_is_reported(self):
        rg_id = f"/subscriptions/{SUB}/resourceGroups/{RG}"
        drifts = self.compare([managed(rg_id)], live=[], exists=False)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["type"], "Microsoft.Resources/resourceGroups")
        self.assertEqual(drifts[0]["name"], RG)


class TestScopeHelpers(unittest.TestCase):
    def test_top_level_vs_child(self):
        self.assertTrue(_is_top_level(rid_of("sa1").lower()))
        self.assertFalse(_is_top_level((rid_of("sa1") + "/blobServices/default").lower()))

    def test_subscription_scan_sees_all_its_own_rgs(self):
        self.assertTrue(_in_scan_scope(rid_of("sa1", rg="other").lower(), "subscription", SUB, RG))

    def test_other_subscription_is_never_in_scope(self):
        foreign = rid_of("sa1").replace(SUB, "99999999-0000-0000-0000-000000000009").lower()
        self.assertFalse(_in_scan_scope(foreign, "subscription", SUB, RG))


class TestOwnershipAnnotation(unittest.TestCase):
    def drift(self, name, drift_type="extra_in_azure", details=None):
        return {"type": "Microsoft.Storage/storageAccounts", "name": name,
                "drift_type": drift_type, "details": details if details is not None else {}}

    def test_extras_are_tagged_managed_or_unmanaged(self):
        s = stack(resources=[managed(rid_of("owned"))])
        live = [{"id": rid_of("owned"), "type": "Microsoft.Storage/storageAccounts", "name": "owned"},
                {"id": rid_of("orphan"), "type": "Microsoft.Storage/storageAccounts", "name": "orphan"}]
        drifts = [self.drift("owned"), self.drift("orphan")]

        self.assertEqual(annotate_stack_ownership(drifts, s, live), 2)
        self.assertEqual(drifts[0]["details"]["stack_ownership"], "managed")
        self.assertEqual(drifts[1]["details"]["stack_ownership"], "unmanaged")

    def test_only_extras_are_tagged(self):
        s = stack(resources=[managed(rid_of("sa1"))])
        live = [{"id": rid_of("sa1"), "type": "Microsoft.Storage/storageAccounts", "name": "sa1"}]
        drifts = [self.drift("sa1", drift_type="missing_in_azure")]
        self.assertEqual(annotate_stack_ownership(drifts, s, live), 0)
        self.assertNotIn("stack_ownership", drifts[0]["details"])

    def test_unresolvable_id_is_left_untagged_not_called_an_orphan(self):
        s = stack(resources=[managed(rid_of("sa1"))])
        drifts = [self.drift("mystery-child")]
        self.assertEqual(annotate_stack_ownership(drifts, s, live_resources=[]), 0)
        self.assertNotIn("stack_ownership", drifts[0]["details"])

    def test_no_stack_means_no_annotation(self):
        drifts = [self.drift("sa1")]
        self.assertEqual(annotate_stack_ownership(drifts, None, []), 0)


class TestDedupe(unittest.TestCase):
    def test_drift_already_reported_by_the_template_compare_is_dropped(self):
        class RD:
            resource_type, resource_name = "Microsoft.Storage/storageAccounts", "sa1"

        stack_drifts = [
            {"type": "Microsoft.Storage/storageAccounts", "name": "sa1", "drift_type": "missing_in_azure"},
            {"type": "Microsoft.Storage/storageAccounts", "name": "sa2", "drift_type": "missing_in_azure"},
        ]
        kept = dedupe_against(stack_drifts, [RD()])
        self.assertEqual([d["name"] for d in kept], ["sa2"])


class TestManagedIds(unittest.TestCase):
    def test_ids_are_normalized_and_filtered_to_managed(self):
        s = stack(resources=[
            {"id": rid_of("SA1").upper(), "status": "managed"},
            {"id": rid_of("sa2"), "status": "detached"},
            {"status": "managed"},
        ])
        self.assertEqual(managed_ids(s), {rid_of("SA1").upper().lower()})


if __name__ == "__main__":
    unittest.main()


class TestOwnerRouting(unittest.TestCase):
    def test_stack_drift_routes_to_the_platform_team(self):
        """The stack is the IaC control plane: its deny settings are the platform
        team's to answer for, whatever workload it deploys."""
        from tools.ownership import classify_owner, PLATFORM
        self.assertEqual(classify_owner(STACK_TYPE), PLATFORM)
