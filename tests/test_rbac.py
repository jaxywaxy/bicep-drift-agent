"""
Unit tests for RBAC role-assignment drift detection (tools/rbac.py).

Role assignments match on IDENTITY (role GUID + principalId + scope), never on
resource name - names are guid(...) expressions in bicep and random GUIDs live.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ownership import PLATFORM, WORKLOAD, classify_owner
from tools.rbac import (
    _extract_guid,
    _scope_rg,
    _scope_target_type,
    compare_role_assignments,
    extract_bicep_role_assignments,
    filter_assignments_to_scope,
    rbac_enabled,
)

SUB = "00000000-0000-0000-0000-000000000001"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
BLOB_READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"


def live(role_guid, principal, scope, name="a1", principal_type="ServicePrincipal",
         created_by=None, created_on=None, role_name="SomeRole"):
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
        "name": name,
        "scope": scope,
        "role_guid": role_guid,
        "role_name": role_name,
        "principal_id": principal.lower(),
        "principal_type": principal_type,
        "created_on": created_on,
        "created_by": created_by,
        "condition": None,
        "description": None,
    }


def bicep_assignment(role_def_id, principal, scope=None, name="[guid(resourceGroup().id)]"):
    r = {
        "type": "Microsoft.Authorization/roleAssignments",
        "name": name,
        "properties": {"roleDefinitionId": role_def_id, "principalId": principal},
    }
    if scope is not None:
        r["scope"] = scope
    return r


class GuidExtractionTests(unittest.TestCase):
    def test_extracts_from_unresolved_expression(self):
        expr = f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{CONTRIBUTOR}')]"
        self.assertEqual(_extract_guid(expr), CONTRIBUTOR)

    def test_extracts_from_full_arm_id(self):
        full = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{READER}"
        self.assertEqual(_extract_guid(full), READER)

    def test_bare_guid_and_case_normalization(self):
        self.assertEqual(_extract_guid(CONTRIBUTOR.upper()), CONTRIBUTOR)

    def test_no_guid_returns_none(self):
        self.assertIsNone(_extract_guid("[parameters('customRoleId')]"))
        self.assertIsNone(_extract_guid(None))

    def test_variable_based_role_def_id_resolved_by_normalizer(self):
        # Regression: roleDefinitionId built with variables()/parameters() hides
        # the GUID (subscriptionResourceId(..., variables('roleId'))) so _extract_guid
        # returned None and the declared assignment matched nothing -> live one
        # became a false extra. The normalizer now resolves the embedded variable;
        # feeding its output, the GUID is recovered.
        from tools.normalizer import _eval_embedded_refs
        raw = "subscriptionResourceId('Microsoft.Authorization/roleDefinitions', variables('roleId'))"
        resolved = _eval_embedded_refs(raw, {}, {"roleId": READER})
        self.assertEqual(_extract_guid(resolved), READER)


class ScopeParsingTests(unittest.TestCase):
    def test_scope_rg(self):
        self.assertEqual(_scope_rg(f"/subscriptions/{SUB}/resourceGroups/rg-app"), "rg-app")
        self.assertIsNone(_scope_rg(f"/subscriptions/{SUB}"))

    def test_scope_target_type(self):
        s = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1"
        self.assertEqual(_scope_target_type(s), "Microsoft.Network/virtualNetworks")
        self.assertIsNone(_scope_target_type(f"/subscriptions/{SUB}/resourceGroups/rg"))

    def test_management_group_scope_has_no_target_type(self):
        s = "/providers/Microsoft.Management/managementGroups/landingzones"
        self.assertIsNone(_scope_target_type(s))


class ScopeFilterTests(unittest.TestCase):
    def _assignments(self):
        return [
            live(READER, "p1", f"/subscriptions/{SUB}"),                                    # sub-level
            live(READER, "p2", f"/subscriptions/{SUB}/resourceGroups/rg-app"),              # RG-level
            live(READER, "p3", f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/st1"),
            live(READER, "p4", f"/subscriptions/{SUB}/resourceGroups/rg-other"),
            live(READER, "p5", "/providers/Microsoft.Management/managementGroups/lz"),      # MG-level
            live(READER, "p6", "/subscriptions/ffffffff-0000-0000-0000-000000000000"),      # other sub
        ]

    def test_rg_scan_keeps_only_that_rg_and_below(self):
        kept = filter_assignments_to_scope(self._assignments(), SUB, "rg-app", "resource_group")
        self.assertEqual({a["principal_id"] for a in kept}, {"p2", "p3"})

    def test_rg_scan_excludes_inherited_sub_level(self):
        kept = filter_assignments_to_scope(self._assignments(), SUB, "rg-app", "resource_group")
        self.assertNotIn("p1", {a["principal_id"] for a in kept})

    def test_sub_scan_wildcard_keeps_sub_and_all_rgs(self):
        kept = filter_assignments_to_scope(self._assignments(), SUB, "*", "subscription")
        self.assertEqual({a["principal_id"] for a in kept}, {"p1", "p2", "p3", "p4"})

    def test_sub_scan_glob_filters_rgs_but_keeps_sub_level(self):
        kept = filter_assignments_to_scope(self._assignments(), SUB, "rg-app*", "subscription")
        self.assertEqual({a["principal_id"] for a in kept}, {"p1", "p2", "p3"})

    def test_mg_and_foreign_sub_always_excluded(self):
        kept = filter_assignments_to_scope(self._assignments(), SUB, "*", "subscription")
        self.assertNotIn("p5", {a["principal_id"] for a in kept})
        self.assertNotIn("p6", {a["principal_id"] for a in kept})


class BicepExtractionTests(unittest.TestCase):
    def test_extracts_role_guid_and_literal_principal(self):
        arm = [bicep_assignment(
            f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{CONTRIBUTOR}')]",
            "11111111-1111-1111-1111-111111111111",
        )]
        extracted, skipped = extract_bicep_role_assignments(arm)
        self.assertEqual(skipped, 0)
        self.assertEqual(extracted[0]["role_guid"], CONTRIBUTOR)
        self.assertEqual(extracted[0]["principal_id"], "11111111-1111-1111-1111-111111111111")

    def test_runtime_principal_is_none(self):
        arm = [bicep_assignment(CONTRIBUTOR, "[reference(resourceId('Microsoft.Web/sites', 'app')).identity.principalId]")]
        extracted, _ = extract_bicep_role_assignments(arm)
        self.assertIsNone(extracted[0]["principal_id"])

    def test_unresolvable_role_id_is_skipped_not_drifted(self):
        arm = [bicep_assignment("[parameters('customRoleDefinitionId')]", "p")]
        extracted, skipped = extract_bicep_role_assignments(arm)
        self.assertEqual(extracted, [])
        self.assertEqual(skipped, 1)

    def test_non_assignment_resources_ignored(self):
        extracted, skipped = extract_bicep_role_assignments(
            [{"type": "Microsoft.Storage/storageAccounts", "name": "st1", "properties": {}}]
        )
        self.assertEqual((extracted, skipped), ([], 0))


class CompareTests(unittest.TestCase):
    def test_exact_identity_match_produces_no_drift(self):
        principal = "11111111-1111-1111-1111-111111111111"
        arm = [bicep_assignment(CONTRIBUTOR, principal)]
        azure = [live(CONTRIBUTOR, principal, f"/subscriptions/{SUB}/resourceGroups/rg")]
        self.assertEqual(compare_role_assignments(arm, azure), [])

    def test_runtime_principal_matches_by_role_guid(self):
        arm = [bicep_assignment(BLOB_READER, "[reference('...').principalId]")]
        azure = [live(BLOB_READER, "some-msi-principal", f"/subscriptions/{SUB}/resourceGroups/rg")]
        self.assertEqual(compare_role_assignments(arm, azure), [])

    def test_exact_matches_claim_before_runtime_fallback(self):
        # One resolved-principal binding and one runtime binding share a role.
        # The resolved one must claim ITS live row, leaving the other for the
        # runtime binding - order of the pools must not steal the exact match.
        p_literal = "22222222-2222-2222-2222-222222222222"
        arm = [
            bicep_assignment(READER, "[reference('...').principalId]"),
            bicep_assignment(READER, p_literal),
        ]
        azure = [
            live(READER, p_literal, f"/subscriptions/{SUB}/resourceGroups/rg", name="lit"),
            live(READER, "33333333-3333-3333-3333-333333333333", f"/subscriptions/{SUB}/resourceGroups/rg", name="msi"),
        ]
        self.assertEqual(compare_role_assignments(arm, azure), [])

    def test_unmatched_live_is_extra_with_provenance(self):
        azure = [live(
            CONTRIBUTOR, "44444444-4444-4444-4444-444444444444",
            f"/subscriptions/{SUB}", principal_type="User",
            created_by="55555555-5555-5555-5555-555555555555",
            created_on="2026-07-01T10:00:00Z", role_name="Contributor",
        )]
        drifts = compare_role_assignments([], azure)
        self.assertEqual(len(drifts), 1)
        d = drifts[0]
        self.assertEqual(d["drift_type"], "extra_in_azure")
        self.assertEqual(d["type"], "Microsoft.Authorization/roleAssignments")
        self.assertIn("Contributor", d["name"])
        self.assertTrue(d["details"]["privileged"])
        self.assertEqual(d["details"]["created_by"], "55555555-5555-5555-5555-555555555555")

    def test_reader_extra_is_not_privileged(self):
        azure = [live(READER, "p", f"/subscriptions/{SUB}", role_name="Reader")]
        drifts = compare_role_assignments([], azure)
        self.assertFalse(drifts[0]["details"]["privileged"])

    def test_unmatched_bicep_is_missing(self):
        arm = [bicep_assignment(CONTRIBUTOR, "66666666-6666-6666-6666-666666666666")]
        drifts = compare_role_assignments(arm, [])
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "missing_in_azure")
        self.assertIn("Contributor", drifts[0]["name"])

    def test_same_role_twice_needs_two_live_rows(self):
        # Two runtime-principal bindings of the same role must consume two live
        # assignments - not double-match the same one.
        arm = [
            bicep_assignment(BLOB_READER, "[reference('a').principalId]"),
            bicep_assignment(BLOB_READER, "[reference('b').principalId]"),
        ]
        azure = [live(BLOB_READER, "p1", f"/subscriptions/{SUB}/resourceGroups/rg", name="x")]
        drifts = compare_role_assignments(arm, azure)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "missing_in_azure")

    def test_no_assignments_no_drift(self):
        self.assertEqual(compare_role_assignments([], []), [])


class OwnershipTests(unittest.TestCase):
    def _drift(self, scope):
        return {"details": {"scope": scope}}

    def test_subscription_scope_is_platform(self):
        d = self._drift(f"/subscriptions/{SUB}")
        self.assertEqual(classify_owner("Microsoft.Authorization/roleAssignments", d), PLATFORM)

    def test_rg_scope_is_workload(self):
        d = self._drift(f"/subscriptions/{SUB}/resourceGroups/rg-app")
        self.assertEqual(classify_owner("Microsoft.Authorization/roleAssignments", d), WORKLOAD)

    def test_grant_on_platform_fabric_is_platform(self):
        d = self._drift(f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1")
        self.assertEqual(classify_owner("Microsoft.Authorization/roleAssignments", d), PLATFORM)

    def test_grant_on_workload_resource_is_workload(self):
        d = self._drift(f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1")
        self.assertEqual(classify_owner("Microsoft.Authorization/roleAssignments", d), WORKLOAD)


class EnabledFlagTests(unittest.TestCase):
    def test_default_on(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(rbac_enabled())

    def test_disabled_by_env(self):
        for v in ("false", "0", "no", "OFF"):
            with mock.patch.dict(os.environ, {"INCLUDE_ROLE_ASSIGNMENTS": v}):
                self.assertFalse(rbac_enabled())


class NotificationDetailTests(unittest.TestCase):
    def test_rbac_extra_event_carries_grantor(self):
        from tools.send_notifications import _event_from_drift
        drift = {
            "type": "Microsoft.Authorization/roleAssignments",
            "name": "Contributor -> User:4444",
            "drift_type": "extra_in_azure",
            "details": {
                "role_name": "Contributor",
                "scope": f"/subscriptions/{SUB}",
                "privileged": True,
                "created_by": "5555",
                "created_on": "2026-07-01T10:00:00Z",
            },
        }
        event = _event_from_drift(drift)
        self.assertIn("PRIVILEGED", event.details)
        self.assertIn("granted by 5555", event.details)
        self.assertIn("2026-07-01", event.details)

    def test_plain_extra_event_unchanged(self):
        from tools.send_notifications import _event_from_drift
        drift = {"type": "t", "name": "n", "drift_type": "extra_in_azure", "details": {}}
        self.assertEqual(_event_from_drift(drift).details, "deployed but not in Bicep")


if __name__ == "__main__":
    unittest.main()


class RuntimePrincipalPreferenceTests(unittest.TestCase):
    """A bicep role assignment whose principalId is a runtime expression
    (reference(<identity>).outputs.principalId) can only match by role GUID.
    When an orphaned assignment to the same role exists - a prior deploy's
    identity, since deleted - Pass 2 must prefer the CURRENTLY-deployed
    identity's assignment, so the declared grant matches and the orphan flags,
    not the reverse (a false positive seen live on the Monitoring Reader grant).
    """

    MON_READER = "43d0d8ad-25c7-4714-9337-8ba259a9fe05"
    DEPLOYED = "4968cb6f-660a-4417-815c-a18971ea52f1"
    ORPHAN = "c0630203-1b63-4b51-ba40-3d2d42c32bdc"
    RG = f"/subscriptions/{SUB}/resourcegroups/rg-drift-test"

    def _bicep_runtime(self):
        # principalId is an unresolved module output; role id resolves to a GUID.
        return [bicep_assignment(
            f"subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{self.MON_READER}')",
            "reference(resourceId('Microsoft.Resources/deployments', 'deploy-identity'), "
            "'2025-04-01').outputs.principalId.value",
        )]

    def test_prefers_deployed_identity_flags_orphan(self):
        azure = [live(self.MON_READER, self.ORPHAN, self.RG, name="orphan"),
                 live(self.MON_READER, self.DEPLOYED, self.RG, name="declared")]
        drifts = compare_role_assignments(
            self._bicep_runtime(), azure, deployed_principals={self.DEPLOYED},
        )
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "extra_in_azure")
        self.assertEqual(drifts[0]["details"]["principal_id"], self.ORPHAN)

    def test_declared_grant_alone_is_clean(self):
        azure = [live(self.MON_READER, self.DEPLOYED, self.RG)]
        drifts = compare_role_assignments(
            self._bicep_runtime(), azure, deployed_principals={self.DEPLOYED},
        )
        self.assertEqual(drifts, [])

    def test_without_hint_falls_back_to_role_only(self):
        # No deployed-principal set: still matches ONE (best-effort), never both.
        azure = [live(self.MON_READER, self.ORPHAN, self.RG, name="a"),
                 live(self.MON_READER, self.DEPLOYED, self.RG, name="b")]
        drifts = compare_role_assignments(self._bicep_runtime(), azure)
        self.assertEqual(len(drifts), 1)

    def test_collect_managed_identity_principals(self):
        from tools.rbac import collect_managed_identity_principals
        live_resources = [
            {"type": "microsoft.managedidentity/userassignedidentities",
             "name": "id-x", "properties": {"principalId": self.DEPLOYED.upper()}},
            {"type": "microsoft.storage/storageaccounts", "name": "st",
             "identity": {"principalId": "AAAA-SYS"}, "properties": {}},
        ]
        got = collect_managed_identity_principals(live_resources)
        self.assertIn(self.DEPLOYED, got)          # lowercased
        self.assertIn("aaaa-sys", got)             # system-assigned too
