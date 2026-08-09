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

from tools.ignore_patterns import IgnorePatternList
from tools.ownership import PLATFORM, WORKLOAD, classify_owner
from tools.rbac import (
    _declaration_discriminator,
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


def _remediation_grant(policy_assignment_name):
    """The exact shape from issue #351: a remediation grant whose only
    distinguishing argument is the policy assignment it belongs to."""
    return bicep_assignment(
        f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{CONTRIBUTOR}')]",
        "[reference(resourceId('Microsoft.Authorization/policyAssignments', "
        f"'{policy_assignment_name}'), '2022-06-01', 'full').identity.principalId]",
        name=(
            "[guid(resourceGroup().id, resourceId("
            "'Microsoft.Authorization/policyAssignments', "
            f"'{policy_assignment_name}'), '{CONTRIBUTOR}')]"
        ),
    )


class DeclarationDiscriminatorTests(unittest.TestCase):
    """The guid() arguments survive compilation even though the guid does not."""

    def test_picks_the_policy_assignment_out_of_the_expression(self):
        expr = ("[guid(resourceGroup().id, resourceId("
                "'Microsoft.Authorization/policyAssignments', 'drift-inherit-costcentre'), "
                f"'{CONTRIBUTOR}')]")
        self.assertEqual(_declaration_discriminator(expr), "drift-inherit-costcentre")

    def test_skips_arm_plumbing(self):
        # type string (has '/'), role GUID, and api-version are all noise.
        expr = (f"[guid('Microsoft.Authorization/policyAssignments', '{CONTRIBUTOR}', "
                "'2022-06-01', 'the-real-one')]")
        self.assertEqual(_declaration_discriminator(expr), "the-real-one")

    def test_no_literal_is_none_not_a_guess(self):
        self.assertIsNone(_declaration_discriminator("[guid(resourceGroup().id)]"))
        self.assertIsNone(_declaration_discriminator(""))


class CollidingRoleAssignmentNamesTests(unittest.TestCase):
    """Issue #351: two different declarations must not become one row twice.

    Both remediation grants carry an unresolvable principalId, so both used to
    render 'Contributor -> unresolved-principal' with the same synthetic
    resource_id - and both are privileged.
    """

    def _drifts(self):
        arm = [_remediation_grant("drift-inherit-costcentre"),
               _remediation_grant("drift-inherit-environment")]
        return compare_role_assignments(arm, [])

    def test_the_two_grants_are_distinguishable(self):
        drifts = self._drifts()
        self.assertEqual(len(drifts), 2)
        names = sorted(d["name"] for d in drifts)
        self.assertNotEqual(names[0], names[1])
        self.assertIn("drift-inherit-costcentre", names[0])
        self.assertIn("drift-inherit-environment", names[1])

    def test_the_synthetic_resource_id_no_longer_collides(self):
        # The id is built from the name (orchestration/attribution.py), so
        # distinct names are what stops both rows adopting one identity.
        drifts = self._drifts()
        ids = {f"/providers/{d['type']}/{d['name']}" for d in drifts}
        self.assertEqual(len(ids), 2)

    def test_the_declaration_is_recorded_for_the_reader(self):
        drifts = self._drifts()
        self.assertTrue(all("declared_as" in d["details"] for d in drifts))

    def test_both_remain_privileged_missing_grants(self):
        # Legibility fix only: detection and severity must not move.
        drifts = self._drifts()
        self.assertTrue(all(d["drift_type"] == "missing_in_azure" for d in drifts))
        self.assertTrue(all(d["details"]["privileged"] for d in drifts))

    def test_a_lone_unresolved_grant_keeps_todays_name(self):
        # No collision, no suffix - an unambiguous row gains no noise.
        drifts = compare_role_assignments([_remediation_grant("only-one")], [])
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["name"], "Contributor -> unresolved-principal")

    def test_collision_with_no_literal_still_separates(self):
        arm = [
            bicep_assignment(
                f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{CONTRIBUTOR}')]",
                "[reference('a').principalId]", name="[guid(resourceGroup().id)]"),
            bicep_assignment(
                f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{CONTRIBUTOR}')]",
                "[reference('b').principalId]", name="[guid(subscription().id)]"),
        ]
        names = [d["name"] for d in compare_role_assignments(arm, [])]
        self.assertEqual(len(set(names)), 2, f"still collapsed: {names}")

    def test_names_are_deterministic_across_runs(self):
        first = [d["name"] for d in self._drifts()]
        second = [d["name"] for d in self._drifts()]
        self.assertEqual(first, second)


class SeveralDeployedPrincipalsCollideTests(unittest.TestCase):
    """PR #299 taught Pass 2 to prefer a DEPLOYED principal over a deleted
    (orphaned) one. It cannot choose between several deployed ones.

    Live, 2026-08-02: the template declares two policy-remediation Contributors
    with `principalId: reference(...).identity.principalId` - unresolvable, so
    both match by role GUID alone. An out-of-band Contributor was then granted
    to id-drift-test, a THIRD deployed managed identity. Three live rows, two
    declarations, every principal deployed: Pass 2 paired two first-come-
    first-served and called the leftover extra_in_azure.

    The result was a false positive AND a false negative at once - it named a
    declared, pipeline-created assignment (acting on it revokes a role the tag
    policy needs) while the real privilege escalation went unreported.

    The disproof was already on the row we emit: `created_by` is the authorized
    deployer for the declared ones, and a human for the out-of-band grant.
    """

    PIPELINE = "8edd43ce-a6cb-4dad-a89a-5bb580ebf777"
    HUMAN = "someone@example.com"
    POLICY_MI_A = "8bf7baa2-8bc8-4947-9f84-d293452327c1"
    POLICY_MI_B = "d1ee1741-a799-4eba-a307-54a01bdfa4c6"
    WORKLOAD_MI = "1346f29e-771b-44e9-8493-b468164163f8"
    RG = f"/subscriptions/{SUB}/resourcegroups/rg-drift-test"

    def _declared_runtime_pair(self):
        # Both policy-remediation Contributors: role resolves, principal does not.
        role = (f"subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                f"'{CONTRIBUTOR}')")
        principal = ("reference(resourceId('Microsoft.Authorization/policyAssignments', "
                     "'drift-inherit-{}'), '2022-06-01', 'full').identity.principalId")
        return [
            bicep_assignment(role, principal.format("costcentre"),
                             name="[guid(resourceGroup().id, 'costcentre')]"),
            bicep_assignment(role, principal.format("environment"),
                             name="[guid(resourceGroup().id, 'environment')]"),
        ]

    def _live_three(self):
        # The out-of-band grant is listed FIRST on purpose: first-come-first-
        # served would consume it, so asserting on a favourable input order
        # would pass without the fix and prove nothing.
        return [
            live(CONTRIBUTOR, self.WORKLOAD_MI, self.RG, name="out-of-band",
                 created_by=self.HUMAN, created_on="2026-08-02T20:55:00Z",
                 role_name="Contributor"),
            live(CONTRIBUTOR, self.POLICY_MI_A, self.RG, name="declared-a",
                 created_by=self.PIPELINE, created_on="2026-08-02T20:01:39Z",
                 role_name="Contributor"),
            live(CONTRIBUTOR, self.POLICY_MI_B, self.RG, name="declared-b",
                 created_by=self.PIPELINE, created_on="2026-08-02T20:01:40Z",
                 role_name="Contributor"),
        ]

    def _all_deployed(self):
        return {self.WORKLOAD_MI, self.POLICY_MI_A, self.POLICY_MI_B}

    def test_the_out_of_band_grant_is_the_one_reported(self):
        drifts = compare_role_assignments(
            self._declared_runtime_pair(), self._live_three(),
            deployed_principals=self._all_deployed(),
            authorized_deployers={self.PIPELINE},
        )
        self.assertEqual(len(drifts), 1, f"expected exactly one extra, got {len(drifts)}")
        self.assertEqual(drifts[0]["details"]["principal_id"], self.WORKLOAD_MI,
                         "the real out-of-band grant must be the one flagged")

    def test_a_pipeline_created_assignment_is_never_called_extra(self):
        drifts = compare_role_assignments(
            self._declared_runtime_pair(), self._live_three(),
            deployed_principals=self._all_deployed(),
            authorized_deployers={self.PIPELINE},
        )
        flagged = {d["details"]["principal_id"] for d in drifts}
        self.assertNotIn(self.POLICY_MI_A, flagged,
                         "a declared, pipeline-created assignment was called unmanaged")
        self.assertNotIn(self.POLICY_MI_B, flagged)

    def test_the_privileged_flag_and_provenance_still_ride_along(self):
        # These two worked live and must not regress while fixing the binding.
        drifts = compare_role_assignments(
            self._declared_runtime_pair(), self._live_three(),
            deployed_principals=self._all_deployed(),
            authorized_deployers={self.PIPELINE},
        )
        self.assertTrue(drifts[0]["details"]["privileged"])
        self.assertEqual(drifts[0]["details"]["created_by"], self.HUMAN)

    def test_unset_authorized_deployers_preserves_existing_behaviour(self):
        # With nothing configured the new tier is inert: the result must be
        # whatever it is today, not an exception and not a changed shape.
        drifts = compare_role_assignments(
            self._declared_runtime_pair(), self._live_three(),
            deployed_principals=self._all_deployed(),
        )
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["drift_type"], "extra_in_azure")

    def test_pr299_orphan_preference_still_holds(self):
        # The deployed-vs-deleted tier must survive: one declaration, one
        # deployed principal, one orphan, no provenance to help.
        role = (f"subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                f"'{CONTRIBUTOR}')")
        arm = [bicep_assignment(role, "reference('x').outputs.principalId")]
        orphan = "c0630203-1b63-4b51-ba40-3d2d42c32bdc"
        azure = [live(CONTRIBUTOR, orphan, self.RG, name="orphan"),
                 live(CONTRIBUTOR, self.POLICY_MI_A, self.RG, name="declared")]
        drifts = compare_role_assignments(
            arm, azure, deployed_principals={self.POLICY_MI_A},
            authorized_deployers={self.PIPELINE},
        )
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["details"]["principal_id"], orphan)


class TheDeployerTierIsWiredIntoThePipelineTests(unittest.TestCase):
    """Every test above passes `authorized_deployers` by hand, which proves the
    comparator and NOT the wiring - deleting the kwarg from the call site in
    phase1._run_rbac_sidecar leaves them all green. Same trap the
    project has hit repeatedly, so this one drives the real step.
    """

    PIPELINE = "8edd43ce-a6cb-4dad-a89a-5bb580ebf777"

    def _call_step(self, env_value):
        import importlib
        from orchestration import phase1 as rdc

        captured = {}

        def fake_compare(arm, live, **kwargs):
            captured.update(kwargs)
            return []

        with mock.patch.dict(os.environ, {"DRIFT_AUTHORIZED_DEPLOYERS": env_value}), \
             mock.patch.object(rdc, "rbac_enabled", return_value=True), \
             mock.patch.object(rdc, "fetch_role_assignments", return_value=[]), \
             mock.patch.object(rdc, "collect_managed_identity_principals", return_value=set()), \
             mock.patch.object(rdc, "compare_role_assignments", side_effect=fake_compare):
            # tools.config reads the env var at import time, so reload it inside
            # the patched environment or this asserts on a stale frozenset.
            import tools.config
            importlib.reload(tools.config)
            # A real IgnorePatternList, not []: the sidecar's log-and-skip would
            # otherwise swallow an AttributeError AFTER the call we assert on,
            # and the test would pass through a broken step.
            rdc._run_rbac_sidecar([], [], "rg", "resource_group",
                                  IgnorePatternList(), [])
        return captured

    def test_the_configured_deployer_reaches_the_comparator(self):
        captured = self._call_step(self.PIPELINE)
        self.assertIn("authorized_deployers", captured,
                      "the comparator was called without the deployer tier")
        self.assertIn(self.PIPELINE, {str(x).lower() for x in captured["authorized_deployers"]})

    def test_unconfigured_passes_an_empty_set_not_a_crash(self):
        captured = self._call_step("")
        self.assertEqual(set(captured.get("authorized_deployers") or set()), set())
