"""
Unit tests for authorized-deployer attribution.

Changes made by the pipeline identity that deploys the estate (or any
DRIFT_AUTHORIZED_DEPLOYERS-configured identity) were classified as
"Manual change (unauthorized)" - the tool labelled its own CI as an attacker.
authorized_deployment fixes the ATTRIBUTION only: expected stays False so the
drift itself remains in the actionable set (a pipeline-created orphan is
still drift).

Also covers detect_scanning_identity(): the deployer SP is DISCOVERED from
the scan's own token claims, never hardcoded - the tool is used at many
clients with different deployer identities.
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.activity_log import detect_scanning_identity
from tools.change_origin import (
    classify_change_origin,
    build_resource_lifecycle,
    ChangeOrigin,
    ChangeCategory,
    ChangeSeverity,
)

DEPLOYER_OID = "ef83bff1-c6c1-4cb1-84be-9bd758e8fc41"


def _log(operation, caller=DEPLOYER_OID, properties=None):
    return [{
        "timestamp": "2026-07-16T21:14:43Z",
        "operation": operation,
        "caller": caller,
        "status": "Succeeded",
        "properties": properties or {},
    }]


class ClassifyAuthorizedDeployerTests(unittest.TestCase):

    def test_deployer_caller_is_authorized_deployment(self):
        info = classify_change_origin(
            _log("microsoft.storage/storageaccounts/write"),
            authorized_deployers={DEPLOYER_OID},
        )
        self.assertEqual(info.origin, ChangeOrigin.AUTHORIZED_DEPLOYMENT)
        self.assertEqual(info.category, ChangeCategory.AUTHORIZED)
        self.assertEqual(info.severity, ChangeSeverity.LOW)

    def test_deployer_drift_stays_actionable(self):
        # expected=False keeps the drift OUT of policy_enforced_drifts - a
        # pipeline-created orphan is still drift; only attribution changes.
        info = classify_change_origin(
            _log("microsoft.authorization/roleassignments/write"),
            authorized_deployers={DEPLOYER_OID},
        )
        self.assertFalse(info.expected)

    def test_without_deployer_set_same_caller_is_manual(self):
        # Pre-existing behavior is unchanged when no deployer set is passed.
        info = classify_change_origin(_log("microsoft.storage/storageaccounts/write"))
        self.assertEqual(info.origin, ChangeOrigin.MANUAL_CHANGE)
        self.assertEqual(info.category, ChangeCategory.OUT_OF_BAND)

    def test_manual_reason_is_out_of_band_not_unauthorized(self):
        # "unauthorized" reads as an accusation - out-of-band is the neutral,
        # accurate term (the change bypassed the pipeline; the actor may well
        # have had every right to make it).
        info = classify_change_origin(_log("microsoft.storage/storageaccounts/write"))
        self.assertIn("out-of-band", info.reason)
        self.assertNotIn("unauthorized", info.reason)

    def test_manual_reason_omits_via_clause_when_method_unknown(self):
        # method is null/Unknown on most manual edits; the reason must not
        # render "via None" / "via Unknown".
        info = classify_change_origin(_log("microsoft.storage/storageaccounts/write"))
        for noise in ("via None", "via Unknown", " via "):
            self.assertNotIn(noise, info.reason)

    def test_manual_reason_includes_method_when_known(self):
        log = _log("microsoft.storage/storageaccounts/write")
        log[0]["method"] = "Portal"
        info = classify_change_origin(log)
        self.assertIn("via Portal", info.reason)

    def test_non_deployer_caller_still_manual(self):
        info = classify_change_origin(
            _log("microsoft.storage/storageaccounts/write", caller="jane@corp.com"),
            authorized_deployers={DEPLOYER_OID},
        )
        self.assertEqual(info.origin, ChangeOrigin.MANUAL_CHANGE)

    def test_policy_msi_wins_over_deployer_allowlist(self):
        # A policy MSI in BOTH sets must stay policy-attributed (expected=True,
        # split to the policy-enforced section), not become a deployment.
        msi = "4ba5674e-b9e7-46c1-9945-329f529f4512"
        info = classify_change_origin(
            _log("microsoft.authorization/locks/write", caller=msi),
            policy_principal_ids={msi: "DINE lock"},
            authorized_deployers={msi},
        )
        self.assertTrue(info.expected)
        self.assertNotEqual(info.origin, ChangeOrigin.AUTHORIZED_DEPLOYMENT)

    def test_lifecycle_events_attributed_to_deployer(self):
        lifecycle = build_resource_lifecycle(
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1",
            _log("microsoft.storage/storageaccounts/write"),
            authorized_deployers={DEPLOYER_OID},
        )
        self.assertEqual(len(lifecycle.events), 1)
        event = lifecycle.events[0]
        self.assertEqual(event.origin, ChangeOrigin.AUTHORIZED_DEPLOYMENT)
        self.assertIn("authorized pipeline identity", event.reason)
        self.assertNotIn("Manual change", event.reason)


class _FakeToken:
    def __init__(self, token):
        self.token = token


class _FakeCredential:
    def __init__(self, claims):
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        self._token = f"eyJhbGciOiJSUzI1NiJ9.{payload}.fakesig"

    def get_token(self, *scopes):
        return _FakeToken(self._token)


class DetectScanningIdentityTests(unittest.TestCase):

    def test_service_principal_aliases_from_token_claims(self):
        cred = _FakeCredential({
            "oid": DEPLOYER_OID.upper(),  # claims may be any case
            "appid": "BCFC3973-F472-4B19-B850-749AF958B7A9",
        })
        aliases = detect_scanning_identity(credential=cred)
        # Both the object id (Activity Log caller for SPs) and appId, lowercased.
        self.assertIn(DEPLOYER_OID, aliases)
        self.assertIn("bcfc3973-f472-4b19-b850-749af958b7a9", aliases)

    def test_user_login_aliases_include_upn(self):
        cred = _FakeCredential({"oid": "abc-123", "upn": "Jacqui@Example.com"})
        aliases = detect_scanning_identity(credential=cred)
        self.assertIn("jacqui@example.com", aliases)

    def test_failure_returns_empty_set_never_raises(self):
        class _Broken:
            def get_token(self, *scopes):
                raise RuntimeError("no credential available")
        self.assertEqual(detect_scanning_identity(credential=_Broken()), set())

    def test_garbage_token_returns_empty_set(self):
        class _GarbageCred:
            def get_token(self, *scopes):
                return _FakeToken("not-a-jwt")
        self.assertEqual(detect_scanning_identity(credential=_GarbageCred()), set())


class ReportBadgeTests(unittest.TestCase):

    def test_authorized_deployment_gets_pipeline_badge(self):
        from tools.html_report import _get_origin_badge
        badge = _get_origin_badge({"origin": "authorized_deployment"})
        self.assertIn("🚀 Pipeline", badge)
        self.assertNotIn("Manual", badge)


class ConfigAllowlistTests(unittest.TestCase):

    def test_env_allowlist_parsed_lowercased(self):
        import importlib
        os.environ["DRIFT_AUTHORIZED_DEPLOYERS"] = " EF83BFF1-AAAA , deploy@corp.com ,,"
        try:
            import tools.config as config
            importlib.reload(config)
            self.assertEqual(
                config.AUTHORIZED_DEPLOYERS,
                frozenset({"ef83bff1-aaaa", "deploy@corp.com"}),
            )
        finally:
            del os.environ["DRIFT_AUTHORIZED_DEPLOYERS"]
            importlib.reload(config)

    def test_env_absent_gives_empty_set(self):
        import importlib
        os.environ.pop("DRIFT_AUTHORIZED_DEPLOYERS", None)
        import tools.config as config
        importlib.reload(config)
        self.assertEqual(config.AUTHORIZED_DEPLOYERS, frozenset())


if __name__ == "__main__":
    unittest.main()
