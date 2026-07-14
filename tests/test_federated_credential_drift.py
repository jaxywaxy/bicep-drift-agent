"""
Federated identity credential trust-boundary drift is CRITICAL.

Repointing a federated credential's subject or issuer lets a different external
repo/branch/IdP mint tokens as the managed identity - a persistence / supply-
chain escalation. Live round: the subject repoint (jaxywaxy -> evil-fork) was
detected correctly but rated only 'warning'; subject/issuer are now critical.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator


FED_TYPE = "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"


def _cred(subject, issuer="https://token.actions.githubusercontent.com"):
    return {
        "type": FED_TYPE,
        "name": "id-drift-test/github-main",
        "properties": {
            "issuer": issuer,
            "subject": subject,
            "audiences": ["api://AzureADTokenExchange"],
        },
    }


class FederatedCredentialDriftTests(unittest.TestCase):
    def test_subject_repoint_is_critical(self):
        bicep = _cred("repo:jaxywaxy/drift-test-resources:ref:refs/heads/main")
        live = _cred("repo:evil-fork/drift-test-resources:ref:refs/heads/main")
        diffs = [d for d in PropertyComparator.compare_properties(bicep, live)
                 if d.property_path == "properties.subject"]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].severity, "critical")

    def test_issuer_change_is_critical(self):
        bicep = _cred("repo:jaxywaxy/drift-test-resources:ref:refs/heads/main")
        live = _cred("repo:jaxywaxy/drift-test-resources:ref:refs/heads/main",
                     issuer="https://evil-idp.example.com")
        diffs = [d for d in PropertyComparator.compare_properties(bicep, live)
                 if d.property_path == "properties.issuer"]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].severity, "critical")

    def test_identical_credential_no_drift(self):
        cred = _cred("repo:jaxywaxy/drift-test-resources:ref:refs/heads/main")
        paths = [d.property_path for d in PropertyComparator.compare_properties(cred, cred)]
        self.assertNotIn("properties.subject", paths)
        self.assertNotIn("properties.issuer", paths)

    def test_subject_severity_via_get_severity(self):
        self.assertEqual(PropertyComparator._get_severity("properties.subject"), "critical")
        self.assertEqual(PropertyComparator._get_severity("properties.issuer"), "critical")

    def test_eventgrid_filter_subject_not_falsely_critical(self):
        # EG subscriptions use filter.subjectBeginsWith - must NOT collide with
        # the bare properties.subject critical rule.
        self.assertEqual(
            PropertyComparator._get_severity("properties.filter.subjectbeginswith"),
            "warning",
        )
        self.assertEqual(
            PropertyComparator._get_severity("properties.oidcissuerprofile.issuerurl"),
            "warning",
        )


if __name__ == "__main__":
    unittest.main()
