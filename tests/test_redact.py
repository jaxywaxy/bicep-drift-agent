import unittest

from tools.redact import redact_secrets, REDACTED


class TestRedactSecrets(unittest.TestCase):
    def test_redacts_admin_login_password(self):
        res = {
            "name": "sql-prod",
            "properties": {"administratorLoginPassword": "P@ssw0rd!", "version": "12.0"},
        }
        out = redact_secrets(res)
        self.assertEqual(out["properties"]["administratorLoginPassword"], REDACTED)
        self.assertEqual(out["properties"]["version"], "12.0")

    def test_redacts_by_suffix(self):
        out = redact_secrets({"runtimeADUserPassword": "x", "storageConnectionString": "y"})
        self.assertEqual(out["runtimeADUserPassword"], REDACTED)
        self.assertEqual(out["storageConnectionString"], REDACTED)

    def test_preserves_none(self):
        # Azure returns null for write-only props; a null is not a leaked secret.
        out = redact_secrets({"publishingPassword": None})
        self.assertIsNone(out["publishingPassword"])

    def test_does_not_over_redact_benign_keys(self):
        # Contains "password" but is a bool flag, not a secret value.
        out = redact_secrets({"disablePasswordAuthentication": True})
        self.assertIs(out["disablePasswordAuthentication"], True)

    def test_recurses_lists_and_nested(self):
        data = {"items": [{"clientSecret": "abc"}, {"name": "ok"}]}
        out = redact_secrets(data)
        self.assertEqual(out["items"][0]["clientSecret"], REDACTED)
        self.assertEqual(out["items"][1]["name"], "ok")

    def test_does_not_mutate_input(self):
        original = {"password": "secret"}
        redact_secrets(original)
        self.assertEqual(original["password"], "secret")

    def test_case_insensitive_key_match(self):
        out = redact_secrets({"AdminPassword": "x"})
        self.assertEqual(out["AdminPassword"], REDACTED)


if __name__ == "__main__":
    unittest.main()
