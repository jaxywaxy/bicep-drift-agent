"""A provider failure in the eval runner must say WHICH provider and WHY.

Twice in one session, running `python3 -m evals.run` without
`DRIFT_LLM_PROVIDER` set produced:

    PROVIDER ERROR (TypeError): "Could not resolve authentication method..."

which names neither the provider that failed nor the reason. It was Anthropic's
SDK complaining about a missing key while the operator believed they were
talking to Azure - they had set GitHub repo VARIABLES, which exist only inside
Actions and are invisible to a local shell.

The pipeline already turns these into plain language via each provider's
`explain_error`. The runner was throwing that away.
"""

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import evals.run as runner


class _Boom:
    name = "anthropic"
    default_model = "m"

    @staticmethod
    def explain_error(exc):
        return "ANTHROPIC_API_KEY is invalid or revoked"


class ProviderFailuresAreExplainedTests(unittest.TestCase):

    def _run(self):
        buf = io.StringIO()
        with mock.patch.object(runner, "_analyse",
                               side_effect=TypeError("Could not resolve authentication method")), \
             mock.patch.object(runner, "_current_provider", return_value=_Boom()), \
             redirect_stdout(buf):
            runner.main(["--fixture", "nothing_attributed"])
        return buf.getvalue()

    def test_it_names_the_provider_actually_used(self):
        out = self._run()
        self.assertIn("anthropic", out,
                      "the operator could not tell which provider failed")

    def test_it_gives_the_plain_language_cause(self):
        self.assertIn("ANTHROPIC_API_KEY", self._run())

    def test_it_still_shows_the_raw_error_for_anything_unexplained(self):
        buf = io.StringIO()

        class Silent:
            name = "azure_openai"
            default_model = "m"
            @staticmethod
            def explain_error(exc):
                return None

        with mock.patch.object(runner, "_analyse", side_effect=RuntimeError("connection reset")), \
             mock.patch.object(runner, "_current_provider", return_value=Silent()), \
             redirect_stdout(buf):
            runner.main(["--fixture", "nothing_attributed"])
        out = buf.getvalue()
        self.assertIn("connection reset", out, "an unexplained error must not be swallowed")
        self.assertIn("azure_openai", out)


if __name__ == "__main__":
    unittest.main()
