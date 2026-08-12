"""
Every tunable the CODE reads must reach a CI scan.

`DRIFT_MODEL_PRICING` shipped as config, was documented as a repo variable, was
SET as a repo variable - and did nothing, because no workflow passed it to the
scan step. The cost line read "unknown" for a day and looked like the documented
"no price for this model" behaviour rather than a plumbing hole.

Auditing instead of fixing the one found six more in the same state, including
all three sidecar disable switches: a client wanting RBAC scanning off had no
way to do it through the workflow.

This is the same family as the DEAD `platform_types` parameter - documented in a
comment as the escape hatch, never passed by its only call site. A knob that
cannot be turned is worse than no knob, because the documentation says otherwise.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/drift-check-lz-hybrid.yml"

# Read from the environment by the scan itself. Secrets and values the workflow
# synthesises (DRIFT_NOTIFICATIONS, WEBHOOK_SECRETS) are covered too - they are
# equally useless if unplumbed.
# AZURE_* included after two Azure OpenAI variables were found documented
# and unplumbed - the first version of this guard could not see them,
# which is the same class of blind spot it exists to prevent.
_NAME = r"(DRIFT_[A-Z_]+|INCLUDE_[A-Z_]+|AZURE_[A-Z_]+|ARM_PARAMETERS)"
_ENV_READ = (
    # os.environ.get("DRIFT_X") / os.environ["DRIFT_X"]
    re.compile(r"""environ(?:\.get)?[\(\[]["']""" + _NAME + r"""["']"""),
    # ..._ENV = "DRIFT_X", then os.environ.get(THAT_CONSTANT). The variable that
    # exposed this whole hole is declared exactly that way, and a scanner that
    # only matched the literal call missed it.
    re.compile(r"""^[A-Z][A-Z0-9_]*ENV\s*=\s*["']""" + _NAME + r"""["']""", re.M),
)


#: Read by the code and deliberately NOT reachable from the production scan
#: workflow. This is the one legitimate reason to be unplumbed, and it is the
#: opposite of the hole this file guards: these switch on record/replay, and a
#: production scan that could be talked into recording would write a client's
#: raw ARM payloads into a CI artifact. Recording is a developer action against
#: a verification estate, run locally or from the fixture-recording workflow.
#: Adding a name here needs the same argument - "it is inconvenient to plumb"
#: is not one.
_DELIBERATELY_NOT_IN_THE_SCAN_WORKFLOW = frozenset(
    {"DRIFT_RECORD_CASSETTE", "DRIFT_REPLAY_CASSETTE", "DRIFT_CASSETTE_NOTE",
     "DRIFT_CASSETTE_MAX_BYTES", "DRIFT_CASSETTE_BUDGET_BYTES"}
)


def _env_vars_the_code_reads() -> dict[str, str]:
    found: dict[str, str] = {}
    for sub in ("tools", "agent", "orchestration"):
        for path in sorted((ROOT / sub).rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for pattern in _ENV_READ:
                for m in pattern.finditer(text):
                    found.setdefault(m.group(1), str(path.relative_to(ROOT)))
    for path in sorted(ROOT.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in _ENV_READ:
            for m in pattern.finditer(text):
                found.setdefault(m.group(1), path.name)
    return found


class WorkflowPassesEveryTunableTests(unittest.TestCase):
    def test_the_scanner_finds_the_known_variables(self):
        # Guards the guard: a broken regex would make every assertion below pass
        # vacuously, which is how the original hole survived.
        names = _env_vars_the_code_reads()
        self.assertIn("DRIFT_MODEL_PRICING", names)
        self.assertIn("INCLUDE_ROLE_ASSIGNMENTS", names)
        self.assertIn("AZURE_OPENAI_TOKEN_SCOPE", names)
        self.assertGreater(len(names), 8, f"only found {sorted(names)}")

    def test_every_env_var_the_code_reads_is_passed_by_the_workflow(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        missing = {v: src for v, src in _env_vars_the_code_reads().items()
                   if v not in workflow
                   and v not in _DELIBERATELY_NOT_IN_THE_SCAN_WORKFLOW}
        self.assertEqual(
            missing, {},
            "these are read by the code but never reach a CI scan, so setting "
            f"them changes nothing: {missing}")

    def test_the_exemptions_are_still_absent_from_the_scan_workflow(self):
        # Guards the exemption, not the rule. If a cassette variable ever DOES
        # appear in the production scan workflow, that is a scan which can be
        # made to write raw ARM payloads to a CI artifact, and it must fail here
        # rather than be quietly covered by the allowance above.
        workflow = WORKFLOW.read_text(encoding="utf-8")
        leaked = sorted(v for v in _DELIBERATELY_NOT_IN_THE_SCAN_WORKFLOW
                        if v in workflow)
        self.assertEqual(
            leaked, [],
            f"record/replay must not be reachable from a production scan: {leaked}")


class EmptyEnvIsUnsetTests(unittest.TestCase):
    """An unset repo variable arrives as "". Passing every knob unconditionally
    is only safe if empty means unset - `int("")` used to raise at import and
    would have killed every scan rather than falling back to the default."""

    def _reload(self, **env):
        import importlib
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, env):
            import tools.config as config
            return importlib.reload(config)

    def test_empty_numeric_falls_back_to_the_default(self):
        c = self._reload(DRIFT_BICEP_TIMEOUT="", DRIFT_WEBHOOK_TIMEOUT="")
        self.assertEqual(c.BICEP_BUILD_TIMEOUT, 120)
        self.assertEqual(c.WEBHOOK_TIMEOUT_SECONDS, 10)

    def test_empty_log_level_falls_back(self):
        self.assertEqual(self._reload(DRIFT_LOG_LEVEL="").LOG_LEVEL, "INFO")

    def test_an_explicit_value_still_wins(self):
        c = self._reload(DRIFT_BICEP_TIMEOUT="300", DRIFT_LOG_LEVEL="debug")
        self.assertEqual(c.BICEP_BUILD_TIMEOUT, 300)
        self.assertEqual(c.LOG_LEVEL, "DEBUG")

    def test_empty_does_not_disable_a_sidecar(self):
        # `.get(name, "true") not in (false,0,no,off)` - "" is not in that set,
        # so the sidecar stays ON. Verified rather than assumed: the opposite
        # would silently drop RBAC scanning from every run.
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"INCLUDE_ROLE_ASSIGNMENTS": "",
                                          "INCLUDE_POLICY_ASSIGNMENTS": ""}):
            from tools.policy import policy_drift_enabled
            from tools.rbac import rbac_enabled
            self.assertTrue(rbac_enabled())
            self.assertTrue(policy_drift_enabled())

    def test_false_still_disables(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"INCLUDE_ROLE_ASSIGNMENTS": "false"}):
            from tools.rbac import rbac_enabled
            self.assertFalse(rbac_enabled())


if __name__ == "__main__":
    unittest.main()
