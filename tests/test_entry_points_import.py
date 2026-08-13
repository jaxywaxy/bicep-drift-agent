"""Every entry point a workflow invokes must actually start.

`tools/` is a package whose modules import each other relatively. Run one of
them by SCRIPT PATH - `python3 tools/publish_lz_issue.py` - and Python gives it
no package context, so every `from .x import y` in the import chain fails.

That is not theoretical. It took down `Publish drift issue to landing-zone
repo` on main, and the way it failed is the reason this file exists:

    tools/publish_lz_issue.py:  from .http_util import ...   -> ImportError
      caught, falls back to:    from http_util import ...
    tools/http_util.py:         from . import recording      -> ImportError
      caught, falls back to:    import recording
    tools/recording/sanitize.py: from ..rbac import ...      -> ImportError
                                 "beyond top-level package"  -> UNCAUGHT

The dual-import fallbacks made it look handled. They were not: the third
failure is one frame deeper than the `except ImportError` that was supposed to
cover it, so a chain that had worked for months broke the moment anything in it
grew a second level of relative import. No unit test saw it because unit tests
import `tools.x` properly, which is the one arrangement that always works.

So there are two guards here, and they check different things:

- `ImportsCleanlyTests` - the modules themselves are importable.
- `WorkflowsUsePackageContextTests` - the workflows actually INVOKE them in a
  form that supplies package context. This is the one that would have caught
  the outage, because the modules were fine; the invocation was not.

Both derive their list from the workflow files rather than hard-coding it, so a
new entry point is covered the day it is added instead of the day it breaks.
"""

import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github/workflows"

#: `python3 tools/foo.py` / `python foo.py` - a bare script path.
_SCRIPT_INVOCATION = re.compile(r"python3?\s+(?!-m\b)([\w./-]+\.py)\b")
#: `python3 -m tools.foo`
_MODULE_INVOCATION = re.compile(r"python3?\s+-m\s+([\w.]+)")

#: Invoked by script path on purpose. `.github/scripts/` is not a package - the
#: files there are standalone and import nothing relatively - so a script path
#: is the correct way to run them and `-m` would not work.
_STANDALONE_SCRIPTS = ("\u200E.github/scripts/",)

#: Top-level entry points that live outside a package and are meant to be run
#: by path (`python analyze_drift.py ...`), as the README documents.
_TOP_LEVEL_ENTRY_POINTS = {"analyze_drift.py", "run_drift_check.py"}


def _workflow_text() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(WORKFLOW_DIR.glob("*.yml"))}


def _module_invocations() -> set[str]:
    found = set()
    for text in _workflow_text().values():
        found.update(m for m in _MODULE_INVOCATION.findall(text)
                     if m.startswith("tools.") or m.startswith("evals."))
    return found


def _script_invocations() -> dict[str, str]:
    """{script path: workflow file} for every bare-path python invocation."""
    found = {}
    for name, text in _workflow_text().items():
        for path in _SCRIPT_INVOCATION.findall(text):
            found.setdefault(path, name)
    return found


class WorkflowsUsePackageContextTests(unittest.TestCase):
    def test_the_scanner_sees_the_known_invocations(self):
        # Guards the guard. A regex that matched nothing would make every
        # assertion below pass vacuously - the same failure shape as the outage.
        modules = _module_invocations()
        self.assertIn("tools.rg_selector", modules)
        self.assertGreaterEqual(len(modules), 4, f"only found {sorted(modules)}")

    def test_no_workflow_runs_a_packaged_module_by_script_path(self):
        offenders = {
            path: workflow
            for path, workflow in _script_invocations().items()
            if path.startswith("tools/") or path.startswith("agent/")
            or path.startswith("orchestration/")
        }
        self.assertEqual(
            offenders, {},
            "these run a module of a package by script path, so Python gives "
            "them no package context and their relative imports fail at "
            "runtime. Use `python3 -m tools.<name>` (add PYTHONPATH=<dir> if "
            f"the checkout is not the working directory): {offenders}")

    def test_top_level_entry_points_may_still_be_run_by_path(self):
        # Not everything must be a module: analyze_drift.py and
        # run_drift_check.py sit at the repo root, import `tools.x` absolutely,
        # and are documented as `python analyze_drift.py ...`. Asserted so the
        # rule above is not later "tightened" into breaking them.
        for entry in _TOP_LEVEL_ENTRY_POINTS:
            self.assertTrue((ROOT / entry).exists(), entry)
            self.assertNotIn("/", entry)


class ImportsCleanlyTests(unittest.TestCase):
    """Each module a workflow runs must import with no package context problems.

    Imported rather than executed: the import chain is what broke, and running
    these for real needs reports, tokens and a subscription. A subprocess is
    used so the check is a genuine cold import, not one already satisfied by
    this test process.
    """

    def _import(self, module: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )

    def test_every_module_a_workflow_invokes_imports(self):
        failures = {}
        for module in sorted(_module_invocations()):
            result = self._import(module)
            if result.returncode != 0:
                failures[module] = result.stderr.strip().splitlines()[-1:]
        self.assertEqual(failures, {}, f"import failures: {failures}")

    def test_the_publisher_chain_that_broke_imports(self):
        # Named explicitly as a regression: this exact chain
        # (publish_lz_issue -> http_util -> recording -> ..rbac) is what failed.
        result = self._import("tools.publish_lz_issue")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ImportError", result.stderr)


if __name__ == "__main__":
    unittest.main()
