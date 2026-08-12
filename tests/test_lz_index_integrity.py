"""
Every registered landing zone must resolve to something that exists.

The index carried three placeholder entries copied from documentation —
`frontend`, `backend` and `database`, pointing at `myorg/*` repos that do not
exist, two of them naming workflow files that do not exist either. They sat in a
live index looking like configuration.

Nothing caught them because nothing looked: the index is data, the workflows are
data, and no test compared the two. Same shape as the tunables that were read by
the code and never passed by CI — a reference that resolves to nothing fails
silently, because the thing it points at is only consulted when someone
dispatches it.
"""

import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / ".github/lz-index.yml"
WORKFLOWS = ROOT / ".github/workflows"

# Fixture estates. Deployed for a verification round and torn down after, so a
# schedule here means a daily failure against an estate that is usually absent.
#
# NONE ARE CURRENTLY REGISTERED — the verification estates were not migrated
# (see docs/TEST_ESTATE.md), so the check below is dormant rather than passing
# on merit. It is kept, and these names kept in it, because the next fixture
# someone registers should inherit the rule instead of rediscovering it. Add new
# fixture names here when an estate returns.
FIXTURE_LANDING_ZONES = {
    "spoke-drifttest", "test-resources", "vhub-test",
    "test-stack-resources", "database-testing",
}


def _index() -> dict:
    return yaml.safe_load(INDEX.read_text(encoding="utf-8"))["landing_zones"]


class IndexResolvesTests(unittest.TestCase):
    def test_the_index_is_not_empty(self):
        # Guards the guard: an empty parse would make everything below vacuous.
        # The threshold was 2 when five fixture estates were registered
        # alongside the production LZs; they were removed when the estates were
        # not migrated, so anything above zero is now a real index.
        self.assertGreaterEqual(len(_index()), 1)

    def test_every_entry_names_a_workflow_that_exists(self):
        missing = {name: cfg.get("workflow")
                   for name, cfg in _index().items()
                   if not (WORKFLOWS / str(cfg.get("workflow"))).is_file()}
        self.assertEqual(missing, {},
                         f"registered landing zones naming absent workflows: {missing}")

    def test_every_entry_has_a_repo_and_config_path(self):
        incomplete = {name: sorted(k for k in ("repo", "config_path", "workflow")
                                   if not cfg.get(k))
                      for name, cfg in _index().items()
                      if not all(cfg.get(k) for k in ("repo", "config_path", "workflow"))}
        self.assertEqual(incomplete, {})

    def test_no_placeholder_repos(self):
        # `myorg/...` is the documentation example. In the index it is a landing
        # zone that can never be scanned.
        placeholders = {name: cfg["repo"] for name, cfg in _index().items()
                        if str(cfg.get("repo", "")).startswith(("myorg/", "org/", "example/"))}
        self.assertEqual(placeholders, {},
                         f"example repos registered as real landing zones: {placeholders}")


class FixtureWorkflowsDoNotRunOnASchedule(unittest.TestCase):
    """A scheduled scan of an estate that is normally torn down fails every day
    and teaches people to ignore red. The TEMPLATE proved it: a live cron against
    the unregistered `myteam` landing zone failed seven times before being
    disabled by hand."""

    def _triggers(self, path: pathlib.Path) -> set:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        # PyYAML parses the bare key `on:` as the boolean True.
        return set((loaded.get(True) or loaded.get("on") or {}).keys())

    def test_fixture_landing_zone_workflows_are_dispatch_only(self):
        scheduled = {}
        for name, cfg in _index().items():
            if name not in FIXTURE_LANDING_ZONES:
                continue
            path = WORKFLOWS / str(cfg.get("workflow"))
            if path.is_file() and "schedule" in self._triggers(path):
                scheduled[name] = path.name
        self.assertEqual(scheduled, {},
                         f"fixture estates on a schedule: {scheduled}")

    def test_the_template_does_not_execute(self):
        path = WORKFLOWS / "drift-lz-template.yml"
        self.assertNotIn("schedule", self._triggers(path),
                         "the copy-me template has a live cron; it ran daily "
                         "against a landing zone that was never registered")


if __name__ == "__main__":
    unittest.main()
