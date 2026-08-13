"""There are TWO name-correspondence rules, and merging them would be a bug.

They look like duplicates. They are not: they answer different questions, and
the asymmetry is deliberate and load-bearing in both directions.

    tools.smart_matching.names_plausibly_correspond   - PAIRING
        "which live resource is this declared one?"
        Permissive. It is one input to a best-of-N selection
        (`_find_best_match`), which can fall back to pairing in order, so a
        loose accept is corrected downstream. A false REJECT here is the
        expensive error: the declared resource pairs with nothing and reports
        missing_in_azure, fabricating a deletion.

    tools.activity_log.could_be_same_resource         - ATTRIBUTION
        "is this Activity Log event about this resource?"
        Strict. Nothing downstream corrects it, and a false accept asserts that
        a NAMED PERSON did something they did not. Issue #350: the function app
        `func-drift-[86c9cbf6]` adopted the App Service `app-test-drift` - its
        name, its deletion event and its actor - because both are
        Microsoft.Web/sites.

So the correct relationship is a documented boundary, not a shared
implementation. This file pins the boundary: each divergence below is a case
where making the two agree would reintroduce a defect that was fixed on a live
estate. If you are here because you were consolidating identity matching, this
is the part that should stay separate - the PAIRING rule is already shared, by
PRs #425-#427 and the diff_states fix that followed.
"""

import unittest

from tools.activity_log import _shared_affix_len, could_be_same_resource
from tools.smart_matching import (
    _common_prefix_len,
    _common_suffix_len,
    names_plausibly_correspond,
)


def _pair(declared: str, deployed: str) -> bool:
    return names_plausibly_correspond(declared.lower(), deployed.lower())


class AttributionIsStricterWhereEvidenceIsWeakTests(unittest.TestCase):
    """Pairing accepts on weak evidence; attribution refuses. Making attribution
    as permissive as pairing is how one resource adopts another's actor."""

    WEAK = (
        # A literal lead too short to discriminate.
        ("d-[a1b2c3d4]", "datadisk-vm1"),
        # Nothing literal at all - `name: uniqueString(...)`. Attribution
        # refusing this is the #350 fix; a bare '[^/]+' pattern would match
        # every sibling of the type.
        ("[a1b2c3d4]", "anything-at-all"),
    )

    def test_pairing_accepts_weak_evidence(self):
        # Because a false reject fabricates a deletion, and a false accept is
        # corrected by best-of-N selection.
        for declared, deployed in self.WEAK:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertTrue(_pair(declared, deployed))

    def test_attribution_refuses_it(self):
        # Because nothing downstream corrects it and the output names a person.
        for declared, deployed in self.WEAK:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertFalse(could_be_same_resource(declared, deployed))


class AttributionIsLooserOnSegmentDepthTests(unittest.TestCase):
    """And in the other direction, which is why neither is simply 'the strict
    one'. An extension's event id names only the extension, while the declared
    name qualifies it with its parent, so attribution aligns from the right
    over the segments both names have."""

    DECLARED, EVENT_ID = "kvdrift[86c9cbf6]/kv-audit", "kv-audit"

    def test_attribution_matches_the_unqualified_event_id(self):
        self.assertTrue(could_be_same_resource(self.DECLARED, self.EVENT_ID))

    def test_pairing_does_not(self):
        # A live row always carries its full parent-qualified name, so a bare
        # leaf is a different resource. Loosening this would pair a child with
        # any same-named child of another parent.
        self.assertFalse(_pair(self.DECLARED, self.EVENT_ID))


class WhereTheyMustStillAgreeTests(unittest.TestCase):
    """The boundary is not licence to differ everywhere. On a resolved
    placeholder name - the common case both were built for - they agree, and a
    change that broke that would be a real divergence rather than a deliberate
    one."""

    AGREE = (
        ("sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/driftdb", True),
        ("sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7weddxr3s/master", False),
        ("st[86c9cbf6]", "stabcdef123", True),
        ("asp-test-drift", "asp-func-drift-test", False),
        ("func-drift-[86c9cbf6]", "app-test-drift", False),
    )

    def test_both_rules_agree(self):
        for declared, deployed, expected in self.AGREE:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertIs(_pair(declared, deployed), expected)
                self.assertIs(could_be_same_resource(declared, deployed), expected)


class AffixPrimitivesShareOneContractTests(unittest.TestCase):
    """One layer below the two rules sits the same primitive, twice.

    `smart_matching._common_prefix_len`/`_common_suffix_len` and
    `activity_log._shared_affix_len` both compute longest common prefix/suffix.
    They stay separate copies on purpose - attribution does not import from the
    pairing path - so what has to be shared is the CONTRACT, or they drift the
    way the correspondence rule drifted across four modules.

    The contract: **case is folded by the function, never by the caller.** The
    smart_matching pair used to be case-SENSITIVE, working only because both
    call sites happened to lowercase first. Azure preserves the casing a
    resource was created with, so a raw live name reaching either of them
    mixed-case would silently under-count the shared run.
    """

    MIXED = (
        ("Func-Drift-[86C9CBF6]", "func-drift-3s7c7wed"),
        ("STDRIFTDATA", "stdriftdata"),
        ("kvdrift[86c9cbf6]/KV-Audit", "kvdrift3s7c7wed/kv-audit"),
    )

    def test_the_pairing_primitives_fold_case_themselves(self):
        for declared, deployed in self.MIXED:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertEqual(_common_prefix_len(declared, deployed),
                                 _common_prefix_len(declared.lower(), deployed.lower()))
                self.assertEqual(_common_suffix_len(declared, deployed),
                                 _common_suffix_len(declared.lower(), deployed.lower()))

    def test_the_attribution_primitive_folds_case_too(self):
        for declared, deployed in self.MIXED:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertEqual(_shared_affix_len(declared, deployed),
                                 _shared_affix_len(declared.lower(), deployed.lower()))

    def test_the_two_copies_compute_the_same_thing(self):
        # _shared_affix_len is max(prefix, suffix) over the same computation.
        # Pinning the identity is what stops the copies diverging; the
        # AGGREGATION differing is fine and deliberate.
        pairs = list(self.MIXED) + [
            ("asp-test-drift", "asp-func-drift-test"),
            ("sqldrift[86c9cbf6]/driftdb", "sqldrift3s7c7wed/master"),
            ("", "anything"),
            ("identical", "identical"),
        ]
        for declared, deployed in pairs:
            with self.subTest(f"{declared} vs {deployed}"):
                self.assertEqual(
                    _shared_affix_len(declared, deployed),
                    max(_common_prefix_len(declared, deployed),
                        _common_suffix_len(declared, deployed)))

    def test_mixed_case_actually_exercises_the_folding(self):
        # Guards the guard: if every fixture above were already lowercase the
        # case assertions would pass without the folding existing at all.
        self.assertTrue(any(d != d.lower() or l != l.lower()
                            for d, l in self.MIXED))
        # And the folding must be load-bearing, not a no-op: without it these
        # two names share nothing at the front.
        self.assertEqual(_common_prefix_len("STDRIFT", "stdrift"), 7)


class TheRulesAreNotTheSameFunctionTests(unittest.TestCase):
    def test_they_are_distinct_callables(self):
        # A "consolidation" that aliased one to the other would pass every
        # agreement case above and silently break the divergences.
        self.assertIsNot(names_plausibly_correspond, could_be_same_resource)

    def test_at_least_one_divergence_survives_in_each_direction(self):
        # Guards the guard: if a refactor made the two agree everywhere, the
        # subTests above would still pass one by one while the boundary this
        # file exists to protect had quietly gone.
        pair_looser = any(_pair(d, l) and not could_be_same_resource(d, l)
                          for d, l in AttributionIsStricterWhereEvidenceIsWeakTests.WEAK)
        attrib_looser = (
            could_be_same_resource(AttributionIsLooserOnSegmentDepthTests.DECLARED,
                                   AttributionIsLooserOnSegmentDepthTests.EVENT_ID)
            and not _pair(AttributionIsLooserOnSegmentDepthTests.DECLARED,
                          AttributionIsLooserOnSegmentDepthTests.EVENT_ID))
        self.assertTrue(pair_looser, "pairing is no longer looser anywhere")
        self.assertTrue(attrib_looser, "attribution is no longer looser anywhere")


if __name__ == "__main__":
    unittest.main()
