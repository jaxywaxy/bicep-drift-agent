"""Schema-derived facts are ADDITIVE, TYPE-SCOPED, and must never fail vacuously.

`tools/schema/` distils two facts out of the published Azure type definitions:
which properties an RP declares write-only, and which properties a given
apiVersion declares at all. Both refine suppression - they can only ever make
the pipeline report LESS - so every failure mode here is a silent false
negative, and the tests are shaped accordingly:

  * The vacuity guard. A lookup that answered "unknown" for everything would
    disable both checks with the whole suite still green - the exact failure
    that left the backup comparators dead for a month. So the corpus is
    asserted non-empty AND asserted to discriminate: known-true, known-false
    and known-unknown lookups must give three different answers.

  * The mutation guard. Doctoring the vendored facts must change what
    compare_properties emits. A check wired up but never consulted passes every
    per-case assertion.

  * The over-match guard. The hand-maintained WRITE_ONLY_PROPERTIES was curated
    to be safe as a global substring set; the schema's flags were not.
    Microsoft.Resources/deployments marks `identity` write-only - if that ever
    leaks out of its type, managed-identity drift goes dark estate-wide.

Tests enter through compare_properties and detect_drift, never through
tools.schema.flags alone: a fact the comparator never reaches is not a feature.
"""

import json
import logging
import unittest
from unittest.mock import patch

from tools.property_drift.comparator import PropertyComparator
from tools.property_drift.detector import DriftDetector
from tools.property_drift.extractor import PropertyExtractor
from tools.schema import flags


def _paths(diffs):
    return {d.property_path for d in diffs}


def _storage(properties, api_version="2023-01-01"):
    """A bicep-side storage account, extracted the way the pipeline extracts it.

    Going through PropertyExtractor matters: it is what drops `apiVersion` from
    the comparable surface (ARM metadata, not a deployed property). Handing
    compare_properties a raw resource dict instead would compare apiVersion
    against a live payload that has none, and every case here would be reading
    a diff the pipeline never produces.
    """
    return PropertyExtractor.extract_bicep_properties({
        "type": "Microsoft.Storage/storageAccounts",
        "name": "stdrifttest",
        "apiVersion": api_version,
        "properties": properties,
    })


def _live_storage(properties):
    return PropertyExtractor.extract_azure_properties({
        "type": "Microsoft.Storage/storageAccounts",
        "name": "stdrifttest",
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stdrifttest",
        "properties": properties,
    })


#: A property genuinely added to storage accounts after 2023-01-01. Its value is
#: deliberately truthy: the removed-property branch already drops falsy desired
#: values as "optional property not set", so a False here would be suppressed by
#: a rule that has nothing to do with schema coverage, and both halves of the
#: A/B below would pass without the check existing at all.
_POST_2023_PROPERTY = {"allowSharedKeyAccessForServices": {"blob": {"enabled": True}}}


class CorpusIsNotVacuousTests(unittest.TestCase):
    """If these fail, every other test in this file passes for the wrong reason."""

    def test_corpus_covers_the_types_the_repo_has_opinions_about(self):
        types, pairs = flags.coverage_size()
        self.assertGreater(types, 50, "vendored corpus lost its types")
        self.assertGreaterEqual(pairs, types, "every type needs at least one apiVersion")

    def test_lookup_discriminates_between_true_false_and_unknown(self):
        # Declared.
        self.assertIs(
            True,
            flags.property_declared(
                "microsoft.storage/storageaccounts", "2023-01-01",
                "properties.supportsHttpsTrafficOnly",
            ),
        )
        # Positively absent at this version.
        self.assertIs(
            False,
            flags.property_declared(
                "microsoft.storage/storageaccounts", "2023-01-01",
                "properties.notARealProperty",
            ),
        )
        # Uncovered apiVersion - unknowable, NOT absent.
        self.assertIsNone(
            flags.property_declared(
                "microsoft.storage/storageaccounts", "1999-01-01",
                "properties.notARealProperty",
            ),
        )

    def test_write_only_facts_are_present_and_type_scoped(self):
        self.assertTrue(flags.is_write_only(
            "microsoft.sql/servers", "2025-01-01", "properties.administratorLoginPassword"))
        self.assertFalse(flags.is_write_only(
            "microsoft.storage/storageaccounts", "2023-01-01", "properties.administratorLoginPassword"))


class ApiVersionExistenceTests(unittest.TestCase):
    """A property the target apiVersion does not define was dropped by ARM at
    deploy time; it can never appear live, so it is not drift."""

    def test_property_added_after_the_pinned_version_is_not_drift(self):
        # allowSharedKeyAccessForServices is real, and genuinely absent from
        # 2023-01-01 - a template pinned there has it dropped by ARM silently.
        diffs = PropertyComparator.compare_properties(
            _storage({"supportsHttpsTrafficOnly": True, **_POST_2023_PROPERTY}),
            _live_storage({"supportsHttpsTrafficOnly": True}),
            "2023-01-01",
        )
        self.assertEqual(set(), _paths(diffs))

    def test_the_same_property_IS_drift_at_a_version_that_defines_it(self):
        """The A to the previous test's B: same template, same live payload,
        different pinned version. Only the schema fact separates them."""
        diffs = PropertyComparator.compare_properties(
            _storage({"supportsHttpsTrafficOnly": True, **_POST_2023_PROPERTY},
                     api_version="2026-04-01"),
            _live_storage({"supportsHttpsTrafficOnly": True}),
            "2026-04-01",
        )
        self.assertIn(
            "properties.allowSharedKeyAccessForServices.blob.enabled", _paths(diffs),
            "a declared-but-absent property the API DOES define is real drift",
        )

    def test_uncovered_api_version_suppresses_nothing(self):
        diffs = PropertyComparator.compare_properties(
            _storage({"supportsHttpsTrafficOnly": True, "madeUpEntirely": "x"},
                     api_version="1999-01-01"),
            _live_storage({"supportsHttpsTrafficOnly": True}),
            "1999-01-01",
        )
        self.assertIn("properties.madeUpEntirely", _paths(diffs))

    def test_no_api_version_suppresses_nothing(self):
        """Every pre-existing call site omits the argument; none may change."""
        diffs = PropertyComparator.compare_properties(
            _storage({"supportsHttpsTrafficOnly": True, "madeUpEntirely": "x"}),
            _live_storage({"supportsHttpsTrafficOnly": True}),
        )
        self.assertIn("properties.madeUpEntirely", _paths(diffs))

    def test_free_form_maps_are_never_judged_absent(self):
        """`tags` is a free-form map: the schema declares no key under it. If
        that read as "not declared", every removed tag would be suppressed -
        and a deleted policy-mandated tag is exactly what this tool exists to
        catch."""
        diffs = PropertyComparator.compare_properties(
            {**_storage({"supportsHttpsTrafficOnly": True}), "tags": {"owner": "platform"}},
            {**_live_storage({"supportsHttpsTrafficOnly": True}), "tags": {}},
            "2023-01-01",
        )
        self.assertIn("tags.owner", _paths(diffs))

    def test_synthesised_empty_keys_are_never_judged_at_all(self):
        """The check runs LAST in the removed-property branch, after the
        emptiness filters.

        Not every key in the flattened bicep surface was written by a human:
        the normaliser gives every resource a top-level `zones` key, null on
        types that have no such concept. Judging those changed no outcome (the
        emptiness filter drops them either way) but emitted 25 lines per scan
        telling the operator their template declares `zones` at a bad
        apiVersion, on templates that never mention zones. Found on the live
        fixture estate, not by any unit test.
        """
        bicep = _storage({"supportsHttpsTrafficOnly": True})
        bicep["zones"] = None  # what normalize_resource actually produces
        with self.assertLogs("tools.property_drift.comparator", level="INFO") as captured:
            logging.getLogger("tools.property_drift.comparator").info("anchor")
            PropertyComparator.compare_properties(
                bicep, _live_storage({"supportsHttpsTrafficOnly": True}), "2023-01-01",
            )
        self.assertEqual(
            [], [line for line in captured.output if "zones" in line],
            "a synthesised empty key was judged against the schema",
        )

    def test_array_element_paths_are_never_judged_absent(self):
        """The corpus omits array interiors by construction (flatten_dict keeps
        arrays whole). An element path must read unknown, not absent."""
        self.assertIsNone(flags.property_declared(
            "microsoft.network/networksecuritygroups", "2023-04-01",
            "properties.securityRules[0].properties.access",
        ))


class WriteOnlyIsAdditiveAndScopedTests(unittest.TestCase):

    def test_schema_write_only_adds_to_the_hand_list_without_replacing_it(self):
        from tools.property_drift import severity

        # Hand-listed, schema-silent: Compute annotates none of the osProfile
        # family. Losing this would false-positive on every VM.
        self.assertTrue(severity.is_write_only_for_type(
            "microsoft.compute/virtualmachines", "2024-11-01",
            "properties.osProfile.adminPassword",
        ))
        self.assertFalse(flags.is_write_only(
            "microsoft.compute/virtualmachines", "2024-11-01",
            "properties.osProfile.adminPassword",
        ))
        # Schema-derived, absent from the hand list.
        self.assertTrue(severity.is_write_only_for_type(
            "microsoft.sql/servers/databases", "2025-01-01", "properties.sourceDatabaseId"))
        self.assertFalse(severity.is_write_only_property("properties.sourcedatabaseid"))

    def test_deployments_identity_flag_does_not_leak_to_other_types(self):
        """Microsoft.Resources/deployments marks `identity` write-only. Folded
        into a global list it would blind identity drift on every resource."""
        from tools.property_drift import severity

        self.assertTrue(severity.is_write_only_for_type(
            "microsoft.resources/deployments", "2025-04-01", "identity"))
        self.assertFalse(severity.is_write_only_for_type(
            "microsoft.storage/storageaccounts", "2023-01-01", "identity"))

    def test_schema_write_only_never_suppresses_a_property_azure_returned(self):
        """Microsoft.Web/sites flags `properties.siteConfig` write-only, and
        Azure returns it in full. Honouring the flag where the property is
        PRESENT would re-open the invisible-siteConfig false negative (#234)."""
        diffs = PropertyComparator.compare_properties(
            {
                "type": "Microsoft.Web/sites",
                "name": "app-drift",
                "apiVersion": "2025-03-01",
                "properties": {"siteConfig": {"minTlsVersion": "1.2"}},
            },
            {
                "type": "Microsoft.Web/sites",
                "name": "app-drift",
                "properties": {"siteConfig": {"minTlsVersion": "1.0"}},
            },
            "2025-03-01",
        )
        self.assertIn("properties.siteConfig.minTlsVersion", _paths(diffs))


class ApiVersionReachesTheComparatorTests(unittest.TestCase):
    """The plumbing, not the facts: apiVersion is ARM metadata that the
    property extractor deliberately drops, so it travels as its own argument.
    Entering at detect_drift proves the argument is actually supplied."""

    def test_detect_drift_passes_the_templates_api_version_through(self):
        bicep = [{
            "type": "Microsoft.Storage/storageAccounts",
            "name": "stdrifttest",
            "apiVersion": "2023-01-01",
            "properties": {"supportsHttpsTrafficOnly": True, **_POST_2023_PROPERTY},
        }]
        live = [{
            "type": "Microsoft.Storage/storageAccounts",
            "name": "stdrifttest",
            "id": "/subscriptions/s/resourceGroups/rg/providers/"
                  "Microsoft.Storage/storageAccounts/stdrifttest",
            "properties": {"supportsHttpsTrafficOnly": True},
        }]

        drifts = DriftDetector.detect_drift(bicep, live)
        modified = [d for d in drifts if d.drift_type == "modified"]
        self.assertEqual(
            [], [p for d in modified for p in _paths(d.property_diffs)],
            "apiVersion did not reach the comparator - the suppression never fired",
        )


class MutationGuardTests(unittest.TestCase):
    """Doctor the vendored facts; the comparator's output must follow. A check
    that is wired but never consulted passes every assertion above."""

    def setUp(self):
        flags._facts.cache_clear()
        self.addCleanup(flags._facts.cache_clear)

    def _with_facts(self, facts):
        return patch.object(flags, "_facts", lambda: facts)

    def test_removing_a_path_from_the_corpus_suppresses_its_drift(self):
        bicep = _storage({"supportsHttpsTrafficOnly": True})
        live = _live_storage({})

        doctored = {
            "microsoft.storage/storageaccounts": {
                "2023-01-01": {"paths": [], "write_only": [], "opaque": []},
            }
        }
        with self._with_facts(doctored):
            diffs = PropertyComparator.compare_properties(bicep, live, "2023-01-01")
        self.assertEqual(set(), _paths(diffs), "doctored corpus had no effect")

    def test_adding_a_write_only_path_to_the_corpus_suppresses_its_drift(self):
        bicep = _storage({"supportsHttpsTrafficOnly": True})
        live = _live_storage({"minimumTlsVersion": "TLS1_2"})

        with self._with_facts({}):
            baseline = _paths(PropertyComparator.compare_properties(bicep, live, "2023-01-01"))
        self.assertIn("properties.supportsHttpsTrafficOnly", baseline)

        doctored = {
            "microsoft.storage/storageaccounts": {
                "2023-01-01": {
                    "paths": ["properties.supportshttpstrafficonly"],
                    "write_only": ["properties.supportshttpstrafficonly"],
                    "opaque": [],
                },
            }
        }
        with self._with_facts(doctored):
            diffs = PropertyComparator.compare_properties(bicep, live, "2023-01-01")
        self.assertNotIn("properties.supportsHttpsTrafficOnly", _paths(diffs))

    def test_an_empty_or_unreadable_corpus_disables_the_checks_and_reports_more(self):
        """Degradation must be toward reporting, never toward silence."""
        bicep = _storage({"supportsHttpsTrafficOnly": True, "madeUpEntirely": "x"})
        live = _live_storage({"supportsHttpsTrafficOnly": True})

        with self._with_facts({}):
            diffs = PropertyComparator.compare_properties(bicep, live, "2023-01-01")
        self.assertIn("properties.madeUpEntirely", _paths(diffs))


class VendoredCorpusShapeTests(unittest.TestCase):

    def test_file_is_sorted_lowercased_and_declares_its_provenance(self):
        with open(flags.DATA_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(flags.SUPPORTED_SCHEMA_VERSION, data["schema_version"])
        self.assertEqual("Azure/bicep-types-az", data["source"]["repo"])
        for rtype, versions in data["types"].items():
            self.assertEqual(rtype.lower(), rtype)
            for version, entry in versions.items():
                self.assertEqual(version.lower(), version)
                for key in ("paths", "write_only", "opaque"):
                    self.assertEqual(sorted(entry[key]), entry[key],
                                     f"{rtype}@{version}.{key} is unsorted - "
                                     "the vendored file must be diffable")

    def test_schema_version_mismatch_disables_the_corpus(self):
        """A future distiller format must switch the checks OFF, not be
        misread by an older reader."""
        flags._facts.cache_clear()
        self.addCleanup(flags._facts.cache_clear)
        payload = json.dumps({"schema_version": 999, "types": {"x": {}}})
        with patch("builtins.open", unittest.mock.mock_open(read_data=payload)):
            self.assertEqual({}, flags._facts())


if __name__ == "__main__":
    unittest.main()
