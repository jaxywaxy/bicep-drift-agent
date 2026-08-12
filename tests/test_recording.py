"""Record/replay of real Azure payloads.

The point of the cassette corpus is to replace hand-typed fixtures - which
encode our BELIEFS about Azure - with evidence of what Azure actually returned.
That only holds if three things are true, and each has a test class here:

- replay really does bypass the network (`NoNetworkOnReplayTests`),
- a cassette that does not cover a request FAILS rather than returning nothing
  (`MissesAreLoudTests`), because an empty collection means "deleted" in this
  pipeline and a lenient replayer would manufacture missing_in_azure rows,
- the recorded bytes are actually reaching the comparison (`CassetteIsLoadBearingTests`),
  proven by mutation rather than by the tests merely passing.

That last one is the guard-the-guard. A replayer that silently returned empty
for everything would leave every test in this file green except that class -
which is precisely the failure that left two backup comparators dead for a
month, and why the tests enter through a real collector rather than calling the
recording helpers directly.
"""

import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from tools import recording
from tools.recording.cassette import Cassette, CassetteMiss
from tools.recording.sanitize import Sanitiser, alias_guid

SUB = "594e0bd0-2a8d-4419-b281-87869c20fd03"
LOCKS_URL = (
    f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-plat"
    "/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
)
LOCKS_PAYLOAD = {
    "value": [
        {
            "id": (
                f"/subscriptions/{SUB}/resourceGroups/rg-plat/providers"
                "/Microsoft.Authorization/locks/dont-delete"
            ),
            "name": "dont-delete",
            "properties": {"level": "CanNotDelete", "notes": "platform baseline"},
        }
    ]
}


class _FakeHTTPResponse(io.BytesIO):
    """Stands in for what urllib.request.urlopen returns during a recording."""

    def __init__(self, payload, status=200):
        super().__init__(json.dumps(payload).encode("utf-8"))
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _urlopen_returning(payload, status=200):
    return lambda req, **_: _FakeHTTPResponse(payload, status)


def _exploding_urlopen(*_a, **_k):
    raise AssertionError(
        "replay touched the network - the cassette was bypassed"
    )


class _RecordingTestCase(unittest.TestCase):
    """Gives each test a scratch cassette path and guarantees the global session
    is torn down, so one leaked session cannot silently put every later test
    into replay mode."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "cassette.json"
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(recording.stop)

    def _record_locks(self, payload=LOCKS_PAYLOAD):
        """Drive the real locks collector once in record mode."""
        from tools.live_state.collectors.locks import _query_locks

        recording.start_recording(self.path)
        with mock.patch("urllib.request.urlopen", _urlopen_returning(payload)):
            result = _query_locks("rg-plat", SUB, "resource_group", token="fake-token")
        recording.stop()
        return result


class SanitiserTests(unittest.TestCase):
    def test_a_guid_becomes_a_guid_shaped_pseudonym(self):
        # Shape matters: resource ids are parsed downstream, so a pseudonym that
        # was not GUID-shaped would change the code path under test.
        alias = alias_guid(SUB)
        self.assertNotEqual(alias, SUB)
        self.assertRegex(alias, r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
        self.assertEqual(alias, alias_guid(SUB.upper()), "must be case-stable")

    def test_aliasing_a_known_alias_is_a_no_op(self):
        # Replay drives the pipeline with the ALIAS subscription id, so a
        # sanitiser that re-aliased it would never match a recorded key.
        s = Sanitiser(known_aliases={alias_guid(SUB)})
        self.assertEqual(s.guid(alias_guid(SUB)), alias_guid(SUB))

    def test_credential_query_parameters_are_dropped(self):
        s = Sanitiser()
        out = s.url("https://x.blob.core.windows.net/c/b?sig=SECRET&api-version=2021-04-01")
        self.assertNotIn("SECRET", out)
        self.assertIn("api-version=2021-04-01", out)

    def test_query_parameter_order_does_not_change_the_key(self):
        # A dozen collectors build these URLs by f-string; a key that depended
        # on parameter order would turn a harmless edit into a silent miss.
        s = Sanitiser()
        self.assertEqual(
            s.url("https://m.azure.com/x?b=2&api-version=1"),
            s.url("https://m.azure.com/x?api-version=1&b=2"),
        )

    def test_secret_values_in_a_body_are_redacted_not_aliased(self):
        s = Sanitiser()
        out = s.body({"properties": {"administratorLoginPassword": "hunter2"}})
        self.assertNotIn("hunter2", json.dumps(out))


class CassetteTests(unittest.TestCase):
    def test_round_trips_through_disk(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.json"
            c = Cassette()
            c.record("GET", LOCKS_URL, 200, LOCKS_PAYLOAD)
            c.save(path)
            loaded = Cassette.load(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded.lookup("GET", LOCKS_URL).status, 200)

    def test_a_changed_api_version_misses(self):
        # The decay property: a collector moving to a new api-version must miss
        # the old recording rather than replay a payload that version never
        # produced.
        c = Cassette()
        c.record("GET", LOCKS_URL, 200, LOCKS_PAYLOAD)
        with self.assertRaises(CassetteMiss):
            c.lookup("GET", LOCKS_URL.replace("2016-09-01", "2023-07-01"))

    def test_a_miss_names_the_closest_recorded_key(self):
        c = Cassette()
        c.record("GET", LOCKS_URL, 200, LOCKS_PAYLOAD)
        with self.assertRaises(CassetteMiss) as ctx:
            c.lookup("GET", LOCKS_URL.replace("2016-09-01", "2023-07-01"))
        self.assertIn("2016-09-01", str(ctx.exception))

    def test_a_stale_version_is_rejected_outright(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.json"
            path.write_text(json.dumps({"version": 0, "interactions": {}}))
            with self.assertRaises(ValueError):
                Cassette.load(path)

    def test_a_conflicting_rerecord_keeps_the_first_body(self):
        c = Cassette()
        c.record("GET", LOCKS_URL, 200, {"value": [1]})
        with self.assertLogs("tools.recording.cassette", "WARNING"):
            c.record("GET", LOCKS_URL, 200, {"value": [2]})
        self.assertEqual(c.lookup("GET", LOCKS_URL).body, {"value": [1]})


class NoNetworkOnReplayTests(_RecordingTestCase):
    def test_a_collector_replays_without_touching_the_network(self):
        recorded = self._record_locks()
        self.assertEqual(len(recorded), 1)

        from tools.live_state.collectors.locks import _query_locks

        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            replayed = _query_locks("rg-plat", SUB, "resource_group", token="fake-token")

        # Identical except that every id speaks in the pseudonym - see
        # ReplaySpeaksInAliasesTests for why that is load-bearing, not cosmetic.
        self.assertEqual(
            replayed,
            json.loads(json.dumps(recorded).replace(SUB, alias_guid(SUB))),
        )

    def test_recording_leaves_the_response_readable_by_its_caller(self):
        # Recording consumes the real single-use stream. If the caller were not
        # handed an equivalent one back, every collector would see an empty body
        # while recording - and record an estate that looks entirely deleted.
        self.assertEqual(self._record_locks()[0]["name"], "dont-delete")

    def test_a_recorded_404_replays_as_a_404(self):
        # resource_group_exists is tri-state and branches on e.code == 404. A
        # replayed error that lost its status would turn "definitively absent"
        # into "could not tell", which are handled differently on purpose.
        from tools.live_state.common import resource_group_exists

        def raise_404(req, **_):
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error":{}}')
            )

        recording.start_recording(self.path)
        with mock.patch("urllib.request.urlopen", raise_404):
            self.assertIs(
                resource_group_exists("gone-rg", SUB, token="fake-token"), False
            )
        recording.stop()

        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            self.assertIs(
                resource_group_exists("gone-rg", SUB, token="fake-token"), False
            )


class ReplaySpeaksInAliasesTests(_RecordingTestCase):
    """The operational contract for every cassette-backed test.

    Recorded resource ids carry the PSEUDONYM subscription, because the real one
    never touches disk. A test therefore has to drive the pipeline with the
    alias id: matched against a Bicep template still naming the real
    subscription, every resource would fail to correspond and the run would
    report the whole estate as simultaneously missing and extra.

    The alias for a given cassette is printed by `python -m tools.recording.decay
    --aliases <cassette>`.
    """

    def test_a_request_made_with_the_alias_hits_the_same_recording(self):
        self._record_locks()
        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            hit = recording.replay_urlopen(
                urllib.request.Request(LOCKS_URL.replace(SUB, alias_guid(SUB)))
            )
        self.assertEqual(hit.status, 200)

    def test_the_real_subscription_also_still_hits_it(self):
        # Both work, because sanitising is applied to the lookup key as well as
        # to the stored one. Recording and replay must never disagree about what
        # a key looks like.
        self._record_locks()
        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            hit = recording.replay_urlopen(urllib.request.Request(LOCKS_URL))
        self.assertEqual(hit.status, 200)


class MissesAreLoudTests(_RecordingTestCase):
    def test_an_uncovered_request_raises_instead_of_returning_nothing(self):
        self._record_locks()
        recording.start_replay(self.path)
        with self.assertRaises(CassetteMiss):
            recording.replay_urlopen(
                urllib.request.Request(LOCKS_URL.replace("rg-plat", "rg-other"))
            )

    def test_a_different_subscription_is_a_miss_not_a_silent_match(self):
        # Pseudonyms are one-way, so a cassette recorded against one estate
        # cannot quietly serve another.
        self._record_locks()
        recording.start_replay(self.path)
        other = SUB.replace("594e0bd0", "00000000")
        with self.assertRaises(CassetteMiss):
            recording.replay_urlopen(
                urllib.request.Request(LOCKS_URL.replace(SUB, other))
            )


class CassetteIsLoadBearingTests(_RecordingTestCase):
    """Mutation checks. Without these, a replayer that returned empty for every
    request would leave the rest of this file green - and the corpus would be
    decorative."""

    def test_editing_the_cassette_changes_what_the_collector_returns(self):
        self._record_locks()
        raw = json.loads(self.path.read_text())
        for interaction in raw["interactions"].values():
            interaction["body"]["value"][0]["properties"]["level"] = "ReadOnly"
        self.path.write_text(json.dumps(raw))

        from tools.live_state.collectors.locks import _query_locks

        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            locks = _query_locks("rg-plat", SUB, "resource_group", token="fake-token")
        self.assertEqual(locks[0]["properties"]["level"], "ReadOnly")

    def test_emptying_the_cassette_body_empties_the_result(self):
        self._record_locks()
        raw = json.loads(self.path.read_text())
        for interaction in raw["interactions"].values():
            interaction["body"] = {"value": []}
        self.path.write_text(json.dumps(raw))

        from tools.live_state.collectors.locks import _query_locks

        recording.start_replay(self.path)
        with mock.patch("urllib.request.urlopen", _exploding_urlopen):
            self.assertEqual(
                _query_locks("rg-plat", SUB, "resource_group", token="fake-token"), []
            )


class NothingSensitiveReachesDiskTests(_RecordingTestCase):
    def test_the_real_subscription_id_is_not_written(self):
        self._record_locks()
        self.assertNotIn(SUB, self.path.read_text())
        self.assertIn(alias_guid(SUB), self.path.read_text())

    def test_a_secret_property_value_is_not_written(self):
        self._record_locks(
            payload={"value": [{"id": f"/subscriptions/{SUB}/x", "name": "n",
                                "properties": {"connectionString": "AccountKey=REALKEY"}}]}
        )
        self.assertNotIn("REALKEY", self.path.read_text())

    def test_no_request_header_is_ever_recorded(self):
        # Headers are dropped wholesale rather than filtered - a bearer token is
        # not something to be clever about. Asserted against the parsed cassette
        # rather than its text, because "Authorization" is also a legitimate
        # Azure resource-provider namespace and a text search matches that.
        self._record_locks()
        self.assertNotIn("fake-token", self.path.read_text())
        raw = json.loads(self.path.read_text())
        for interaction in raw["interactions"].values():
            self.assertNotIn("headers", interaction)


class OnlyAzureIsRecordedTests(_RecordingTestCase):
    """`urlopen_checked` is shared with the GitHub Issue publisher, so the
    seam sees more than Azure. A committed corpus of Azure state must not end up
    carrying issue bodies and notification content."""

    def test_a_github_call_is_not_written_to_the_cassette(self):
        from tools.http_util import urlopen_checked

        recording.start_recording(self.path)
        with mock.patch("urllib.request.urlopen",
                        _urlopen_returning({"html_url": "https://github.com/x/1"})):
            urlopen_checked("https://api.github.com/repos/x/y/issues")
        recording.stop()
        self.assertEqual(len(Cassette.load(self.path)), 0)

    def test_the_response_is_still_returned_to_its_caller(self):
        # Declining to record must not break the call being made.
        from tools.http_util import urlopen_checked

        recording.start_recording(self.path)
        with mock.patch("urllib.request.urlopen",
                        _urlopen_returning({"html_url": "u"})):
            body = json.load(urlopen_checked("https://api.github.com/x"))
        self.assertEqual(body, {"html_url": "u"})

    def test_a_non_azure_call_during_replay_raises_rather_than_going_live(self):
        # The asymmetry is deliberate: an unrecorded GitHub call during a replay
        # would reach the real API and could WRITE. A loud miss is the safe end.
        self._record_locks()
        recording.start_replay(self.path)
        with self.assertRaises(CassetteMiss):
            recording.replay_urlopen(
                urllib.request.Request("https://api.github.com/repos/x/y/issues")
            )


class RequestBodiesAreSanitisedTests(unittest.TestCase):
    """urllib carries a request body as raw bytes, which is a type the body
    walker has to handle explicitly - it fell straight through the str branch
    and put the real subscription id into both the stored interaction and the
    lookup key."""

    def test_a_bytes_request_body_has_its_guids_aliased(self):
        c = Cassette()
        body = json.dumps({"subscriptions": [SUB]}).encode("utf-8")
        c.record("POST", "https://management.azure.com/x?api-version=1", 200,
                 {"data": []}, request_body=body)
        stored = json.dumps(c.to_dict())
        self.assertNotIn(SUB, stored)
        self.assertIn(alias_guid(SUB), stored)

    def test_two_bodies_differing_only_in_subscription_share_a_key(self):
        # Follows from aliasing being applied to the key as well as the payload.
        c = Cassette()
        url = "https://management.azure.com/x?api-version=1"
        self.assertEqual(
            c.key_for("POST", url, json.dumps({"s": [SUB]}).encode()),
            c.key_for("POST", url, json.dumps({"s": [alias_guid(SUB)]}).encode()),
        )


class InactiveIsANoOpTests(unittest.TestCase):
    def test_no_session_means_the_read_path_is_unchanged(self):
        self.assertFalse(recording.is_active())
        from tools.http_util import urlopen_checked

        sentinel = _FakeHTTPResponse({"ok": True})
        with mock.patch("urllib.request.urlopen", return_value=sentinel):
            self.assertIs(urlopen_checked("https://management.azure.com/x"), sentinel)

    def test_the_scheme_guard_still_fires_before_any_hook(self):
        from tools.http_util import urlopen_checked

        with self.assertRaises(ValueError):
            urlopen_checked("file:///etc/passwd")

    def test_setting_both_modes_is_a_configuration_error(self):
        import os

        with mock.patch.dict(os.environ, {recording.RECORD_ENV: "a",
                                          recording.REPLAY_ENV: "b"}):
            with self.assertRaises(ValueError):
                recording.configure_from_env()


class SdkTransportSeamTests(_RecordingTestCase):
    """The second seam. Resource Graph, RBAC, policy, monitor and targeting all
    reach Azure through the shared azure-core transport rather than urllib."""

    def _request(self):
        from azure.core.pipeline.transport import HttpRequest

        req = HttpRequest("POST", "https://management.azure.com/providers/"
                                  "Microsoft.ResourceGraph/resources?api-version=2021-03-01")
        req.set_json_body({"subscriptions": [SUB], "query": "Resources"})
        return req

    def test_an_sdk_call_records_and_replays_through_the_transport(self):
        from azure.core.pipeline.transport import RequestsTransport

        rows = {"data": [{"name": "vnet-hub", "type": "microsoft.network/virtualnetworks"}]}

        # Stand in for the network BEFORE the hook is installed, so the hook
        # captures this as "the original send" and the seam under test is the
        # real one rather than a re-implementation of it.
        with mock.patch.object(
            RequestsTransport, "send",
            lambda self, req, **k: _FakeSdkResponse(rows),
        ):
            recording.start_recording(self.path)
            RequestsTransport().send(self._request())
            recording.stop()

        self.assertEqual(len(Cassette.load(self.path)), 1)

        def explode(self, req, **k):
            raise AssertionError("replay fell through to the transport")

        # Installed as the "original" the hook would delegate to, so reaching it
        # at all is the failure - replay must answer from the cassette.
        with mock.patch.object(RequestsTransport, "send", explode):
            recording.start_replay(self.path)
            replayed = RequestsTransport().send(self._request())
            recording.stop()
        self.assertEqual(json.loads(replayed.body()), rows)

    def test_the_transport_patch_is_removed_on_stop(self):
        # A patch that outlived its session would leave every later scan - and
        # every later test - talking to a cassette that is no longer loaded.
        from azure.core.pipeline.transport import RequestsTransport

        before = RequestsTransport.send
        recording.start_recording(self.path)
        self.assertIsNot(RequestsTransport.send, before)
        recording.stop()
        self.assertIs(RequestsTransport.send, before)


class DecayTests(unittest.TestCase):
    """Re-recording and diffing is what turns silent API decay into a review.

    The discriminating property is that VALUES may change freely and SHAPE may
    not: a differ that fired on values would be ignored within a week, and one
    that missed a removed field would miss the only change that can make a
    comparator start reporting healthy resources as deleted.
    """

    def _pair(self, before, after):
        from tools.recording.decay import Decay

        old, new = Cassette(), Cassette()
        old.record("GET", LOCKS_URL, 200, before)
        new.record("GET", LOCKS_URL, 200, after)
        return Decay(old, new)

    def test_a_value_change_is_not_decay(self):
        decay = self._pair(
            {"properties": {"level": "CanNotDelete"}},
            {"properties": {"level": "ReadOnly"}},
        )
        self.assertFalse(decay, decay.report())

    def test_a_longer_list_is_not_decay(self):
        decay = self._pair({"value": [{"a": 1}]}, {"value": [{"a": 1}, {"a": 2}]})
        self.assertFalse(decay, decay.report())

    def test_a_field_azure_stopped_returning_is_reported(self):
        decay = self._pair(
            {"properties": {"level": "CanNotDelete", "notes": "x"}},
            {"properties": {"level": "CanNotDelete"}},
        )
        self.assertTrue(decay)
        self.assertIn("properties.notes", decay.report())
        self.assertIn("no longer returns", decay.report().lower())

    def test_a_field_that_changed_type_is_reported(self):
        decay = self._pair({"properties": {"capacity": 1}},
                           {"properties": {"capacity": "1"}})
        self.assertIn("int -> str", decay.report())

    def test_present_but_null_is_its_own_shape(self):
        # The unset-vs-default question turns on exactly this distinction, so a
        # field going null must not be flattened into the type it used to hold.
        decay = self._pair({"properties": {"tier": "Standard"}},
                           {"properties": {"tier": None}})
        self.assertIn("str -> null", decay.report())

    def test_volatile_bookkeeping_fields_are_ignored(self):
        decay = self._pair({"etag": "W/1", "properties": {}},
                           {"etag": "W/2", "properties": {}})
        self.assertFalse(decay, decay.report())

    def test_a_moved_api_version_shows_as_a_dropped_and_a_new_request(self):
        from tools.recording.decay import Decay

        old, new = Cassette(), Cassette()
        old.record("GET", LOCKS_URL, 200, {"value": []})
        new.record("GET", LOCKS_URL.replace("2016-09-01", "2023-07-01"), 200, {"value": []})
        decay = Decay(old, new)
        self.assertTrue(decay)
        self.assertIn("no prior shape evidence", decay.report())

    def test_the_cli_exits_nonzero_only_when_something_changed(self):
        from tools.recording import decay as decay_mod

        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.json", Path(d) / "b.json"
            old = Cassette()
            old.record("GET", LOCKS_URL, 200, {"properties": {"level": "x"}})
            old.save(a)
            old.save(b)
            self.assertEqual(decay_mod.main([str(a), str(b)]), 0)

            changed = Cassette()
            changed.record("GET", LOCKS_URL, 200, {"properties": {}})
            changed.save(b)
            self.assertEqual(decay_mod.main([str(a), str(b)]), 1)

    def test_the_cli_prints_the_aliases_a_replay_test_must_use(self):
        from tools.recording import decay as decay_mod

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "a.json"
            c = Cassette()
            c.record("GET", LOCKS_URL, 200, {"value": []})
            c.save(path)
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(decay_mod.main([str(path), "--aliases"]), 0)
            self.assertIn(alias_guid(SUB), out.getvalue())


class _FakeSdkResponse:
    """Minimal stand-in for an azure-core transport response."""

    def __init__(self, payload, status=200):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status_code = status

    def body(self):
        return self._payload


if __name__ == "__main__":
    unittest.main()
