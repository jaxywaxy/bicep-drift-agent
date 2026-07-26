"""Tests that the retry is actually WIRED INTO the read paths, not just correct
in isolation (tests/test_retry_backoff.py covers the decorator itself).

The failure this guards against is silent: a collector that goes back to plain
urlopen_checked still passes every drift test, because a throttled ARM endpoint
only shows up as a child expansion quietly missing from the scan. So each test
here drives a real collector with a transport that throws a transient error
first, and asserts the collector still produced its rows.

The write paths are asserted to be EXCLUDED: retrying a GitHub issue POST or a
Slack webhook would duplicate it. time.sleep is patched so backoff adds no delay.
"""

import io
import json
import os
import sys
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from azure.core.exceptions import HttpResponseError

from tools.live_state.collectors.appservice import _expand_appservice_config
from tools.live_state.collectors.backup import _query_backup_children
from tools.live_state.common import arm_urlopen
from tools.live_state.resource_graph import _run_resource_graph_query, get_live_state

# retry_with_backoff()'s default: 1 initial attempt + 3 retries.
MAX_ATTEMPTS = 4


def _http_error(code):
    return urllib.error.HTTPError(url="https://management.azure.com", code=code,
                                  msg="err", hdrs=None, fp=None)


def _sdk_error(status):
    e = HttpResponseError(message=f"HTTP {status}")
    e.status_code = status
    return e


def _response(payload):
    """A JSON body usable as `with arm_urlopen(...) as resp` - BytesIO is its own
    context manager and json.load reads binary."""
    return io.BytesIO(json.dumps(payload).encode())


class _FakeTransport:
    """Stands in for urlopen_checked: raises `errors` on the first N calls, then
    serves a payload per URL substring. Records every URL it was asked for."""

    def __init__(self, errors=(), payloads=None, default=None):
        self.errors = list(errors)
        self.payloads = payloads or {}
        self.default = default if default is not None else {}
        self.urls = []

    def __call__(self, req, timeout=30):
        url = req.full_url if isinstance(req, urllib.request.Request) else req
        self.urls.append(url)
        if self.errors:
            raise self.errors.pop(0)
        for fragment, payload in self.payloads.items():
            if fragment in url:
                return _response(payload)
        return _response(self.default)

    @property
    def calls(self):
        return len(self.urls)


class _RetryTestCase(unittest.TestCase):
    """Patches out the backoff sleep for every test in this module."""

    def setUp(self):
        mock.patch("tools.live_state.common.time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def patch_transport(self, transport):
        """Patch the opener arm_urlopen delegates to, so the decorator still runs."""
        return mock.patch("tools.live_state.common.urlopen_checked", transport).start()


class ArmUrlopenTests(_RetryTestCase):
    def test_delegates_request_and_timeout_to_urlopen_checked(self):
        checked = mock.Mock(return_value="resp")
        self.patch_transport(checked)
        req = urllib.request.Request("https://management.azure.com/x")

        self.assertEqual(arm_urlopen(req, timeout=17), "resp")
        checked.assert_called_once_with(req, timeout=17)

    def test_retries_transient_then_returns_the_response(self):
        transport = _FakeTransport(errors=[_http_error(429)], default={"ok": True})
        self.patch_transport(transport)

        with arm_urlopen(urllib.request.Request("https://management.azure.com/x")) as resp:
            self.assertEqual(json.load(resp), {"ok": True})
        self.assertEqual(transport.calls, 2)

    def test_non_transient_is_not_retried(self):
        transport = _FakeTransport(errors=[_http_error(404)])
        self.patch_transport(transport)

        with self.assertRaises(urllib.error.HTTPError):
            arm_urlopen(urllib.request.Request("https://management.azure.com/x"))
        self.assertEqual(transport.calls, 1)


class AppServiceCollectorRetryTests(_RetryTestCase):
    """_expand_appservice_config's inner _call goes through arm_urlopen, so a
    throttled config/web GET must not cost the site its siteConfig overlay -
    that overlay is the only reason TLS/ftpsState are compared at all."""

    SITE = {
        "type": "Microsoft.Web/sites",
        "name": "app-drift-test",
        "id": "/subscriptions/S/resourceGroups/rg/providers/Microsoft.Web/sites/app-drift-test",
        "resource_group": "rg",
        "properties": {"siteConfig": {"alwaysOn": True}},
    }

    def _run(self, errors):
        transport = _FakeTransport(
            errors=errors,
            payloads={
                "/config/web": {"id": "web-id", "properties": {"minTlsVersion": "1.2",
                                                               "ftpsState": None}},
                "/config/appsettings/list": {"id": "as-id", "properties": {"KEY": "secret"}},
            },
        )
        self.patch_transport(transport)
        site = json.loads(json.dumps(self.SITE))  # deep copy; the collector mutates it
        children = _expand_appservice_config([site], token="t")
        return children, site, transport

    def test_transient_on_config_web_still_yields_child_and_overlay(self):
        children, site, transport = self._run([_http_error(503), _http_error(429)])

        names = [c["name"] for c in children]
        self.assertIn("app-drift-test/web", names)
        self.assertIn("app-drift-test/appsettings", names)
        # The overlay landed, and the null from the GET did not clobber alwaysOn.
        self.assertEqual(site["properties"]["siteConfig"]["minTlsVersion"], "1.2")
        self.assertTrue(site["properties"]["siteConfig"]["alwaysOn"])
        self.assertEqual(transport.calls, 4)  # 2 failures + web + appsettings

    def test_exhausted_retries_skip_only_that_child(self):
        # config/web never recovers; appsettings (a separate _call) still succeeds.
        children, site, transport = self._run([_http_error(429)] * MAX_ATTEMPTS)

        self.assertEqual([c["name"] for c in children], ["app-drift-test/appsettings"])
        self.assertEqual(site["properties"]["siteConfig"], {"alwaysOn": True})  # untouched
        self.assertEqual(transport.calls, MAX_ATTEMPTS + 1)


class BackupCollectorRetryTests(_RetryTestCase):
    """vaults/backupconfig is invisible to Resource Graph, so a throttled fetch
    means softDeleteFeatureState is never compared - the drift goes silent."""

    VAULT = {
        "type": "Microsoft.RecoveryServices/vaults",
        "name": "rsv-drift-test",
        "id": "/subscriptions/S/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv-drift-test",
        "resource_group": "rg",
    }
    CONFIG = {"name": "vaultconfig", "id": "cfg-id",
              "properties": {"softDeleteFeatureState": "Enabled"}}

    def test_transient_retries_and_the_vault_config_still_lands(self):
        transport = _FakeTransport(errors=[_http_error(500)], default=self.CONFIG)
        self.patch_transport(transport)

        out = _query_backup_children([dict(self.VAULT)], "S", token="t")

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "rsv-drift-test/vaultconfig")
        self.assertEqual(out[0]["properties"]["softDeleteFeatureState"], "Enabled")
        self.assertEqual(transport.calls, 2)

    def test_exhausted_retries_log_and_skip_the_vault(self):
        transport = _FakeTransport(errors=[_http_error(503)] * MAX_ATTEMPTS)
        self.patch_transport(transport)

        out = _query_backup_children([dict(self.VAULT)], "S", token="t")

        self.assertEqual(out, [])  # sidecar contract: skip, don't sink the scan
        self.assertEqual(transport.calls, MAX_ATTEMPTS)


class ResourceGraphRetryTests(_RetryTestCase):
    """The Resource Graph query is the primary call; a 429 there must retry
    BEFORE the slower ResourceManagementClient fallback is chosen."""

    def test_query_retries_transient_then_succeeds(self):
        client = mock.Mock()
        client.resources.side_effect = [_sdk_error(429), _sdk_error(503), "response"]

        self.assertEqual(_run_resource_graph_query(client, mock.sentinel.request), "response")
        self.assertEqual(client.resources.call_count, 3)

    def test_fallback_is_used_only_after_retries_are_exhausted(self):
        client = mock.Mock()
        client.resources.side_effect = _sdk_error(503)
        fallback = mock.Mock(return_value=[{"name": "from-fallback"}])
        mock.patch("tools.live_state.resource_graph.ResourceGraphClient",
                   return_value=client).start()
        mock.patch("tools.live_state.resource_graph.DefaultAzureCredential").start()
        mock.patch("tools.live_state.resource_graph.QueryRequest").start()
        mock.patch("tools.live_state.resource_graph._get_live_state_fallback", fallback).start()

        result = get_live_state(resource_group="rg-drift-test", subscription_id="S")

        self.assertEqual(result, [{"name": "from-fallback"}])
        self.assertEqual(client.resources.call_count, MAX_ATTEMPTS)
        fallback.assert_called_once()


class WritePathsAreNotRetriedTests(unittest.TestCase):
    """Idempotent reads only. Re-running a GitHub issue POST or a webhook send
    would publish a duplicate, so those modules must keep their own opener."""

    def test_write_modules_do_not_use_arm_urlopen(self):
        import inspect

        from tools import publish_lz_issue, send_notifications

        for module in (publish_lz_issue, send_notifications):
            with self.subTest(module=module.__name__):
                self.assertNotIn("arm_urlopen", inspect.getsource(module))


if __name__ == "__main__":
    unittest.main()
