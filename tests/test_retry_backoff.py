"""Tests for retry_with_backoff (tools/live_state/common.py): it must retry the
transient 429/5xx statuses of BOTH exception types the Azure-facing calls raise
(azure SDK HttpResponseError and urllib HTTPError), and fail fast on everything
else. time.sleep is patched so the backoff adds no real delay.
"""
import unittest
import urllib.error
from unittest import mock

from azure.core.exceptions import HttpResponseError

from tools.live_state.common import retry_with_backoff


def _sdk_error(status):
    e = HttpResponseError(message=f"HTTP {status}")
    e.status_code = status
    return e


def _urllib_error(code):
    return urllib.error.HTTPError(url="https://x", code=code, msg="err", hdrs=None, fp=None)


class RetryBackoffTests(unittest.TestCase):
    def setUp(self):
        mock.patch("tools.live_state.common.time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def _flaky(self, errors):
        """A function that raises errors[0..n-1] on the first len(errors) calls,
        then returns 'ok'. Returns (decorated_fn, call_counter)."""
        calls = {"n": 0}

        @retry_with_backoff(max_retries=3, initial_delay=0.01)
        def f():
            calls["n"] += 1
            if calls["n"] <= len(errors):
                raise errors[calls["n"] - 1]
            return "ok"

        return f, calls

    def test_sdk_transient_retries_then_succeeds(self):
        f, calls = self._flaky([_sdk_error(503), _sdk_error(429)])
        self.assertEqual(f(), "ok")
        self.assertEqual(calls["n"], 3)  # 2 failures + 1 success

    def test_urllib_transient_retries_then_succeeds(self):
        f, calls = self._flaky([_urllib_error(429)])
        self.assertEqual(f(), "ok")
        self.assertEqual(calls["n"], 2)

    def test_sdk_non_transient_fails_fast(self):
        f, calls = self._flaky([_sdk_error(404)])
        with self.assertRaises(HttpResponseError):
            f()
        self.assertEqual(calls["n"], 1)  # 404 is not retried

    def test_urllib_non_transient_fails_fast(self):
        f, calls = self._flaky([_urllib_error(403)])
        with self.assertRaises(urllib.error.HTTPError):
            f()
        self.assertEqual(calls["n"], 1)

    def test_non_http_error_raises_immediately(self):
        f, calls = self._flaky([ValueError("boom")])
        with self.assertRaises(ValueError):
            f()
        self.assertEqual(calls["n"], 1)

    def test_exhausted_retries_raises_last_error(self):
        f, calls = self._flaky([_sdk_error(503)] * 10)  # always transient
        with self.assertRaises(HttpResponseError):
            f()
        self.assertEqual(calls["n"], 4)  # 1 initial + 3 retries


if __name__ == "__main__":
    unittest.main()
