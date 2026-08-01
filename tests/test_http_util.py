"""urlopen_checked rejects non-HTTP(S) schemes (defense-in-depth vs file://).

The ARM/GitHub callers build https URLs, but urllib also speaks file://, ftp://,
data://; the guard refuses those before urlopen ever sees them (and centralises
the one dynamic-urllib call Semgrep flags).

It is also where the TLS trust store is pinned. urllib verifies against the
SYSTEM store, and a Python whose CAs were never installed has an empty one - so
every ARM REST call failed CERTIFICATE_VERIFY_FAILED and 27 declared children
false-flagged as missing_in_azure on a local run (2026-08-01). The failure is
silent-by-construction: an uncollected child looks exactly like a deleted one.
"""

import os
import ssl
import sys
import tempfile
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.http_util import _trust_context, urlopen_checked


class UrlopenCheckedTests(unittest.TestCase):
    def test_rejects_file_scheme(self):
        with self.assertRaises(ValueError):
            urlopen_checked(urllib.request.Request("file:///etc/passwd"))

    def test_rejects_ftp_and_data_schemes(self):
        for bad in ("ftp://host/x", "data:text/plain,hi"):
            with self.assertRaises(ValueError):
                urlopen_checked(urllib.request.Request(bad))

    def test_rejects_plain_string_url_too(self):
        # Accepts a URL string as well as a Request, like urllib.request.urlopen.
        with self.assertRaises(ValueError):
            urlopen_checked("file:///etc/passwd")

    def test_https_passes_the_scheme_guard(self):
        # https must get PAST the guard (it then fails to connect, which is fine
        # - a ValueError here would mean the guard wrongly blocked it).
        try:
            urlopen_checked(
                urllib.request.Request("https://management.azure.com/"), timeout=1
            )
        except ValueError:
            self.fail("https URL was blocked by the scheme guard")
        except Exception:
            pass  # network/URL errors are expected and acceptable


class TrustStoreTests(unittest.TestCase):
    """The context must carry a usable CA set - an empty one is the bug."""

    def setUp(self):
        _trust_context.cache_clear()

    def tearDown(self):
        _trust_context.cache_clear()

    def test_the_context_actually_has_certificate_authorities(self):
        # The whole defect was a context with nothing to verify against.
        self.assertTrue(_trust_context().get_ca_certs())

    def test_verification_is_not_weakened(self):
        ctx = _trust_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_urlopen_is_given_the_context(self):
        """Drives the real urlopen_checked - asserting on _trust_context alone
        would pass even if nothing wired it into the call."""
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen_checked(urllib.request.Request("https://example.invalid/x"))
        ctx = urlopen.call_args.kwargs["context"]
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.get_ca_certs())

    def test_the_environment_wins_over_certifi(self):
        """A corporate proxy CA (or any deliberately narrowed bundle) must not
        be overridden - SSL_CERT_FILE is what OpenSSL itself reads."""
        one_cert = _trust_context().get_ca_certs(binary_form=True)[0]
        _trust_context.cache_clear()
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(one_cert))
            narrow_bundle = f.name
        try:
            with mock.patch.dict(os.environ, {"SSL_CERT_FILE": narrow_bundle}):
                self.assertEqual(len(_trust_context().get_ca_certs()), 1)
        finally:
            os.unlink(narrow_bundle)

    def test_the_scheme_guard_still_runs_first(self):
        # A bad scheme must be refused before any TLS work happens.
        with mock.patch("urllib.request.urlopen") as urlopen, \
                self.assertRaises(ValueError):
            urlopen_checked("file:///etc/passwd")
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
