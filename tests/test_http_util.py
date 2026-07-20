"""urlopen_checked rejects non-HTTP(S) schemes (defense-in-depth vs file://).

The ARM/GitHub callers build https URLs, but urllib also speaks file://, ftp://,
data://; the guard refuses those before urlopen ever sees them (and centralises
the one dynamic-urllib call Semgrep flags)."""

import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.http_util import urlopen_checked


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


if __name__ == "__main__":
    unittest.main()
