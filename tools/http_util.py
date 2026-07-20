"""Shared HTTP helper: urlopen() with an HTTP(S)-only scheme guard.

Callers here build ARM REST and GitHub API URLs that are always https, but
urllib also speaks file://, ftp://, data://, etc. Validating the scheme before
opening is cheap defense-in-depth against a URL ever being built from an
unexpected source, and keeps the dynamic-urllib call in exactly one place
(Semgrep dynamic-urllib-use).
"""

import urllib.parse
import urllib.request

_ALLOWED_SCHEMES = ("http", "https")


def urlopen_checked(req, timeout=30):
    """urlopen() that refuses any non-HTTP(S) URL scheme.

    Accepts a urllib Request or a URL string, mirroring urllib.request.urlopen.
    Raises ValueError for schemes like file://, ftp://, or data://.
    """
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Refusing to open non-HTTP(S) URL (scheme={scheme!r})")
    # Scheme validated above; only http/https reach urlopen.
    return urllib.request.urlopen(req, timeout=timeout)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
