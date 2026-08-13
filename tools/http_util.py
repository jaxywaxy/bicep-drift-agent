"""Shared HTTP helper: urlopen() with an HTTP(S)-only scheme guard.

Callers here build ARM REST and GitHub API URLs that are always https, but
urllib also speaks file://, ftp://, data://, etc. Validating the scheme before
opening is cheap defense-in-depth against a URL ever being built from an
unexpected source, and keeps the dynamic-urllib call in exactly one place
(Semgrep dynamic-urllib-use).

It is also the single place every ARM REST read passes through, so the TLS
trust store is pinned here - see _trust_context.
"""

import functools
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

# Package-relative, with NO top-level fallback. The fallback that used to be
# here could not work and hid that fact: `tools.recording` imports `..rbac` and
# `..redact`, so loading it as a top-level `recording` raises "attempted
# relative import beyond top-level package" - one frame deeper than the
# ImportError being caught, and therefore uncatchable here. It took down the
# notification publisher on main. Every entry point now runs as a module
# (`python -m tools.x`), the only arrangement in which this package's relative
# imports are valid; see tests/test_entry_points_import.py.
from . import recording

_ALLOWED_SCHEMES = ("http", "https")

#: OpenSSL reads these itself, so a corporate proxy CA or a deliberately
#: narrowed bundle keeps working - the environment always wins over certifi.
_TRUST_ENV_VARS = ("SSL_CERT_FILE", "SSL_CERT_DIR")


@functools.lru_cache(maxsize=1)
def _trust_context() -> ssl.SSLContext:
    """Verification context backed by certifi's CA bundle.

    urllib verifies against the SYSTEM trust store, and a Python whose CAs were
    never installed (the default state of a python.org build on macOS) has an
    empty one. Every ARM REST call then fails CERTIFICATE_VERIFY_FAILED - and
    since a declared child with no collected counterpart is indistinguishable
    from a deleted one, the scan reports the gap as drift. A local run on
    2026-08-01 fabricated 27 `missing_in_azure` rows this way, on an estate
    where all 27 resources existed. The Azure SDK path never saw it: it ships
    its own bundle, so only the urllib path was exposed.

    Cached because building a context parses the whole bundle and a scan makes
    hundreds of these calls. Tests that change the environment must call
    `_trust_context.cache_clear()`.
    """
    if any(os.environ.get(var) for var in _TRUST_ENV_VARS):
        return ssl.create_default_context()
    try:
        import certifi
    except ImportError:  # pragma: no cover - certifi is a declared dependency
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def urlopen_checked(req, timeout=30):
    """urlopen() that refuses any non-HTTP(S) URL scheme.

    Accepts a urllib Request or a URL string, mirroring urllib.request.urlopen.
    Raises ValueError for schemes like file://, ftp://, or data://.

    Record/replay hangs off here rather than off a wrapper, because this really
    is the one place every ARM REST read passes through and a parallel path
    would make that claim false. Both hooks are no-ops unless a session is
    running (see tools/recording). Replay returns before any socket is opened;
    recording captures the real response - including HTTPError, since a 404 is
    load-bearing signal to callers like resource_group_exists, not noise.
    """
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Refusing to open non-HTTP(S) URL (scheme={scheme!r})")
    if recording.is_replaying():
        return recording.replay_urlopen(req)
    try:
        # Scheme validated above; only http/https reach urlopen.
        response = urllib.request.urlopen(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            req, timeout=timeout, context=_trust_context()
        )
    except urllib.error.HTTPError as e:
        recording.capture_http_error(req, e)
        raise
    return recording.capture_urlopen(req, response)
