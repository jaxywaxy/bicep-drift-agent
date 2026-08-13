"""Sanitise recorded Azure payloads before they are written to a cassette.

A cassette is a checked-in fixture. It is read by CI, it travels with the repo,
and the whole point of the corpus is that it can be shared - so nothing in it
may identify a real tenant, subscription, or principal, and nothing in it may
carry a credential.

Three separate concerns, deliberately not merged:

1. **Credentials** never reach the recorder at all. Request headers are dropped
   wholesale rather than filtered (see cassette.py) and URL query parameters in
   `_SECRET_QUERY_PARAMS` are stripped, because a bearer token or a SAS `sig=`
   is not something to be clever about.
2. **Secret-bearing property values** in response bodies go through the existing
   `tools/redact.py`, which is already the single definition of "this value is a
   secret" for the report artifact. Reusing it means a new secret key learned in
   one place is learned in both.
3. **Identifiers** (subscription, tenant, principal, and any other GUID) are
   replaced with a pseudonym derived by one-way hash.

## Why the pseudonyms are one-way and unmapped

`alias_guid` is `sha256(guid)` reformatted as a UUID. There is no mapping file,
in the cassette or beside it, so the real GUID cannot be recovered from a
committed fixture even by whoever recorded it. That is the property that makes
the corpus safe to ship with the repo.

It costs idempotence, which replay needs: a test drives the pipeline with the
*alias* subscription id, so sanitising an already-aliased URL must be a no-op or
no key would ever match. The cassette therefore carries the set of aliases it
used (aliases are safe - they are the pseudonyms), and `Sanitiser` seeds itself
from that set on load and passes those values through untouched.

A GUID that is neither a known alias nor being recorded is aliased normally,
which will simply fail to match any recorded key. That is the correct outcome:
replaying a cassette against a different subscription is a miss, and misses are
loud (see cassette.CassetteMiss).

## What is NOT pseudonymised: resource names

Deliberate. Name correspondence - `uniqueString()` placeholders, parent/child
qualification, sibling disambiguation - is the single largest defect family in
this codebase, and a corpus with scrambled names could not exercise it at all.
The corpus is recorded from a synthetic verification estate whose names are
already fictional, so there is nothing to protect. `Sanitiser(name_map=...)`
exists for the case where a corpus must be recorded from an estate whose names
are themselves sensitive; it is off by default because using it trades away
most of the fixture's value.
"""

import hashlib
import re
import urllib.parse
from typing import Any

from ..rbac import BUILTIN_ROLE_NAMES, PRIVILEGED_ROLE_GUIDS
from ..redact import redact_secrets

#: GUIDs that are PUBLIC Azure constants, not tenant data, and must survive
#: sanitising unchanged.
#:
#: Found by replaying a recorded scan and diffing it against its own recording:
#: three role-assignment drifts came back reading `8d36ee6f-… -> ServicePrincipal:…`
#: where the live run said `Owner -> …`. Aliasing had rewritten the built-in
#: role definition id, so `BUILTIN_ROLE_NAMES` no longer resolved it.
#:
#: The name was the visible half. The dangerous half is that the same GUID
#: decides `PRIVILEGED_ROLE_GUIDS` membership, so a replayed subscription-Owner
#: grant classified as NOT privileged - a fixture that silently softens
#: severity, which is the exact failure mode the corpus exists to end.
#:
#: Sourced from rbac.py rather than restated, so a role added there cannot be
#: forgotten here.
_PUBLIC_GUIDS = frozenset(
    g.lower() for g in (set(BUILTIN_ROLE_NAMES) | set(PRIVILEGED_ROLE_GUIDS))
)

#: Matches a bare GUID anywhere in a string (URL path, id, property value).
_GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

#: Query parameters that carry a credential. Dropped, not aliased - there is no
#: version of a SAS signature that is safe to keep.
_SECRET_QUERY_PARAMS = frozenset(
    {"sig", "sv", "se", "sp", "skoid", "sktid", "code", "access_token", "token"}
)


def alias_guid(guid: str) -> str:
    """Deterministic, non-reversible pseudonym for a GUID, in GUID shape.

    Shaped as a valid v4-looking UUID because Azure ids are parsed by callers
    (and by our own `_extract_resource_group_from_id`); a pseudonym that is not
    GUID-shaped would change code paths the fixture is supposed to exercise.
    """
    digest = hashlib.sha256(guid.lower().encode("utf-8")).hexdigest()
    return (
        f"{digest[0:8]}-{digest[8:12]}-4{digest[13:16]}-"
        f"8{digest[17:20]}-{digest[20:32]}"
    )


class Sanitiser:
    """Rewrites URLs and response bodies into their cassette-safe form.

    Stateful only in `known_aliases`, which makes sanitising idempotent so the
    same instance can be used to build a lookup key at replay time and a stored
    key at record time.
    """

    def __init__(
        self,
        known_aliases: set[str] | None = None,
        name_map: dict[str, str] | None = None,
    ) -> None:
        #: Aliases already in play - seeded from a loaded cassette, and grown as
        #: new GUIDs are aliased during a recording.
        self.known_aliases: set[str] = {a.lower() for a in (known_aliases or ())}
        self.name_map = {k.lower(): v for k, v in (name_map or {}).items()}

    def guid(self, value: str) -> str:
        """Alias one GUID, passing through public constants and known aliases."""
        if value.lower() in _PUBLIC_GUIDS:
            return value
        if value.lower() in self.known_aliases:
            return value.lower()
        alias = alias_guid(value)
        self.known_aliases.add(alias)
        return alias

    def text(self, value: str) -> str:
        """Alias every GUID in a string, then apply the optional name map."""
        out = _GUID_RE.sub(lambda m: self.guid(m.group(0)), value)
        for real, fake in self.name_map.items():
            out = re.sub(re.escape(real), fake, out, flags=re.IGNORECASE)
        return out

    def url(self, url: str) -> str:
        """Cassette-safe URL: credentials dropped, GUIDs aliased, query sorted.

        The query is sorted so that two requests differing only in parameter
        order produce one key. Callers build these URLs by f-string in a dozen
        collectors, and a key that depended on that ordering would turn a
        harmless edit into a silent cassette miss.
        """
        parts = urllib.parse.urlsplit(url)
        kept = [
            (k, v)
            for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in _SECRET_QUERY_PARAMS
        ]
        query = urllib.parse.urlencode(sorted(kept))
        rebuilt = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, "")
        )
        return self.text(rebuilt)

    def body(self, obj: Any) -> Any:
        """Cassette-safe response body: secrets redacted, then GUIDs aliased.

        Redaction runs FIRST so a secret is replaced before its characters are
        walked for GUIDs - a connection string containing an account GUID must
        end up as the redaction marker, not as a partially-aliased secret.
        """
        return self._walk(redact_secrets(obj))

    def _walk(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(v) for v in obj]
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, bytes):
            # urllib carries a request body as raw bytes. Without this branch a
            # POST body fell through untouched, putting the real subscription id
            # into both the stored interaction and the lookup key.
            return self.text(obj.decode("utf-8", "replace"))
        return obj
