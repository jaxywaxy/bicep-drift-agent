"""On-disk record of what Azure actually returned, and the lookup over it.

## Why this exists

Every fixture in `tests/` today is a payload someone typed by hand. That makes
the suite an encoding of *our beliefs* about Azure: a wrong belief produces a
green test, which is exactly how 1,366 passing tests failed to catch a deletion
false negative, and how two backup comparators shipped dead for a month. A
cassette replaces the belief with evidence - the bytes a real subscription sent
back, for a real API version, on a known date.

The second job is decay. Whether an absent property means "unset" or "default"
is API-version-dependent and is not derivable from a template; it is only
observable by watching what Azure returns. Re-recording a cassette and diffing
it against the committed one turns that invisible drift-in-the-drift-detector
into a reviewable change (see `decay.py`).

## Keying

`(method, sanitised URL, canonical request body)`. The api-version query
parameter is part of the URL and therefore part of the key, on purpose: a
collector that moves to a new api-version *should* miss the old cassette rather
than quietly replay a payload that version never produced.

One response per key. These are all idempotent reads, so two identical requests
returning different bodies would be non-determinism this pipeline forbids
outright ("a given (bicep, live-state, ignore-profile) triple must produce the
same drift set every time"). Recording the same key twice with a different body
warns rather than building a sequence to replay in order.

## Misses raise

`CassetteMiss` is an exception and never a default value. A replayer that
answered a miss with `[]` would be worse than useless here: an empty collection
is indistinguishable from a deleted resource, so every unmatched request would
manufacture `missing_in_azure` rows while the suite stayed green - the same
shape as the failure this whole exercise is meant to end.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sanitize import Sanitiser

logger = logging.getLogger(__name__)

#: Bumped when the on-disk shape changes incompatibly, so a stale cassette is
#: rejected outright instead of half-matching.
CASSETTE_VERSION = 1


class CassetteMiss(LookupError):
    """A replayed request has no recorded response.

    Carries the near-miss candidates because the overwhelmingly common cause is
    a changed api-version or a changed URL shape, and the diff between the
    wanted key and the closest recorded one says so immediately.
    """

    def __init__(self, key: str, candidates: list[str]) -> None:
        detail = "\n  ".join(candidates[:5]) or "(cassette is empty)"
        super().__init__(
            f"No recorded response for:\n  {key}\n"
            f"Closest recorded keys:\n  {detail}\n"
            "Re-record the cassette if the request shape changed legitimately."
        )
        self.key = key
        self.candidates = candidates


@dataclass
class Interaction:
    """One request/response pair, already sanitised."""

    method: str
    url: str
    status: int
    body: Any = None
    #: Present only for requests that carry one (Resource Graph KQL POSTs).
    request_body: Any = None
    #: Free-text note about provenance, e.g. which estate and scan it came from.
    note: str = ""

    def to_dict(self) -> dict:
        out = {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "body": self.body,
        }
        if self.request_body is not None:
            out["request_body"] = self.request_body
        if self.note:
            out["note"] = self.note
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "Interaction":
        return cls(
            method=d["method"],
            url=d["url"],
            status=d.get("status", 200),
            body=d.get("body"),
            request_body=d.get("request_body"),
            note=d.get("note", ""),
        )


def _canonical(obj: Any) -> str:
    """Stable string for a request body, so key building never depends on dict
    ordering - which json.dumps would otherwise leak into the key."""
    if obj is None:
        return ""
    if isinstance(obj, (str, bytes)):
        text = obj.decode("utf-8", "replace") if isinstance(obj, bytes) else obj
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            return text
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass
class Cassette:
    """A keyed collection of recorded interactions, loadable from and saved to
    a single JSON file."""

    interactions: dict[str, Interaction] = field(default_factory=dict)
    sanitiser: Sanitiser = field(default_factory=Sanitiser)
    #: Provenance for humans reviewing a re-record diff. Never keyed on.
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- keying ----------------------------------------------------------

    def key_for(self, method: str, url: str, request_body: Any = None) -> str:
        """The lookup key for a request, sanitising as it goes.

        Used for BOTH recording and replay so the two can never disagree about
        what a key looks like - the single-definition rule that the identity
        matching in this codebase learned the hard way.
        """
        safe_url = self.sanitiser.url(url)
        safe_body = _canonical(self.sanitiser.body(request_body) if request_body else None)
        suffix = f" {safe_body}" if safe_body else ""
        return f"{method.upper()} {safe_url}{suffix}"

    # -- recording -------------------------------------------------------

    def record(
        self,
        method: str,
        url: str,
        status: int,
        body: Any,
        request_body: Any = None,
        note: str = "",
    ) -> None:
        """Store one sanitised interaction, warning on a conflicting re-record."""
        key = self.key_for(method, url, request_body)
        interaction = Interaction(
            method=method.upper(),
            url=self.sanitiser.url(url),
            status=status,
            body=self.sanitiser.body(body),
            request_body=self.sanitiser.body(request_body) if request_body else None,
            note=note,
        )
        existing = self.interactions.get(key)
        if existing is not None and existing.body != interaction.body:
            logger.warning(
                "Cassette: %s returned a different body on a repeat read. "
                "Keeping the first. An idempotent read that is not idempotent "
                "is worth investigating before trusting this fixture.",
                key,
            )
            return
        self.interactions[key] = interaction

    # -- replay ----------------------------------------------------------

    def lookup(self, method: str, url: str, request_body: Any = None) -> Interaction:
        """The recorded response for a request, or raise `CassetteMiss`."""
        key = self.key_for(method, url, request_body)
        found = self.interactions.get(key)
        if found is None:
            raise CassetteMiss(key, self._near_misses(key))
        return found

    def _near_misses(self, key: str) -> list[str]:
        """Recorded keys sharing the longest prefix with the wanted one.

        A prefix match rather than an edit distance because the discriminating
        part of these URLs is at the end - the api-version and the child type -
        so the closest prefix is reliably the key someone actually meant.
        """
        def shared(candidate: str) -> int:
            n = 0
            for a, b in zip(key, candidate):
                if a != b:
                    break
                n += 1
            return n

        return sorted(self.interactions, key=shared, reverse=True)

    # -- persistence -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": CASSETTE_VERSION,
            "metadata": self.metadata,
            # Sorted so a re-record produces a reviewable line diff rather than
            # a reshuffle - decay detection depends on this being readable.
            "aliases": sorted(self.sanitiser.known_aliases),
            "interactions": {
                k: self.interactions[k].to_dict() for k in sorted(self.interactions)
            },
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        logger.info("Cassette: wrote %d interaction(s) to %s", len(self.interactions), path)

    @classmethod
    def load(cls, path: str | Path) -> "Cassette":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        version = raw.get("version")
        if version != CASSETTE_VERSION:
            raise ValueError(
                f"Cassette {path} is version {version!r}, this build reads "
                f"{CASSETTE_VERSION}. Re-record it rather than half-matching."
            )
        return cls(
            interactions={
                k: Interaction.from_dict(v) for k, v in raw.get("interactions", {}).items()
            },
            sanitiser=Sanitiser(known_aliases=set(raw.get("aliases", ()))),
            metadata=raw.get("metadata", {}),
        )

    def merge(self, other: "Cassette") -> None:
        """Fold another cassette's interactions in. Used to assemble one corpus
        from several scans (per-RG, per-scope) without re-running them all."""
        self.sanitiser.known_aliases |= other.sanitiser.known_aliases
        for key, interaction in other.interactions.items():
            self.interactions.setdefault(key, interaction)

    def __len__(self) -> int:
        return len(self.interactions)
