"""Detect API decay by diffing a fresh recording against the committed one.

## The problem this exists for

Whether an absent property means "unset" or "default" is API-version-dependent
and is not derivable from a template - it is only observable by watching what
Azure returns. That makes a comparator proven correct in August quietly wrong in
November, with no failing test anywhere, because the unit tests encode our
beliefs and the beliefs did not change. Rounds have to run continuously just to
stand still.

Re-recording a cassette against a live estate and diffing it against the
committed one turns that invisible decay into a reviewable change.

## Shape, not values

Values are expected to differ between two recordings of the same estate - a tag
was edited, a capacity was scaled, a timestamp moved. Reporting those would bury
the signal. What matters is the SHAPE: a property Azure stopped returning,
started returning, or changed the type of.

A **removal is the dangerous direction**. A property that vanishes from the
response is exactly the case the comparator cannot distinguish from "someone
deleted this", so removals are reported first and separately.

Interaction keys include the api-version, so a collector moving to a new version
shows up as a whole key disappearing and another appearing - which is the right
way to see it, since none of the old shape evidence carries over.

## Usage

    python -m tools.recording.decay committed.json fresh.json
    python -m tools.recording.decay --aliases committed.json

Exit code is 1 when any shape changed, so it can gate a scheduled re-record.
"""

import argparse
import sys
from typing import Any

from .cassette import Cassette

#: Response fields that legitimately differ between two recordings of the same
#: estate and carry no schema information. Matched on the LAST path segment.
_VOLATILE_LEAVES = frozenset(
    {"etag", "changedtime", "createdtime", "lastmodifiedtime", "provisioningstate"}
)


def _shape(obj: Any, path: str = "") -> dict[str, str]:
    """Map of JSON path -> type name, with list indices collapsed to `[]`.

    Collapsing means a three-element and a five-element list of the same thing
    compare equal; only a list whose ELEMENTS changed shape is reported. Without
    it, every re-record of a growing estate would read as decay.
    """
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else key
            if key.lower() in _VOLATILE_LEAVES:
                continue
            out.update(_shape(value, child))
    elif isinstance(obj, list):
        for item in obj:
            out.update(_shape(item, f"{path}[]"))
    else:
        # None is recorded as its own "type": a property present-but-null is the
        # exact case that decides unset-vs-default, so it must not be flattened
        # into the type of whatever it held last time.
        out[path] = "null" if obj is None else type(obj).__name__
    return out


class Decay:
    """The shape difference between two cassettes."""

    def __init__(self, old: Cassette, new: Cassette) -> None:
        self.removed_keys = sorted(set(old.interactions) - set(new.interactions))
        self.added_keys = sorted(set(new.interactions) - set(old.interactions))
        self.removed_fields: dict[str, list[str]] = {}
        self.added_fields: dict[str, list[str]] = {}
        self.retyped_fields: dict[str, list[str]] = {}

        for key in sorted(set(old.interactions) & set(new.interactions)):
            before = _shape(old.interactions[key].body)
            after = _shape(new.interactions[key].body)
            gone = sorted(set(before) - set(after))
            new_fields = sorted(set(after) - set(before))
            retyped = sorted(
                f"{p}: {before[p]} -> {after[p]}"
                for p in set(before) & set(after)
                if before[p] != after[p]
            )
            if gone:
                self.removed_fields[key] = gone
            if new_fields:
                self.added_fields[key] = new_fields
            if retyped:
                self.retyped_fields[key] = retyped

    def __bool__(self) -> bool:
        return bool(
            self.removed_keys
            or self.added_keys
            or self.removed_fields
            or self.added_fields
            or self.retyped_fields
        )

    def report(self) -> str:
        lines: list[str] = []

        def section(title: str, mapping: dict[str, list[str]]) -> None:
            if not mapping:
                return
            lines.append(title)
            for key, entries in sorted(mapping.items()):
                lines.append(f"  {key}")
                lines.extend(f"    {e}" for e in entries)
            lines.append("")

        # Removals first and named bluntly: a property Azure stopped returning
        # is indistinguishable from a deletion to every comparator downstream.
        section(
            "FIELDS AZURE NO LONGER RETURNS "
            "(a comparator may now read these as deleted):",
            self.removed_fields,
        )
        section("FIELD TYPES THAT CHANGED:", self.retyped_fields)
        section("FIELDS AZURE NOW RETURNS (may need normalising or ignoring):",
                self.added_fields)
        if self.removed_keys:
            lines.append("REQUESTS NO LONGER MADE (moved api-version, or dropped):")
            lines.extend(f"  {k}" for k in self.removed_keys)
            lines.append("")
        if self.added_keys:
            lines.append("REQUESTS THAT ARE NEW (no prior shape evidence):")
            lines.extend(f"  {k}" for k in self.added_keys)
            lines.append("")
        return "\n".join(lines) if lines else "No shape change.\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.recording.decay", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("cassette", help="the committed cassette")
    parser.add_argument("fresh", nargs="?", help="a freshly recorded cassette")
    parser.add_argument(
        "--aliases",
        action="store_true",
        help="print the pseudonymised GUIDs in the cassette and exit; a "
             "cassette-backed test must drive the pipeline with these",
    )
    args = parser.parse_args(argv)

    old = Cassette.load(args.cassette)
    if args.aliases:
        for alias in sorted(old.sanitiser.known_aliases):
            print(alias)
        return 0
    if not args.fresh:
        parser.error("a second cassette is required unless --aliases is given")

    decay = Decay(old, Cassette.load(args.fresh))
    print(decay.report())
    return 1 if decay else 0


if __name__ == "__main__":
    sys.exit(main())
