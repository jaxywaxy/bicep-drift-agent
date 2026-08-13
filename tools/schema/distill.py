"""
tools/schema/distill.py

OFFLINE generator for the vendored Azure type-schema facts in
`tools/schema/data/az_type_flags.json`. Fetches `Azure/bicep-types-az`, walks
the type graph for every entry in `data/coverage.txt`, and writes the three
facts the comparator can actually use:

    write_only  - properties the RP declares as never-returned (flag 4)
    paths       - every property path declared at this type@apiVersion
    opaque      - prefixes below which the schema declares NOTHING, so a path
                  underneath them can never be judged absent

This is a build step, not part of a scan. The drift pipeline reads only the
vendored JSON (`tools/schema/flags.py`) and never reaches the network - a scan
that fetched schemas would make drift results depend on GitHub availability and
on whichever schema commit happened to be live that day.

    python -m tools.schema.distill                 # regenerate from coverage.txt
    python -m tools.schema.distill --check         # fail if the vendored file is stale

Why the flags are NOT a drop-in replacement for the hand-maintained
WRITE_ONLY_PROPERTIES: the flag is CONTRACTUAL (an RP author wrote
`x-ms-secret` / `x-ms-mutability` in the REST spec) while the hand list is
EMPIRICAL (Azure was observed not to return the value). Measured 2026-08-14,
the flag reproduces 2 of the 17 hand-listed paths across 7,829 declared paths -
Microsoft.Compute annotates none of the osProfile family at any API version
from 2021-07-01 to 2024-11-01. The vendored facts are therefore ADDITIVE, and
type-scoped: see tools/schema/flags.py.
"""

import argparse
import json
import os
import sys
import urllib.request
from functools import lru_cache

BASE = "https://raw.githubusercontent.com/Azure/bicep-types-az/main/generated/"
COMMIT_API = "https://api.github.com/repos/Azure/bicep-types-az/commits/main"

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
COVERAGE_FILE = os.path.join(DATA_DIR, "coverage.txt")
OUTPUT_FILE = os.path.join(DATA_DIR, "az_type_flags.json")

SCHEMA_VERSION = 1
WRITE_ONLY_FLAG = 4

#: Depth at which the walk stops descending. Anything deeper is recorded as
#: OPAQUE rather than dropped - a truncated branch must read as "we do not
#: know", never as "the schema does not declare it", or the existence check
#: would suppress real drift on deeply nested properties.
MAX_DEPTH = 8


@lru_cache(maxsize=None)
def _fetch(path: str) -> object:
    with urllib.request.urlopen(BASE + path) as response:
        return json.load(response)


def _resolve(ref: str, current_file: str) -> tuple[str, dict]:
    """'provider/types.json#/31' or a local '#/31' -> (file, type entry)."""
    file_part, _, index = ref.partition("#/")
    path = file_part or current_file
    return path, _fetch(path)[int(index)]


def _latest_stable(index: dict, resource_type: str) -> str | None:
    versions = [
        key for key in index["resources"]
        if key.lower().startswith(resource_type.lower() + "@")
    ]
    stable = [v for v in versions if "preview" not in v.lower()]
    return sorted(stable or versions)[-1] if versions else None


class _Walk:
    """Accumulates the three fact sets for one type@apiVersion."""

    def __init__(self):
        self.paths: set[str] = set()
        self.write_only: set[str] = set()
        self.opaque: set[str] = set()

    def visit(self, file: str, entry: dict, prefix: str, depth: int, seen: frozenset):
        kind = entry.get("$type")

        if depth >= MAX_DEPTH:
            # Truncation is an admission of ignorance, not a statement about
            # the schema. Record it so descendants stay unjudgeable.
            if prefix:
                self.opaque.add(prefix)
            return

        if kind == "ObjectType":
            # A free-form map (tags, userAssignedIdentities) declares no keys of
            # its own. Without this, `tags.env` would read as "not declared" and
            # the existence check would suppress every tag drift.
            if entry.get("additionalProperties") is not None and prefix:
                self.opaque.add(prefix)
            for name, prop in (entry.get("properties") or {}).items():
                path = f"{prefix}.{name}" if prefix else name
                self.paths.add(path)
                if prop.get("flags", 0) & WRITE_ONLY_FLAG:
                    self.write_only.add(path)
                ref = (prop.get("type") or {}).get("$ref")
                if not ref:
                    continue
                if (file, ref) in seen:
                    # Recursive type (a rule referencing its own shape). Same
                    # rule as truncation: unexpanded means unjudgeable.
                    self.opaque.add(path)
                    continue
                child_file, child = _resolve(ref, file)
                self.visit(child_file, child, path, depth + 1, seen | {(file, ref)})

        elif kind == "DiscriminatedObjectType":
            # Union members are recorded at the SAME prefix as the union itself:
            # a flattened live payload carries `properties.schedulePolicy`, not
            # `properties[AzureIaasVM].schedulePolicy`. Unioning the members
            # over-declares rather than under-declares, which is the safe
            # direction for an existence check.
            for element in (entry.get("elements") or {}).values():
                child_file, child = _resolve(element["$ref"], file)
                if (file, element["$ref"]) not in seen:
                    self.visit(child_file, child, prefix, depth + 1,
                               seen | {(file, element["$ref"])})

        elif kind == "AnyType":
            if prefix:
                self.opaque.add(prefix)

        elif kind == "ArrayType":
            # Arrays are NOT descended into: the comparator's flatten_dict keeps
            # arrays as native list values, so no flattened key ever addresses an
            # array element. Marked opaque rather than left silent so that if
            # some caller ever does present an element path, it reads as
            # unjudgeable instead of undeclared.
            if prefix:
                self.opaque.add(prefix)

        # UnionType/StringLiteralType/scalar types are leaves.


def distill(coverage: list[str]) -> dict:
    index = _fetch("index.json")
    types: dict[str, dict] = {}
    unresolved: list[str] = []

    for entry_spec in coverage:
        resource_type, _, pinned = entry_spec.partition("@")
        type_at_version = entry_spec if pinned else _latest_stable(index, resource_type)
        if not type_at_version or type_at_version not in index["resources"]:
            # Case in the index is the RP's own; coverage.txt is lowercased.
            match = next(
                (k for k in index["resources"] if k.lower() == (type_at_version or "").lower()),
                None,
            )
            if not match:
                unresolved.append(entry_spec)
                continue
            type_at_version = match

        file, resource = _resolve(index["resources"][type_at_version]["$ref"], "index.json")
        if resource.get("$type") == "ResourceType" and resource.get("body"):
            file, resource = _resolve(resource["body"]["$ref"], file)

        walk = _Walk()
        walk.visit(file, resource, "", 0, frozenset())

        rtype, _, version = type_at_version.partition("@")
        types.setdefault(rtype.lower(), {})[version.lower()] = {
            "paths": sorted(p.lower() for p in walk.paths),
            "write_only": sorted(p.lower() for p in walk.write_only),
            "opaque": sorted(p.lower() for p in walk.opaque),
        }

    if unresolved:
        print(f"WARNING: {len(unresolved)} coverage entries not in the index: "
              f"{', '.join(unresolved)}", file=sys.stderr)

    return {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "repo": "Azure/bicep-types-az",
            "commit": _source_commit(),
        },
        "types": dict(sorted(types.items())),
    }


def _source_commit() -> str:
    try:
        with urllib.request.urlopen(COMMIT_API) as response:
            return json.load(response).get("sha", "unknown")
    except Exception as exc:  # provenance only - never fail the build for it
        print(f"WARNING: could not read source commit: {exc}", file=sys.stderr)
        return "unknown"


def read_coverage(path: str = COVERAGE_FILE) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [
            line.strip().lower()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[3])
    parser.add_argument("--coverage", default=COVERAGE_FILE)
    parser.add_argument("--out", default=OUTPUT_FILE)
    parser.add_argument("--check", action="store_true",
                        help="regenerate in memory and diff against the vendored file")
    args = parser.parse_args(argv)

    distilled = distill(read_coverage(args.coverage))
    rendered = json.dumps(distilled, indent=1, sort_keys=True) + "\n"

    if args.check:
        with open(args.out, encoding="utf-8") as fh:
            current = json.load(fh)
        # The upstream commit moves on its own; compare the FACTS only.
        if current.get("types") != distilled["types"]:
            print("STALE: vendored schema facts differ from upstream", file=sys.stderr)
            return 1
        print("vendored schema facts are current")
        return 0

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    counts = distilled["types"]
    versions = sum(len(v) for v in counts.values())
    paths = sum(len(d["paths"]) for v in counts.values() for d in v.values())
    write_only = sum(len(d["write_only"]) for v in counts.values() for d in v.values())
    print(f"wrote {args.out}: {len(counts)} types, {versions} type@version pairs, "
          f"{paths} paths, {write_only} write-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
