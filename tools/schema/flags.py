"""
tools/schema/flags.py

Runtime lookup over the vendored Azure type-schema facts. Offline by
construction: reads `data/az_type_flags.json` (produced by `distill.py`) and
never touches the network, so a scan's result does not depend on GitHub being
up or on which upstream commit was live that day.

Two facts are exposed, and BOTH are type-scoped:

  is_write_only(rtype, api_version, path)
      the RP declares this property as never returned, so a desired-vs-null
      diff on it is noise.

  property_declared(rtype, api_version, path) -> True | False | None
      whether the type declares this path at this apiVersion. **None means
      "not covered", and every caller must treat None as "do not act"** - the
      vendored corpus is deliberately partial.

Why type-scoped, when the hand-maintained WRITE_ONLY_PROPERTIES is global:
the hand list was curated path by path to be safe everywhere, the schema list
was not. Microsoft.Resources/deployments marks `identity` write-only and
Microsoft.Web/sites marks `properties.siteConfig`; folding either into a global
list would blind identity drift on every resource in the estate and siteConfig
drift on every Function App. Schema facts only ever apply to the type that
declared them.
"""

import json
import os
from functools import lru_cache

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "az_type_flags.json")

SUPPORTED_SCHEMA_VERSION = 1


@lru_cache(maxsize=1)
def _facts() -> dict:
    """Load the vendored facts. A missing or unreadable file disables every
    schema-derived check rather than failing the scan - these checks refine an
    existing signal, they are not a precondition for producing one."""
    try:
        with open(DATA_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if data.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        return {}
    return data.get("types") or {}


def _entry(rtype: str, api_version: str | None) -> dict | None:
    if not rtype or not api_version:
        return None
    versions = _facts().get(rtype.lower())
    if not versions:
        return None
    return versions.get(api_version.lower())


def _under(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p + ".") for p in prefixes)


def is_write_only(rtype: str, api_version: str | None, property_path: str) -> bool:
    """True if this type declares the path (or an ancestor of it) write-only."""
    entry = _entry(rtype, api_version)
    if not entry:
        return False
    return _under((property_path or "").lower(), entry["write_only"])


def property_declared(rtype: str, api_version: str | None, property_path: str) -> bool | None:
    """Does this type@apiVersion declare this property path?

    Returns None when the answer is unknowable: the type@apiVersion is not in
    the vendored corpus, or the path sits under a prefix the schema leaves
    open (a free-form map like `tags`, an untyped `any`, an array element, or a
    branch the distiller truncated). Callers must not treat None as False -
    "the schema does not cover this" and "the schema says this cannot exist"
    are opposite conclusions.
    """
    entry = _entry(rtype, api_version)
    if not entry:
        return None

    path = (property_path or "").lower()
    if not path:
        return None
    # Granular comparators synthesise indexed paths (ruleCollections[0].rules);
    # those address array elements, which the corpus deliberately omits.
    if "[" in path:
        return None
    if _under(path, entry["opaque"]):
        return None
    if path in entry["paths"]:
        return True
    # A path whose ANCESTOR is declared but which is not itself declared is a
    # genuine "not in this API version" - the distiller expands every object it
    # does not mark opaque, so an unexpanded parent would have been opaque.
    return False


def covered_versions(rtype: str) -> list[str]:
    """API versions covered for a type. Diagnostics and tests only."""
    return sorted((_facts().get((rtype or "").lower()) or {}).keys())


def coverage_size() -> tuple[int, int]:
    """(types, type@version pairs) in the vendored corpus. Used by the
    guard-the-guard test: a corpus that silently emptied would make every
    schema-derived check a no-op while the suite stayed green."""
    facts = _facts()
    return len(facts), sum(len(v) for v in facts.values())
