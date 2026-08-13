"""
tools/schema/

Vendored facts derived from `Azure/bicep-types-az`, and the offline build step
that produces them.

    flags.py    - runtime lookup (offline, used by the comparator)
    distill.py  - build step that regenerates data/az_type_flags.json
    data/       - coverage.txt (what to cover) + az_type_flags.json (the facts)

The facts are ADDITIVE and TYPE-SCOPED. They do not replace the hand-maintained
suppression lists in tools/property_drift/severity.py: measured across the 73
types this repo has opinions about, the schema's WriteOnly flag reproduces 2 of
the 17 hand-listed paths, because the flag records what an RP author annotated
while the hand list records what Azure was observed to return.
"""

from .flags import is_write_only, property_declared

__all__ = ["is_write_only", "property_declared"]
