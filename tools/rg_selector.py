"""
Resolve a check's ``resource_groups`` selectors into concrete resource groups.

Phase 4 #4 (subscription-scope checks): a check may target a whole subscription
or a glob of resource groups rather than an explicit list, e.g.

    resource_groups: ["*"]              # every RG in the subscription
    resource_groups: ["rg-conn-*"]      # all RGs matching the glob
    resource_groups: ["rg-hub", "rg-*-spoke"]   # mix of explicit + glob

The expansion is done BEFORE the per-RG loop so each resolved RG still runs the
full single-RG pipeline (ignore filtering + owner tagging + per-RG JSON report),
which is what owner-based notification routing depends on. This module is pure
(no Azure SDK): the caller supplies the list of available RGs (from ``az group
list``) so the logic stays unit-testable.
"""

import fnmatch
import sys
from typing import List

WILDCARD = "*"
_GLOB_CHARS = set("*?[]")


def is_glob(pattern: str) -> bool:
    """True if the selector is a glob (contains wildcard characters)."""
    return any(c in _GLOB_CHARS for c in pattern)


def needs_expansion(patterns: List[str]) -> bool:
    """True if any selector is a wildcard/glob and the caller must enumerate RGs."""
    return any(is_glob(p) for p in patterns)


def resolve_resource_groups(patterns: List[str], available: List[str]) -> List[str]:
    """Expand ``resource_groups`` selectors against the available RGs.

    Rules (order preserved, duplicates removed):
      * ``*``                -> every available RG.
      * a glob (``rg-a-*``)  -> every available RG matching it (case-insensitive).
      * a plain name         -> kept as-is even if not currently in ``available``,
                                so an explicitly named but undeployed RG still
                                surfaces as missing-resource drift (existing
                                behavior for explicit names is unchanged).

    A glob that matches nothing contributes nothing (and is not an error).
    """
    available = list(available or [])
    avail_lower = {a.lower(): a for a in available}
    resolved: List[str] = []
    seen = set()

    def _add(rg: str):
        if rg and rg not in seen:
            seen.add(rg)
            resolved.append(rg)

    for pattern in patterns or []:
        pattern = (pattern or "").strip()
        if not pattern:
            continue
        if pattern == WILDCARD:
            for rg in sorted(available, key=str.lower):
                _add(rg)
        elif is_glob(pattern):
            matches = [a for low, a in avail_lower.items()
                       if fnmatch.fnmatch(low, pattern.lower())]
            for rg in sorted(matches, key=str.lower):
                _add(rg)
        else:
            _add(pattern)

    return resolved


def _main(argv: List[str]) -> int:
    """CLI: expand selectors, reading available RGs (one per line) from stdin.

    Usage:  az group list --query "[].name" -o tsv \\
              | python3 -m tools.rg_selector 'rg-conn-*' '*' rg-hub
    Prints the resolved RGs, one per line.
    """
    patterns = argv[1:]
    available = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    for rg in resolve_resource_groups(patterns, available):
        print(rg)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
