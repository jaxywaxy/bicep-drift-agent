"""
tools/live_state/common.py

Small utilities shared across the live-state package:
- retry_with_backoff decorator for transient Azure errors
- resource-group selector helpers (KQL filter, glob detection, in-Python filter)
- id → RG-name extractor
- dedupe + child-name qualification passes that run over the assembled list
"""

import fnmatch
import logging
import re
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)

# Resource-group selectors that mean "the whole subscription" (no filter).
_ALL_RG_SELECTORS = {None, "", "*"}

# Legal Azure resource-group name: alphanumerics, underscores, parentheses,
# hyphens, periods (can't end in a period). Anything else is rejected before
# being interpolated into a KQL query - RG names arrive from LZ configs and
# workflow inputs, so this closes the KQL-injection surface.
_RG_NAME_RE = re.compile(r"^[\w\-\.\(\)]{1,90}$")

T = TypeVar('T')


def _kql_rg_filter(resource_group: str) -> str:
    """Build the KQL RG filter clause, validating the name first."""
    if not _RG_NAME_RE.match(resource_group or ""):
        raise ValueError(
            f"Invalid resource group name for query: {resource_group!r} "
            "(allowed: alphanumerics, '_', '-', '.', '(', ')')"
        )
    return f"Resources | where resourceGroup =~ '{resource_group}'"


def _is_rg_glob(selector: str | None) -> bool:
    """True if the selector is a glob (e.g. 'jacquidev-*') needing multi-RG match."""
    return bool(selector) and any(c in selector for c in "*?[")


def _extract_resource_group_from_id(resource_id: str) -> str | None:
    """Extract resource group name from Azure resource ID.

    Example: /subscriptions/SUB_ID/resourceGroups/MY_RG/providers/... → MY_RG
    """
    if not resource_id:
        return None
    parts = resource_id.lower().split('/')
    try:
        rg_index = parts.index('resourcegroups')
        if rg_index + 1 < len(parts):
            return parts[rg_index + 1]
    except (ValueError, IndexError):
        pass
    return None


def _rg_of(resource: dict) -> str:
    """Return a resource's resource-group name (from the field or its id)."""
    rg = resource.get("resource_group")
    if rg:
        return rg
    return _extract_resource_group_from_id(resource.get("id", "")) or ""


def _filter_by_rg_selector(resources: list[dict], selector: str | None) -> list[dict]:
    """Keep only resources whose RG matches a glob selector (case-insensitive).

    Used for a subscription-scoped scan restricted to a set of RGs (e.g. one
    landing-zone instance, 'jacquidev-*'). A None/'*'/exact selector is handled
    by the KQL query itself, so this is a no-op for those.
    """
    if not _is_rg_glob(selector):
        return resources
    sel = selector.lower()
    return [r for r in resources if fnmatch.fnmatch(_rg_of(r).lower(), sel)]


def _has_unresolved(value: str) -> bool:
    """True if a value still contains unresolved template expression markers."""
    v = (value or "").lower()
    return any(m in v for m in ("(", "[", "subscription-id", "parameters"))


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0) -> Callable:
    """Decorator to retry Azure SDK calls with exponential backoff.

    Retries on transient HTTP errors (5xx, 429 rate limiting). Non-transient
    errors fail immediately. Logs each retry and the final failure.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            last_error = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except HttpResponseError as e:
                    last_error = e
                    if e.status_code not in (429, 500, 502, 503, 504):
                        raise
                    if attempt < max_retries:
                        logger.debug(
                            f"Transient error in {func.__name__} (attempt {attempt + 1}/{max_retries}): "
                            f"HTTP {e.status_code}, retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= 2
                    else:
                        logger.warning(
                            f"Failed after {max_retries + 1} attempts in {func.__name__}: {e}"
                        )
                except Exception:
                    raise

            if last_error:
                raise last_error
            return func(*args, **kwargs)

        return wrapper
    return decorator


def _dedupe_resources_by_id(resources: list[dict]) -> None:
    """Drop rows whose resource id duplicates an earlier one (mutates in place).

    Resource Graph is progressively indexing child types (Cognitive Services
    projects, virtualNetworkLinks, ...), so an ARM-REST expansion can add a
    second copy of a row the base query already returned. First-seen wins:
    base Resource Graph rows precede expansion rows, and Graph rows carry
    richer properties. Rows without an id are always kept (nothing to key on).
    """
    seen: set = set()
    deduped: list[dict] = []
    dropped = 0
    for r in resources:
        rid = str(r.get("id") or "").lower()
        if rid and rid in seen:
            dropped += 1
            continue
        if rid:
            seen.add(rid)
        deduped.append(r)
    if dropped:
        logger.info(f"Deduped {dropped} duplicate live resource row(s) by id")
    resources[:] = deduped


def _qualify_child_resource_names(resources: list[dict]) -> None:
    """Give Resource-Graph-indexed child resources their parent-qualified name.

    Resource Graph returns some child rows (SQL databases, ...) with the BARE
    child name ('driftdb'), while bicep child resources compile to
    'parent/child' ('sqlserver1/driftdb') - so they can never match and
    double-report as missing + extra. A child type has more segments than its
    name; rebuild the full name from the resource id's path (which alternates
    type/name segments after the provider namespace). Mutates in place.
    """
    for r in resources:
        rtype = r.get("type") or ""
        name = r.get("name") or ""
        expected_segments = len(rtype.split("/")) - 1
        if expected_segments < 2 or name.count("/") == expected_segments - 1:
            continue
        rid = r.get("id") or ""
        marker = "/providers/"
        idx = rid.lower().rfind(marker)
        if idx < 0:
            continue
        segs = rid[idx + len(marker):].split("/")  # [namespace, typeA, nameA, typeB, nameB, ...]
        names = segs[2::2]
        if len(names) == expected_segments:
            r["name"] = "/".join(names)


# Re-exports for the package-internal typing marker.
__all__ = [
    "_ALL_RG_SELECTORS",
    "_RG_NAME_RE",
    "_dedupe_resources_by_id",
    "_extract_resource_group_from_id",
    "_filter_by_rg_selector",
    "_has_unresolved",
    "_is_rg_glob",
    "_kql_rg_filter",
    "_qualify_child_resource_names",
    "_rg_of",
    "retry_with_backoff",
    "Any",
]
