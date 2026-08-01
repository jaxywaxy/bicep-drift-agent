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
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from azure.core.exceptions import HttpResponseError

from ..http_util import urlopen_checked

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
    """True if the selector is a glob (e.g. 'contosodev-*') needing multi-RG match."""
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
    landing-zone instance, 'contosodev-*'). A None/'*'/exact selector is handled
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


# 429 (throttling) and 5xx are transient; anything else is a real answer.
_TRANSIENT_STATUS = (429, 500, 502, 503, 504)


def _transient_status(err: Exception) -> int | None:
    """The retryable HTTP status of an error, or None. Bridges the two exception
    types the Azure-facing calls raise: azure SDK HttpResponseError (.status_code)
    and urllib HTTPError (.code)."""
    status = getattr(err, "status_code", None)
    if status is None:
        status = getattr(err, "code", None)  # urllib.error.HTTPError
    return status if status in _TRANSIENT_STATUS else None


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0) -> Callable:
    """Retry an Azure-facing call on transient HTTP errors with exponential backoff.

    Handles both exception types the codebase raises: azure SDK HttpResponseError
    (Resource Graph / ARM SDK) and urllib HTTPError (the raw ARM REST collectors).
    Only 429 and 5xx are retried; every other status - and any non-HTTP error -
    fails immediately. Logs each retry (debug) and the final give-up (warning).
    Decorate idempotent reads only, never non-idempotent writes.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (HttpResponseError, urllib.error.HTTPError) as e:
                    status = _transient_status(e)
                    if status is None or attempt >= max_retries:
                        if status is not None:
                            logger.warning(
                                f"Failed after {max_retries + 1} attempts in {func.__name__}: {e}"
                            )
                        raise
                    logger.debug(
                        f"Transient error in {func.__name__} (attempt {attempt + 1}/{max_retries}): "
                        f"HTTP {status}, retrying in {delay}s..."
                    )
                    time.sleep(delay)
                    delay *= 2
            return func(*args, **kwargs)  # unreachable; keeps type checkers happy

        return wrapper
    return decorator


class ScopeNotFoundError(Exception):
    """The scan scope itself could not be confirmed to exist.

    Distinct from "the scope is empty". Resource Graph answers a query for a
    resource group that does not exist with a SUCCESSFUL, empty result set -
    byte-identical to a resource group that exists and holds nothing. Treating
    the first as drift turns one configuration error (a decommissioned or
    renamed RG, a stale lz-index entry, the wrong subscription) into one
    'deleted' finding per declared resource, at maximum severity, routed to
    whoever owns the landing zone. That is the loudest possible alarm carrying
    the least real signal.

    Same principle as the per-type CollectionGaps one level up: a thing we
    could not read is unverified, never deleted.
    """


def resource_group_exists(
    resource_group: str, sub_id: str, token: str | None = None
) -> bool | None:
    """Does the resource group exist? None when the question cannot be settled.

    Deliberately tri-state. False is a definitive 404 from ARM; None means the
    check itself failed (403, network, no credential) and the caller must not
    read it as either answer. Callers treat None the same as False for the
    purpose of *not* reporting mass deletion, because an unverifiable scope is
    exactly as unsafe to report on as an absent one.
    """
    if not resource_group or not sub_id:
        return None
    try:
        if token is None:
            from azure.identity import DefaultAzureCredential
            token = DefaultAzureCredential().get_token(
                "https://management.azure.com/.default"
            ).token
        url = (
            f"https://management.azure.com/subscriptions/{sub_id}"
            f"/resourcegroups/{resource_group}?api-version=2021-04-01"
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with arm_urlopen(req, timeout=30) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        logger.warning(f"Could not confirm resource group '{resource_group}' exists: HTTP {e.code}")
        return None
    except Exception as e:
        logger.warning(f"Could not confirm resource group '{resource_group}' exists: {e}")
        return None


@retry_with_backoff()
def arm_urlopen(req, timeout: int = 30):
    """urlopen_checked with transient-error retry, for idempotent ARM REST reads.

    The live-state collectors use this instead of urlopen_checked so a throttled
    (429) or briefly-unavailable (5xx) ARM endpoint is retried rather than
    silently dropping a child-resource expansion. Reads only (incl. ARM
    list-via-POST) - never non-idempotent writes."""
    return urlopen_checked(req, timeout=timeout)


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


class CollectionGaps:
    """Resource types the collectors could not read on this run.

    Every collector logs-and-skips so one ARM outage never sinks a scan - the
    documented sidecar contract. The cost is silent: a declared child with no
    collected counterpart is INDISTINGUISHABLE from a deleted one, so a failed
    listing turns straight into `missing_in_azure`. A local run on 2026-08-01
    produced 27 such rows for resources that all existed, and the data-plane
    expander's own comment records an earlier one (a transient agentPools
    failure reporting a healthy declared pool as deleted).

    Recording the failure lets the diff say "could not verify" instead of
    "gone". Cannot collect is not the same as is not there.
    """

    def __init__(self) -> None:
        self._reasons: dict[str, str] = {}

    def record(self, resource_type: str | None, reason: str) -> None:
        """Note that `resource_type` could not be collected. First reason wins -
        a per-parent loop can fail many times for one type and the first failure
        is the informative one."""
        if not resource_type:
            return
        self._reasons.setdefault(str(resource_type).lower(), str(reason))

    def record_all(self, resource_types, reason: str) -> None:
        """Record one reason against every type a failed collector owns."""
        for resource_type in resource_types or ():
            self.record(resource_type, reason)

    def covers(self, resource_type: str | None) -> bool:
        return bool(resource_type) and str(resource_type).lower() in self._reasons

    def reason_for(self, resource_type: str | None) -> str | None:
        return self._reasons.get(str(resource_type or "").lower())

    def as_dict(self) -> dict[str, str]:
        """Sorted so a report artifact is byte-stable across runs."""
        return dict(sorted(self._reasons.items()))

    def __bool__(self) -> bool:
        return bool(self._reasons)

    def __len__(self) -> int:
        return len(self._reasons)


# Re-exports for the package-internal typing marker.
__all__ = [
    "_ALL_RG_SELECTORS",
    "_RG_NAME_RE",
    "CollectionGaps",
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
