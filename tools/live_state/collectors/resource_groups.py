"""Resource groups via Resource Graph's ResourceContainers table.

Resource Graph's `Resources` table contains NO resource groups - verified
against a live subscription, it returns a count of zero for
`microsoft.resources/subscriptions/resourcegroups`. They live in a separate
table, `ResourceContainers`.

A subscription-scoped template DECLARES its resource groups: in a CAF platform
landing zone the RGs are part of what the template owns, not incidental
infrastructure. So the flattener stops skipping them at that scope - and
without this collector every declared RG would compare against nothing and
report missing_in_azure across every subscription-scoped landing zone.

Collector before comparator, in that order. The reverse order is how the backup
comparators shipped dead for a month (see
tests/test_ignore_patterns.CollectedTypesAreNotBlanketIgnoredTests). Living in
this directory is also what puts the type under that structural guard, so a
future type-only ignore rule cannot silently discard it.

At resource-group scope this is not collected at all: there the RG is the frame
of the scan rather than a resource inside it, and its absence is a targeting
failure handled before the diff.
"""

import logging

logger = logging.getLogger(__name__)

RESOURCE_GROUP_TYPE = "Microsoft.Resources/resourceGroups"

_KQL = (
    "ResourceContainers "
    "| where type =~ 'microsoft.resources/subscriptions/resourcegroups' "
    "| project name, location, tags, id"
)


def query_resource_groups(run_query, sub_id: str, gaps=None) -> list[dict]:
    """Fetch the subscription's resource groups as comparable resources.

    `run_query` is injected (rather than building a client here) so this stays
    testable without a live Resource Graph and so the caller's retry-wrapped,
    PAGED query path is reused. It takes KQL and returns every matching row -
    not a single response object, because one response is only the first page
    and a subscription's resource groups can exceed it like anything else.

    A failure records a collection gap and returns nothing: "we could not read
    the resource groups" must never render as "the resource groups are gone".
    """
    try:
        rows = run_query(_KQL)
    except Exception as e:
        logger.warning(f"Could not read resource groups: {e}")
        if gaps is not None:
            gaps.record(RESOURCE_GROUP_TYPE, f"resource-group query failed: {e}")
        return []

    groups = [
        {
            "type": RESOURCE_GROUP_TYPE,
            "name": item.get("name"),
            "location": item.get("location"),
            "tags": item.get("tags", {}),
            "sku": None,
            "kind": None,
            "zones": None,
            "properties": {},
            "id": item.get("id"),
            "resource_group": item.get("name"),
        }
        for item in (rows or [])
    ]
    logger.info(f"Found {len(groups)} resource group(s) via ResourceContainers")
    return groups
