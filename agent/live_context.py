"""
agent/live_context.py

Pulls the small, relevant slice of live Azure state (public-network access, TLS
floors, sku.capacity, ...) onto each finding so the classifier and the prompt can
reason about actual exposure instead of just the diff. LIVE_CONTEXT_PROPERTIES is
the allowlist of paths worth surfacing.
"""

from typing import Any

from .findings import DriftFinding


class LiveContextMixin:
    # Live properties attached to every finding as `live_context`. Deliberately
    # a short allowlist, not the whole resource: a single live payload can run
    # to thousands of tokens (the AI account's callRateLimit alone is ~8k), and
    # the analysis only needs the state that changes its ANSWER -
    #   - a sibling that BOUNDS the blast radius of the drifted property
    #     (publicNetworkAccess Disabled while networkAccessPolicy opened to
    #     AllowAll: real drift, bounded exposure - stating one without the other
    #     overstates it),
    #   - or state that decides whether the remediation is even POSSIBLE
    #     (sku.capacity 0 means encryptionAtHost can be written; diskState /
    #     managedBy say whether a disk is attached and therefore in use).
    # Paths are dotted and resolved leniently - a resource type that has none of
    # them simply gets an empty context.
    # NOT in this list, deliberately: `zones`. It is a drift TARGET, not
    # context - it bounds no blast radius and decides no remediation. Carrying
    # it made a VMSS finding (whose zones never drifted) arrive with
    # zones: ["1","2","3"] in its payload, and the analysis reported in its
    # TL;DR that "both resources drifted a zones value that is immutable" -
    # contradicting its own body two sections later. Anything whose live value
    # could be mistaken for a mismatch belongs in details or nowhere.
    LIVE_CONTEXT_PROPERTIES = (
        "sku.capacity",
        "properties.provisioningState",
        "properties.publicNetworkAccess",
        "properties.networkAccessPolicy",
        "properties.diskState",
        "properties.managedBy",
        "properties.encryption.type",
        "properties.minimumTlsVersion",
        "properties.allowBlobPublicAccess",
        "properties.enableRbacAuthorization",
        "properties.enablePurgeProtection",
        "properties.disableLocalAuth",
    )

    @staticmethod
    def _index_live_resources(live_resources) -> dict[str, dict[str, Any]]:
        """Index live resources by resource ID and by (type, name).

        Both keys because a finding may carry only one of them: property drift
        records reliably have a resource_id from attribution, while a
        missing/extra record may only have type+name.
        """
        index: dict[str, dict[str, Any]] = {}
        for resource in live_resources or []:
            if not isinstance(resource, dict):
                continue
            resource_id = resource.get("id")
            if resource_id:
                index[str(resource_id).lower()] = resource
            rtype, name = resource.get("type"), resource.get("name")
            if rtype and name:
                index[f"{str(rtype).lower()}/{str(name).lower()}"] = resource
        return index

    def _extract_live_context(
        self,
        finding: DriftFinding,
        live_by_key: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Pull the LIVE_CONTEXT_PROPERTIES present on this finding's resource.

        Only properties that did NOT drift are included - a value already in
        `details` would just be repeated at a second, contradictory-looking
        path. Returns None when nothing matched, so a resource with no relevant
        siblings adds nothing to the prompt.
        """
        if not live_by_key:
            return None
        live = None
        if finding.resource_id:
            live = live_by_key.get(finding.resource_id.lower())
        if live is None:
            key = f"{(finding.resource_type or '').lower()}/{(finding.resource_name or '').lower()}"
            live = live_by_key.get(key)
        if live is None:
            return None

        changed = (finding.details or {}).get("changed_properties") or {}
        changed_paths = {str(p).lower() for p in changed} if isinstance(changed, dict) else set()

        context: dict[str, Any] = {}
        for path in self.LIVE_CONTEXT_PROPERTIES:
            if path.lower() in changed_paths:
                continue
            value = self._resolve_path(live, path)
            if value is not None:
                context[path] = value
        return context or None

    @staticmethod
    def _resolve_path(resource: dict[str, Any], path: str) -> Any:
        node: Any = resource
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
            if node is None:
                return None
        return node
