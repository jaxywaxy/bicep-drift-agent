"""
tools/get_live_state.py

Compatibility shim. The implementation moved to tools/live_state/ (a package
split by resource family for maintainability). This module re-exports the full
public + private-but-imported surface, so callers keep using
`from tools.get_live_state import ...` unchanged.

New code should import from `tools.live_state` directly.
"""

from .live_state import *  # noqa: F401,F403

# `from tools.live_state import *` only exports the __all__ list. The test suite
# reaches for several private names via `from tools.get_live_state import _foo`,
# so re-bind them explicitly.
from .live_state import (  # noqa: F401
    _ALL_RG_SELECTORS,
    _augment_untracked_resources,
    _CHILD_EXPANSION_SPECS,
    _cognitive_child,
    _cognitive_deployment_child,
    _dedupe_resources_by_id,
    _DCR_ASSOCIATION_PARENT_TYPES,
    _DIAGNOSTIC_PARENT_TYPES,
    _EXTENSION_EXPANSION_SPECS,
    _EXTENSION_TYPES_LOWER,
    _expand_appservice_config,
    _expand_data_plane_children,
    _expand_diagnostic_settings,
    _expand_extension_resources,
    _expand_vnet_peerings,
    _extract_resource_group_from_id,
    _filter_by_rg_selector,
    _get_live_state_fallback,
    _GRANDCHILD_EXPANSION_SPECS,
    _has_unresolved,
    _is_rg_glob,
    _is_system_managed_rai_policy,
    _kql_rg_filter,
    _normalize_aci_container_groups,
    _normalize_cosmos_account_locations,
    _qualify_child_resource_names,
    _query_backup_children,
    _query_backup_policies,
    _query_cognitive_deployments,
    _query_cosmos_children,
    _query_locks,
    _RECORDSET_SPECS,
    _rg_of,
    _RG_NAME_RE,
    _shape_backup_config,
    _shape_backup_policy,
    _skip_apex_ns_soa,
    _skip_builtin_hub_route_table,
    _skip_default_consumer_group,
    HAS_RESOURCE_GRAPH,
)
