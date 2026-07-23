"""
tools/live_state

Queries live Azure state for all resources in a resource group.
Uses DefaultAzureCredential — works with `az login` or a service principal.

Split from the old single-file tools/get_live_state.py into a package:
- common: retry/backoff, RG selector helpers, id → RG, dedupe/qualification
- resource_graph: base RG query + fallback + augmentation orchestrator
- collectors/*: one file per ARM-REST resource family (locks, cosmos, backup,
  cognitive, aci, appservice, extensions, peerings, cross_sub, defender,
  data_plane)

The public API is preserved on the top-level module so callers keep using
`from tools.get_live_state import ...` (via the shim in tools/get_live_state.py)
or `from tools.live_state import ...` directly.
"""

# Re-exports are intentional (tests reach for private names via the top-level
# module). Silence F401 for this facade.
from .collectors.aci import _normalize_aci_container_groups  # noqa: F401
from .collectors.appservice import _expand_appservice_config  # noqa: F401
from .collectors.backup import (  # noqa: F401
    _query_backup_children,
    _query_backup_policies,
    _shape_backup_config,
    _shape_backup_policy,
)
from .collectors.cognitive import (  # noqa: F401
    _cognitive_child,
    _cognitive_deployment_child,
    _is_system_managed_rai_policy,
    _query_cognitive_deployments,
)
from .collectors.cosmos import (  # noqa: F401
    _normalize_cosmos_account_locations,
    _query_cosmos_children,
)
from .collectors.cross_sub import fetch_cross_subscription_resources  # noqa: F401
from .collectors.data_plane import (  # noqa: F401
    _CHILD_EXPANSION_SPECS,
    _GRANDCHILD_EXPANSION_SPECS,
    _RECORDSET_SPECS,
    _expand_data_plane_children,
    _skip_apex_ns_soa,
    _skip_builtin_hub_route_table,
    _skip_default_consumer_group,
)
from .collectors.defender import fetch_declared_defender_pricings  # noqa: F401
from .collectors.extensions import (  # noqa: F401
    _DCR_ASSOCIATION_PARENT_TYPES,
    _DIAGNOSTIC_PARENT_TYPES,
    _EXTENSION_EXPANSION_SPECS,
    _EXTENSION_TYPES_LOWER,
    _expand_diagnostic_settings,
    _expand_extension_resources,
    qualify_diagnostic_setting_names,
    qualify_extension_resource_names,
)
from .collectors.locks import _query_locks  # noqa: F401
from .collectors.peerings import _expand_vnet_peerings  # noqa: F401
from .common import (  # noqa: F401
    _ALL_RG_SELECTORS,
    _RG_NAME_RE,
    _dedupe_resources_by_id,
    _extract_resource_group_from_id,
    _filter_by_rg_selector,
    _has_unresolved,
    _is_rg_glob,
    _kql_rg_filter,
    _qualify_child_resource_names,
    _rg_of,
    retry_with_backoff,
)
from .resource_graph import (  # noqa: F401
    HAS_RESOURCE_GRAPH,
    _augment_untracked_resources,
    _get_live_state_fallback,
    get_live_state,
)

__all__ = [
    # Primary entry points
    "get_live_state",
    "fetch_cross_subscription_resources",
    "fetch_declared_defender_pricings",
    "qualify_extension_resource_names",
    "qualify_diagnostic_setting_names",
    "retry_with_backoff",
]
