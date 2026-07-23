"""
tools/normalizer

Normalizes ARM template and live Azure resources to a common shape.

Split into three sibling modules:
- expressions: ARM-expression resolver (parameters/variables/format/concat/…)
- template: parameter/variable extraction from an ARM template
- flatten: resource flattening + normalisation

The public surface is re-exported here so callers keep using
`from tools.normalizer import ...`.
"""

# Re-exports are intentional (tests and internal callers reach for a few
# private names via the top-level module). Silence F401 for this facade.
from .expressions import (  # noqa: F401
    _EMBEDDED_REF_RE,
    _as_bool,
    _eval_embedded_formats,
    _eval_embedded_refs,
    _parse_format_call,
    _resolve_boolean,
    _resolve_concat,
    _resolve_function_call,
    _resolve_resource_id,
    _split_function_arguments,
    resolve_expression,
)
from .flatten import (  # noqa: F401
    _normalize_resource,
    _resolve_value,
    flatten_resources,
    normalize_live_resources,
    resource_key,
)
from .template import (  # noqa: F401
    _extract_nested_parameters,
    extract_parameters,
    extract_variables,
)

__all__ = [
    # expressions
    "resolve_expression",
    # template
    "extract_parameters",
    "extract_variables",
    # flatten
    "flatten_resources",
    "normalize_live_resources",
    "resource_key",
]
