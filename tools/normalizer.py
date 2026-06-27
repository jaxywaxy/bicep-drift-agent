"""
tools/normalizer.py

Normalizes ARM template and live Azure resources to a common shape.
Handles ARM expression resolution and flattening nested resources.
"""

import re
from typing import Any


def extract_parameters(arm_template: dict) -> dict:
    """
    Extract parameters and their default values from an ARM template.

    Args:
        arm_template: Parsed ARM template dict

    Returns:
        Dict mapping parameter name -> default value
        e.g. {'vmName': 'my-vm', 'location': 'australiaeast'}
    """
    params = {}
    template_params = arm_template.get("parameters", {})

    for param_name, param_def in template_params.items():
        # Use default value if provided
        if "defaultValue" in param_def:
            params[param_name] = param_def["defaultValue"]
        # Otherwise mark as unknown (will leave expressions unresolved)
        else:
            params[param_name] = None

    return params


def _parse_format_call(call_str: str, parameters: dict, variables: dict) -> tuple:
    """
    Parse a format() function call and extract template + resolved arguments.

    Handles: format('template', arg1, arg2, ...)
    where arguments can be nested function calls.

    Args:
        call_str: The function call string without outer brackets
        parameters: Available parameters dict
        variables: Available variables dict

    Returns:
        Tuple (template_string, [resolved_args]) or (None, []) if parse fails
    """
    # Extract everything after 'format('
    if not call_str.startswith("format"):
        return None, []

    # Find the opening paren and extract content
    match = re.match(r"format\s*\(\s*'([^']*)'(.*)", call_str)
    if not match:
        return None, []

    template = match.group(1)
    args_part = match.group(2).strip()

    # Remove trailing closing paren
    if args_part.endswith(")"):
        args_part = args_part[:-1]

    # Parse arguments (separated by comma at the top level)
    args = []
    if args_part:
        args = _split_function_arguments(args_part)

        # Resolve each argument
        resolved_args = []
        for arg in args:
            arg = arg.strip()
            if not arg:
                continue

            # Try to resolve if it's an expression
            if arg.startswith("[") and arg.endswith("]"):
                arg = resolve_expression(arg, parameters, variables)
            elif "(" in arg and ")" in arg:
                # It's a function call - try to resolve it
                arg = _resolve_function_call(arg, parameters, variables)

            resolved_args.append(arg)

        args = resolved_args

    return template, args


def _split_function_arguments(args_str: str) -> list:
    """
    Split function arguments by comma, respecting nested parentheses and quotes.

    Args:
        args_str: String like ", arg1, arg2, arg3"

    Returns:
        List of argument strings
    """
    args = []
    current = ""
    depth = 0
    in_quote = False
    escape = False

    for char in args_str:
        if escape:
            current += char
            escape = False
            continue

        if char == "\\":
            escape = True
            current += char
            continue

        if char == "'" and not in_quote:
            in_quote = True
            current += char
        elif char == "'" and in_quote:
            in_quote = False
            current += char
        elif char == "(" and not in_quote:
            depth += 1
            current += char
        elif char == ")" and not in_quote:
            depth -= 1
            current += char
        elif char == "," and depth == 0 and not in_quote:
            # End of this argument
            arg = current.strip()
            if arg and arg != ",":
                args.append(arg)
            current = ""
        else:
            current += char

    # Don't forget the last argument
    if current.strip():
        args.append(current.strip())

    return args


def _resolve_function_call(call: str, parameters: dict, variables: dict) -> str:
    """
    Resolve simple function calls like uniqueString(), copyIndex(), etc.

    Most of these can't be resolved without runtime context, but we can
    at least extract the essence.

    Args:
        call: Function call string like "uniqueString(something)"
        parameters: Available parameters
        variables: Available variables

    Returns:
        Best-effort resolved string or the call as-is
    """
    call = call.strip()

    # uniqueString() — can't resolve, use a placeholder
    if call.startswith("uniqueString"):
        return "unique-string"

    # copyIndex() — can't resolve, use a placeholder
    if call.startswith("copyIndex"):
        return "copy-index"

    # substring() — try to extract at least the string part
    if call.startswith("substring"):
        match = re.match(r"substring\s*\(\s*([^,]+),", call)
        if match:
            str_arg = match.group(1).strip()
            return _resolve_function_call(str_arg, parameters, variables)

    # take() — extract the first argument
    if call.startswith("take"):
        match = re.match(r"take\s*\(\s*([^,]+),", call)
        if match:
            str_arg = match.group(1).strip()
            return _resolve_function_call(str_arg, parameters, variables)

    # last() — try to extract a meaningful value
    if call.startswith("last"):
        match = re.match(r"last\s*\(\s*([^)]+)\)", call)
        if match:
            arg = match.group(1).strip()
            # If it's a split() call, extract the string being split
            if "split" in arg:
                split_match = re.match(r"split\s*\(\s*([^,]+),", arg)
                if split_match:
                    str_arg = split_match.group(1).strip()
                    return _resolve_function_call(str_arg, parameters, variables)

    # Default: return the call as-is (can't resolve)
    return call


def extract_variables(arm_template: dict) -> dict:
    """
    Extract variables and their values from an ARM template.

    Args:
        arm_template: Parsed ARM template dict

    Returns:
        Dict mapping variable name -> value
    """
    variables = {}
    template_vars = arm_template.get("variables", {})

    if isinstance(template_vars, dict):
        for var_name, var_value in template_vars.items():
            # Recursively resolve variable values
            variables[var_name] = var_value

    return variables


def resolve_expression(expr: str, parameters: dict, variables: dict = None) -> str:
    """
    Resolve ARM expressions to actual values.

    Currently handles:
    - [parameters('name')] -> parameter value
    - [variables('name')] -> variable value
    - [format('string', param1, param2)] -> simple string formatting
    - [deployment().location] -> 'deployment-location' (placeholder)

    Unresolvable expressions are returned with a best-effort simplification.

    Args:
        expr: Expression string like "[parameters('vmName')]"
        parameters: Dict of {param_name: value}
        variables: Dict of {var_name: value}

    Returns:
        Resolved value or expression name if unresolvable
    """
    if not expr or not isinstance(expr, str):
        return expr

    if variables is None:
        variables = {}

    expr = expr.strip()

    # Not an expression
    if not expr.startswith("[") or not expr.endswith("]"):
        return expr

    # Strip outer brackets
    inner = expr[1:-1].strip()

    # Handle [parameters('name')] expressions
    param_match = re.match(r"parameters\s*\(\s*'([^']+)'\s*\)", inner)
    if param_match:
        param_name = param_match.group(1)
        if param_name in parameters and parameters[param_name] is not None:
            return str(parameters[param_name])
        # Unresolved parameter — return the name as fallback
        return param_name

    # Handle [variables('name')] expressions
    var_match = re.match(r"variables\s*\(\s*'([^']+)'\s*\)", inner)
    if var_match:
        var_name = var_match.group(1)
        if var_name in variables and variables[var_name] is not None:
            val = variables[var_name]
            if isinstance(val, str):
                return val
            else:
                return str(val)
        return var_name

    # Handle [format('template', arg1, arg2, ...)]
    if inner.startswith("format"):
        # Extract template string and arguments
        template, args = _parse_format_call(inner, parameters, variables)
        if template is not None:
            result = template
            for i, arg in enumerate(args):
                result = result.replace(f"{{{i}}}", str(arg))
            return result

    # Handle [deployment().location] — we can't resolve this without runtime context
    if "deployment()" in inner and "location" in inner:
        return "deployment-location"

    # Other expressions — try to extract a meaningful name
    # For complex expressions, just return a generic fallback
    return inner


def flatten_resources(arm_template: dict, parameters: dict = None, variables: dict = None) -> list[dict]:
    """
    Flatten ARM template resources, handling nested deployments and copy loops.

    For Phase 1, we:
    - Extract top-level resources
    - Recursively flatten nested deployments
    - Resolve expression-based names using parameters and variables

    Args:
        arm_template: Parsed ARM template
        parameters: Resolved parameters dict (from extract_parameters)
        variables: Resolved variables dict (from extract_variables)

    Returns:
        Flat list of normalized resources
    """
    if parameters is None:
        parameters = extract_parameters(arm_template)
    if variables is None:
        variables = extract_variables(arm_template)

    flattened = []
    resources = arm_template.get("resources", [])

    # Handle both array format [{}] and dict format {name: {}}
    resource_list = []
    if isinstance(resources, dict):
        resource_list = list(resources.values())
    elif isinstance(resources, list):
        resource_list = resources
    else:
        resource_list = []

    for resource in resource_list:
        # Skip non-dict resources (can happen with copy loops, etc.)
        if not isinstance(resource, dict):
            continue

        normalized = _normalize_resource(resource, parameters, variables)
        flattened.append(normalized)

        # If this is a nested deployment, extract its resources
        if resource.get("type") == "Microsoft.Resources/deployments":
            nested_template = resource.get("properties", {}).get("template", {})
            if nested_template:
                nested_params = _extract_nested_parameters(
                    resource.get("properties", {}), parameters, variables
                )
                nested_vars = extract_variables(nested_template)
                nested_resources = flatten_resources(nested_template, nested_params, nested_vars)
                flattened.extend(nested_resources)

    return flattened


def _normalize_resource(resource: dict, parameters: dict, variables: dict = None) -> dict:
    """
    Normalize a single resource, resolving expression-based fields.

    Args:
        resource: ARM resource object
        parameters: Resolved parameters dict
        variables: Resolved variables dict

    Returns:
        Normalized resource with resolved names/locations
    """
    if variables is None:
        variables = {}

    normalized = {
        "type": resource.get("type", ""),
        "name": resolve_expression(resource.get("name", ""), parameters, variables),
        "location": resolve_expression(resource.get("location"), parameters, variables) or "unknown",
        "apiVersion": resource.get("apiVersion", ""),
        "tags": resource.get("tags") or {},
        "sku": resource.get("sku"),
        "kind": resource.get("kind"),
    }

    # Keep original resource for debugging if needed
    normalized["_raw"] = resource

    return normalized


def _extract_nested_parameters(deployment_props: dict, parent_params: dict, parent_vars: dict = None) -> dict:
    """
    Extract parameters passed to a nested deployment.

    Nested deployments pass parameters via properties.parameters.
    We need to resolve those against the parent's context.

    Args:
        deployment_props: The 'properties' dict of the deployment resource
        parent_params: Parent template's resolved parameters
        parent_vars: Parent template's resolved variables

    Returns:
        Dict of nested parameters
    """
    if parent_vars is None:
        parent_vars = {}

    nested_params = {}
    params_section = deployment_props.get("parameters", {})

    for param_name, param_spec in params_section.items():
        # param_spec can be {"value": ...} or just a value
        if isinstance(param_spec, dict) and "value" in param_spec:
            value = param_spec["value"]
            # Resolve if it's an expression
            if isinstance(value, str):
                value = resolve_expression(value, parent_params, parent_vars)
            nested_params[param_name] = value
        else:
            nested_params[param_name] = param_spec

    return nested_params


def normalize_live_resources(live_resources: list[dict]) -> list[dict]:
    """
    Normalize live Azure resources to match ARM template shape.

    Args:
        live_resources: Output from get_live_state()

    Returns:
        List of normalized resources
    """
    normalized = []

    for resource in live_resources:
        normalized_res = {
            "type": resource.get("type", ""),
            "name": resource.get("name", ""),
            "location": resource.get("location", "unknown"),
            "tags": resource.get("tags") or {},
            "sku": resource.get("sku"),
            "kind": resource.get("kind"),
            "apiVersion": "",  # Not available in live state
            "_raw": resource,
        }
        normalized.append(normalized_res)

    return normalized


def resource_key(resource: dict) -> tuple[str, str]:
    """
    Generate a stable key for resource matching.

    Key is (type, name) normalized for comparison.

    Args:
        resource: Normalized resource dict

    Returns:
        Tuple (normalized_type, normalized_name)
    """
    res_type = resource.get("type", "").lower().strip()
    res_name = resource.get("name", "").lower().strip()

    return (res_type, res_name)
