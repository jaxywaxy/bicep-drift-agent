"""
tools/normalizer/template.py

Extract parameters and variables from an ARM template. Handles nested
deployments (their parameters resolve against the parent's context).
"""

from .expressions import resolve_expression


def extract_parameters(arm_template: dict) -> dict:
    """Extract parameters and their default values from an ARM template.

    Returns a dict mapping parameter name -> default value (or None when the
    template declares no default).
    """
    params = {}
    for param_name, param_def in arm_template.get("parameters", {}).items():
        params[param_name] = param_def.get("defaultValue")
    return params


def extract_variables(arm_template: dict, parameters: dict = None) -> dict:
    """Extract variables and their values from an ARM template.

    Recursively resolves variable expressions that reference parameters.
    """
    if parameters is None:
        parameters = extract_parameters(arm_template)

    variables = {}
    template_vars = arm_template.get("variables", {})

    if isinstance(template_vars, dict):
        for var_name, var_value in template_vars.items():
            if isinstance(var_value, str) and (var_value.startswith("[") and var_value.endswith("]")):
                variables[var_name] = resolve_expression(var_value, parameters, {})
            else:
                variables[var_name] = var_value

    return variables


def _extract_nested_parameters(deployment_props: dict, parent_params: dict, parent_vars: dict = None) -> dict:
    """Extract parameters passed to a nested deployment.

    Nested deployments pass parameters via properties.parameters. We resolve
    those against the parent's context.
    """
    if parent_vars is None:
        parent_vars = {}

    nested_params = {}
    for param_name, param_spec in deployment_props.get("parameters", {}).items():
        # param_spec can be {"value": ...} or just a value
        if isinstance(param_spec, dict) and "value" in param_spec:
            value = param_spec["value"]
            if isinstance(value, str):
                value = resolve_expression(value, parent_params, parent_vars)
            nested_params[param_name] = value
        else:
            nested_params[param_name] = param_spec

    return nested_params
