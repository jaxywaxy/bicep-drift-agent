"""
tools/normalizer/expressions.py

ARM-expression resolver. Handles [parameters('x')], [variables('x')],
[format(...)], [concat(...)], [resourceId(...)], boolean and/or/not,
and best-effort evaluation of a handful of ARM string functions.

Unresolvable expressions are returned with a best-effort simplification so
smart matching downstream can still recover the resource.
"""

import hashlib
import json
import re

_EMBEDDED_REF_RE = re.compile(r"\b(variables|parameters)\(\s*'([^']+)'\s*\)")


def _eval_embedded_formats(s: str, parameters: dict, variables: dict) -> str:
    """Evaluate format('...', args) calls embedded ANYWHERE in a partially
    resolved string, when every argument resolves to a literal.

    A module child name compiles to e.g.
    "format('app-{0}-drift', parameters('environment'))/appsettings" - the
    site part is fully resolvable, but no earlier pass evaluates a format()
    that isn't the whole expression. Left unevaluated, the name can only be
    rescued by fuzzy matching, which mis-pairs same-type siblings
    (web vs appsettings). Calls whose arguments stay unresolved are left
    intact for smart matching.
    """
    if not isinstance(s, str) or "format(" not in s:
        return s
    out = s
    for _ in range(3):  # outer formats may reveal inner ones; few passes suffice
        changed = False
        search_from = 0
        while True:
            idx = out.find("format(", search_from)
            if idx == -1:
                break
            # balanced-paren extraction of the whole call
            depth, j = 0, idx + len("format")
            end = -1
            while j < len(out):
                if out[j] == "(":
                    depth += 1
                elif out[j] == ")":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
                j += 1
            if end == -1:
                break
            call = out[idx:end + 1]
            template, args = _parse_format_call(call, parameters, variables)
            resolvable = (
                template is not None
                and args
                and not any(ch in str(a) for a in args for ch in "([")
            )
            if resolvable:
                result = template
                for i, arg in enumerate(args):
                    result = result.replace(f"{{{i}}}", str(arg))
                out = out[:idx] + result + out[end + 1:]
                changed = True
                search_from = 0
            else:
                search_from = idx + 1
        if not changed:
            break
    return out


def _parse_format_call(call_str: str, parameters: dict, variables: dict) -> tuple:
    """
    Parse a format() function call and extract template + resolved arguments.

    Handles: format('template', arg1, arg2, ...)
    where arguments can be nested function calls. Properly handles escaped quotes
    in template strings (e.g., format('it\'s a name', arg)).

    Returns:
        Tuple (template_string, [resolved_args]) or (None, []) if parse fails
    """
    if not call_str.startswith("format"):
        return None, []

    paren_idx = call_str.find("(")
    if paren_idx == -1 or paren_idx + 1 >= len(call_str):
        return None, []

    content = call_str[paren_idx + 1:].strip()

    if not content.startswith("'"):
        return None, []

    template = ""
    i = 1  # Skip opening quote
    while i < len(content):
        char = content[i]
        if char == "\\" and i + 1 < len(content):
            template += char + content[i + 1]
            i += 2
        elif char == "'":
            break
        else:
            template += char
            i += 1
    else:
        return None, []

    args_part = content[i + 1:].strip()
    args_part = args_part.removesuffix(")")

    args = []
    if args_part:
        args = _split_function_arguments(args_part)

        resolved_args = []
        for arg in args:
            arg = arg.strip()
            if not arg:
                continue

            if arg.startswith("[") and arg.endswith("]"):
                arg = resolve_expression(arg, parameters, variables)
            elif arg.startswith("parameters("):
                param_match = re.match(r"parameters\s*\(\s*'([^']+)'\s*\)", arg)
                if param_match:
                    param_name = param_match.group(1)
                    if param_name in parameters:
                        arg = str(parameters[param_name])
            elif arg.startswith("variables("):
                var_match = re.match(r"variables\s*\(\s*'([^']+)'\s*\)", arg)
                if var_match:
                    var_name = var_match.group(1)
                    if var_name in variables:
                        arg = str(variables[var_name])
            elif "(" in arg and ")" in arg:
                arg = _resolve_function_call(arg, parameters, variables)
            elif len(arg) >= 2 and arg.startswith("'") and arg.endswith("'"):
                # Plain string literal: strip the ARM quotes. Otherwise a child
                # resource name like format('{0}/{1}', vnet, 'spoke-to-hub')
                # resolves to "vnet/'spoke-to-hub'" and never matches the live
                # child's name.
                arg = arg[1:-1]

            resolved_args.append(arg)

        args = resolved_args

    return template, args


def _split_function_arguments(args_str: str) -> list:
    """Split function arguments by comma, respecting nested parentheses and quotes."""
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
            arg = current.strip()
            if arg and arg != ",":
                args.append(arg)
            current = ""
        else:
            current += char

    if current.strip():
        args.append(current.strip())

    return args


def _as_bool(value):
    """Coerce a resolved expression value to a Python bool, or None if it isn't
    a definitive boolean (unresolved param names, dicts, etc.)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


def _resolve_boolean(inner: str, parameters: dict, variables: dict):
    """Evaluate ARM boolean functions and()/or()/not() when their arguments
    reduce to booleans. Returns True/False, or None when the expression is not
    one of these functions or an argument can't be resolved to a bool.

    Without this a compound resource condition like
      and(parameters('deployVirtualHub'), not(parameters('deployHubFirewall')))
    stays unresolvable, so flatten_resources conservatively KEEPS the gated-off
    resource and it false-flags as missing_in_azure. Nested calls (the not() here)
    resolve via the recursion back through resolve_expression. equals() is left
    out on purpose: an unresolved arg returns its bare name, which would compare
    equal to another bare name and manufacture a false True.
    """
    m = re.match(r"(and|or|not)\s*\((.*)\)\s*$", inner, re.DOTALL)
    if not m:
        return None
    fn = m.group(1)
    raw_args = _split_function_arguments(m.group(2))

    bools = []
    for arg in raw_args:
        arg = arg.strip()
        expr = arg if (arg.startswith("[") and arg.endswith("]")) else f"[{arg}]"
        b = _as_bool(resolve_expression(expr, parameters, variables))
        if b is None:
            return None  # unresolvable arg -> leave the whole condition unresolved
        bools.append(b)

    if not bools:
        return None
    if fn == "not":
        return (not bools[0]) if len(bools) == 1 else None
    if fn == "and":
        return all(bools)
    if fn == "or":
        return any(bools)
    return None


def _resolve_concat(concat_expr: str, parameters: dict, variables: dict) -> str:
    """Resolve [concat(...)] expressions from Bicep string interpolation.

    Example: [concat('st', parameters('environment'), 'drift', variables('uniqueSuffix'))]
    """
    match = re.match(r"concat\s*\((.*)\)", concat_expr)
    if not match:
        return concat_expr

    args_str = match.group(1)
    args = _split_function_arguments(args_str)

    result = ""
    for arg in args:
        arg = arg.strip().strip("'\"")
        if arg.startswith("parameters("):
            param_match = re.match(r"parameters\s*\(\s*'([^']+)'\s*\)", arg)
            if param_match:
                param_name = param_match.group(1)
                if param_name in parameters:
                    result += str(parameters[param_name])
                    continue
        elif arg.startswith("variables("):
            var_match = re.match(r"variables\s*\(\s*'([^']+)'\s*\)", arg)
            if var_match:
                var_name = var_match.group(1)
                if var_name in variables:
                    result += str(variables[var_name])
                    continue
        result += arg

    return result if result else concat_expr


def _resolve_resource_id(resource_id_expr: str, parameters: dict, variables: dict) -> str:
    """Resolve [resourceId(...)] expressions.

    Returns a formatted representation showing the resource type and name.
    """
    match = re.match(r"resourceId\s*\((.*)\)", resource_id_expr)
    if not match:
        return "resourceId-unresolved"

    args_str = match.group(1)
    args = _split_function_arguments(args_str)

    if len(args) < 2:
        return "resourceId-unresolved"

    resource_type = args[0].strip().strip("'\"")

    name_expr = args[1].strip()
    name = name_expr.strip("'\"")

    if name.startswith("format(") or name.startswith("parameters(") or name.startswith("variables("):
        if name.startswith("format("):
            template, template_args = _parse_format_call(name, parameters, variables)
            if template is not None:
                result = template
                for i, arg in enumerate(template_args):
                    result = result.replace(f"{{{i}}}", str(arg))
                name = result
        elif name.startswith("parameters("):
            param_match = re.match(r"parameters\s*\(\s*'([^']+)'\s*\)", name)
            if param_match:
                param_name = param_match.group(1)
                if param_name in parameters:
                    name = str(parameters[param_name])
        elif name.startswith("variables("):
            var_match = re.match(r"variables\s*\(\s*'([^']+)'\s*\)", name)
            if var_match:
                var_name = var_match.group(1)
                if var_name in variables:
                    name = str(variables[var_name])

    return f"resourceId('{resource_type}', '{name}')"


def _resolve_function_call(call: str, parameters: dict, variables: dict) -> str:
    """Resolve simple function calls like uniqueString(), copyIndex(), etc.

    Most of these can't be resolved without runtime context, but we can at
    least extract the essence.
    """
    call = call.strip()

    # uniqueString() — can't resolve at compile time, generate a consistent placeholder
    if call.startswith("uniqueString"):
        hash_val = hashlib.md5(call.encode()).hexdigest()[:8]
        return f"[{hash_val}]"

    # copyIndex() — can't resolve, leave as expression for smart matching
    if call.startswith("copyIndex"):
        return f"[{call}]"

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
            if "split" in arg:
                split_match = re.match(r"split\s*\(\s*([^,]+),", arg)
                if split_match:
                    str_arg = split_match.group(1).strip()
                    return _resolve_function_call(str_arg, parameters, variables)

    return call


def resolve_expression(expr: str, parameters: dict, variables: dict = None) -> str:
    """Resolve ARM expressions to actual values.

    Currently handles:
    - [parameters('name')] -> parameter value
    - [variables('name')] -> variable value
    - [format('string', param1, param2)] -> simple string formatting
    - [deployment().location] -> 'deployment-location' (placeholder)

    Unresolvable expressions are returned with a best-effort simplification.
    """
    if not expr or not isinstance(expr, str):
        return expr

    if variables is None:
        variables = {}

    expr = expr.strip()

    # Handle embedded expressions like "prefix[uniqueString(...)]"
    # This pattern appears when Bicep compiler outputs partially-resolved names
    if "[" in expr and "]" in expr and not (expr.startswith("[") and expr.endswith("]")):
        match = re.search(r"\[([^\[\]]+)\]", expr)
        if match:
            inner_expr = match.group(1)
            prefix = expr[:match.start()]
            suffix = expr[match.end():]

            if inner_expr.startswith("uniqueString"):
                hash_val = hashlib.md5(inner_expr.encode()).hexdigest()[:8]
                resolved = f"[{hash_val}]"
            elif inner_expr.startswith("format"):
                template, args = _parse_format_call(inner_expr, parameters, variables)
                if template is not None:
                    resolved = template
                    for i, arg in enumerate(args):
                        resolved = resolved.replace(f"{{{i}}}", str(arg))
                else:
                    resolved = f"[{inner_expr}]"
            else:
                resolved = resolve_expression(f"[{inner_expr}]", parameters, variables)

            return prefix + resolved + suffix
        return expr

    # Not an expression
    if not expr.startswith("[") or not expr.endswith("]"):
        return expr

    inner = expr[1:-1].strip()

    # Handle [parameters('name')] expressions. When the WHOLE expression is a
    # single parameter reference, return the value AS-IS (dict/list/int/bool),
    # not str() - otherwise an object param like `tags` becomes the string
    # "{'environment': 'dev', ...}" and never matches the live dict. Callers that
    # need a string (format/concat args) str() it themselves.
    param_match = re.match(r"parameters\s*\(\s*'([^']+)'\s*\)", inner)
    if param_match:
        param_name = param_match.group(1)
        if param_name in parameters and parameters[param_name] is not None:
            return parameters[param_name]
        return param_name

    # Handle [variables('name')] expressions (same: return value as-is)
    var_match = re.match(r"variables\s*\(\s*'([^']+)'\s*\)", inner)
    if var_match:
        var_name = var_match.group(1)
        if var_name in variables and variables[var_name] is not None:
            return variables[var_name]
        return var_name

    if inner.startswith("concat"):
        return _resolve_concat(inner, parameters, variables)

    if inner.startswith("format"):
        template, args = _parse_format_call(inner, parameters, variables)
        if template is not None:
            result = template
            for i, arg in enumerate(args):
                result = result.replace(f"{{{i}}}", str(arg))
            return result

    if "deployment()" in inner and "location" in inner:
        return "deployment-location"

    if "subscription()" in inner:
        if "tenantId" in inner:
            return "subscription-tenant-id"
        elif "subscriptionId" in inner:
            return "subscription-id"
        else:
            return "subscription-context"

    if inner.startswith("resourceId"):
        return _resolve_resource_id(inner, parameters, variables)

    # Handle [json('literal')] — Bicep's json() coerces a JSON literal to a real
    # typed value (commonly a numeric Container Apps CPU like json('0.25'), which
    # Azure returns as 0.25). Parse the literal so it compares as the typed value,
    # not the raw string "json('0.25')". Non-literal args (json(variables('x')))
    # don't match and fall through to the unresolved fallback below.
    if inner.startswith("json"):
        json_match = re.match(r"json\s*\(\s*'(.*)'\s*\)\s*$", inner, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except (ValueError, TypeError):
                pass

    # Boolean logic in conditions: and()/or()/not(). Resolve when the arguments
    # reduce to booleans, so a compound resource gate resolves to a definitive
    # True/False instead of staying unresolvable (which conservatively keeps a
    # gated-off resource and false-flags it as missing_in_azure).
    bool_result = _resolve_boolean(inner, parameters, variables)
    if bool_result is not None:
        return bool_result

    # Other expressions — resolve any EMBEDDED variables()/parameters() so that
    # identity extractors still see literal values even when the OUTER function
    # can't be resolved. e.g. a policy assignment's
    #   tenantResourceId('Microsoft.Authorization/policyDefinitions', variables('policyId'))
    # keeps its GUID literal, so policy.py can match it (otherwise the GUID stays
    # hidden behind variables(...) and the assignment is skipped -> false extra).
    return _eval_embedded_refs(inner, parameters, variables)


def _eval_embedded_refs(s: str, parameters: dict, variables: dict) -> str:
    """Replace embedded variables('x')/parameters('x') calls with their literal
    scalar value (quoted, since they sit inside a larger expression). Names that
    don't resolve to a scalar literal are left intact for smart matching.
    """
    if not isinstance(s, str) or ("variables(" not in s and "parameters(" not in s):
        return s

    def _sub(m: "re.Match[str]") -> str:
        src = variables if m.group(1) == "variables" else parameters
        val = src.get(m.group(2))
        if isinstance(val, str):
            return "'%s'" % val
        if isinstance(val, (int, float, bool)):
            return str(val)
        return m.group(0)  # unresolved / non-scalar — leave intact

    return _EMBEDDED_REF_RE.sub(_sub, s)
