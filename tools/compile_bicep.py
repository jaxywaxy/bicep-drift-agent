"""
tools/compile_bicep.py

Compiles a Bicep file to ARM JSON using the az CLI.
Returns the parsed ARM template as a dict.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import json
import subprocess
import tempfile
import os
import re
from pathlib import Path


def _sanitize_error_message(error_text: str) -> str:
    """Remove potential secrets from error messages."""
    sanitized = error_text
    # Redact API keys (various formats)
    sanitized = re.sub(r'sk-[a-zA-Z0-9_\-]{40,}', '***API_KEY_REDACTED***', sanitized)
    # Redact Azure connection strings
    sanitized = re.sub(r'DefaultEndpointsProtocol=[^;]+;[^"]*', '***CONNECTION_STRING_REDACTED***', sanitized)
    # Redact environment variable values
    sanitized = re.sub(r'(AZURE_[A-Z_]+)=([^\s\'"]+)', r'\1=***REDACTED***', sanitized)
    return sanitized


def compile_bicep(bicep_file_path: str) -> dict:
    """
    Compile a Bicep file to ARM JSON.

    Shells out to `az bicep build` — requires Azure CLI with Bicep extension.
    Check with: az bicep version

    Args:
        bicep_file_path: Absolute or relative path to the .bicep file.

    Returns:
        Parsed ARM template as a dict.

    Raises:
        FileNotFoundError: If the Bicep file doesn't exist.
        RuntimeError: If az bicep build fails.
    """
    bicep_path = Path(bicep_file_path).resolve()

    if not bicep_path.exists():
        raise FileNotFoundError(f"Bicep file not found: {bicep_path}")

    if bicep_path.suffix != ".bicep":
        raise ValueError(f"Expected a .bicep file, got: {bicep_path.suffix}")

    # Write compiled ARM JSON to a temp file so we don't pollute the source dir
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "compiled.json"

        result = subprocess.run(
            ["az", "bicep", "build", "--file", str(bicep_path), "--outfile", str(output_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            safe_stdout = _sanitize_error_message(result.stdout)
            safe_stderr = _sanitize_error_message(result.stderr)
            raise RuntimeError(
                f"az bicep build failed:\nSTDOUT: {safe_stdout}\nSTDERR: {safe_stderr}"
            )

        with open(output_path) as f:
            arm_template = json.load(f)

    return arm_template


def detect_deployment_scope(arm_template: dict) -> str:
    """
    Detect the deployment scope from an ARM template.

    Args:
        arm_template: Parsed ARM template dict

    Returns:
        "subscription" or "resource_group" (default)
    """
    schema = arm_template.get("$schema", "")

    # Subscription-scoped templates have specific schema patterns
    if "subscriptionDeploymentTemplate" in schema:
        return "subscription"

    # Check metadata for scope hint
    metadata = arm_template.get("metadata", {})
    if metadata.get("targetScope") == "subscription":
        return "subscription"

    # Default to resource group
    return "resource_group"


def extract_resources_from_arm(arm_template: dict, parameter_overrides: dict = None) -> list[dict]:
    """
    Extract and normalize resources from an ARM template.

    Handles:
    - Parameter resolution (e.g., [parameters('vmName')] → actual value)
    - Nested deployment flattening
    - Shape normalization for comparison against live state

    Args:
        arm_template: Parsed ARM template dict
        parameter_overrides: Optional dict of parameter values to override defaults

    Returns:
        List of normalized resource dicts
    """
    from .normalizer import flatten_resources, extract_parameters

    parameters = extract_parameters(arm_template)
    # Override with provided values (e.g., from environment or CLI)
    if parameter_overrides:
        parameters.update(parameter_overrides)

    normalized = flatten_resources(arm_template, parameters)
    return normalized


if __name__ == "__main__":
    # Quick smoke test — point at any .bicep file you have handy
    import sys

    if len(sys.argv) < 2:
        print("Usage: python compile_bicep.py <path-to-file.bicep>")
        sys.exit(1)

    template = compile_bicep(sys.argv[1])
    resources = extract_resources_from_arm(template)

    print(f"\nCompiled OK. Found {len(resources)} resource(s):\n")
    for r in resources:
        print(f"  {r.get('type')} — {r.get('name')}")

    print("\nFull ARM JSON:")
    print(json.dumps(template, indent=2))
