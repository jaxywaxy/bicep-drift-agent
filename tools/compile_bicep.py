"""
tools/compile_bicep.py

Compiles a Bicep file to ARM JSON using the az CLI.
Returns the parsed ARM template as a dict.

Phase 1 goal: get this returning real data before touching the agent loop.
"""

import json
import subprocess
import tempfile
import re
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)


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

        # Verify output file was created
        if not output_path.exists():
            raise RuntimeError(
                f"Bicep compilation succeeded but output file not created: {output_path}"
            )

        try:
            with open(output_path) as f:
                arm_template = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Failed to parse compiled Bicep output as JSON: {e}\n"
                f"File: {output_path}\n"
                f"This may indicate an issue with the az bicep build output."
            )
        except OSError as e:
            raise RuntimeError(f"Failed to read compiled Bicep output: {e}")

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


def extract_resources_from_arm(arm_template: dict, parameter_overrides: dict = None) -> List[Dict]:
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
    from pathlib import Path
    try:
        from .logger import setup_logging
    except ImportError:
        # When run as standalone script, add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent))
        from logger import setup_logging

    setup_logging(level="INFO")

    if len(sys.argv) < 2:
        logger.error("Usage: python compile_bicep.py <path-to-file.bicep>")
        sys.exit(1)

    template = compile_bicep(sys.argv[1])
    resources = extract_resources_from_arm(template)
    logger.info(f"Compiled OK. Found {len(resources)} resource(s)")
