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
from pathlib import Path


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
            raise RuntimeError(
                f"az bicep build failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )

        with open(output_path) as f:
            arm_template = json.load(f)

    return arm_template


def extract_resources_from_arm(arm_template: dict) -> list[dict]:
    """
    Pull out the resources array from an ARM template and normalise minimally.

    ARM resources look like:
    {
        "type": "Microsoft.Compute/virtualMachines",
        "apiVersion": "2023-03-01",
        "name": "[parameters('vmName')]",
        "location": "[parameters('location')]",
        "properties": { ... }
    }

    This is the shape we'll compare against live state.
    """
    resources = arm_template.get("resources", [])

    # Flatten any nested resource collections (some templates use copy loops)
    # For now, return as-is. Normalisation is phase 2.
    return resources


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
