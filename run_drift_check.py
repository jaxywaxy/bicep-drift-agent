"""
run_drift_check.py

CLI wrapper around Phase 1. The pipeline itself lives in
`orchestration/phase1.py`; this file is argument handling and exit codes.

Usage:
    python run_drift_check.py <bicep-file> <resource-group>

Example:
    python run_drift_check.py ./infra/main.bicep my-resource-group
"""

import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from orchestration.phase1 import run
from tools.get_live_state import ScopeNotFoundError
from tools.logger import get_logger, setup_logging

logger = get_logger(__name__)


def main():
    # Initialize logging (DRIFT_LOG_LEVEL overrides the default)
    from tools.config import LOG_LEVEL, validate_config
    setup_logging(level=LOG_LEVEL)
    for warning in validate_config():
        logger.warning(f"Config: {warning}")

    if len(sys.argv) < 3:
        logger.error("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    if not Path(bicep_file).exists():
        logger.error(f"Bicep file not found: {bicep_file}")
        sys.exit(1)

    if not bicep_file.endswith(".bicep"):
        logger.error(f"Expected .bicep file, got: {bicep_file}")
        sys.exit(1)

    try:
        run(bicep_file, resource_group)
    except ScopeNotFoundError as e:
        # Exit 2, not 1: a scope that cannot be read is a targeting/config
        # failure, and CI should be able to tell it apart from both a real
        # error (1) and a clean scan (0) without parsing logs.
        logger.error(f"Scope not found: {e}")
        sys.exit(2)
    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Value error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
