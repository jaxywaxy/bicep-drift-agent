"""
Centralized logging configuration for drift detection.

Usage:
    from tools.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Processing resource...")
    logger.debug("Detailed trace info")
    logger.warning("Unexpected state")
    logger.error("Failed to process")
"""

import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: str = None) -> None:
    """
    Configure root logger with console (and optional file) handlers.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for file handler
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "[%(levelname)s] %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        log_path = Path(log_file).parent
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
