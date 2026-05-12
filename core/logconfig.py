"""
Logging configuration for tshark-tool.

Provides a consistent logging setup across all modules, replacing
bare print() calls with structured logging.
"""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure the root logger once.

    Args:
        level: Logging level (default: INFO).

    Returns:
        Configured root logger instance.
    """
    logger = logging.getLogger("tshark_tool")
    logger.setLevel(level)

    # Avoid duplicate handlers on re-import
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger of the tshark_tool namespace.

    Usage:
        logger = get_logger(__name__)
        logger.info("Processing %s", path)
    """
    return logging.getLogger(f"tshark_tool.{name}")
