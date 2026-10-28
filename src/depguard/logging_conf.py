"""Structured-safe standard logging configuration."""

from __future__ import annotations

import logging
import os


def configure_logging() -> None:
    """Configure concise logs without request headers or credential values."""
    level = os.getenv("DEPGUARD_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
