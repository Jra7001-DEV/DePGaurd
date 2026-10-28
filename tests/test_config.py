"""Tests for validated environment configuration and logging setup."""

from __future__ import annotations

import logging

from depguard.logging_conf import configure_logging


def test_logging_configuration_reads_level(monkeypatch) -> None:
    monkeypatch.setenv("DEPGUARD_LOG_LEVEL", "WARNING")
    configure_logging()
    assert logging.getLogger().level == logging.WARNING
